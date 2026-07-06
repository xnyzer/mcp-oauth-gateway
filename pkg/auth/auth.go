package auth

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templateFS embed.FS

type AuthRouter struct {
	passwordHash         []string
	providers            []Provider
	loginTemplate        *template.Template
	unauthorizedTemplate *template.Template
	errorTemplate        *template.Template
	settingsTemplate     *template.Template
	// When true, do not auto-redirect to the sole provider even if
	// there is only one provider and no password is set.
	noProviderAutoSelect bool
	// userInfoFields is a list of top-level keys to retain from the
	// provider's userinfo response. When non-empty, all other keys are
	// stripped before the data is stored in the session cookie. This
	// prevents oversized cookies when the provider returns many claims.
	userInfoFields []string
	// users persists the operator account + passkeys; nil disables
	// passkey support and the settings page (SPEC §1.12).
	users    repository.UserStorage
	webAuthn *webauthn.WebAuthn
	logger   *zap.Logger
}

// Config carries all options for the user-authentication surface
// (SPEC §1.12).
type Config struct {
	// PasswordHashes are the bcrypt hashes accepted for password login
	// (the env-config source of truth — decision F-005e).
	PasswordHashes       []string
	NoProviderAutoSelect bool
	UserInfoFields       []string
	Providers            []Provider
	// Users persists the operator account and passkeys. nil disables
	// passkey login and the settings page.
	Users repository.UserStorage
	// ExternalURL is the normalized issuer (SPEC §0); it derives the
	// WebAuthn RP ID and allowed origin. Required when Users is set.
	ExternalURL string
	Logger      *zap.Logger
}

func NewAuthRouter(cfg Config) (*AuthRouter, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/login.html", "templates/webauthn_script.html")
	if err != nil {
		return nil, err
	}

	unauthorizedTmpl, err := template.ParseFS(templateFS, "templates/unauthorized.html")
	if err != nil {
		return nil, err
	}

	errorTmpl, err := template.ParseFS(templateFS, "templates/error.html")
	if err != nil {
		return nil, err
	}

	settingsTmpl, err := template.ParseFS(templateFS, "templates/settings.html", "templates/webauthn_script.html")
	if err != nil {
		return nil, err
	}

	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	var webAuthn *webauthn.WebAuthn
	if cfg.Users != nil {
		webAuthn, err = newWebAuthn(cfg.ExternalURL)
		if err != nil {
			return nil, err
		}
	}

	return &AuthRouter{
		passwordHash:         cfg.PasswordHashes,
		providers:            cfg.Providers,
		loginTemplate:        tmpl,
		unauthorizedTemplate: unauthorizedTmpl,
		errorTemplate:        errorTmpl,
		settingsTemplate:     settingsTmpl,
		noProviderAutoSelect: cfg.NoProviderAutoSelect,
		userInfoFields:       cfg.UserInfoFields,
		users:                cfg.Users,
		webAuthn:             webAuthn,
		logger:               cfg.Logger,
	}, nil
}

const (
	LoginEndpoint        = "/.auth/login"
	LogoutEndpoint       = "/.auth/logout"
	OIDCAuthEndpoint     = "/.auth/oidc"
	OIDCCallbackEndpoint = "/.auth/oidc/callback"

	// Passkey ceremonies and the settings page (SPEC §1.12). The login
	// ceremony is public; registration and settings are session-gated.
	WebAuthnLoginBeginEndpoint       = "/.auth/webauthn/login/begin"
	WebAuthnLoginFinishEndpoint      = "/.auth/webauthn/login/finish"
	WebAuthnRegisterBeginEndpoint    = "/.auth/webauthn/register/begin"
	WebAuthnRegisterFinishEndpoint   = "/.auth/webauthn/register/finish"
	SettingsEndpoint                 = "/.auth/settings"
	SettingsPasswordEndpoint         = "/.auth/settings/password"
	SettingsCredentialDeleteEndpoint = "/.auth/settings/credentials/delete"

	PasswordProvider = "password"
	// PasswordUserID is the legacy subject used when no user store is
	// configured (programmatic use); with a store, the persisted user's ID
	// is the subject (SPEC §1.7).
	PasswordUserID = "password_user"

	// defaultUsername names the single operator account (FR-4); shown by
	// authenticators during passkey registration.
	defaultUsername = "admin"

	SessionKeyAuthorized  = "authorized"
	SessionKeyRedirectURL = "redirect_url"
	SessionKeyOAuthState  = "oauth_state"
	SessionKeyUserID      = "user_id"
	SessionKeyUserInfo    = "user_info"

	sessionKeyWebAuthnLogin        = "webauthn_login"
	sessionKeyWebAuthnRegistration = "webauthn_registration"
)

func (a *AuthRouter) SetupRoutes(router gin.IRouter) {
	router.GET(LoginEndpoint, a.handleLogin)
	router.POST(LoginEndpoint, a.handleLoginPost)
	router.GET(LogoutEndpoint, a.handleLogout)
	if a.webAuthn != nil {
		router.POST(WebAuthnLoginBeginEndpoint, a.handleWebAuthnLoginBegin)
		router.POST(WebAuthnLoginFinishEndpoint, a.handleWebAuthnLoginFinish)
		router.POST(WebAuthnRegisterBeginEndpoint, a.RequireAuth(), a.handleWebAuthnRegisterBegin)
		router.POST(WebAuthnRegisterFinishEndpoint, a.RequireAuth(), a.handleWebAuthnRegisterFinish)
		router.GET(SettingsEndpoint, a.RequireAuth(), a.handleSettings)
		router.POST(SettingsPasswordEndpoint, a.RequireAuth(), a.handleSettingsPassword)
		router.POST(SettingsCredentialDeleteEndpoint, a.RequireAuth(), a.handleSettingsCredentialDelete)
	}
	for _, provider := range a.providers {
		router.GET(provider.RedirectURL(), func(c *gin.Context) {
			session := sessions.Default(c)
			state := session.Get(SessionKeyOAuthState)
			if state == nil {
				a.renderError(c, errors.New("OAuth state is missing"))
				return
			}
			token, err := provider.Exchange(c, state.(string))
			if err != nil {
				a.renderError(c, err)
				return
			}
			ok, user, userInfo, err := provider.Authorization(c, token)
			if err != nil {
				a.renderError(c, err)
				return
			}
			if !ok {
				a.renderUnauthorized(c, user, provider.Name())
				return
			}
			session.Set(SessionKeyAuthorized, true)
			session.Set(SessionKeyUserID, user)
			if userInfo != nil {
				if len(a.userInfoFields) > 0 {
					userInfo = filterUserInfo(userInfo, a.userInfoFields)
				}
				if userInfoJSON, err := json.Marshal(userInfo); err == nil {
					session.Set(SessionKeyUserInfo, string(userInfoJSON))
				}
			}
			redirectURL := session.Get(SessionKeyRedirectURL)
			if redirectURL != nil {
				session.Delete(SessionKeyRedirectURL)
			}
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}

			if redirectURL == nil {
				c.Redirect(http.StatusFound, "/")
			} else {
				c.Redirect(http.StatusFound, redirectURL.(string))
			}
		})

		router.GET(provider.AuthURL(), func(c *gin.Context) {
			session := sessions.Default(c)

			state, err := utils.GenerateState()
			if err != nil {
				a.renderError(c, err)
				return
			}
			url, err := provider.AuthCodeURL(state)
			if err != nil {
				a.renderError(c, err)
				return
			}
			session.Set(SessionKeyOAuthState, state)
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, url)
		})
	}
}

func (a *AuthRouter) handleLogin(c *gin.Context) {
	if c.Request.Method == "POST" {
		a.handleLoginPost(c)
		return
	}
	// Auto-redirect to the sole provider if enabled and no password is set
	if !a.noProviderAutoSelect && len(a.passwordHash) == 0 && len(a.providers) == 1 {
		c.Redirect(http.StatusFound, a.providers[0].AuthURL())
		return
	}
	a.renderLogin(c, "")
}

func (a *AuthRouter) handleLoginPost(c *gin.Context) {
	password := c.PostForm("password")
	if password == "" {
		a.renderLogin(c, "Password is required")
		return
	}

	// The bcrypt comparison always runs first so the disabled-fallback
	// check below cannot be distinguished by response timing (SR-6).
	var isValid bool
	for _, hash := range a.passwordHash {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err == nil {
			isValid = true
			break
		}
	}
	if !isValid {
		a.renderLogin(c, "Invalid password")
		return
	}

	// Bootstrap or load the operator account (SPEC §1.12); the subject
	// becomes the persisted user ID (SPEC §1.7).
	subject := PasswordUserID
	if a.users != nil {
		user, passkeyCount, err := a.ensureUser(c.Request.Context())
		if err != nil {
			a.renderError(c, err)
			return
		}
		// Uniform error when the password fallback is disabled — the same
		// message as a wrong password (SR-6, no state enumeration).
		if !a.isPasswordLoginActive(user, passkeyCount) {
			a.renderLogin(c, "Invalid password")
			return
		}
		subject = user.ID
	}

	session := sessions.Default(c)
	session.Set(SessionKeyAuthorized, true)
	session.Set(SessionKeyUserID, subject)
	redirectURL := session.Get(SessionKeyRedirectURL)
	if redirectURL != nil {
		session.Delete(SessionKeyRedirectURL)
	}
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}

	if redirectURL == nil {
		c.Redirect(http.StatusFound, "/")
	} else {
		c.Redirect(http.StatusFound, redirectURL.(string))
	}
}

// ensureUser loads the operator account, creating it on the first
// successful password login (bootstrap, SPEC §1.12). It returns the number
// of registered passkeys alongside.
func (a *AuthRouter) ensureUser(ctx context.Context) (*models.User, int, error) {
	user, err := a.users.GetUser(ctx)
	if errors.Is(err, fosite.ErrNotFound) {
		id, err := utils.GenerateUserID()
		if err != nil {
			return nil, 0, err
		}
		user = &models.User{
			ID:        id,
			Username:  defaultUsername,
			CreatedAt: time.Now().UTC(),
		}
		if err := a.users.CreateUser(ctx, user); err != nil {
			return nil, 0, err
		}
		a.logger.Info("Bootstrapped operator account", zap.String("username", user.Username))
		return user, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	credentials, err := a.users.ListWebAuthnCredentials(ctx, user.ID)
	if err != nil {
		return nil, 0, err
	}
	return user, len(credentials), nil
}

// isPasswordLoginActive applies the fallback rule (SPEC §1.12): the stored
// disable flag only takes effect while at least one passkey exists, so the
// operator can never lock themselves out entirely.
func (a *AuthRouter) isPasswordLoginActive(user *models.User, passkeyCount int) bool {
	if len(a.passwordHash) == 0 {
		return false
	}
	return !user.PasswordLoginDisabled || passkeyCount == 0
}

func (a *AuthRouter) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Delete(SessionKeyAuthorized)
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}
	c.Redirect(http.StatusFound, LoginEndpoint)
}

func (a *AuthRouter) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		authorized := session.Get(SessionKeyAuthorized)
		if authorized == nil {
			session.Set(SessionKeyRedirectURL, c.Request.URL.String())
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, LoginEndpoint)
			// Without Abort the downstream handler would still run (and on
			// bodyless redirects even override the status) — fail closed.
			c.Abort()
			return
		}

		if !authorized.(bool) {
			// not expected
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		c.Next()
	}
}

type loginTemplateData struct {
	Providers     []Provider
	HasPassword   bool
	PasswordError string
	// PasskeyAvailable shows the passkey button once the operator account
	// has at least one registered credential (SPEC §1.12).
	PasskeyAvailable bool
}

type unauthorizedTemplateData struct {
	UserID   string
	Provider string
}

type errorTemplateData struct {
	ErrorMessage string
}

func (a *AuthRouter) renderLogin(c *gin.Context, passwordError string) {
	data := loginTemplateData{
		Providers:        a.providers,
		HasPassword:      len(a.passwordHash) > 0,
		PasswordError:    passwordError,
		PasskeyAvailable: a.hasPasskeys(c.Request.Context()),
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if passwordError != "" {
		c.Status(http.StatusBadRequest)
	} else {
		c.Status(http.StatusOK)
	}
	if err := a.loginTemplate.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func (a *AuthRouter) renderUnauthorized(c *gin.Context, userID, providerName string) {
	data := unauthorizedTemplateData{
		UserID:   userID,
		Provider: providerName,
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusForbidden)
	if err := a.unauthorizedTemplate.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

// filterUserInfo returns a copy of m containing only the listed keys.
func filterUserInfo(m map[string]any, keys []string) map[string]any {
	filtered := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := m[k]; ok {
			filtered[k] = v
		}
	}
	return filtered
}

func (a *AuthRouter) renderError(c *gin.Context, err error) {
	data := errorTemplateData{
		ErrorMessage: err.Error(),
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusInternalServerError)
	if templateErr := a.errorTemplate.Execute(c.Writer, data); templateErr != nil {
		c.AbortWithError(http.StatusInternalServerError, templateErr)
		return
	}
	c.Abort()
}
