package auth

import (
	"embed"
	"errors"
	"html/template"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
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
	users repository.UserStorage
	// clients backs the settings page's client list and kill switch (F-024).
	// It is required whenever users is set — the list is part of the settings
	// page, not a separately switchable feature.
	clients  repository.InventoryStorage
	webAuthn *webauthn.WebAuthn
	logger   *zap.Logger
	// loginRateLimit guards the login surfaces (SR-6); nil disables.
	loginRateLimit gin.HandlerFunc
	// lockout locks the operator account after consecutive failed password
	// logins (SR-6); nil disables.
	lockout *ratelimit.Lockout
	// version is the build version shown on the session-gated settings page
	// and nowhere else (SPEC §1.12); empty renders nothing.
	version string
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
	// Clients backs the client list and the kill switch on that same settings
	// page (F-024). Required when Users is set.
	Clients repository.InventoryStorage
	// ExternalURL is the normalized issuer (SPEC §0); it derives the
	// WebAuthn RP ID and allowed origin. Required when Users is set.
	ExternalURL string
	Logger      *zap.Logger
	// LoginRateLimit is applied to the password login and the passkey
	// login ceremony (SR-6); nil disables.
	LoginRateLimit gin.HandlerFunc
	// Lockout locks the account after consecutive failed password logins
	// (SR-6); nil disables. Passkey logins are exempt — assertions are
	// cryptographic, not guessable.
	Lockout *ratelimit.Lockout
	// Version is the build version rendered in the settings page footer, so
	// the operator can confirm which build is live. It is passed in rather
	// than read from pkg/version so a test can render a distinctive value.
	// Only the session-gated settings page shows it — the public pages and
	// /healthz never disclose the version (SPEC §1.13).
	Version string
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
		// The settings page renders the client list, so a user store without
		// an inventory would serve a page that cannot answer "who has access"
		// — fail fast at construction rather than at the operator's first
		// visit (§7, config validation at startup).
		if cfg.Clients == nil {
			return nil, errors.New("auth: Clients is required when Users is set")
		}
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
		clients:              cfg.Clients,
		webAuthn:             webAuthn,
		logger:               cfg.Logger,
		loginRateLimit:       cfg.LoginRateLimit,
		lockout:              cfg.Lockout,
		version:              cfg.Version,
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
	SettingsPasswordEndpoint         = "/.auth/settings/password"           //nolint:gosec // G101: endpoint path, not a credential
	SettingsCredentialDeleteEndpoint = "/.auth/settings/credentials/delete" //nolint:gosec // G101: endpoint path, not a credential

	// Client list actions (F-024). All three are session-gated and
	// CSRF-checked like the settings POSTs above.
	SettingsClientRevokeEndpoint = "/.auth/settings/clients/revoke"
	SettingsGrantRevokeEndpoint  = "/.auth/settings/clients/grants/revoke"
	SettingsRevokeAllEndpoint    = "/.auth/settings/clients/revoke-all"

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
	// SessionKeyCSRF stores the per-session anti-CSRF token (SPEC §1.12).
	SessionKeyCSRF = "csrf_token"

	sessionKeyWebAuthnLogin        = "webauthn_login"
	sessionKeyWebAuthnRegistration = "webauthn_registration"
)
