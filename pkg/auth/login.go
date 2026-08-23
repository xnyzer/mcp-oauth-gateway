package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/authevent"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// handleLogin serves the login page (the route is GET-only; POST is wired
// straight to handleLoginPost in SetupRoutes).
func (a *AuthRouter) handleLogin(c *gin.Context) {
	// Auto-redirect to the sole provider if enabled and no password is set
	if !a.noProviderAutoSelect && len(a.passwordHash) == 0 && len(a.providers) == 1 {
		c.Redirect(http.StatusFound, a.providers[0].AuthURL())
		return
	}
	a.renderLogin(c, "")
}

// lockoutKey identifies the single operator account in the lockout store
// (FR-4 — there is exactly one account to protect).
const lockoutKey = "operator"

func (a *AuthRouter) handleLoginPost(c *gin.Context) {
	password := c.PostForm("password")

	// The bcrypt comparison always runs first — over every configured hash
	// (no early break) and for an empty password too — so neither the
	// lockout state, the disabled-fallback check below, nor the match
	// position can be distinguished by response timing or body (SR-6).
	var isValid bool
	for _, hash := range a.passwordHash {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
			isValid = true
		}
	}
	now := time.Now().UTC()
	// A locked account rejects even the correct password, with the same
	// uniform error (SR-6 — the lockout must not become an oracle).
	if !isValid || a.lockout.Locked(lockoutKey, now) {
		if !isValid {
			a.lockout.Fail(lockoutKey, now)
		}
		a.loginFailed(c, "password")
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
		// message as a wrong password (SR-6, no state enumeration). Not a
		// guessing signal, so it does not count toward the lockout.
		if !a.isPasswordLoginActive(user, passkeyCount) {
			a.loginFailed(c, "password")
			return
		}
		subject = user.ID
	}
	a.lockout.Reset(lockoutKey)
	authevent.Log(a.logger, authevent.LoginOK,
		zap.String("method", "password"),
		zap.String("client_ip", c.ClientIP()))

	session := sessions.Default(c)
	session.Set(SessionKeyAuthorized, true)
	session.Set(SessionKeyUserID, subject)
	redirectTarget := takeRedirectTarget(session)
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}
	c.Redirect(http.StatusFound, redirectTarget)
}

// takeRedirectTarget consumes the stored post-login redirect target and
// normalises it to a safe local path. Only RequireAuth writes the value —
// from a matched route — but the session value must never be able to become
// an open redirect, even if that changes (SR-6 hardening).
func takeRedirectTarget(session sessions.Session) string {
	stored, ok := session.Get(SessionKeyRedirectURL).(string)
	if !ok || stored == "" {
		return "/"
	}
	session.Delete(SessionKeyRedirectURL)
	return safeRedirectTarget(stored)
}

// safeRedirectTarget returns stored if it is a same-origin local path —
// starting with a single "/" and not "//" or "/\", both of which browsers
// resolve as scheme-relative (cross-origin) URLs — otherwise "/".
func safeRedirectTarget(stored string) string {
	if !strings.HasPrefix(stored, "/") ||
		strings.HasPrefix(stored, "//") ||
		strings.HasPrefix(stored, `/\`) {
		return "/"
	}
	return stored
}

// loginFailed emits the login_fail event (SR-8) and renders the uniform
// login error (SR-6).
func (a *AuthRouter) loginFailed(c *gin.Context, method string) {
	authevent.Log(a.logger, authevent.LoginFail,
		zap.String("method", method),
		zap.String("client_ip", c.ClientIP()))
	a.renderLogin(c, "Invalid password")
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
	// Drop the entire session — identity, user info, WebAuthn ceremony
	// state and pending redirect targets — not just the authorized flag,
	// and expire the cookie client-side (MaxAge -1).
	session.Clear()
	session.Options(sessions.Options{Path: "/", MaxAge: -1})
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
