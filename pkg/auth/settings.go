package auth

import (
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"go.uber.org/zap"
)

// settingsMessages maps message codes (passed as ?msg=) to the fixed texts
// rendered on the settings page — query input is never reflected (SPEC
// §1.12, no XSS).
var settingsMessages = map[string]string{
	"saved":        "Settings saved.",
	"deleted":      "Passkey deleted.",
	"need_passkey": "Register a passkey before disabling the password login.",
	"error":        "The change could not be saved.",
	"revoked":      "Access revoked. The client must authorize again to return.",
	"revoked_all":  "Every client's access revoked. Your own login is untouched.",
	// The sweep is atomic, so a failure really did change nothing.
	"revoke_failed": "The revoke failed. Nothing was changed.",
}

type credentialView struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

type settingsTemplateData struct {
	Username string
	// Credentials lists the registered passkeys, oldest first.
	Credentials []credentialView
	// HasPassword reports whether password hashes are configured at all.
	HasPassword bool
	// PasswordLoginDisabled is the stored preference; it only takes effect
	// while a passkey exists (PasswordLoginActive is the effective state).
	PasswordLoginDisabled bool
	PasswordLoginActive   bool
	Message               string
	// CSRFToken is the per-session anti-CSRF token embedded in the settings
	// forms and the passkey-register fetch header (SPEC §1.12).
	CSRFToken string
	// Clients lists who holds access, newest activity first (F-024).
	Clients []clientView
	// ConfirmRevokeAll renders the panic button's confirmation panel instead
	// of the button, so revoking everything takes two deliberate actions.
	ConfirmRevokeAll bool
}

// handleSettings renders the session-gated settings page (SPEC §1.12):
// passkey enrollment, credential management, the password-fallback toggle,
// and the client list with its kill switch (F-024).
func (a *AuthRouter) handleSettings(c *gin.Context) {
	user, records, ok := a.requireOwnUser(c)
	if !ok {
		return
	}
	// Fail closed on the client list: a settings page that renders an empty
	// list because enumeration failed would tell the operator nobody holds
	// access (§6).
	clients, err := a.clientViews(c.Request.Context())
	if err != nil {
		a.renderError(c, err)
		return
	}
	// Mint (or reuse) the per-session CSRF token and persist it before the
	// forms are served (SPEC §1.12); the settings POSTs and the register
	// ceremony are checked against it.
	session := sessions.Default(c)
	csrfToken, err := EnsureCSRFToken(session)
	if err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	if err := session.Save(); err != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	data := settingsTemplateData{
		Username:              user.user.Username,
		Credentials:           credentialViews(records),
		HasPassword:           len(a.passwordHash) > 0,
		PasswordLoginDisabled: user.user.PasswordLoginDisabled,
		PasswordLoginActive:   a.isPasswordLoginActive(user.user, len(records)),
		Message:               settingsMessages[c.Query("msg")],
		CSRFToken:             csrfToken,
		Clients:               clients,
		// Compared, never reflected: the query only selects a fixed panel
		// (SPEC §1.12, no XSS).
		ConfirmRevokeAll: c.Query("confirm") == "revoke_all",
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := a.settingsTemplate.Execute(c.Writer, data); err != nil {
		// The return value only echoes the attached error; the abort
		// itself cannot fail.
		_ = c.AbortWithError(http.StatusInternalServerError, err)
	}
}

// credentialViews projects the stored passkeys onto what the page shows.
func credentialViews(records []models.WebAuthnCredential) []credentialView {
	views := make([]credentialView, 0, len(records))
	for _, record := range records {
		views = append(views, credentialView{
			ID:         record.ID,
			Name:       record.Name,
			CreatedAt:  record.CreatedAt,
			LastUsedAt: record.LastUsedAt,
		})
	}
	return views
}

// handleSettingsPassword toggles the password fallback. Disabling requires
// at least one registered passkey (SPEC §1.12 — never lock out entirely).
func (a *AuthRouter) handleSettingsPassword(c *gin.Context) {
	ctx := c.Request.Context()
	user, records, ok := a.requireOwnUser(c)
	if !ok {
		return
	}
	disable := c.PostForm("disabled") == "true"
	if disable && len(records) == 0 {
		c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=need_passkey")
		return
	}
	user.user.PasswordLoginDisabled = disable
	if err := a.users.UpdateUser(ctx, user.user); err != nil {
		a.logger.Error("Failed to update user", zap.Error(err))
		c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=error")
		return
	}
	c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=saved")
}

// handleSettingsCredentialDelete removes one of the user's passkeys. If the
// last one goes, the password fallback re-activates by the login-time rule.
func (a *AuthRouter) handleSettingsCredentialDelete(c *gin.Context) {
	ctx := c.Request.Context()
	_, records, ok := a.requireOwnUser(c)
	if !ok {
		return
	}
	id := c.PostForm("id")
	for _, record := range records {
		if record.ID != id {
			continue
		}
		if err := a.users.DeleteWebAuthnCredential(ctx, id); err != nil {
			a.logger.Error("Failed to delete passkey credential", zap.Error(err))
			c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=error")
			return
		}
		c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=deleted")
		return
	}
	// Unknown ID: nothing to delete — plain redirect, no oracle.
	c.Redirect(http.StatusFound, SettingsEndpoint)
}
