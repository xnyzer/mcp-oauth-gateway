package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/authevent"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"go.uber.org/zap"
)

// newWebAuthn builds the relying party from the normalized issuer
// (SPEC §1.12): RP ID is the bare host, the issuer itself is the sole
// allowed origin.
func newWebAuthn(externalURL string) (*webauthn.WebAuthn, error) {
	parsed, err := url.Parse(externalURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse external URL for WebAuthn: %w", err)
	}
	return webauthn.New(&webauthn.Config{
		RPID:          parsed.Hostname(),
		RPDisplayName: "mcp-oauth-gateway",
		RPOrigins:     []string{externalURL},
	})
}

// webAuthnUser adapts the persisted operator account to go-webauthn's User.
type webAuthnUser struct {
	user        *models.User
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webAuthnUser) WebAuthnName() string                       { return u.user.Username }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// loadWebAuthnUser returns the operator account with decoded passkeys plus
// the raw credential records (for persistence updates).
func (a *AuthRouter) loadWebAuthnUser(ctx context.Context) (*webAuthnUser, []models.WebAuthnCredential, error) {
	user, err := a.users.GetUser(ctx)
	if err != nil {
		return nil, nil, err
	}
	records, err := a.users.ListWebAuthnCredentials(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}
	credentials := make([]webauthn.Credential, 0, len(records))
	for _, record := range records {
		var credential webauthn.Credential
		if err := json.Unmarshal(record.Credential, &credential); err != nil {
			return nil, nil, fmt.Errorf("failed to decode passkey credential %s: %w", record.ID, err)
		}
		credentials = append(credentials, credential)
	}
	return &webAuthnUser{user: user, credentials: credentials}, records, nil
}

// storeCeremony keeps a ceremony's server-side state (challenge, user
// handle) in the cookie session between begin and finish.
func storeCeremony(session sessions.Session, key string, data *webauthn.SessionData) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to encode WebAuthn session data: %w", err)
	}
	session.Set(key, string(payload))
	return session.Save()
}

// takeCeremony consumes the pending ceremony state; each begin allows
// exactly one finish.
func takeCeremony(session sessions.Session, key string) (*webauthn.SessionData, error) {
	raw, ok := session.Get(key).(string)
	if !ok || raw == "" {
		return nil, errors.New("no pending WebAuthn ceremony")
	}
	session.Delete(key)
	if err := session.Save(); err != nil {
		return nil, err
	}
	var data webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, fmt.Errorf("failed to decode WebAuthn session data: %w", err)
	}
	return &data, nil
}

// hasPasskeys reports whether the operator account exists and has at least
// one registered passkey (drives the login-page button and the password-
// fallback rule).
func (a *AuthRouter) hasPasskeys(ctx context.Context) bool {
	if a.webAuthn == nil || a.users == nil {
		return false
	}
	user, err := a.users.GetUser(ctx)
	if err != nil {
		return false
	}
	credentials, err := a.users.ListWebAuthnCredentials(ctx, user.ID)
	return err == nil && len(credentials) > 0
}

// -- Login ceremony (public) ------------------------------------

func (a *AuthRouter) handleWebAuthnLoginBegin(c *gin.Context) {
	ctx := c.Request.Context()
	user, _, err := a.loadWebAuthnUser(ctx)
	if err != nil || len(user.credentials) == 0 {
		// Uniform error: no detail about whether a user or passkey exists.
		a.logger.Warn("Passkey login unavailable", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "passkey login is not available"})
		return
	}
	// Discoverable (client-side) login: no allow-list, so the response never
	// enumerates the operator's credential IDs to an anonymous caller. The
	// authenticator selects the resident passkey and returns its user handle,
	// which FinishDiscoverableLogin resolves via the handler below (SPEC §1.12).
	options, sessionData, err := a.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		a.logger.Error("Failed to begin passkey login", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "passkey login failed"})
		return
	}
	if err := storeCeremony(sessions.Default(c), sessionKeyWebAuthnLogin, sessionData); err != nil {
		a.logger.Error("Failed to store passkey login state", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "passkey login failed"})
		return
	}
	c.JSON(http.StatusOK, options)
}

func (a *AuthRouter) handleWebAuthnLoginFinish(c *gin.Context) {
	ctx := c.Request.Context()
	session := sessions.Default(c)

	// Fail-closed: any error in the ceremony denies the login (SR-3).
	deny := func(err error) {
		a.logger.Warn("Passkey login failed", zap.Error(err))
		authevent.Log(a.logger, authevent.LoginFail,
			zap.String("method", "passkey"),
			zap.String("client_ip", c.ClientIP()))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "passkey login failed"})
	}

	sessionData, err := takeCeremony(session, sessionKeyWebAuthnLogin)
	if err != nil {
		deny(err)
		return
	}
	user, records, err := a.loadWebAuthnUser(ctx)
	if err != nil {
		deny(err)
		return
	}
	// Single-operator discoverable-login handler: the user handle from the
	// assertion is validated against the sole operator account. go-webauthn
	// additionally enforces that the asserted credential belongs to this user
	// and that the handle matches the user ID (fail-closed).
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		if string(userHandle) != user.user.ID {
			return nil, errors.New("user handle does not match the operator account")
		}
		return user, nil
	}
	credential, err := a.webAuthn.FinishDiscoverableLogin(handler, *sessionData, c.Request)
	if err != nil {
		deny(err)
		return
	}
	if credential.Authenticator.CloneWarning {
		deny(errors.New("authenticator clone warning: sign count regressed"))
		return
	}

	// Persist the updated sign count — it is the clone-detection state, so
	// a store failure denies the login rather than degrading silently.
	if err := a.persistUsedCredential(ctx, records, credential); err != nil {
		deny(err)
		return
	}

	session.Set(SessionKeyAuthorized, true)
	session.Set(SessionKeyUserID, user.user.ID)
	redirectURL := takeRedirectTarget(session)
	if err := session.Save(); err != nil {
		deny(err)
		return
	}
	authevent.Log(a.logger, authevent.LoginOK,
		zap.String("method", "passkey"),
		zap.String("client_ip", c.ClientIP()))
	c.JSON(http.StatusOK, gin.H{"redirect": redirectURL})
}

// persistUsedCredential writes the post-ceremony credential state (sign
// count) and last-used timestamp back to the store.
func (a *AuthRouter) persistUsedCredential(ctx context.Context, records []models.WebAuthnCredential, credential *webauthn.Credential) error {
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	for i := range records {
		if records[i].ID != id {
			continue
		}
		payload, err := json.Marshal(credential)
		if err != nil {
			return fmt.Errorf("failed to encode passkey credential: %w", err)
		}
		records[i].Credential = payload
		records[i].LastUsedAt = time.Now().UTC()
		return a.users.UpdateWebAuthnCredential(ctx, &records[i])
	}
	return fmt.Errorf("assertion credential %s is not registered", id)
}

// -- Registration ceremony (session-gated, SPEC §1.12) ----------

// requireOwnUser ensures the session belongs to the persisted operator
// account — enrollment and settings are not available to OIDC-provider
// sessions.
func (a *AuthRouter) requireOwnUser(c *gin.Context) (*webAuthnUser, []models.WebAuthnCredential, bool) {
	ctx := c.Request.Context()
	user, records, err := a.loadWebAuthnUser(ctx)
	if err != nil {
		if !errors.Is(err, fosite.ErrNotFound) {
			a.logger.Error("Failed to load user", zap.Error(err))
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "passkey management requires the gateway's own login"})
		return nil, nil, false
	}
	sessionUserID, _ := sessions.Default(c).Get(SessionKeyUserID).(string)
	if sessionUserID != user.user.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "passkey management requires the gateway's own login"})
		return nil, nil, false
	}
	return user, records, true
}

func (a *AuthRouter) handleWebAuthnRegisterBegin(c *gin.Context) {
	user, _, ok := a.requireOwnUser(c)
	if !ok {
		return
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for _, credential := range user.credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	options, sessionData, err := a.webAuthn.BeginRegistration(user,
		webauthn.WithExclusions(exclusions),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// Require a resident (discoverable) credential so every newly
			// enrolled passkey supports the discoverable login ceremony
			// (empty allow-list, SPEC §1.12).
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		a.logger.Error("Failed to begin passkey registration", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "passkey registration failed"})
		return
	}
	if err := storeCeremony(sessions.Default(c), sessionKeyWebAuthnRegistration, sessionData); err != nil {
		a.logger.Error("Failed to store passkey registration state", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "passkey registration failed"})
		return
	}
	c.JSON(http.StatusOK, options)
}

// maxCredentialNameLength bounds the operator-chosen passkey label.
const maxCredentialNameLength = 64

func (a *AuthRouter) handleWebAuthnRegisterFinish(c *gin.Context) {
	ctx := c.Request.Context()
	user, _, ok := a.requireOwnUser(c)
	if !ok {
		return
	}
	sessionData, err := takeCeremony(sessions.Default(c), sessionKeyWebAuthnRegistration)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "passkey registration failed"})
		return
	}
	credential, err := a.webAuthn.FinishRegistration(user, *sessionData, c.Request)
	if err != nil {
		a.logger.Warn("Passkey registration failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "passkey registration failed"})
		return
	}

	name := c.Query("name")
	if len(name) > maxCredentialNameLength {
		name = name[:maxCredentialNameLength]
	}
	payload, err := json.Marshal(credential)
	if err != nil {
		a.logger.Error("Failed to encode passkey credential", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "passkey registration failed"})
		return
	}
	record := &models.WebAuthnCredential{
		ID:         base64.RawURLEncoding.EncodeToString(credential.ID),
		UserID:     user.user.ID,
		Name:       name,
		Credential: payload,
		CreatedAt:  time.Now().UTC(),
	}
	if err := a.users.AddWebAuthnCredential(ctx, record); err != nil {
		a.logger.Error("Failed to store passkey credential", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "passkey registration failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
