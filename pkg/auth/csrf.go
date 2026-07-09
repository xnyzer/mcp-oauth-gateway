package auth

// Per-session anti-CSRF token (SPEC §1.12): a 32-byte crypto/rand token stored
// in the HMAC-signed session, embedded in the login/consent/settings forms, and
// checked in constant time on every state-changing POST — defence-in-depth on
// top of the session cookie's SameSite=Lax attribute.

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
)

const (
	// CSRFFieldName is the hidden form field carrying the token on form POSTs;
	// CSRFHeaderName carries it on the WebAuthn fetch() calls (SPEC §1.12).
	CSRFFieldName  = "csrf_token"
	CSRFHeaderName = "X-CSRF-Token"
)

// EnsureCSRFToken returns the session's per-session CSRF token, minting and
// storing one on first use (SPEC §1.12). The caller is responsible for saving
// the session afterwards.
func EnsureCSRFToken(session sessions.Session) (string, error) {
	if token, ok := session.Get(SessionKeyCSRF).(string); ok && token != "" {
		return token, nil
	}
	token, err := utils.GenerateCSRFToken()
	if err != nil {
		return "", err
	}
	session.Set(SessionKeyCSRF, token)
	return token, nil
}

// validCSRF reports whether submitted equals the session's stored token in
// constant time; a missing or empty stored token never matches (fail-closed).
func validCSRF(session sessions.Session, submitted string) bool {
	stored, ok := session.Get(SessionKeyCSRF).(string)
	if !ok || stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(submitted)) == 1
}

// RequireCSRF rejects a state-changing POST whose token does not match the
// session's stored token (SPEC §1.12), defence-in-depth on top of SameSite=Lax.
// The X-CSRF-Token header is checked first so the JSON WebAuthn fetches never
// trigger form-body parsing (which would consume the ceremony request body);
// form POSTs fall back to the hidden csrf_token field.
func (a *AuthRouter) RequireCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		submitted := c.GetHeader(CSRFHeaderName)
		if submitted == "" {
			submitted = c.PostForm(CSRFFieldName)
		}
		if !validCSRF(sessions.Default(c), submitted) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid CSRF token"})
			return
		}
		c.Next()
	}
}
