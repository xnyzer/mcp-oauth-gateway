package auth

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type loginTemplateData struct {
	Providers     []Provider
	HasPassword   bool
	PasswordError string
	// PasskeyAvailable shows the passkey button once the operator account
	// has at least one registered credential (SPEC §1.12).
	PasskeyAvailable bool
	// CSRFToken is the per-session anti-CSRF token embedded in the password
	// form and the passkey fetch header (SPEC §1.12).
	CSRFToken string
}

type unauthorizedTemplateData struct {
	UserID   string
	Provider string
}

type errorTemplateData struct {
	ErrorMessage string
}

func (a *AuthRouter) renderLogin(c *gin.Context, passwordError string) {
	// Mint (or reuse) the per-session CSRF token and persist it before the
	// form is served, so the subsequent login POST / passkey fetch can be
	// checked against it (SPEC §1.12).
	session := sessions.Default(c)
	csrfToken, err := EnsureCSRFToken(session)
	if err != nil {
		a.renderError(c, err)
		return
	}
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}
	data := loginTemplateData{
		Providers:        a.providers,
		HasPassword:      len(a.passwordHash) > 0,
		PasswordError:    passwordError,
		PasskeyAvailable: a.hasPasskeys(c.Request.Context()),
		CSRFToken:        csrfToken,
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if passwordError != "" {
		c.Status(http.StatusBadRequest)
	} else {
		c.Status(http.StatusOK)
	}
	if err := a.loginTemplate.Execute(c.Writer, data); err != nil {
		// The return value only echoes the attached error; the abort
		// itself cannot fail.
		_ = c.AbortWithError(http.StatusInternalServerError, err)
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
		_ = c.AbortWithError(http.StatusInternalServerError, err)
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
	// Never leak internal error detail to the client (SR-8, CODING-STANDARDS
	// §6): log the cause server-side and render a fixed generic message.
	a.logger.Error("auth request failed", zap.Error(err))
	data := errorTemplateData{
		ErrorMessage: "An unexpected error occurred. Please try again.",
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusInternalServerError)
	if templateErr := a.errorTemplate.Execute(c.Writer, data); templateErr != nil {
		_ = c.AbortWithError(http.StatusInternalServerError, templateErr)
		return
	}
	c.Abort()
}
