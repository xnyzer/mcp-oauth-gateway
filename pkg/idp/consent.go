package idp

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
)

// consentTemplateData feeds the consent page. All fields are attacker-
// influenced (the client picks its client_id, redirect_uri and scopes), so the
// template must auto-escape them — hence html/template.
type consentTemplateData struct {
	ClientID    string
	RedirectURI string
	Scopes      []string
	// CSRFToken is the per-session anti-CSRF token embedded in the approval
	// form and checked on the consent POST (SPEC §1.5/§1.12), defence-in-depth
	// on top of the ar_id session binding.
	CSRFToken string
	// LoopbackOnly marks a client whose every registered redirect URI points
	// at this machine. A Client ID Metadata Document proves who published it,
	// but not which local process is listening on the port — any program on
	// the device could have claimed it. The MCP authorization spec therefore
	// asks for an explicit warning in this case.
	LoopbackOnly bool
}

// consentTemplate shows the client identity and requested scopes (SPEC §1.5):
// the operator's only signal to recognise and decline a foreign client, since
// a valid session would otherwise auto-grant any authorize request that reaches
// this page (anti-phishing).
var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authorize</title></head>
<body>
<h1>Authorize application</h1>
<p>An application is requesting access to this MCP server. Approve only if you started this yourself and recognise the details below.</p>
{{if .LoopbackOnly}}<p><strong>This application runs on the device you are using.</strong> It receives the authorization on a local port, which any program on that device could have claimed. Approve only if you started it yourself just now.</p>{{end}}
<dl>
<dt>Client</dt><dd>{{.ClientID}}</dd>
<dt>Redirect to</dt><dd>{{.RedirectURI}}</dd>
<dt>Requested scopes</dt><dd>{{if .Scopes}}{{range .Scopes}}<code>{{.}}</code> {{end}}{{else}}(none){{end}}</dd>
</dl>
<form method="post"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button type="submit">Authorize</button></form>
</body>
</html>`))

func (a *IDPRouter) handleAuthorizationReturnForm(c *gin.Context) {
	arID := c.Param("ar_id")
	session := sessions.Default(c)
	if !hasAuthorizeRequestID(session, arID) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid authorization session"})
		return
	}

	ar, err := a.repo.GetAuthorizeRequest(c.Request.Context(), arID)
	if err != nil {
		a.logger.Error("Failed to load authorize request for consent", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Mint (or reuse) the per-session CSRF token and persist it before the
	// approval form is served; the consent POST is checked against it (SPEC
	// §1.5/§1.12).
	csrfToken, err := auth.EnsureCSRFToken(session)
	if err != nil {
		a.logger.Error("Failed to mint CSRF token for consent", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if err := session.Save(); err != nil {
		a.logger.Error("Failed to save consent session", zap.Error(err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	var redirectURI string
	if uri := ar.GetRedirectURI(); uri != nil {
		redirectURI = uri.String()
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := consentTemplate.Execute(c.Writer, consentTemplateData{
		ClientID:     ar.GetClient().GetID(),
		RedirectURI:  redirectURI,
		Scopes:       ar.GetRequestedScopes(),
		CSRFToken:    csrfToken,
		LoopbackOnly: allRedirectsLoopback(ar.GetClient().GetRedirectURIs()),
	}); err != nil {
		a.logger.Error("Failed to render consent page", zap.Error(err))
	}
}

func (a *IDPRouter) handleAuthorizationReturn(c *gin.Context) {
	ctx := c.Request.Context()
	arID := c.Param("ar_id")
	session := sessions.Default(c)
	if !hasAuthorizeRequestID(session, arID) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid authorization session"})
		return
	}

	ar, err := a.repo.GetAuthorizeRequest(ctx, arID)
	if err != nil {
		a.logger.Error("Failed to get authorize requester", zap.Error(err))
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}
	defer func() {
		if err := a.repo.DeleteAuthorizeRequest(ctx, arID); err != nil {
			a.logger.Error("Failed to delete authorize requester", zap.Error(err))
		}
	}()

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	ar.GrantAudience(a.externalURL)

	subject := "user"
	if userID, ok := session.Get(auth.SessionKeyUserID).(string); ok && userID != "" {
		subject = userID
	}
	var userInfo map[string]any
	if userInfoJSON, ok := session.Get(auth.SessionKeyUserInfo).(string); ok && userInfoJSON != "" {
		// A malformed value only loses the optional claims; the session
		// cookie is HMAC-authenticated, so this should not happen.
		if err := json.Unmarshal([]byte(userInfoJSON), &userInfo); err != nil {
			a.logger.Warn("failed to decode session user info; continuing without claims", zap.Error(err))
		}
	}

	jwtSession, err := NewJWTSession(a.externalURL, subject, ar.GetClient().GetID(), userInfo)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	response, err := a.provider.NewAuthorizeResponse(ctx, ar, jwtSession)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to generate authorization response", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}
	// RFC 9207: identify the issuer in the authorization response (SPEC §1.5).
	response.AddParameter("iss", a.externalURL)

	removeAuthorizeRequestID(session, arID)
	if err := session.Save(); err != nil {
		a.logger.Error("Failed to remove authorize request from session", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}

	a.provider.WriteAuthorizeResponse(ctx, c.Writer, ar, response)
}
