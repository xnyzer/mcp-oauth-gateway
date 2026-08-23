package idp

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"unicode"

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
	// ConnectionName prefills the operator's name for this connection (F-025).
	// Empty in F-025a; F-025b fills it from the name the client declares.
	ConnectionName string
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
<form method="post">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<p><label for="connection_name">Name for this connection (optional)</label><br>
<input type="text" id="connection_name" name="connection_name" maxlength="64" value="{{.ConnectionName}}"></p>
<button type="submit">Authorize</button>
</form>
</body>
</html>`))

// maxLabelLength bounds the operator's connection name. It is displayed on the
// settings page and repeated in the auth log, so it is capped where it enters
// rather than at each place that renders it.
const maxLabelLength = 64

// sanitizeLabel trims the submitted name, drops control characters and caps the
// length. `html/template` escapes on output, but a control character would
// still travel into the structured log, where escaping is not the renderer's
// job — so the value is cleaned once, at the only place that writes it.
func sanitizeLabel(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, raw)
	cleaned = strings.TrimSpace(cleaned)

	runes := []rune(cleaned)
	if len(runes) > maxLabelLength {
		cleaned = strings.TrimSpace(string(runes[:maxLabelLength]))
	}
	return cleaned
}

// declaredClientName returns the name the client gives itself — from its CIMD
// document (SPEC §1.3) or from the stored DCR registration (§1.4) — so the
// consent page can show it and prefill the operator's own label (§1.5).
//
// Best-effort on purpose: a name that cannot be read must not keep the operator
// from authorizing, so every failure yields an empty prefill rather than an
// error. The CIMD lookup goes through the resolver fosite already used for this
// request, so its cache answers and no second document is fetched.
func (a *IDPRouter) declaredClientName(ctx context.Context, clientID string) string {
	if strings.HasPrefix(clientID, "https://") {
		if a.cimdResolver == nil {
			return ""
		}
		doc, err := a.cimdResolver.Resolve(ctx, clientID)
		if err != nil {
			return ""
		}
		return doc.ClientName
	}
	name, err := a.repo.GetClientName(ctx, clientID)
	if err != nil {
		a.logger.Warn("Failed to read the client name for consent", zap.Error(err))
		return ""
	}
	return name
}

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
		ClientID:    ar.GetClient().GetID(),
		RedirectURI: redirectURI,
		Scopes:      ar.GetRequestedScopes(),
		CSRFToken:   csrfToken,
		// Sanitized like the operator's own input: it is prefill, but it is the
		// client's text and it reaches the same store and log if approved.
		ConnectionName: sanitizeLabel(a.declaredClientName(c.Request.Context(), ar.GetClient().GetID())),
		LoopbackOnly:   allRedirectsLoopback(ar.GetClient().GetRedirectURIs()),
	}); err != nil {
		a.logger.Error("Failed to render consent page", zap.Error(err))
	}
}

// grantRequested grants exactly what the request asked for, plus this gateway
// as the audience. Approval is all-or-nothing by design (SPEC §1.5): the
// operator approves the authorization on the consent page, not scope by scope.
func (a *IDPRouter) grantRequested(ar fosite.AuthorizeRequester) {
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	ar.GrantAudience(a.externalURL)
}

// approvedSession assembles the session an approved authorization carries: the
// subject from the operator's login, the optional OIDC claims, and the name the
// operator gave this connection.
func (a *IDPRouter) approvedSession(c *gin.Context, ar fosite.AuthorizeRequester) (*Session, error) {
	session := sessions.Default(c)

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
		return nil, err
	}
	// The operator's name for this connection rides the session, so it is
	// stored with every record of the grant and deleted with it (F-025). Set
	// here rather than passed to NewJWTSession: the value comes from this
	// form, and the constructor already carries as many parameters as §3
	// allows.
	jwtSession.Label = sanitizeLabel(c.PostForm("connection_name"))
	return jwtSession, nil
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

	a.grantRequested(ar)

	jwtSession, err := a.approvedSession(c, ar)
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
