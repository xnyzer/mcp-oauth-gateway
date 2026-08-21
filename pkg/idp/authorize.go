package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
)

// errInvalidTarget is the RFC 8707 error for resource values the gateway
// does not serve.
var errInvalidTarget = &fosite.RFC6749Error{
	ErrorField:       "invalid_target",
	DescriptionField: "The requested resource is not served by this authorization server.",
	CodeField:        http.StatusBadRequest,
}

// validateResource enforces SPEC §1.5/§1.6: the gateway fronts exactly one
// resource — itself. Absent values default to the issuer; anything else is
// rejected with invalid_target (RFC 8707).
func (a *IDPRouter) validateResource(resources []string) error {
	for _, resource := range resources {
		if resource != "" && strings.TrimSuffix(resource, "/") != a.externalURL {
			return errInvalidTarget
		}
	}
	return nil
}

// issRedirectWriter appends the RFC 9207 `iss` parameter to redirect
// responses written by fosite's WriteAuthorizeError, which has no built-in
// RFC 9207 support in v0.49. Non-redirect responses pass through untouched.
type issRedirectWriter struct {
	http.ResponseWriter
	issuer string
}

func (w *issRedirectWriter) WriteHeader(statusCode int) {
	if statusCode >= 300 && statusCode < 400 {
		if location := w.Header().Get("Location"); location != "" {
			if u, err := url.Parse(location); err == nil {
				q := u.Query()
				if q.Get("iss") == "" {
					q.Set("iss", w.issuer)
					u.RawQuery = q.Encode()
					w.Header().Set("Location", u.String())
				}
			}
		}
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// writeAuthorizeError delegates to fosite while ensuring redirected errors
// carry the RFC 9207 `iss` parameter (SPEC §1.5).
func (a *IDPRouter) writeAuthorizeError(ctx context.Context, w http.ResponseWriter, ar fosite.AuthorizeRequester, err error) {
	a.provider.WriteAuthorizeError(ctx, &issRedirectWriter{ResponseWriter: w, issuer: a.externalURL}, ar, err)
}

func (a *IDPRouter) handleAuth(c *gin.Context) {
	ctx := c.Request.Context()

	// RFC 6749 makes state RECOMMENDED, not REQUIRED, but fosite enforces
	// minimum entropy (8 chars). Generate a server-side state for clients
	// that omit it (e.g., MCP Inspector, Cursor CLI) so they can complete
	// the OAuth flow. The generated state is echoed back in the redirect;
	// clients that didn't send state will simply ignore it.
	if c.Request.URL.Query().Get("state") == "" {
		state, err := utils.GenerateState()
		if err != nil {
			a.writeAuthorizeError(ctx, c.Writer, nil, fosite.ErrServerError.WithWrap(err))
			return
		}
		q := c.Request.URL.Query()
		q.Set("state", state)
		c.Request.URL.RawQuery = q.Encode()
	}

	// Hand the raw redirect_uri to GetClient (see requestedRedirectURIKey) so
	// a loopback client using the "localhost" hostname can be matched with a
	// varying port. Only this path stashes it; every other GetClient caller —
	// token, introspection, revocation — keeps the unmodified client.
	ctx = withRequestedRedirectURI(ctx, c.Request.URL.Query().Get("redirect_uri"))

	ar, err := a.provider.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// RFC 8707: the only valid resource is the gateway itself (SPEC §1.5).
	if err := a.validateResource(c.Request.URL.Query()["resource"]); err != nil {
		a.writeAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	if err := a.repo.CreateAuthorizeRequest(ctx, ar); err != nil {
		a.logger.Error("Failed to create authorize requester", zap.Error(err))
		a.writeAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	session := sessions.Default(c)
	addAuthorizeRequestID(session, ar.GetID())
	if err := session.Save(); err != nil {
		a.logger.Error("Failed to save authorize request in session", zap.Error(err))
		_ = a.repo.DeleteAuthorizeRequest(ctx, ar.GetID())
		a.writeAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	c.Redirect(302, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ar.GetID()))
}

func authorizeRequestIDs(session sessions.Session) []string {
	value, ok := session.Get(sessionKeyAuthorizeRequestIDs).(string)
	if !ok || value == "" {
		return nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(value), &ids); err != nil {
		return nil
	}
	return ids
}

func addAuthorizeRequestID(session sessions.Session, arID string) {
	ids := authorizeRequestIDs(session)
	if hasAuthorizeRequestID(session, arID) {
		return
	}
	ids = append(ids, arID)
	data, _ := json.Marshal(ids)
	session.Set(sessionKeyAuthorizeRequestIDs, string(data))
}

func hasAuthorizeRequestID(session sessions.Session, arID string) bool {
	for _, id := range authorizeRequestIDs(session) {
		if id == arID {
			return true
		}
	}
	return false
}

func removeAuthorizeRequestID(session sessions.Session, arID string) {
	ids := authorizeRequestIDs(session)
	remaining := ids[:0]
	for _, id := range ids {
		if id != arID {
			remaining = append(remaining, id)
		}
	}
	if len(remaining) == 0 {
		session.Delete(sessionKeyAuthorizeRequestIDs)
		return
	}
	data, _ := json.Marshal(remaining)
	session.Set(sessionKeyAuthorizeRequestIDs, string(data))
}
