package idp

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/authevent"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
)

func (a *IDPRouter) handleToken(c *gin.Context) {
	ctx := c.Request.Context()

	session, err := NewJWTSession("", "", "", nil)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session for token", zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, nil, fosite.ErrServerError.WithWrap(err))
		return
	}

	// RFC 8707: the only valid resource is the gateway itself (SPEC §1.6).
	if err := c.Request.ParseForm(); err != nil {
		a.provider.WriteAccessError(ctx, c.Writer, nil, fosite.ErrInvalidRequest.WithWrap(err))
		return
	}
	if err := a.validateResource(c.Request.PostForm["resource"]); err != nil {
		a.provider.WriteAccessError(ctx, c.Writer, nil, err)
		return
	}

	accessRequest, err := a.provider.NewAccessRequest(ctx, c.Request, session)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access request", zap.String("grant_type", c.PostForm("grant_type")))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	response, err := a.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access response", zap.String("grant_type", c.PostForm("grant_type")), zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	// Active DCR clients never expire mid-use: refresh the registration
	// TTL on successful issuance (SR-5). CIMD clients are not persisted.
	if a.dcrClientTTL > 0 {
		clientID := accessRequest.GetClient().GetID()
		if !strings.HasPrefix(clientID, "https://") {
			if err := a.repo.TouchClient(ctx, clientID, time.Now().UTC().Add(a.dcrClientTTL)); err != nil {
				a.logger.Warn("Failed to refresh client registration TTL", zap.String("client_id", clientID), zap.Error(err))
			}
		}
	}

	authevent.Log(a.logger, authevent.TokenIssued,
		zap.String("client_id", accessRequest.GetClient().GetID()),
		zap.Strings("grant_types", accessRequest.GetGrantTypes()),
		zap.String("client_ip", c.ClientIP()))
	a.provider.WriteAccessResponse(ctx, c.Writer, accessRequest, response)
}

func (a *IDPRouter) handleIntrospect(c *gin.Context) {
	ctx := c.Request.Context()
	session, err := NewJWTSession("", "", "", nil)
	if err != nil {
		a.provider.WriteIntrospectionError(ctx, c.Writer, fosite.ErrServerError.WithWrap(err))
		return
	}

	ir, err := a.provider.NewIntrospectionRequest(ctx, c.Request, session)
	if err != nil {
		a.provider.WriteIntrospectionError(ctx, c.Writer, err)
		return
	}

	a.provider.WriteIntrospectionResponse(ctx, c.Writer, ir)
}

// handleRevoke implements RFC 7009 (SPEC §1.9). fosite authenticates the
// client, resolves the token (access or refresh), and revokes the grant via
// the repository; unknown tokens still yield 200 (no token-existence oracle).
func (a *IDPRouter) handleRevoke(c *gin.Context) {
	ctx := c.Request.Context()
	err := a.provider.NewRevocationRequest(ctx, c.Request)
	if err != nil {
		a.logger.With(utils.Err(err)...).Warn("Token revocation failed")
		// Fail closed on a storage failure (SPEC §1.9, SR-3): fosite's
		// WriteRevocationResponse writes 200 for anything other than
		// invalid_request/invalid_client, which would falsely signal success
		// while the token record still exists (and keeps passing the proxy's
		// presence check). Surface the 5xx store error as an explicit 503 so
		// the operator knows the revocation did not take effect.
		if code := fosite.ErrorToRFC6749Error(err).CodeField; code == http.StatusServiceUnavailable || code == http.StatusInternalServerError {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "temporarily_unavailable"})
			return
		}
	} else {
		// Accepted revocation request (also for unknown tokens — RFC 7009
		// hides existence, so the event does too).
		authevent.Log(a.logger, authevent.Revoked, zap.String("client_ip", c.ClientIP()))
	}
	a.provider.WriteRevocationResponse(ctx, c.Writer, err)
}
