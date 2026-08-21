package idp

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/authevent"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
)

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	RedirectURIs            []string `json:"redirect_uris"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	// ClientSecretExpiresAt is 0 when the registration never expires
	// (RFC 7591 §3.2.1); otherwise the SR-5 registration TTL.
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at"`
}

var supportedAuthMethods = map[string]bool{"none": true, "client_secret_basic": true, "client_secret_post": true}

// validateRegistration enforces the SPEC §1.4 metadata rules. It returns an
// RFC 7591 error code and description, or empty strings when valid.
func validateRegistration(req *registrationRequest) (string, string) {
	if len(req.RedirectURIs) == 0 {
		return "invalid_redirect_uri", "redirect_uris must not be empty"
	}
	for _, redirectURI := range req.RedirectURIs {
		if err := cimd.ValidateRedirectURI(redirectURI); err != nil {
			return "invalid_redirect_uri", err.Error()
		}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic" // RFC 7591 default
	}
	if !supportedAuthMethods[req.TokenEndpointAuthMethod] {
		return "invalid_client_metadata", "unsupported token_endpoint_auth_method"
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	for _, grantType := range req.GrantTypes {
		if !cimd.IsSupportedGrantType(grantType) {
			return "invalid_client_metadata", "unsupported grant_type: " + grantType
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	for _, responseType := range req.ResponseTypes {
		if !cimd.IsSupportedResponseType(responseType) {
			return "invalid_client_metadata", "unsupported response_type: " + responseType
		}
	}
	return "", ""
}

func (a *IDPRouter) handleRegister(c *gin.Context) {
	ctx := c.Request.Context()

	var req registrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Don't echo the parser's internal detail (SR-8/§6); the code is enough.
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "request body must be valid JSON"})
		return
	}

	if errCode, errDesc := validateRegistration(&req); errCode != "" {
		c.JSON(400, gin.H{"error": errCode, "error_description": errDesc})
		return
	}

	clientID, err := utils.GenerateClientID()
	if err != nil {
		a.logger.Error("Failed to generate client ID", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	var clientSecret string
	var hashedSecret []byte
	isPublic := req.TokenEndpointAuthMethod == "none"

	if !isPublic {
		// Generate client secret for confidential clients
		clientSecret, err = utils.GenerateClientSecret()
		if err != nil {
			a.logger.Error("Failed to generate client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}

		hashedSecret, err = a.hasher.Hash(ctx, []byte(clientSecret))
		if err != nil {
			a.logger.Error("Failed to hash client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
		Scopes:        strings.Fields(req.Scope),
		Audience:      []string{a.externalURL},
		Public:        isPublic,
	}
	// Registration TTL (SR-5): refreshed on token issuance (handleToken).
	var expiresAt time.Time
	if a.dcrClientTTL > 0 {
		expiresAt = time.Now().UTC().Add(a.dcrClientTTL)
	}
	// The cap is enforced atomically inside the write transaction (SR-5, no
	// TOCTOU): the store counts non-expired registrations and inserts in one
	// step, returning ErrClientCapReached rather than evicting active clients.
	if err := a.repo.RegisterClient(ctx, client, expiresAt, a.dcrMaxClients); err != nil {
		if errors.Is(err, repository.ErrClientCapReached) {
			a.logger.Warn("DCR client cap reached", zap.Int("cap", a.dcrMaxClients))
			c.JSON(503, gin.H{"error": "temporarily_unavailable", "error_description": "client registration is temporarily unavailable"})
			return
		}
		a.logger.Error("Failed to register client", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	authevent.Log(a.logger, authevent.Register,
		zap.String("client_id", clientID),
		zap.String("client_ip", c.ClientIP()))

	registrationClientURI, err := url.JoinPath(RegistrationEndpoint, clientID)
	if err != nil {
		a.logger.Error("Failed to create registration client URI", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	response := registrationResponse{
		ClientID:                clientID,
		RedirectURIs:            req.RedirectURIs,
		ClientName:              req.ClientName,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RegistrationClientURI:   registrationClientURI,
		ClientIDIssuedAt:        time.Now().Unix(),
	}

	if !isPublic {
		response.ClientSecret = clientSecret
		// 0 = never expires (RFC 7591 §3.2.1).
		if !expiresAt.IsZero() {
			response.ClientSecretExpiresAt = expiresAt.Unix()
		}
	}

	c.JSON(201, response)
}
