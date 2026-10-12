package idp

import (
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
	"go.uber.org/zap"
)

type authorizationServerResponse struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	JWKSURI                                    string   `json:"jwks_uri"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	// Always emitted, true or false: clients decide between CIMD and the
	// deprecated DCR fallback by reading it (SPEC §1.2/§1.3).
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported"`
}

func (a *IDPRouter) handleOauthAuthorizationServer(c *gin.Context) {
	authorizationEndpoint, err := url.JoinPath(a.externalURL, AuthorizationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create authorization endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	tokenEndpoint, err := url.JoinPath(a.externalURL, TokenEndpoint)
	if err != nil {
		a.logger.Error("Failed to create token endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	// Advertised only while the deprecated DCR fallback is enabled
	// (SPEC §1.4); CIMD needs no registration endpoint.
	var registrationEndpoint string
	if a.dcrEnabled {
		registrationEndpoint, err = url.JoinPath(a.externalURL, RegistrationEndpoint)
		if err != nil {
			a.logger.Error("Failed to create registration endpoint URL", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
	}
	jwksURI, err := url.JoinPath(a.externalURL, JWKSEndpoint)
	if err != nil {
		a.logger.Error("Failed to create JWKS URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	introspectionEndpoint, err := url.JoinPath(a.externalURL, IntrospectionEndpoint)
	if err != nil {
		a.logger.Error("Failed to create introspection endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	revocationEndpoint, err := url.JoinPath(a.externalURL, RevocationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create revocation endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	grantTypes := []string{"authorization_code"}
	if a.refreshEnabled {
		grantTypes = append(grantTypes, "refresh_token")
	}

	res := &authorizationServerResponse{
		Issuer:                            a.externalURL,
		AuthorizationEndpoint:             authorizationEndpoint,
		TokenEndpoint:                     tokenEndpoint,
		RegistrationEndpoint:              registrationEndpoint,
		JWKSURI:                           jwksURI,
		IntrospectionEndpoint:             introspectionEndpoint,
		RevocationEndpoint:                revocationEndpoint,
		ScopesSupported:                   []string{},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               grantTypes,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		AuthorizationResponseIssParameterSupported: true,
		ClientIDMetadataDocumentSupported:          a.cimdEnabled,
	}
	c.JSON(200, res)
}

type jwks struct {
	Keys []keys.JWK `json:"keys"`
}

// jwksCacheMaxAge bounds client-side JWKS caching so rotated keys propagate
// within minutes (SPEC §1.8: MAY send max-age ≤ 300 s).
const jwksCacheMaxAge = "max-age=300"

// handleJWKS serves the public key set: the active key plus every retiring
// key, so tokens signed before a rotation stay verifiable until they expire
// (SPEC §1.8/§2.3.3).
func (a *IDPRouter) handleJWKS(c *gin.Context) {
	keySet, err := a.keys.PublicJWKs()
	if err != nil {
		a.logger.Error("Failed to build JWKS key set", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	c.Header("Cache-Control", jwksCacheMaxAge)
	c.JSON(200, jwks{Keys: keySet})
}
