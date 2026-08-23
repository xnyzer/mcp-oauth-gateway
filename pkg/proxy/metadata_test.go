package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyRouter_ProtectedResourceTrailingSlash(t *testing.T) {
	_, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com/", Proxy: http.NotFoundHandler(), VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: false, ForwardAuthorizationHeader: false, HeaderMapping: nil, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	req, err := http.NewRequest("GET", OauthProtectedResourceEndpoint, nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp protectedResourceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", resp.Resource)
	assert.Equal(t, []string{"https://example.com"}, resp.AuthorizationServers)
}

func TestProxyRouter_ProtectedResourceMetadataComplete(t *testing.T) {
	_, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: http.NotFoundHandler(), VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	req, err := http.NewRequest("GET", OauthProtectedResourceEndpoint, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// SPEC §1.1: field-complete PRM document.
	var resp protectedResourceResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "https://example.com", resp.Resource)
	assert.Equal(t, []string{"https://example.com"}, resp.AuthorizationServers)
	assert.Equal(t, "https://example.com/.well-known/jwks.json", resp.JWKSURI)
	assert.Equal(t, []string{"header"}, resp.BearerMethodsSupported)
	assert.NotNil(t, resp.ScopesSupported)
	assert.Empty(t, resp.ScopesSupported)
	assert.Equal(t, "mcp-oauth-gateway", resp.ResourceName)
}

func TestProxyRouter_UnauthorizedChallenge(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: http.NotFoundHandler(), VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	// SPEC §1.11.2: without a token the challenge carries only the PRM
	// pointer (RFC 6750 §3: no error attribute).
	req, err := http.NewRequest("POST", "/mcp", nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	challenge := w.Header().Get("WWW-Authenticate")
	assert.Equal(t, `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`, challenge)

	// With an invalid token the challenge adds error="invalid_token".
	req, err = http.NewRequest("POST", "/mcp", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	challenge = w.Header().Get("WWW-Authenticate")
	assert.Contains(t, challenge, `resource_metadata="https://example.com/.well-known/oauth-protected-resource"`)
	assert.Contains(t, challenge, `error="invalid_token"`)

	// Expired tokens are invalid tokens, too.
	expiredToken, err := createJWT(privateKey, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	require.NoError(t, err)
	req, err = http.NewRequest("POST", "/mcp", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
}
