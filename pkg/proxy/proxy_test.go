package proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKid is the kid all test tokens carry; testKeyLookup resolves exactly
// this kid, mirroring the key manager's active-key entry.
const testKid = "test-kid"

func testKeyLookup(pub *rsa.PublicKey) func(string) (crypto.PublicKey, string, bool) {
	return func(kid string) (crypto.PublicKey, string, bool) {
		if kid == testKid {
			return pub, "RS256", true
		}
		return nil, "", false
	}
}

func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createJWT(privateKey *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = "https://example.com"
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = "https://example.com"
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKid
	return token.SignedString(privateKey)
}

func createDummyBackendServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "Hello from backend", "method": "%s", "path": "%s"}`, r.Method, r.URL.Path)
	}))
}

func TestProxyRouter_ReservedNamespacesNeverProxied(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	upstreamHit := false
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})
	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: upstream, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	token, err := createJWT(privateKey, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)

	// Even with a valid token, gateway-owned namespaces are never
	// forwarded upstream (SPEC §0) — disabled endpoints must 404.
	for _, path := range []string{"/.idp/register", "/.auth/whatever", "/.well-known/openid-configuration"} {
		req, err := http.NewRequest("POST", path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code, path)
	}
	assert.False(t, upstreamHit, "reserved namespaces must never reach the upstream")
}

func TestProxyRouter_HTTPStreamingOnlyRejectsSSE(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name          string
		method        string
		acceptHeader  string
		wantStatus    int
		expectBackend bool
		streamingOnly bool
	}{
		{
			name:          "plain text/event-stream",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "event-stream with params",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream; charset=utf-8",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "multiple values",
			method:        http.MethodGet,
			acceptHeader:  "application/json, text/event-stream",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "quality value",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream;q=0.9",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "post should pass through",
			method:        http.MethodPost,
			acceptHeader:  "text/event-stream",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: true,
		},
		{
			name:          "get without accept header",
			method:        http.MethodGet,
			acceptHeader:  "",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: true,
		},
		{
			name:          "get with non-sse accept",
			method:        http.MethodGet,
			acceptHeader:  "application/json",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: true,
		},
		{
			name:          "sse allowed when streamingOnly disabled",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			backendCalled := false
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backendCalled = true
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: tt.streamingOnly, ForwardAuthorizationHeader: false, HeaderMapping: nil, HeaderMappingBase: "/userinfo"})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			token, err := createJWT(privateKey, jwt.MapClaims{
				"sub": "user",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			require.NoError(t, err)

			req, err := http.NewRequest(tt.method, "/mcp", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", tt.acceptHeader)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.expectBackend, backendCalled, "backend call mismatch")
		})
	}
}

// TestProxyRouter_AllowedPathsRestrictUpstream covers SPEC §1.11: with an
// allowlist only its subtrees reach the upstream; everything else is 404,
// with or without a token, and matching stops at segment boundaries.
func TestProxyRouter_AllowedPathsRestrictUpstream(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	var upstreamPaths []string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPaths = append(upstreamPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	proxyRouter, err := NewProxyRouter(Config{
		ExternalURL:         "https://example.com",
		Proxy:               upstream,
		VerificationKey:     testKeyLookup(publicKey),
		ProxyHeaders:        http.Header{},
		HeaderMappingBase:   "/userinfo",
		AllowedPathPrefixes: []string{"/mcp/alice/", " /sse"},
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	token, err := createJWT(privateKey, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)

	serve := func(path string, withToken bool) int {
		req, err := http.NewRequest("POST", path, nil)
		require.NoError(t, err)
		if withToken {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	t.Run("allowed subtrees are forwarded", func(t *testing.T) {
		for _, path := range []string{"/mcp/alice", "/mcp/alice/", "/mcp/alice/messages", "/sse"} {
			assert.Equal(t, http.StatusOK, serve(path, true), path)
		}
		assert.Equal(t, []string{"/mcp/alice", "/mcp/alice/", "/mcp/alice/messages", "/sse"}, upstreamPaths)
	})

	t.Run("other paths are 404 even with a valid token", func(t *testing.T) {
		upstreamPaths = nil
		for _, path := range []string{"/", "/mcp", "/mcp/bob/", "/mcp/alicex", "/v1/admin/delete", "/ssex"} {
			assert.Equal(t, http.StatusNotFound, serve(path, true), path)
		}
		assert.Empty(t, upstreamPaths, "paths outside the allowlist must never reach the upstream")
	})

	t.Run("without a token the allowlist still answers 404, allowed paths 401", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, serve("/v1/admin/delete", false))
		assert.Equal(t, http.StatusUnauthorized, serve("/mcp/alice/", false))
	})
}

// TestNewProxyRouter_ValidatesAllowedPaths covers the fail-fast rules of
// SPEC §3.1 for PROXY_ALLOWED_PATHS.
func TestNewProxyRouter_ValidatesAllowedPaths(t *testing.T) {
	_, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)
	base := Config{ExternalURL: "https://example.com", VerificationKey: testKeyLookup(publicKey)}

	for _, invalid := range [][]string{{"mcp"}, {""}, {"/"}, {"/mcp", "//"}} {
		cfg := base
		cfg.AllowedPathPrefixes = invalid
		_, err := NewProxyRouter(cfg)
		assert.Error(t, err, "%q must be rejected", invalid)
	}

	cfg := base
	cfg.AllowedPathPrefixes = []string{"/mcp/", "/sse"}
	proxyRouter, err := NewProxyRouter(cfg)
	require.NoError(t, err)
	assert.Equal(t, []string{"/mcp", "/sse"}, proxyRouter.cfg.AllowedPathPrefixes)
}
