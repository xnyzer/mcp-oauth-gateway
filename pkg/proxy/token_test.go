package proxy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyRouter_RejectsWrongIssuerOrAudience(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: http.NotFoundHandler(), VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: false, ForwardAuthorizationHeader: false, HeaderMapping: nil, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	cases := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{
			name: "wrong issuer",
			claims: jwt.MapClaims{
				"sub": "test-user",
				"iss": "https://issuer.example.com",
				"aud": "https://example.com",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
		},
		{
			name: "wrong audience",
			claims: jwt.MapClaims{
				"sub": "test-user",
				"iss": "https://example.com",
				"aud": "https://other.example.com",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			token, err := createJWT(privateKey, tt.claims)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodGet, "/test-endpoint", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestProxyRouter_HandleProxy_ValidToken(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	backendServer := createDummyBackendServer()
	defer backendServer.Close()

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(backendServer.URL + r.URL.Path)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)

		buf := make([]byte, 1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	})

	proxyHeaders := make(http.Header)
	proxyHeaders.Set("X-Forwarded-By", "mcp-oauth-gateway")

	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: proxyHeaders, HTTPStreamingOnly: false, ForwardAuthorizationHeader: false, HeaderMapping: nil, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token, err := createJWT(privateKey, claims)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/test-endpoint", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	invalidToken := "invalid"
	req, err = http.NewRequest("GET", "/test-endpoint", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+invalidToken)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestProxyRouter_RejectsTokenWithoutExp: a signed token that simply omits
// exp must not validate as never-expiring (jwt.WithExpirationRequired,
// SPEC §1.11.1 — every issued token carries exp per §1.7).
func TestProxyRouter_RejectsTokenWithoutExp(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	backendCalled := false
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})
	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	tokenWithoutExp, err := createJWT(privateKey, jwt.MapClaims{
		"sub": "test-user",
		"iat": time.Now().Unix(),
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "/mcp", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenWithoutExp)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	assert.False(t, backendCalled, "a token without exp must never reach the upstream")
}

func TestProxyRouter_TokenActiveCheck(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	validToken, err := createJWT(privateKey, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)

	cases := []struct {
		name        string
		tokenActive func(ctx context.Context, rawToken string) error
		wantCode    int
	}{
		{name: "active token passes", tokenActive: func(context.Context, string) error { return nil }, wantCode: http.StatusOK},
		{name: "nil check skips lookup", tokenActive: nil, wantCode: http.StatusOK},
		{name: "revoked token is rejected", tokenActive: func(context.Context, string) error { return ErrTokenInactive }, wantCode: http.StatusUnauthorized},
		{name: "store failure fails closed", tokenActive: func(context.Context, string) error { return errors.New("store down") }, wantCode: http.StatusServiceUnavailable},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: okHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HeaderMappingBase: "/userinfo", TokenActive: tt.tokenActive})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			req, err := http.NewRequest("POST", "/mcp", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+validToken)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
			if tt.wantCode == http.StatusUnauthorized {
				assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
			}
			if tt.wantCode == http.StatusServiceUnavailable {
				assert.Contains(t, w.Body.String(), "temporarily_unavailable")
			}
		})
	}
}

func TestProxyRouter_ClockSkewLeeway(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Token expired 10s ago: rejected without leeway, accepted within a
	// 30s clock-skew window (SPEC §1.11.1).
	justExpired, err := createJWT(privateKey, jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(-10 * time.Second).Unix(),
	})
	require.NoError(t, err)

	cases := []struct {
		name     string
		skew     time.Duration
		wantCode int
	}{
		{name: "no leeway rejects", skew: 0, wantCode: http.StatusUnauthorized},
		{name: "30s leeway accepts", skew: 30 * time.Second, wantCode: http.StatusOK},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: okHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HeaderMappingBase: "/userinfo", ClockSkew: tt.skew})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			req, err := http.NewRequest("POST", "/mcp", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+justExpired)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
		})
	}
}

// TestProxyRouter_MultiKeyVerification covers the kid-based key selection
// (SPEC §2.3.3): unknown or missing kids and algorithm mismatches are
// rejected, and ES256 keys verify when the lookup provides them.
func TestProxyRouter_MultiKeyVerification(t *testing.T) {
	rsaKey, rsaPub, err := generateRSAKeyPair()
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Lookup with one RSA and one EC key, mirroring an active + retiring
	// key set of mixed algorithms after a KEY_ALG switch.
	lookup := func(kid string) (crypto.PublicKey, string, bool) {
		switch kid {
		case "rsa-kid":
			return rsaPub, "RS256", true
		case "ec-kid":
			return &ecKey.PublicKey, "ES256", true
		}
		return nil, "", false
	}

	sign := func(t *testing.T, method jwt.SigningMethod, key any, kid any) string {
		t.Helper()
		token := jwt.NewWithClaims(method, jwt.MapClaims{
			"iss": "https://example.com",
			"aud": "https://example.com",
			"sub": "user",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		if kid != nil {
			token.Header["kid"] = kid
		}
		signed, err := token.SignedString(key)
		require.NoError(t, err)
		return signed
	}

	cases := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{name: "known RSA kid accepted", token: sign(t, jwt.SigningMethodRS256, rsaKey, "rsa-kid"), wantStatus: http.StatusOK},
		{name: "known EC kid accepted", token: sign(t, jwt.SigningMethodES256, ecKey, "ec-kid"), wantStatus: http.StatusOK},
		{name: "unknown kid rejected", token: sign(t, jwt.SigningMethodRS256, rsaKey, "other-kid"), wantStatus: http.StatusUnauthorized},
		{name: "missing kid rejected", token: sign(t, jwt.SigningMethodRS256, rsaKey, nil), wantStatus: http.StatusUnauthorized},
		{name: "alg mismatch for kid rejected", token: sign(t, jwt.SigningMethodES256, ecKey, "rsa-kid"), wantStatus: http.StatusUnauthorized},
		{name: "signature from wrong key rejected", token: sign(t, jwt.SigningMethodRS256, rsaKey, "ec-kid"), wantStatus: http.StatusUnauthorized},
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: okHandler, VerificationKey: lookup, ProxyHeaders: http.Header{}, HeaderMappingBase: "/userinfo"})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/mcp", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantStatus == http.StatusUnauthorized {
				assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
			}
		})
	}
}
