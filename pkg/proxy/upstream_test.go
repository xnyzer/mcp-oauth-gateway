package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyRouter_HeaderMapping(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name            string
		headerMapping   map[string]string
		userinfo        map[string]any
		expectedHeaders map[string]string
	}{
		{
			name:          "string field",
			headerMapping: map[string]string{"/email": "X-Forwarded-Email"},
			userinfo:      map[string]any{"email": "user@example.com"},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
		},
		{
			name:          "array field joined with comma",
			headerMapping: map[string]string{"/groups": "X-Forwarded-Groups"},
			userinfo:      map[string]any{"groups": []any{"admin", "users"}},
			expectedHeaders: map[string]string{
				"X-Forwarded-Groups": "admin,users",
			},
		},
		{
			name:          "multiple mappings",
			headerMapping: map[string]string{"/email": "X-Forwarded-Email", "/preferred_username": "X-Forwarded-User"},
			userinfo:      map[string]any{"email": "user@example.com", "preferred_username": "john"},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
				"X-Forwarded-User":  "john",
			},
		},
		{
			name:            "missing field is skipped",
			headerMapping:   map[string]string{"/email": "X-Forwarded-Email", "/missing": "X-Missing"},
			userinfo:        map[string]any{"email": "user@example.com"},
			expectedHeaders: map[string]string{"X-Forwarded-Email": "user@example.com"},
		},
		{
			name:            "nil headerMapping",
			headerMapping:   nil,
			userinfo:        map[string]any{"email": "user@example.com"},
			expectedHeaders: map[string]string{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeaders := http.Header{}
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range r.Header {
					receivedHeaders[k] = v
				}
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: false, ForwardAuthorizationHeader: false, HeaderMapping: tt.headerMapping, HeaderMappingBase: "/userinfo"})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			claims := jwt.MapClaims{
				"sub": "test-user",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			}
			if tt.userinfo != nil {
				claims["userinfo"] = tt.userinfo
			}

			token, err := createJWT(privateKey, claims)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			for header, expected := range tt.expectedHeaders {
				assert.Equal(t, expected, receivedHeaders.Get(header), "header %s mismatch", header)
			}
		})
	}
}

func TestProxyRouter_HeaderMappingBase(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name              string
		headerMapping     map[string]string
		headerMappingBase string
		claims            jwt.MapClaims
		expectedHeaders   map[string]string
		missingHeaders    []string
	}{
		{
			name:              "base=/ reads top-level claims",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
		},
		{
			name:              "base=/userinfo reads userinfo claims",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":      "test-user",
				"email":    "toplevel@example.com",
				"userinfo": map[string]any{"email": "userinfo@example.com"},
				"exp":      time.Now().Add(time.Hour).Unix(),
				"iat":      time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "userinfo@example.com",
			},
		},
		{
			name:              "base=/ with multiple claims",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email", "/name": "X-Forwarded-Name"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"name":  "John Doe",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
				"X-Forwarded-Name":  "John Doe",
			},
		},
		{
			name:              "base=/userinfo skips when userinfo is absent",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			missingHeaders: []string{"X-Forwarded-Email"},
		},
		{
			name:              "base=/ missing claim is skipped",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email", "/missing": "X-Missing"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
			missingHeaders: []string{"X-Missing"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeaders := http.Header{}
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range r.Header {
					receivedHeaders[k] = v
				}
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: false, ForwardAuthorizationHeader: false, HeaderMapping: tt.headerMapping, HeaderMappingBase: tt.headerMappingBase})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			token, err := createJWT(privateKey, tt.claims)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			for header, expected := range tt.expectedHeaders {
				assert.Equal(t, expected, receivedHeaders.Get(header), "header %s mismatch", header)
			}
			for _, header := range tt.missingHeaders {
				assert.Empty(t, receivedHeaders.Get(header), "header %s should not be set", header)
			}
		})
	}
}

func TestProxyRouter_AuthorizationHeaderDefaultBehavior(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	t.Run("strips authorization header by default", func(t *testing.T) {
		var backendAuthorization string
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		})

		proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: false, ForwardAuthorizationHeader: false, HeaderMapping: nil, HeaderMappingBase: "/userinfo"})
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

		req, err := http.NewRequest(http.MethodGet, "/mcp", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, backendAuthorization)
	})

	t.Run("forwards authorization header when enabled", func(t *testing.T) {
		var backendAuthorization string
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		})

		proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: false, ForwardAuthorizationHeader: true, HeaderMapping: nil, HeaderMappingBase: "/userinfo"})
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

		req, err := http.NewRequest(http.MethodGet, "/mcp", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Bearer "+token, backendAuthorization)
	})
}

func TestProxyRouter_HeaderMappingStripsClientHeaders(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name              string
		headerMapping     map[string]string
		headerMappingBase string
		claims            jwt.MapClaims
		clientHeaders     map[string]string
		expectedHeaders   map[string]string
		missingHeaders    []string
	}{
		{
			name:              "claim missing strips client header",
			headerMapping:     map[string]string{"/groups": "X-Forwarded-Groups"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":      "test-user",
				"userinfo": map[string]any{"email": "user@example.com"},
				"exp":      time.Now().Add(time.Hour).Unix(),
				"iat":      time.Now().Unix(),
			},
			clientHeaders:  map[string]string{"X-Forwarded-Groups": "admin"},
			missingHeaders: []string{"X-Forwarded-Groups"},
		},
		{
			name:              "claim present overwrites client header",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":      "test-user",
				"userinfo": map[string]any{"email": "user@example.com"},
				"exp":      time.Now().Add(time.Hour).Unix(),
				"iat":      time.Now().Unix(),
			},
			clientHeaders: map[string]string{"X-Forwarded-Email": "attacker@example.com"},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
		},
		{
			name:              "base path absent strips client header",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub": "test-user",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			clientHeaders:  map[string]string{"X-Forwarded-Email": "attacker@example.com"},
			missingHeaders: []string{"X-Forwarded-Email"},
		},
		{
			name:              "mixed mappings only set claims that exist",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email", "/groups": "X-Forwarded-Groups"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			clientHeaders: map[string]string{
				"X-Forwarded-Email":  "attacker@example.com",
				"X-Forwarded-Groups": "admin",
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
			missingHeaders: []string{"X-Forwarded-Groups"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeaders := http.Header{}
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range r.Header {
					receivedHeaders[k] = v
				}
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: proxyHandler, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: http.Header{}, HTTPStreamingOnly: false, ForwardAuthorizationHeader: false, HeaderMapping: tt.headerMapping, HeaderMappingBase: tt.headerMappingBase})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			token, err := createJWT(privateKey, tt.claims)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			for k, v := range tt.clientHeaders {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			for header, expected := range tt.expectedHeaders {
				assert.Equal(t, expected, receivedHeaders.Get(header), "header %s mismatch", header)
			}
			for _, header := range tt.missingHeaders {
				assert.Empty(t, receivedHeaders.Get(header), "header %s should be stripped", header)
			}
		})
	}
}
