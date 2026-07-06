package mcpproxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/proxy"
)

func TestRun_NormalizesExternalURLTrailingSlash(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	cases := []struct {
		name        string
		input       string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{name: "no trailing slash", input: "https://example.com", wantURL: "https://example.com"},
		{name: "with trailing slash", input: "https://example.com/", wantURL: "https://example.com"},
		{name: "with path", input: "https://example.com/foo", wantErr: true, errContains: "must not have a path"},
		{name: "with query", input: "https://example.com/?x=1", wantErr: true, errContains: "must not have a query"},
		{name: "relative", input: "example.com", wantErr: true, errContains: "must use http or https"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var receivedURL string
			newProxyRouter = func(cfg proxy.Config) (*proxy.ProxyRouter, error) {
				receivedURL = cfg.ExternalURL
				return nil, errors.New("stop early")
			}

			err := Run(Config{
				Listen:            ":0",
				TLSListen:         ":0",
				DataPath:          t.TempDir(),
				RepositoryBackend: "local",
				ExternalURL:       tt.input,
				Password:          "test-password",
				ProxyTargets:      []string{"http://example.com"},
				HeaderMappingBase: "/userinfo",
				DCREnabled:        true,
			})

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.Error(t, err)
			require.Contains(t, err.Error(), "stop early")
			require.Equal(t, tt.wantURL, receivedURL)
		})
	}
}

func TestRun_ValidatesTTLs(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*Config)
		errContains string
	}{
		{name: "access token TTL too short", mutate: func(c *Config) { c.AccessTokenTTL = 30 * time.Second }, errContains: "access token TTL"},
		{name: "access token TTL too long", mutate: func(c *Config) { c.AccessTokenTTL = 25 * time.Hour }, errContains: "access token TTL"},
		{name: "auth code TTL too short", mutate: func(c *Config) { c.AuthCodeTTL = 10 * time.Second }, errContains: "auth code TTL"},
		{name: "refresh token TTL below minimum", mutate: func(c *Config) { c.RefreshTokenTTL = 30 * time.Minute }, errContains: "refresh token TTL"},
		{name: "unsupported key algorithm", mutate: func(c *Config) { c.KeyAlg = "HS256" }, errContains: "unsupported key algorithm"},
		{name: "key rotation interval below minimum", mutate: func(c *Config) { c.KeyRotationInterval = 30 * time.Minute }, errContains: "key rotation interval"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Listen:            ":0",
				TLSListen:         ":0",
				DataPath:          t.TempDir(),
				RepositoryBackend: "local",
				ExternalURL:       "http://localhost",
				ProxyTargets:      []string{"http://example.com"},
				HeaderMappingBase: "/userinfo",
				DCREnabled:        true,
			}
			tt.mutate(&cfg)
			err := Run(cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestRun_PassesHTTPStreamingOnlyToProxyRouter(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	var streamingOnlyReceived bool
	newProxyRouter = func(cfg proxy.Config) (*proxy.ProxyRouter, error) {
		streamingOnlyReceived = cfg.HTTPStreamingOnly
		return nil, errors.New("proxy router init failed")
	}

	err := Run(Config{
		Listen:            ":0",
		TLSListen:         ":0",
		DataPath:          t.TempDir(),
		RepositoryBackend: "local",
		ExternalURL:       "http://localhost",
		Password:          "test-password",
		ProxyTargets:      []string{"http://example.com"},
		HTTPStreamingOnly: true,
		HeaderMappingBase: "/userinfo",
		DCREnabled:        true,
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create proxy router")
	require.True(t, streamingOnlyReceived, "httpStreamingOnly should be forwarded to proxy router")
}

// TestRun_RequiresAuthBackend covers the SPEC §3.1 fail-fast: without a
// password, an OIDC provider, or an enrolled passkey, startup aborts.
func TestRun_RequiresAuthBackend(t *testing.T) {
	err := Run(Config{
		Listen:            ":0",
		TLSListen:         ":0",
		DataPath:          t.TempDir(),
		RepositoryBackend: "local",
		ExternalURL:       "http://localhost",
		ProxyTargets:      []string{"http://example.com"},
		HeaderMappingBase: "/userinfo",
		DCREnabled:        true,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no authentication backend configured")
}

func TestSessionCookieSecure(t *testing.T) {
	cases := []struct {
		externalURL string
		want        bool
	}{
		{externalURL: "https://example.com", want: true},
		{externalURL: "http://example.com", want: false},
	}

	for _, tt := range cases {
		t.Run(tt.externalURL, func(t *testing.T) {
			parsedURL, err := url.Parse(tt.externalURL)
			require.NoError(t, err)
			require.Equal(t, tt.want, sessionCookieSecure(parsedURL))
		})
	}
}

func TestUserInfoFieldsFromConfig(t *testing.T) {
	t.Run("extracts fields from header mapping and user ID field", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("/email", map[string]string{
			"/email":              "X-Forwarded-Email",
			"/preferred_username": "X-Forwarded-User",
		})
		require.ElementsMatch(t, []string{"email", "preferred_username"}, fields)
	})

	t.Run("handles nested JSON pointers by taking top-level key", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("/email", map[string]string{
			"/address/street": "X-Street",
		})
		require.ElementsMatch(t, []string{"email", "address"}, fields)
	})

	t.Run("deduplicates overlapping fields", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("/email", map[string]string{
			"/email": "X-Forwarded-Email",
		})
		require.Equal(t, []string{"email"}, fields)
	})

	t.Run("empty config returns empty slice", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("", nil)
		require.Empty(t, fields)
	})

	t.Run("handles user ID field without leading slash", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("email", nil)
		require.Equal(t, []string{"email"}, fields)
	})
}

func TestHealthzEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register healthz before auth middleware, same as in Run()
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Add a catch-all that returns 401 to simulate auth middleware
	router.Use(func(c *gin.Context) {
		c.AbortWithStatus(http.StatusUnauthorized)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/healthz", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	require.Equal(t, "ok", body["status"])
}
