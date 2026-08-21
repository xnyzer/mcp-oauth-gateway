package proxy

// Tests for the transport surface the MCP 2026-07-28 revision defines: which
// request headers reach the upstream, and the new server/discover RPC. They
// live apart from proxy_test.go because that file is already far past the
// 500-line hard limit in CODING-STANDARDS §2 (F-022 tracks the split).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProxyRouter_ProxyHeadersStripClientHeaders is the PROXY_HEADERS
// counterpart to TestProxyRouter_HeaderMappingStripsClientHeaders. A client
// controls its own request headers, and MCP 2026-07-28 makes that routine:
// the transport mirrors annotated tool parameters into Mcp-Param-* headers and
// obliges intermediaries to forward the ones they do not recognise. Appending
// the configured value without dropping the inbound copy first would leave the
// client's value in front, where an upstream calling Header.Get reads it and
// never sees the injected credential (FR-6, SR-7).
//
// The assertions compare the full value slice, not Header.Get: Get returns the
// first value and would report "secret" just the same while the client's copy
// sat behind it, so it cannot tell a fixed gateway from a broken one.
func TestProxyRouter_ProxyHeadersStripClientHeaders(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name           string
		proxyHeaders   http.Header
		clientHeaders  map[string]string
		expectedValues map[string][]string
	}{
		{
			name:           "client cannot shadow an injected credential",
			proxyHeaders:   http.Header{"X-Api-Key": []string{"upstream-secret"}},
			clientHeaders:  map[string]string{"X-Api-Key": "attacker-supplied"},
			expectedValues: map[string][]string{"X-Api-Key": {"upstream-secret"}},
		},
		{
			name:           "a multi-value proxy header replaces the client copy entirely",
			proxyHeaders:   http.Header{"X-Tenant": []string{"alpha", "beta"}},
			clientHeaders:  map[string]string{"X-Tenant": "attacker-tenant"},
			expectedValues: map[string][]string{"X-Tenant": {"alpha", "beta"}},
		},
		{
			name:           "Authorization injected via PROXY_HEADERS replaces the client bearer",
			proxyHeaders:   http.Header{"Authorization": []string{"Bearer upstream-token"}},
			expectedValues: map[string][]string{"Authorization": {"Bearer upstream-token"}},
		},
		{
			// The strip must be limited to configured names, or the gateway
			// would eat the transport headers it is required to forward.
			name:          "unconfigured headers pass through untouched",
			proxyHeaders:  http.Header{"X-Api-Key": []string{"upstream-secret"}},
			clientHeaders: map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Method": "tools/call"},
			expectedValues: map[string][]string{
				"X-Api-Key":        {"upstream-secret"},
				"Mcp-Param-Region": {"us-west1"},
				"Mcp-Method":       {"tools/call"},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeaders := http.Header{}
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range r.Header {
					receivedHeaders[k] = v
				}
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter(Config{ExternalURL: "https://example.com", Proxy: upstream, VerificationKey: testKeyLookup(publicKey), ProxyHeaders: tt.proxyHeaders, HeaderMappingBase: "/userinfo"})
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			token, err := createJWT(privateKey, jwt.MapClaims{
				"sub": "test-user",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			require.NoError(t, err)

			req, err := http.NewRequest("POST", "/mcp", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			for k, v := range tt.clientHeaders {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			for header, expected := range tt.expectedValues {
				assert.Equal(t, expected, receivedHeaders.Values(header), "header %s", header)
			}
		})
	}
}

// TestProxyRouter_ProxiesServerDiscover pins down that the reserved-namespace
// guard cannot swallow the RPC that MCP 2026-07-28 requires every server to
// implement. The guard matches URL path prefixes while server/discover is a
// JSON-RPC method in the request body, so today the two cannot collide — but
// nothing recorded that, and a guard later rewritten against method names
// would break the transport with no test to catch it.
func TestProxyRouter_ProxiesServerDiscover(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	const body = `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`

	var receivedBody, receivedMethodHeader string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		require.NoError(t, readErr)
		receivedBody = string(raw)
		receivedMethodHeader = r.Header.Get("Mcp-Method")
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

	req, err := http.NewRequest("POST", "/mcp", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "server/discover")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "server/discover must reach the upstream, not 404")
	assert.Equal(t, body, receivedBody, "the JSON-RPC body must arrive unchanged")
	assert.Equal(t, "server/discover", receivedMethodHeader, "Mcp-Method must be forwarded")
}
