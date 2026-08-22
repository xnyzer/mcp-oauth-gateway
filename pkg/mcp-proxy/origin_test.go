package mcpproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestRequireSameOrigin covers SR-9. The case that must never regress is the
// first one: a request without an Origin header has to pass, because
// server-side MCP clients send none at all. Rejecting it would take the whole
// gateway offline for every real client, which is a far worse outcome than the
// DNS-rebinding scenario this guards against.
func TestRequireSameOrigin(t *testing.T) {
	const expected = "https://gateway.example.com"

	cases := []struct {
		name       string
		origin     string
		setHeader  bool
		wantStatus int
	}{
		{name: "absent Origin passes", setHeader: false, wantStatus: http.StatusOK},
		{name: "exact match passes", origin: "https://gateway.example.com", setHeader: true, wantStatus: http.StatusOK},
		{name: "explicit default port passes", origin: "https://gateway.example.com:443", setHeader: true, wantStatus: http.StatusOK},
		{name: "uppercase host passes", origin: "https://GATEWAY.EXAMPLE.COM", setHeader: true, wantStatus: http.StatusOK},
		{name: "uppercase scheme passes", origin: "HTTPS://gateway.example.com", setHeader: true, wantStatus: http.StatusOK},

		{name: "foreign host is rejected", origin: "https://evil.example.com", setHeader: true, wantStatus: http.StatusForbidden},
		{name: "same host over http is rejected", origin: "http://gateway.example.com", setHeader: true, wantStatus: http.StatusForbidden},
		{name: "non-default port is rejected", origin: "https://gateway.example.com:8443", setHeader: true, wantStatus: http.StatusForbidden},
		{name: "subdomain is rejected", origin: "https://evil.gateway.example.com", setHeader: true, wantStatus: http.StatusForbidden},
		// Browsers send this from sandboxed iframes, file:// documents and
		// some redirect chains — present and invalid, not absent.
		{name: "null Origin is rejected", origin: "null", setHeader: true, wantStatus: http.StatusForbidden},
		{name: "empty-but-present Origin passes as absent", origin: "", setHeader: true, wantStatus: http.StatusOK},
		{name: "garbage is rejected", origin: "::not a url::", setHeader: true, wantStatus: http.StatusForbidden},
		{name: "non-http scheme is rejected", origin: "file://gateway.example.com", setHeader: true, wantStatus: http.StatusForbidden},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(requireSameOrigin(expected, zap.NewNop()))
			router.POST("/mcp", func(c *gin.Context) { c.Status(http.StatusOK) })

			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tt.setHeader {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

// TestNormalizeOrigin pins the comparison form down directly. The IPv6 rows
// exist because url.Hostname strips the brackets, so a naive re-assembly turns
// [::1]:8080 into the unparseable ::1:8080.
func TestNormalizeOrigin(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"https://example.com", "https://example.com"},
		{"https://EXAMPLE.com", "https://example.com"},
		{"HTTPS://example.com", "https://example.com"},
		{"https://example.com:443", "https://example.com"},
		{"http://example.com:80", "http://example.com"},
		{"https://example.com:8443", "https://example.com:8443"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"https://[::1]", "https://[::1]"},
		{"http://[::1]:8080", "http://[::1]:8080"},
		{"https://example.com/path", "https://example.com"},

		// Everything below is not a usable origin and must normalize to "",
		// which can never equal a normalized expected origin — fail-closed.
		{"", ""},
		{"null", ""},
		{"file:///etc/passwd", ""},
		{"https://", ""},
		{"not-a-url", ""},
	}
	for _, tt := range cases {
		assert.Equal(t, tt.want, normalizeOrigin(tt.raw), "input %q", tt.raw)
	}
}

// TestNormalizeOriginRejectsUnusableAsExpectedValue guards the fail-closed
// property from the other side: if the expected origin ever normalized to the
// empty string, every unusable Origin would suddenly match it.
func TestNormalizeOriginRejectsUnusableAsExpectedValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(requireSameOrigin(normalizeOrigin("not-a-url"), zap.NewNop()))
	router.POST("/mcp", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Origin", "null")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code,
		"an unusable expected origin must not turn into a wildcard")
}
