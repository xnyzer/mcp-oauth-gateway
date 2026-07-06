package cimd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestResolver returns a resolver wired to trust the given TLS test
// server and to allow its loopback address (in-package test knobs only —
// production resolvers always run with the SSRF guards on).
func newTestResolver(t *testing.T, server *httptest.Server, cfg Config) *Resolver {
	t.Helper()
	r := NewResolver(cfg)
	r.allowPrivateHosts = true
	client := server.Client()
	client.Timeout = r.cfg.FetchTimeout
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("%w: redirects are not followed", ErrInvalidClientID)
	}
	r.httpClient = client
	return r
}

func serveDocument(t *testing.T, mutate func(serverURL string, doc *Client)) (*httptest.Server, *int) {
	t.Helper()
	fetches := 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		doc := Client{
			ClientID:     server.URL,
			ClientName:   "Test CIMD Client",
			RedirectURIs: []string{"https://client.example.com/callback"},
		}
		if mutate != nil {
			mutate(server.URL, &doc)
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(doc))
	}))
	t.Cleanup(server.Close)
	return server, &fetches
}

func TestResolverHappyPathAndCache(t *testing.T) {
	server, fetches := serveDocument(t, nil)
	resolver := newTestResolver(t, server, Config{})

	client, err := resolver.Resolve(t.Context(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, server.URL, client.ClientID)
	assert.Equal(t, []string{"authorization_code"}, client.GrantTypes, "grant_types default applied")
	assert.Equal(t, []string{"code"}, client.ResponseTypes, "response_types default applied")

	// Second resolution is served from cache — no new fetch.
	_, err = resolver.Resolve(t.Context(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, 1, *fetches, "second resolve must hit the cache")
}

func TestResolverNegativeCache(t *testing.T) {
	server, fetches := serveDocument(t, func(serverURL string, doc *Client) {
		doc.ClientID = "https://mismatch.example.com" // validation failure
	})
	resolver := newTestResolver(t, server, Config{})

	_, err := resolver.Resolve(t.Context(), server.URL)
	require.ErrorIs(t, err, ErrInvalidClientID)
	_, err = resolver.Resolve(t.Context(), server.URL)
	require.ErrorIs(t, err, ErrInvalidClientID)
	assert.Equal(t, 1, *fetches, "failures must be negative-cached")
}

func TestResolverDocumentValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(serverURL string, doc *Client)
	}{
		{name: "client_id mismatch", mutate: func(_ string, doc *Client) { doc.ClientID = "https://other.example.com" }},
		{name: "empty redirect_uris", mutate: func(_ string, doc *Client) { doc.RedirectURIs = nil }},
		{name: "confidential auth method", mutate: func(_ string, doc *Client) { doc.TokenEndpointAuthMethod = "client_secret_basic" }},
		{name: "http redirect for non-loopback", mutate: func(_ string, doc *Client) { doc.RedirectURIs = []string{"http://app.example.com/cb"} }},
		{name: "javascript redirect scheme", mutate: func(_ string, doc *Client) { doc.RedirectURIs = []string{"javascript:alert(1)"} }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server, _ := serveDocument(t, tt.mutate)
			resolver := newTestResolver(t, server, Config{})
			_, err := resolver.Resolve(t.Context(), server.URL)
			require.ErrorIs(t, err, ErrInvalidClientID)
		})
	}
}

func TestResolverRejectsOversizedDocument(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"client_id": %q, "client_name": %q, "redirect_uris": ["https://x.example.com/cb"]}`,
			"https://irrelevant.example.com", strings.Repeat("x", 4096))
	}))
	t.Cleanup(server.Close)
	resolver := newTestResolver(t, server, Config{MaxSize: 1024})

	_, err := resolver.Resolve(t.Context(), server.URL)
	require.ErrorIs(t, err, ErrInvalidClientID)
	require.Contains(t, err.Error(), "exceeds")
}

func TestResolverRejectsRedirects(t *testing.T) {
	target, _ := serveDocument(t, nil)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)
	resolver := newTestResolver(t, server, Config{})

	_, err := resolver.Resolve(t.Context(), server.URL)
	require.ErrorIs(t, err, ErrInvalidClientID)
}

// TestResolverSSRFGuards uses the production configuration (no test knobs):
// every disallowed URL shape must be rejected before or at dial time.
func TestResolverSSRFGuards(t *testing.T) {
	resolver := NewResolver(Config{FetchTimeout: time.Second})

	cases := []struct {
		name     string
		clientID string
	}{
		{name: "http scheme", clientID: "http://example.com/client"},
		{name: "missing host", clientID: "https:///client"},
		{name: "userinfo", clientID: "https://user@example.com/client"},
		{name: "non-default port", clientID: "https://example.com:8443/client"},
		{name: "loopback literal", clientID: "https://127.0.0.1/client"},
		{name: "loopback name", clientID: "https://localhost/client"},
		{name: "private range", clientID: "https://192.168.1.10/client"},
		{name: "metadata service", clientID: "https://169.254.169.254/latest/meta-data"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolver.Resolve(t.Context(), tt.clientID)
			require.Error(t, err)
		})
	}
}

func TestIsDisallowedIP(t *testing.T) {
	disallowed := []string{"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "fe80::1", "fc00::1", "0.0.0.0", "224.0.0.1"}
	for _, raw := range disallowed {
		assert.True(t, isDisallowedIP(net.ParseIP(raw)), "should reject %s", raw)
	}
	allowed := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "8.8.8.8"}
	for _, raw := range allowed {
		assert.False(t, isDisallowedIP(net.ParseIP(raw)), "should allow %s", raw)
	}
}

func TestValidateRedirectURI(t *testing.T) {
	valid := []string{"https://app.example.com/cb", "http://127.0.0.1:8912/cb", "http://localhost/cb", "myapp://callback"}
	for _, raw := range valid {
		assert.NoError(t, ValidateRedirectURI(raw), raw)
	}
	invalid := []string{"http://app.example.com/cb", "javascript:alert(1)", "data:text/html,x", "relative/path", ""}
	for _, raw := range invalid {
		assert.Error(t, ValidateRedirectURI(raw), raw)
	}
}
