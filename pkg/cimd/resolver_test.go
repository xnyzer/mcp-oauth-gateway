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
		// A document that leaves *nothing* this server supports is still
		// rejected: there is no flow left to run. Documents that merely also
		// name something unsupported are narrowed instead — see
		// TestResolverNarrowsUnsupportedFlows.
		{name: "no supported grant_type", mutate: func(_ string, doc *Client) { doc.GrantTypes = []string{"implicit"} }},
		{name: "no supported response_type", mutate: func(_ string, doc *Client) { doc.ResponseTypes = []string{"token"} }},
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
	disallowed := []string{
		// Covered by the address predicates.
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "fe80::1", "fc00::1", "0.0.0.0", "224.0.0.1",
		// Reserved ranges the predicates miss (SPEC §1.3.2, added in F-006b).
		"100.100.100.200", // Alibaba Cloud metadata (CGNAT)
		"100.64.0.1",      // CGNAT
		"192.0.0.1",       // IETF protocol assignments
		"192.0.2.5",       // TEST-NET-1
		"198.18.0.1",      // benchmarking
		"198.51.100.7",    // TEST-NET-2
		"203.0.113.9",     // TEST-NET-3
		"240.0.0.1",       // reserved/future
		"255.255.255.255", // broadcast
		"2001:db8::1",     // IPv6 documentation
		"64:ff9b::7f00:1", // NAT64 embedding 127.0.0.1
		"::ffff:10.0.0.1", // IPv4-mapped private address
	}
	for _, raw := range disallowed {
		assert.True(t, isDisallowedIP(net.ParseIP(raw)), "should reject %s", raw)
	}
	allowed := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "8.8.8.8", "1.1.1.1"}
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

// TestResolverCacheBounded verifies the resolver cache does not grow without
// limit when many distinct client IDs are stored (memory-DoS bound, F-006b).
func TestResolverCacheBounded(t *testing.T) {
	r := NewResolver(Config{})
	for i := 0; i < maxCacheEntries+500; i++ {
		r.store(fmt.Sprintf("https://client-%d.example.com/meta.json", i),
			cacheEntry{expiresAt: r.now().Add(time.Hour)})
	}
	require.LessOrEqual(t, len(r.cache), maxCacheEntries, "cache must stay bounded")
}

// TestResolverNarrowsUnsupportedFlows covers the case that broke the live
// deployment: Claude's published document declares
// urn:ietf:params:oauth:grant-type:jwt-bearer next to authorization_code and
// refresh_token, and the gateway rejected the whole client over it with
// "invalid CIMD client ID: unsupported grant_type". A CIMD document is
// published once and shown to every authorization server, so it names the
// union of the client's abilities; refusing it for naming a grant this server
// does not offer makes CIMD unusable with real clients.
//
// Narrowing must stay fail-closed — the resolved client may only ever end up
// with a subset of what the document asked for.
func TestResolverNarrowsUnsupportedFlows(t *testing.T) {
	cases := []struct {
		name              string
		grantTypes        []string
		responseTypes     []string
		wantGrantTypes    []string
		wantResponseTypes []string
	}{
		{
			name:              "claude's real document",
			grantTypes:        []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
			responseTypes:     []string{"code"},
			wantGrantTypes:    []string{"authorization_code", "refresh_token"},
			wantResponseTypes: []string{"code"},
		},
		{
			name:              "client_credentials dropped, order preserved",
			grantTypes:        []string{"client_credentials", "authorization_code"},
			responseTypes:     []string{"code"},
			wantGrantTypes:    []string{"authorization_code"},
			wantResponseTypes: []string{"code"},
		},
		{
			name:              "implicit response type dropped",
			grantTypes:        []string{"authorization_code"},
			responseTypes:     []string{"token", "code"},
			wantGrantTypes:    []string{"authorization_code"},
			wantResponseTypes: []string{"code"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server, _ := serveDocument(t, func(_ string, doc *Client) {
				doc.GrantTypes = tt.grantTypes
				doc.ResponseTypes = tt.responseTypes
			})
			resolver := newTestResolver(t, server, Config{})

			client, err := resolver.Resolve(t.Context(), server.URL)
			require.NoError(t, err, "the client must resolve, not be rejected")
			assert.Equal(t, tt.wantGrantTypes, client.GrantTypes)
			assert.Equal(t, tt.wantResponseTypes, client.ResponseTypes)
		})
	}
}
