package idp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
)

// TestMatchesLoopbackHostPort pins the rule to "only the port may differ".
// Every negative here is a way the check could turn into an open redirect if
// it were written loosely.
func TestMatchesLoopbackHostPort(t *testing.T) {
	tests := []struct {
		name       string
		registered string
		requested  string
		want       bool
	}{
		{"port added to a portless registration", "http://localhost/callback", "http://localhost:3118/callback", true},
		{"port changed", "http://localhost:1/callback", "http://localhost:65535/callback", true},
		{"identical query preserved", "http://localhost/cb?a=1", "http://localhost:8080/cb?a=1", true},
		{"host case is irrelevant", "http://LOCALHOST/callback", "http://localhost:3118/callback", true},

		{"different path", "http://localhost/callback", "http://localhost:3118/evil", false},
		{"path prefix is not enough", "http://localhost/cb", "http://localhost:3118/cb/evil", false},
		{"different query", "http://localhost/cb?a=1", "http://localhost:3118/cb?a=2", false},
		{"query added", "http://localhost/cb", "http://localhost:3118/cb?a=1", false},
		{"https is not a loopback client", "https://localhost/callback", "https://localhost:3118/callback", false},
		{"scheme downgrade", "https://localhost/callback", "http://localhost:3118/callback", false},
		{"subdomain of localhost is not localhost", "http://localhost/cb", "http://evil.localhost:3118/cb", false},
		{"registered subdomain does not grant the name", "http://evil.localhost/cb", "http://localhost:3118/cb", false},
		{"foreign host", "http://localhost/cb", "http://evil.example.com:3118/cb", false},
		{"IP literal is fosite's job, not ours", "http://127.0.0.1/cb", "http://127.0.0.1:3118/cb", false},
		{"hostname must not bridge to an IP literal", "http://localhost/cb", "http://127.0.0.1:3118/cb", false},
		{"garbage requested", "http://localhost/cb", "://", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, matchesLoopbackHostPort(tc.registered, tc.requested))
		})
	}
}

// TestExpandLoopbackRedirects covers the wrapper's own responsibilities:
// leaving the list alone when nothing matches, and never aliasing the input.
func TestExpandLoopbackRedirects(t *testing.T) {
	registered := []string{"https://web.example.com/cb", "http://localhost/callback"}

	t.Run("appends a port variant", func(t *testing.T) {
		got := expandLoopbackRedirects(registered, "http://localhost:3118/callback")
		require.Equal(t, append(append([]string{}, registered...), "http://localhost:3118/callback"), got)
	})

	t.Run("leaves the input slice untouched", func(t *testing.T) {
		before := append([]string{}, registered...)
		_ = expandLoopbackRedirects(registered, "http://localhost:3118/callback")
		require.Equal(t, before, registered, "the caller's slice must not be mutated")
	})

	t.Run("exact match needs no expansion", func(t *testing.T) {
		got := expandLoopbackRedirects(registered, "http://localhost/callback")
		require.Len(t, got, len(registered))
	})

	t.Run("no match leaves the list as is", func(t *testing.T) {
		got := expandLoopbackRedirects(registered, "http://localhost:3118/evil")
		require.Len(t, got, len(registered))
	})

	t.Run("empty request is a no-op", func(t *testing.T) {
		require.Len(t, expandLoopbackRedirects(registered, ""), len(registered))
	})
}

// TestAllRedirectsLoopback pins the consent warning to native clients only.
func TestAllRedirectsLoopback(t *testing.T) {
	require.True(t, allRedirectsLoopback([]string{"http://localhost/cb", "http://127.0.0.1/cb"}))
	require.True(t, allRedirectsLoopback([]string{"http://[::1]:3118/cb"}))
	require.False(t, allRedirectsLoopback([]string{"http://localhost/cb", "https://web.example.com/cb"}),
		"a client that also has a web callback is not a native client")
	require.False(t, allRedirectsLoopback([]string{"https://web.example.com/cb"}))
	require.False(t, allRedirectsLoopback(nil))
}

// TestLoopbackRedirectAuthorizeFlow drives the real authorize endpoint with
// the exact client shape Claude Code publishes: portless localhost and
// 127.0.0.1 callbacks, then a request on an ephemeral port. It is the test
// that proves the wiring — predicate, context stash and fosite's matcher all
// have to line up for a code to come back.
func TestLoopbackRedirectAuthorizeFlow(t *testing.T) {
	const clientID = "https://client.example.com/oauth/client-metadata.json"
	newServer := func(t *testing.T) *httptest.Server {
		server, _, _ := setupTestServerWith(t, func(cfg *Config) {
			cfg.CIMDResolver = &stubResolver{doc: &cimd.Client{
				ClientID:     clientID,
				ClientName:   "Native Test Client",
				RedirectURIs: []string{"http://localhost/callback", "http://127.0.0.1/callback"},
			}}
		})
		return server
	}

	authURL := func(server *httptest.Server, redirectURI string) string {
		verifier := strings.Repeat("v", 64)
		sum := sha256.Sum256([]byte(verifier))
		return fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=loopback-state&code_challenge=%s&code_challenge_method=S256",
			server.URL, AuthorizationEndpoint,
			url.QueryEscape(clientID), url.QueryEscape(redirectURI),
			base64.RawURLEncoding.EncodeToString(sum[:]))
	}

	t.Run("localhost with an ephemeral port is accepted", func(t *testing.T) {
		server := newServer(t)
		callback := testAuthFlowWithURL(t, server.URL, authURL(server, "http://localhost:3118/callback"))
		require.NotEmpty(t, callback.Query().Get("code"), "an ephemeral-port loopback client must receive a code")
		// The user must land on the port the client actually listens on —
		// not on the portless form it registered.
		require.Equal(t, "localhost", callback.Hostname())
		require.Equal(t, "3118", callback.Port())
		require.Equal(t, "/callback", callback.Path)
	})

	t.Run("the IP-literal form still works", func(t *testing.T) {
		server := newServer(t)
		callback := testAuthFlowWithURL(t, server.URL, authURL(server, "http://127.0.0.1:3118/callback"))
		require.NotEmpty(t, callback.Query().Get("code"), "fosite's own loopback rule must be unaffected")
		require.Equal(t, "127.0.0.1", callback.Hostname())
	})

	// A rejected redirect URI must never reach the consent page, and must
	// never yield a code — fosite refuses to bounce the user to a URI it
	// could not match, so there is nothing to follow.
	assertRejected := func(t *testing.T, server *httptest.Server, redirectURI string) {
		t.Helper()
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Get(authURL(server, redirectURI))
		require.NoError(t, err)
		defer resp.Body.Close()
		location := resp.Header.Get("Location")
		require.NotContains(t, location, "code=", "no authorization code may be issued")
		require.NotContains(t, location, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ""),
			"a rejected redirect_uri must not reach the consent page")
	}

	for _, tc := range []struct {
		name        string
		redirectURI string
	}{
		{"different path on the same port", "http://localhost:3118/evil"},
		{"added query", "http://localhost:3118/callback?next=evil"},
		{"subdomain of localhost", "http://evil.localhost:3118/callback"},
		{"foreign host", "http://evil.example.com:3118/callback"},
		{"https instead of http", "https://localhost:3118/callback"},
	} {
		t.Run("rejected: "+tc.name, func(t *testing.T) {
			assertRejected(t, newServer(t), tc.redirectURI)
		})
	}
}

// TestConsentWarnsForLoopbackOnlyClient checks the template wiring: the flag
// computed from the client's redirect URIs has to actually reach the page.
func TestConsentWarnsForLoopbackOnlyClient(t *testing.T) {
	render := func(loopbackOnly bool) string {
		var buf bytes.Buffer
		require.NoError(t, consentTemplate.Execute(&buf, consentTemplateData{
			ClientID:     "https://client.example.com/oauth/client-metadata.json",
			RedirectURI:  "http://localhost:3118/callback",
			CSRFToken:    "t",
			LoopbackOnly: loopbackOnly,
		}))
		return buf.String()
	}
	require.Contains(t, render(true), "runs on the device you are using")
	require.NotContains(t, render(false), "runs on the device you are using")
}
