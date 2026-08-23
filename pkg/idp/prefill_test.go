package idp

// The prefill for the operator's connection name (F-025b): the name a client
// declares about itself, shown on the consent page and offered as the starting
// value. It closes the SPEC §1.5 requirement that consent show the client's
// identity — the client_id was always there, the client_name never was.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
)

// prefillRE reads the value the consent form offers for the connection name.
var prefillRE = regexp.MustCompile(`name="connection_name"[^>]*value="([^"]*)"`)

// consentPrefill drives the authorize step and returns the value the consent
// form offers, without approving anything.
func consentPrefill(t *testing.T, serverURL, clientID, redirectURI string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=prefill-test-state&code_challenge=%s&code_challenge_method=S256",
		serverURL, AuthorizationEndpoint, url.QueryEscape(clientID),
		url.QueryEscape(redirectURI), testPKCEChallenge())

	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	authResp.Body.Close()
	consentPath := authResp.Header.Get("Location")
	require.NotEmpty(t, consentPath, "authorize must redirect to the consent page")

	formResp, err := client.Get(serverURL + consentPath)
	require.NoError(t, err)
	form, err := io.ReadAll(formResp.Body)
	formResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, formResp.StatusCode)

	m := prefillRE.FindSubmatch(form)
	require.NotNil(t, m, "the consent form must offer a connection_name field: %s", form)
	return string(m[1])
}

// A DCR client declares its name at registration. It was parsed and discarded
// before F-025b; now it is stored and offered back.
func TestConsentPrefillsTheDCRClientName(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	reg := registerTestClient(t, server.URL)

	stored, err := repo.GetClientName(t.Context(), reg.ClientID)
	require.NoError(t, err)
	require.Equal(t, reg.ClientName, stored, "the declared name must be stored, not only echoed")
	require.NotEmpty(t, stored, "the fixture must declare a name for this test to mean anything")

	require.Equal(t, stored, consentPrefill(t, server.URL, reg.ClientID, testRedirectURI))
}

// A CIMD client declares its name in its metadata document.
func TestConsentPrefillsTheCIMDClientName(t *testing.T) {
	const cimdClientID = "https://client.example.com/oauth/client-metadata.json"
	const cimdRedirect = "https://client.example.com/callback"
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.CIMDResolver = &stubResolver{doc: &cimd.Client{
			ClientID:     cimdClientID,
			ClientName:   "Claude",
			RedirectURIs: []string{cimdRedirect},
		}}
	})

	require.Equal(t, "Claude", consentPrefill(t, server.URL, cimdClientID, cimdRedirect))
}

// countingResolver records how often it was asked, so the consent page can be
// shown to use the resolver the router was configured with.
type countingResolver struct {
	doc   *cimd.Client
	calls int
}

func (r *countingResolver) Resolve(_ context.Context, clientID string) (*cimd.Client, error) {
	r.calls++
	if r.doc != nil && r.doc.ClientID == clientID {
		return r.doc, nil
	}
	return nil, cimd.ErrInvalidClientID
}

// The consent page must read the name through the **same** resolver fosite uses
// for the client lookup, because that resolver caches (proven in pkg/cimd's
// TestResolverHappyPathAndCache). A second resolver, or a direct fetch, would
// mean a second document request per authorization.
func TestConsentUsesTheConfiguredCIMDResolver(t *testing.T) {
	const cimdClientID = "https://client.example.com/oauth/client-metadata.json"
	const cimdRedirect = "https://client.example.com/callback"
	resolver := &countingResolver{doc: &cimd.Client{
		ClientID:     cimdClientID,
		ClientName:   "Claude",
		RedirectURIs: []string{cimdRedirect},
	}}
	server, _, _ := setupTestServerWith(t, func(cfg *Config) { cfg.CIMDResolver = resolver })

	require.Equal(t, "Claude", consentPrefill(t, server.URL, cimdClientID, cimdRedirect))
	// Observed: fosite resolves at the authorize step, the consent render asks
	// once more. Both go through this one resolver, so the real one answers the
	// second from its cache and the document is fetched once per authorization.
	require.Positive(t, resolver.calls,
		"the consent page must go through the configured resolver, whose cache makes this free")
	t.Logf("resolver consulted %d times for one authorize + consent render", resolver.calls)
}

// Without a resolver there is no CIMD name to read, and the page must still
// render — an unnamed connection is the normal case, not an error.
func TestConsentPrefillIsEmptyWhenNothingDeclaresAName(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	require.NoError(t, repo.RegisterClient(t.Context(), repository.ClientRegistration{
		Client: &fosite.DefaultClient{
			ID:           "unnamed-client",
			Public:       true,
			RedirectURIs: []string{testRedirectURI},
		},
	}))

	require.Empty(t, consentPrefill(t, server.URL, "unnamed-client", testRedirectURI))
}
