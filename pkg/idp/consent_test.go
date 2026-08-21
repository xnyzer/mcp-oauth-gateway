package idp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
)

// TestConsentPostRejectsMissingOrWrongCSRF covers the consent-form CSRF guard
// (SPEC §1.5/§1.12): the approval POST is refused without a matching token,
// even though the ar_id is bound to the session.
func TestConsentPostRejectsMissingOrWrongCSRF(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state&code_challenge=%s&code_challenge_method=S256",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"), testPKCEChallenge())

	client := &http.Client{
		Jar:           mustCookieJar(t),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	location := requireRedirectLocation(t, mustGetResp(t, client, authURL))

	// Render the consent form so the session holds a token.
	formResp := mustGetResp(t, client, server.URL+location)
	formResp.Body.Close()
	require.Equal(t, http.StatusOK, formResp.StatusCode)

	// No token -> 403.
	missing, err := client.PostForm(server.URL+location, url.Values{})
	require.NoError(t, err)
	missing.Body.Close()
	require.Equal(t, http.StatusForbidden, missing.StatusCode)

	// Wrong token -> 403.
	wrong, err := client.PostForm(server.URL+location, url.Values{auth.CSRFFieldName: {"deadbeef"}})
	require.NoError(t, err)
	wrong.Body.Close()
	require.Equal(t, http.StatusForbidden, wrong.StatusCode)
}

// TestConsentShowsClientIdentityAndScopes verifies the consent page renders the
// client_id, redirect target and requested scopes (SPEC §1.5) so the operator
// can recognise and decline a foreign client (anti-phishing, H1).
func TestConsentShowsClientIdentityAndScopes(t *testing.T) {
	const cimdClientID = "https://phisher.example.com/oauth/client-metadata.json"
	const redirectURI = "https://phisher.example.com/callback"
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.CIMDResolver = &stubResolver{doc: &cimd.Client{
			ClientID:     cimdClientID,
			ClientName:   "Some Client",
			RedirectURIs: []string{redirectURI},
			Scope:        "read",
		}}
	})

	verifier := strings.Repeat("v", 64)
	challengeHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state&scope=read&code_challenge=%s&code_challenge_method=S256",
		server.URL, AuthorizationEndpoint,
		url.QueryEscape(cimdClientID), url.QueryEscape(redirectURI), challenge)

	client := &http.Client{
		Jar:           mustCookieJar(t),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	authResp.Body.Close()
	location := authResp.Header.Get("Location")
	require.Contains(t, location, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ""))

	formResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	defer formResp.Body.Close()
	require.Equal(t, http.StatusOK, formResp.StatusCode)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(formResp.Body)
	require.NoError(t, err)
	page := buf.String()
	require.Contains(t, page, cimdClientID, "consent page must show the client identity")
	require.Contains(t, page, redirectURI, "consent page must show the redirect target")
	require.Contains(t, page, "read", "consent page must show the requested scope")
}
