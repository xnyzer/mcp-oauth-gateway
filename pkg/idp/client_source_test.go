package idp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
)

func TestCIMDClientRoundTrip(t *testing.T) {
	const cimdClientID = "https://client.example.com/oauth/client-metadata.json"
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.CIMDResolver = &stubResolver{doc: &cimd.Client{
			ClientID:     cimdClientID,
			ClientName:   "CIMD Test Client",
			RedirectURIs: []string{"https://client.example.com/callback"},
		}}
	})

	// Public client (SPEC §1.3): PKCE S256 is the proof of possession.
	verifier := strings.Repeat("v", 64)
	challengeHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state&code_challenge=%s&code_challenge_method=S256",
		server.URL, AuthorizationEndpoint,
		url.QueryEscape(cimdClientID),
		url.QueryEscape("https://client.example.com/callback"),
		challenge)

	callbackURL := testAuthFlowWithURL(t, server.URL, authURL)
	code := callbackURL.Query().Get("code")
	require.NotEmpty(t, code, "CIMD client must receive an authorization code")

	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "https://client.example.com/callback")
	tokenReq.Set("client_id", cimdClientID)
	tokenReq.Set("code_verifier", verifier)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenResult))
	accessToken, _ := tokenResult["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// The client_id claim carries the CIMD URL (SPEC §1.7).
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(accessToken, ".")[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, cimdClientID, claims["client_id"])
}

func TestCIMDUnresolvableClientRejected(t *testing.T) {
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.CIMDResolver = &stubResolver{} // resolves nothing
	})

	resp, err := http.Get(fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint,
		url.QueryEscape("https://unknown.example.com/client.json"),
		url.QueryEscape("https://unknown.example.com/callback")))
	require.NoError(t, err)
	defer resp.Body.Close()
	// Unknown client: non-redirectable error (no trusted redirect URI).
	require.GreaterOrEqual(t, resp.StatusCode, 400)
	require.Less(t, resp.StatusCode, 500)
}
