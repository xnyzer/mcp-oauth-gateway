package idp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
)

// TestKeyRotationKeepsOldTokensValid is the F-005d acceptance test: a token
// issued before a rotation stays valid until exp (introspection still
// reports it active), JWKS serves both keys, and new tokens carry the new
// kid (SPEC §2.3).
func TestKeyRotationKeepsOldTokensValid(t *testing.T) {
	var keyManager *keys.Manager
	server, _, _ := setupTestServerWith(t, func(cfg *Config) { keyManager = cfg.Keys })
	regResp := registerTestClient(t, server.URL)

	issueToken := func(t *testing.T) string {
		t.Helper()
		authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
			server.URL, AuthorizationEndpoint, regResp.ClientID,
			url.QueryEscape("http://localhost:8080/callback"))
		callbackURL := testAuthFlowWithURL(t, server.URL, authURL)
		tokenReq := url.Values{}
		tokenReq.Set("grant_type", "authorization_code")
		tokenReq.Set("code", callbackURL.Query().Get("code"))
		tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
		tokenReq.Set("client_id", regResp.ClientID)
		tokenReq.Set("client_secret", regResp.ClientSecret)
		tokenReq.Set("code_verifier", testPKCEVerifier)
		tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
		require.NoError(t, err)
		defer tokenResp.Body.Close()
		require.Equal(t, http.StatusOK, tokenResp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&result))
		return result["access_token"].(string)
	}

	introspectActive := func(t *testing.T, token string) bool {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+IntrospectionEndpoint,
			strings.NewReader(url.Values{"token": {token}}.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(regResp.ClientID, regResp.ClientSecret)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		active, _ := result["active"].(bool)
		return active
	}

	jwksKids := func(t *testing.T) []string {
		t.Helper()
		resp, err := http.Get(server.URL + JWKSEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		var jwksDoc struct {
			Keys []keys.JWK `json:"keys"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwksDoc))
		kids := make([]string, 0, len(jwksDoc.Keys))
		for _, key := range jwksDoc.Keys {
			kids = append(kids, key.Kid)
		}
		return kids
	}

	oldToken := issueToken(t)
	oldKid, _ := decodeJWTSegment(t, strings.Split(oldToken, ".")[0])["kid"].(string)
	require.NotEmpty(t, oldKid)
	require.True(t, introspectActive(t, oldToken))

	require.NoError(t, keyManager.Rotate(time.Now().UTC()))

	// Pre-rotation token: still valid until exp (NFR "no abrupt invalidation").
	require.True(t, introspectActive(t, oldToken), "pre-rotation token must stay valid until exp")

	// JWKS serves the new active and the retiring key (SPEC §1.8).
	kids := jwksKids(t)
	require.Len(t, kids, 2)
	require.Contains(t, kids, oldKid)
	require.Contains(t, kids, keyManager.Active().Kid)

	// New tokens are signed with the new active key only (SPEC §2.3.3).
	newToken := issueToken(t)
	newKid, _ := decodeJWTSegment(t, strings.Split(newToken, ".")[0])["kid"].(string)
	require.Equal(t, keyManager.Active().Kid, newKid)
	require.NotEqual(t, oldKid, newKid)
	require.True(t, introspectActive(t, newToken))
}

// TestES256TokenIssuance runs the full flow with KEY_ALG=ES256 (SPEC §2.2).
func TestES256TokenIssuance(t *testing.T) {
	var keyManager *keys.Manager
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		keyManager = newTestKeyManager(t, keys.AlgES256)
		cfg.Keys = keyManager
	})
	regResp := registerTestClient(t, server.URL)

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))
	callbackURL := testAuthFlowWithURL(t, server.URL, authURL)
	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", callbackURL.Query().Get("code"))
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)
	tokenReq.Set("code_verifier", testPKCEVerifier)
	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&result))
	accessToken := result["access_token"].(string)

	header := decodeJWTSegment(t, strings.Split(accessToken, ".")[0])
	require.Equal(t, "ES256", header["alg"])
	require.Equal(t, keyManager.Active().Kid, header["kid"])

	// JWKS advertises the EC key parameters (SPEC §1.8).
	resp, err := http.Get(server.URL + JWKSEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	var jwksDoc struct {
		Keys []keys.JWK `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwksDoc))
	require.Len(t, jwksDoc.Keys, 1)
	require.Equal(t, "EC", jwksDoc.Keys[0].Kty)
	require.Equal(t, "P-256", jwksDoc.Keys[0].Crv)
}
