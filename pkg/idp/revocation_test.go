package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
)

func TestRevocationEndpoint(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	issueTokens := func(t *testing.T) map[string]any {
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
		return result
	}

	post := func(t *testing.T, endpoint string, form url.Values, withAuth bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+endpoint, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withAuth {
			req.SetBasicAuth(regResp.ClientID, regResp.ClientSecret)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		return resp
	}

	introspectActive := func(t *testing.T, token string) bool {
		t.Helper()
		resp := post(t, IntrospectionEndpoint, url.Values{"token": {token}}, true)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var result map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		active, _ := result["active"].(bool)
		return active
	}

	t.Run("revoking an access token deletes its record", func(t *testing.T) {
		tokens := issueTokens(t)
		accessToken := tokens["access_token"].(string)
		require.True(t, introspectActive(t, accessToken))

		resp := post(t, RevocationEndpoint, url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}, true)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		require.False(t, introspectActive(t, accessToken), "revoked access token must introspect inactive")

		sig := strings.Split(accessToken, ".")[2]
		_, err := repo.GetAccessTokenSession(t.Context(), sig, nil)
		require.ErrorIs(t, err, fosite.ErrNotFound, "server-side record must be gone")
	})

	t.Run("revoking a refresh token cascades to the grant's access tokens", func(t *testing.T) {
		tokens := issueTokens(t)
		accessToken := tokens["access_token"].(string)
		refreshToken, _ := tokens["refresh_token"].(string)
		require.NotEmpty(t, refreshToken)

		resp := post(t, RevocationEndpoint, url.Values{"token": {refreshToken}, "token_type_hint": {"refresh_token"}}, true)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		require.False(t, introspectActive(t, accessToken), "grant's access token must be revoked with the refresh token")

		refreshReq := url.Values{}
		refreshReq.Set("grant_type", "refresh_token")
		refreshReq.Set("refresh_token", refreshToken)
		refreshReq.Set("client_id", regResp.ClientID)
		refreshReq.Set("client_secret", regResp.ClientSecret)
		refreshResp, err := http.PostForm(server.URL+TokenEndpoint, refreshReq)
		require.NoError(t, err)
		defer refreshResp.Body.Close()
		require.NotEqual(t, http.StatusOK, refreshResp.StatusCode, "revoked refresh token must not mint new tokens")
	})

	t.Run("unknown token still yields 200 (no token-existence oracle)", func(t *testing.T) {
		resp := post(t, RevocationEndpoint, url.Values{"token": {"unknown-token"}}, true)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("missing client authentication is rejected", func(t *testing.T) {
		resp := post(t, RevocationEndpoint, url.Values{"token": {"whatever"}}, false)
		defer resp.Body.Close()
		// fosite responds 400 invalid_request for absent credentials;
		// 401 invalid_client for wrong ones — both are rejections.
		require.Contains(t, []int{http.StatusBadRequest, http.StatusUnauthorized}, resp.StatusCode)
	})
}

// failingRevokeRepo makes token revocation fail at the storage layer while
// leaving issuance intact, to exercise the fail-closed 503 path (SPEC §1.9).
type failingRevokeRepo struct {
	repository.Repository
}

func (f *failingRevokeRepo) RevokeAccessToken(context.Context, string) error {
	return fmt.Errorf("simulated store failure")
}

func (f *failingRevokeRepo) RevokeRefreshToken(context.Context, string) error {
	return fmt.Errorf("simulated store failure")
}

// TestRevocationStoreFailureReturns503 verifies that a storage failure during
// revocation surfaces as 503, not a misleading 200 (SPEC §1.9, SR-3): a
// silent no-op would leave the operator believing a compromised token was
// revoked while it stays live.
func TestRevocationStoreFailureReturns503(t *testing.T) {
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.Repo = &failingRevokeRepo{Repository: cfg.Repo}
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
	var tokens map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokens))
	accessToken := tokens["access_token"].(string)

	req, err := http.NewRequest(http.MethodPost, server.URL+RevocationEndpoint,
		strings.NewReader(url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(regResp.ClientID, regResp.ClientSecret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"a store failure during revocation must fail closed with 503, not a misleading 200")
}
