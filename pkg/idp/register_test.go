package idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDCRRegistrationHardening(t *testing.T) {
	register := func(t *testing.T, serverURL string, req registrationRequest) *http.Response {
		t.Helper()
		body, err := json.Marshal(req)
		require.NoError(t, err)
		resp, err := http.Post(serverURL+RegistrationEndpoint, "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		return resp
	}
	validRequest := func() registrationRequest {
		return registrationRequest{
			ClientName:              "Hardening Test Client",
			TokenEndpointAuthMethod: "client_secret_basic",
			RedirectURIs:            []string{"https://app.example.com/callback"},
		}
	}

	t.Run("registration TTL is reported", func(t *testing.T) {
		server, _, _ := setupTestServer(t)
		resp := register(t, server.URL, validRequest())
		defer resp.Body.Close()
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var regResp registrationResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))
		require.Greater(t, regResp.ClientSecretExpiresAt, time.Now().Unix(), "client_secret_expires_at must carry the SR-5 TTL")
	})

	t.Run("client cap returns 503", func(t *testing.T) {
		server, _, _ := setupTestServerWith(t, func(cfg *Config) { cfg.DCRMaxClients = 1 })
		first := register(t, server.URL, validRequest())
		first.Body.Close()
		require.Equal(t, http.StatusCreated, first.StatusCode)

		second := register(t, server.URL, validRequest())
		defer second.Body.Close()
		require.Equal(t, http.StatusServiceUnavailable, second.StatusCode)
		var errBody map[string]any
		require.NoError(t, json.NewDecoder(second.Body).Decode(&errBody))
		require.Equal(t, "temporarily_unavailable", errBody["error"])
	})

	t.Run("invalid metadata is rejected", func(t *testing.T) {
		server, _, _ := setupTestServer(t)
		cases := []struct {
			name    string
			mutate  func(*registrationRequest)
			errCode string
		}{
			{name: "no redirect uris", mutate: func(r *registrationRequest) { r.RedirectURIs = nil }, errCode: "invalid_redirect_uri"},
			{name: "http non-loopback redirect", mutate: func(r *registrationRequest) { r.RedirectURIs = []string{"http://app.example.com/cb"} }, errCode: "invalid_redirect_uri"},
			{name: "javascript redirect", mutate: func(r *registrationRequest) { r.RedirectURIs = []string{"javascript:alert(1)"} }, errCode: "invalid_redirect_uri"},
			{name: "unsupported grant type", mutate: func(r *registrationRequest) { r.GrantTypes = []string{"client_credentials"} }, errCode: "invalid_client_metadata"},
			{name: "unsupported response type", mutate: func(r *registrationRequest) { r.ResponseTypes = []string{"token"} }, errCode: "invalid_client_metadata"},
			{name: "unknown auth method", mutate: func(r *registrationRequest) { r.TokenEndpointAuthMethod = "private_key_jwt" }, errCode: "invalid_client_metadata"},
		}
		for _, tt := range cases {
			t.Run(tt.name, func(t *testing.T) {
				req := validRequest()
				tt.mutate(&req)
				resp := register(t, server.URL, req)
				defer resp.Body.Close()
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				var errBody map[string]any
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
				require.Equal(t, tt.errCode, errBody["error"])
			})
		}
	})
}

func TestDCRDisabled(t *testing.T) {
	server, _, _ := setupTestServerWith(t, func(cfg *Config) { cfg.DCREnabled = false })

	resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "DCR_ENABLED=false must remove the endpoint")

	metaResp, err := http.Get(server.URL + OauthAuthorizationServerEndpoint)
	require.NoError(t, err)
	defer metaResp.Body.Close()
	var metadata map[string]any
	require.NoError(t, json.NewDecoder(metaResp.Body).Decode(&metadata))
	_, present := metadata["registration_endpoint"]
	require.False(t, present, "metadata must not advertise a disabled registration endpoint")
}

func TestExpiredDCRClientRejected(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	// Push the registration's expiry into the past (SPEC §1.4).
	require.NoError(t, repo.TouchClient(t.Context(), regResp.ClientID, time.Now().UTC().Add(-time.Minute)))

	resp, err := http.Get(fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback")))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.GreaterOrEqual(t, resp.StatusCode, 400, "expired registrations must be treated as absent")
	require.Less(t, resp.StatusCode, 500)
}

// TestRegisterMalformedJSONNoInternalLeak verifies the register endpoint
// returns a generic description, not the JSON parser's internal text (SR-8/§6).
func TestRegisterMalformedJSONNoInternalLeak(t *testing.T) {
	server, _, _ := setupTestServer(t)
	resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json",
		strings.NewReader(`{"redirect_uris": "not-an-array"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "invalid_request", body["error"])
	desc, _ := body["error_description"].(string)
	require.NotContains(t, desc, "json:", "must not leak the Go JSON parser's internal message")
	require.NotContains(t, desc, "Go struct")
}
