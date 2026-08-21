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
	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// TestEndpointRateLimits covers SR-5: /register and /token answer 429 with
// a rate_limited event once the per-IP bucket is exhausted.
func TestEndpointRateLimits(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.Logger = zap.New(core)
		registerLimiter := ratelimit.NewLimiter(ratelimit.Limit{Events: 1, Window: time.Hour})
		tokenLimiter := ratelimit.NewLimiter(ratelimit.Limit{Events: 1, Window: time.Hour})
		cfg.RegisterRateLimit = ratelimit.Middleware(registerLimiter, "register", cfg.Logger)
		cfg.TokenRateLimit = ratelimit.Middleware(tokenLimiter, "token", cfg.Logger)
	})

	// First registration passes, second is limited.
	regBody := `{"redirect_uris":["http://localhost:8080/callback"]}`
	resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp, err = http.Post(server.URL+RegistrationEndpoint, "application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	var limited map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&limited))
	require.Equal(t, "temporarily_unavailable", limited["error"])

	// The token endpoint has its own bucket.
	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, url.Values{"grant_type": {"authorization_code"}})
	require.NoError(t, err)
	tokenResp.Body.Close()
	require.NotEqual(t, http.StatusTooManyRequests, tokenResp.StatusCode, "first token request is not limited")
	tokenResp, err = http.PostForm(server.URL+TokenEndpoint, url.Values{"grant_type": {"authorization_code"}})
	require.NoError(t, err)
	tokenResp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, tokenResp.StatusCode)

	events := logs.FilterField(zap.String("event", "rate_limited")).All()
	require.Len(t, events, 2)
	endpoints := []string{events[0].ContextMap()["endpoint"].(string), events[1].ContextMap()["endpoint"].(string)}
	require.ElementsMatch(t, []string{"register", "token"}, endpoints)
}

// TestTokenAndRegisterEvents covers SR-8: token_issued, register, and
// revoked events are emitted with non-secret context only.
func TestTokenAndRegisterEvents(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.Logger = zap.New(core)
	})
	regResp := registerTestClient(t, server.URL)

	registers := logs.FilterField(zap.String("event", "register")).All()
	require.Len(t, registers, 1)
	require.Equal(t, regResp.ClientID, registers[0].ContextMap()["client_id"])

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
	var tokens map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokens))
	tokenResp.Body.Close()
	accessToken := tokens["access_token"].(string)

	issued := logs.FilterField(zap.String("event", "token_issued")).All()
	require.Len(t, issued, 1)
	require.Equal(t, regResp.ClientID, issued[0].ContextMap()["client_id"])

	// Revocation emits the revoked event.
	req, err := http.NewRequest(http.MethodPost, server.URL+RevocationEndpoint,
		strings.NewReader(url.Values{"token": {accessToken}}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(regResp.ClientID, regResp.ClientSecret)
	revokeResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	revokeResp.Body.Close()
	require.Equal(t, http.StatusOK, revokeResp.StatusCode)
	require.Len(t, logs.FilterField(zap.String("event", "revoked")).All(), 1)

	// No auth event carries token material (SR-8).
	for _, entry := range logs.FilterMessage("auth event").All() {
		for key, value := range entry.ContextMap() {
			text, ok := value.(string)
			if !ok {
				continue
			}
			require.NotContains(t, text, accessToken, "field %s must not leak the access token", key)
			require.NotContains(t, text, regResp.ClientSecret, "field %s must not leak the client secret", key)
		}
	}
}
