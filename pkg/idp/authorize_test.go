package idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"go.uber.org/zap"
)

func TestAuthorizationReturnRequiresOriginalSession(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	attackerJar, err := cookiejar.New(nil)
	require.NoError(t, err)
	attackerClient := &http.Client{
		Jar: attackerJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := attackerClient.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	victimJar, err := cookiejar.New(nil)
	require.NoError(t, err)
	victimClient := &http.Client{Jar: victimJar}
	victimResp, err := victimClient.Post(server.URL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer victimResp.Body.Close()
	require.Equal(t, http.StatusForbidden, victimResp.StatusCode)
}

func TestPublicClientRequiresPKCE(t *testing.T) {
	server, _, _ := setupTestServer(t)

	regReq := registrationRequest{
		ClientName:              "Public OAuth Client",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "test",
		RedirectURIs:            []string{"http://localhost:8080/callback"},
	}
	reqBody, err := json.Marshal(regReq)
	require.NoError(t, err)

	resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var regResp registrationResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	require.NoError(t, err)
	require.Empty(t, regResp.ClientSecret)

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	client := &http.Client{
		Jar: mustCookieJar(t),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	formResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	defer formResp.Body.Close()
	require.Equal(t, http.StatusOK, formResp.StatusCode)

	authReturnResp := postConsent(t, client, server.URL+location)
	defer authReturnResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)

	callbackURL, err := url.Parse(authReturnResp.Header.Get("Location"))
	require.NoError(t, err)
	require.Empty(t, callbackURL.Query().Get("code"))
	require.NotEmpty(t, callbackURL.Query().Get("error"))
	// RFC 9207: error redirects identify the issuer, too (SPEC §1.5).
	require.Equal(t, "http://localhost:8080", callbackURL.Query().Get("iss"))
}

// TestConfidentialClientRequiresPKCE verifies EnforcePKCE now applies to
// confidential DCR clients too (SPEC §1.5 / F-012b): an authorize flow
// without code_challenge must end in an error, not an authorization code.
func TestConfidentialClientRequiresPKCE(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)
	require.NotEmpty(t, regResp.ClientSecret, "this client is confidential")

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	client := &http.Client{
		Jar:           mustCookieJar(t),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	formResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	formResp.Body.Close()

	// fosite enforces PKCE presence when the consent POST triggers the
	// authorize response — the redirect carries an error, never a code.
	authReturnResp := postConsent(t, client, server.URL+location)
	defer authReturnResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)

	callbackURL, err := url.Parse(authReturnResp.Header.Get("Location"))
	require.NoError(t, err)
	require.Empty(t, callbackURL.Query().Get("code"), "confidential client without PKCE must not receive a code")
	require.NotEmpty(t, callbackURL.Query().Get("error"), "missing code_challenge must be an error")
}

func TestAuthWithoutState(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	// Build authorization URL manually WITHOUT a state parameter
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	callbackURL := testAuthFlowWithURL(t, server.URL, authURL)

	// Server should have generated a state and echoed it back
	require.NotEmpty(t, callbackURL.Query().Get("state"), "server should generate a state when client omits it")

	// Exchange authorization code for tokens
	code := callbackURL.Query().Get("code")
	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)
	tokenReq.Set("code_verifier", testPKCEVerifier)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResult["access_token"])
}

func TestAuthWithEmptyState(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	// Build authorization URL with an empty state parameter
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	callbackURL := testAuthFlowWithURL(t, server.URL, authURL)

	// Server should have generated a state and echoed it back
	require.NotEmpty(t, callbackURL.Query().Get("state"), "server should generate a state when client sends empty state")

	// Exchange authorization code for tokens
	code := callbackURL.Query().Get("code")
	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)
	tokenReq.Set("code_verifier", testPKCEVerifier)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResult["access_token"])
}

func TestResourceParameterValidation(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	client := &http.Client{
		Jar: mustCookieJar(t),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// RFC 8707: a foreign resource is rejected with invalid_target (SPEC §1.5).
	badResourceURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state&resource=%s",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"),
		url.QueryEscape("https://other.example.com"))
	resp, err := client.Get(badResourceURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode)
	redirect, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "invalid_target", redirect.Query().Get("error"))
	require.Equal(t, "http://localhost:8080", redirect.Query().Get("iss"))

	// The issuer itself is a valid resource: the flow proceeds to consent.
	okResourceURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state&resource=%s",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"),
		url.QueryEscape("http://localhost:8080"))
	callbackURL := testAuthFlowWithURL(t, server.URL, okResourceURL)
	code := callbackURL.Query().Get("code")
	require.NotEmpty(t, code)

	// Token endpoint: a foreign resource at exchange fails with invalid_target (SPEC §1.6).
	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)
	tokenReq.Set("code_verifier", testPKCEVerifier)
	tokenReq.Set("resource", "https://other.example.com")

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusBadRequest, tokenResp.StatusCode)
	var tokenErr map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenErr))
	require.Equal(t, "invalid_target", tokenErr["error"])
}

// TestAuthorizeRateLimitReturns429 verifies the per-IP limiter guards the
// authorize endpoint (M4b): it bounds unauthenticated CIMD-resolution floods.
func TestAuthorizeRateLimitReturns429(t *testing.T) {
	limit, err := ratelimit.ParseLimit("1/m")
	require.NoError(t, err)
	server, _, _ := setupTestServerWith(t, func(cfg *Config) {
		cfg.AuthorizeRateLimit = ratelimit.Middleware(ratelimit.NewLimiter(limit), "authorize", zap.NewNop())
	})
	regResp := registerTestClient(t, server.URL)
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	first, err := client.Get(authURL)
	require.NoError(t, err)
	first.Body.Close()
	require.NotEqual(t, http.StatusTooManyRequests, first.StatusCode)

	second, err := client.Get(authURL)
	require.NoError(t, err)
	defer second.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, second.StatusCode)
}
