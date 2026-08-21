package idp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestPrivateClient(t *testing.T) {
	server, _, _ := setupTestServer(t)

	// Register a test client using the registration endpoint
	regReq := registrationRequest{
		ClientName:              "Private OAuth Client",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
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

	config := &oauth2.Config{
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + AuthorizationEndpoint,
			TokenURL: server.URL + TokenEndpoint,
		},
	}
	state := "test-state"
	// PKCE is mandatory for confidential clients too (EnforcePKCE, SPEC §1.5).
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", testPKCEChallenge()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Make initial authorization request
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()

	// Should get a redirect to the authorization return endpoint
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)
	require.Contains(t, location, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ""))

	// Step 2: GET renders the authorization confirmation form without granting
	authReturnResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()
	require.Equal(t, http.StatusOK, authReturnResp.StatusCode)

	// Step 3: POST the confirmation to complete authorization
	authReturnResp = postConsent(t, client, server.URL+location)
	defer authReturnResp.Body.Close()

	// Should get another redirect with authorization code
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)
	callbackLocation := authReturnResp.Header.Get("Location")
	require.NotEmpty(t, callbackLocation)

	// Step 4: Extract authorization code from callback URL
	callbackURL, err := url.Parse(callbackLocation)
	require.NoError(t, err)
	code := callbackURL.Query().Get("code")
	require.NotEmpty(t, code)
	receivedState := callbackURL.Query().Get("state")
	require.Equal(t, state, receivedState)
	// RFC 9207: the success redirect identifies the issuer (SPEC §1.5).
	require.Equal(t, "http://localhost:8080", callbackURL.Query().Get("iss"))

	// Step 5: Exchange authorization code for tokens using manual HTTP request
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

	// Should get a valid token response
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)

	accessToken, ok := tokenResult["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)

	refreshToken, ok := tokenResult["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, refreshToken)

	tokenType, ok := tokenResult["token_type"].(string)
	require.True(t, ok)
	require.Equal(t, "bearer", tokenType)

	// Step 6: Test token refresh functionality using manual HTTP request
	originalAccessToken := accessToken

	refreshReq := url.Values{}
	refreshReq.Set("grant_type", "refresh_token")
	refreshReq.Set("refresh_token", refreshToken)
	refreshReq.Set("client_id", regResp.ClientID)
	refreshReq.Set("client_secret", regResp.ClientSecret)

	refreshResp, err := http.PostForm(server.URL+TokenEndpoint, refreshReq)
	require.NoError(t, err)
	defer refreshResp.Body.Close()

	require.Equal(t, http.StatusOK, refreshResp.StatusCode)

	var refreshResult map[string]any
	err = json.NewDecoder(refreshResp.Body).Decode(&refreshResult)
	require.NoError(t, err)

	newAccessToken, ok := refreshResult["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, newAccessToken)
	require.NotEqual(t, originalAccessToken, newAccessToken, "Access token should be different after refresh")
}

func TestAccessTokenAudienceClaim(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	config := &oauth2.Config{
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + AuthorizationEndpoint,
			TokenURL: server.URL + TokenEndpoint,
		},
	}

	callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state"))
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

	accessToken := tokenResult["access_token"].(string)

	// Decode JWT payload and verify aud claim contains the external URL
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3, "access token should be a JWT with 3 parts")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	require.NoError(t, err)

	aud, ok := claims["aud"].([]any)
	require.True(t, ok, "aud claim should be present as an array")
	require.Contains(t, aud, "http://localhost:8080", "aud should contain the external URL")

	// SPEC §1.7: jti and client_id claims.
	jti, _ := claims["jti"].(string)
	require.NotEmpty(t, jti, "jti claim should be present")
	require.Equal(t, regResp.ClientID, claims["client_id"], "client_id claim should identify the requesting client")
}

func TestIntrospectionRequiresClientAuth(t *testing.T) {
	server, _, _ := setupTestServer(t)

	resp, err := http.PostForm(server.URL+IntrospectionEndpoint, url.Values{"token": {"whatever"}})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "anonymous introspection must be rejected (SPEC §1.10)")
}

func TestAccessTokenPreservesUserIdentity(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	config := &oauth2.Config{
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + AuthorizationEndpoint,
			TokenURL: server.URL + TokenEndpoint,
		},
	}

	callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state"))
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

	accessToken := tokenResult["access_token"].(string)

	// Decode JWT payload
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	require.NoError(t, err)

	// Verify sub claim is preserved
	sub, ok := claims["sub"].(string)
	require.True(t, ok, "sub claim should be present")
	require.Equal(t, "test-user@example.com", sub)

	// Verify userinfo claim is preserved
	userinfo, ok := claims["userinfo"].(map[string]any)
	require.True(t, ok, "userinfo claim should be present")
	require.Equal(t, "test-user@example.com", userinfo["email"])
	require.Equal(t, "Test User", userinfo["name"])
}
