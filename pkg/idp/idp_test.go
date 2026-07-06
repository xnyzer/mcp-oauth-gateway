package idp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/oauth2"
)

func setupTestServer(t *testing.T) (*httptest.Server, repository.Repository, string) {
	return setupTestServerWith(t, nil)
}

// newTestKeyManager builds a key manager over a fresh temp directory.
func newTestKeyManager(t *testing.T, alg keys.Alg) *keys.Manager {
	t.Helper()
	keyManager, err := keys.NewManager(keys.Config{
		Dir:          filepath.Join(t.TempDir(), "keys"),
		Alg:          alg,
		RetireWindow: time.Hour,
	})
	require.NoError(t, err)
	return keyManager
}

func setupTestServerMirror(t *testing.T, oidcDiscoveryMirror bool) (*httptest.Server, repository.Repository, string) {
	return setupTestServerWith(t, func(cfg *Config) { cfg.OIDCDiscoveryMirror = oidcDiscoveryMirror })
}

func setupTestServerWith(t *testing.T, mutate func(*Config)) (*httptest.Server, repository.Repository, string) {
	// Create temp directory and repository
	tmpDir, err := os.MkdirTemp("", "idp_test_*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := repository.NewKVSRepository(dbPath, "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	secret := sha256.Sum256([]byte("test_secret"))

	keyManager := newTestKeyManager(t, keys.AlgRS256)

	// Setup IDP router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Session middleware
	store := cookie.NewStore(secret[:])
	router.Use(sessions.Sessions("test_session", store))

	// Mock auth middleware that always passes with user identity
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(auth.SessionKeyAuthorized, true)
		session.Set(auth.SessionKeyUserID, "test-user@example.com")
		session.Set(auth.SessionKeyUserInfo, `{"email":"test-user@example.com","name":"Test User"}`)
		err := session.Save()
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to save session"})
			c.Abort()
			return
		}
		c.Next()
	})

	// Create auth router and IDP router
	authRouter, err := auth.NewAuthRouter(auth.Config{})
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	cfg := Config{
		Repo:            repo,
		Keys:            keyManager,
		Logger:          logger,
		ExternalURL:     "http://localhost:8080",
		Secret:          secret[:],
		AuthRouter:      authRouter,
		AccessTokenTTL:  time.Hour,
		AuthCodeTTL:     10 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		DCREnabled:      true,
		DCRClientTTL:    30 * 24 * time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	idpRouter, err := NewIDPRouter(cfg)
	require.NoError(t, err)

	idpRouter.SetupRoutes(router)

	// Start test server
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return server, repo, tmpDir
}

func TestOAuthServerMetadata(t *testing.T) {
	server, _, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + OauthAuthorizationServerEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var metadata map[string]any
	err = json.NewDecoder(resp.Body).Decode(&metadata)
	require.NoError(t, err)

	// Verify OAuth server metadata
	require.Equal(t, "http://localhost:8080", metadata["issuer"])
	authEndpoint, ok := metadata["authorization_endpoint"].(string)
	require.True(t, ok)
	require.Contains(t, authEndpoint, ".idp/auth")

	tokenEndpoint, ok := metadata["token_endpoint"].(string)
	require.True(t, ok)
	require.Contains(t, tokenEndpoint, ".idp/token")

	grantTypes, ok := metadata["grant_types_supported"].([]any)
	require.True(t, ok)
	require.Contains(t, grantTypes, "authorization_code")
	require.Contains(t, grantTypes, "refresh_token")

	responseTypes, ok := metadata["response_types_supported"].([]any)
	require.True(t, ok)
	require.Contains(t, responseTypes, "code")

	challengeMethods, ok := metadata["code_challenge_methods_supported"].([]any)
	require.True(t, ok)
	require.Contains(t, challengeMethods, "S256")
	require.NotContains(t, challengeMethods, "plain")

	// SPEC §1.2: field-complete AS metadata.
	registrationEndpoint, ok := metadata["registration_endpoint"].(string)
	require.True(t, ok)
	require.Contains(t, registrationEndpoint, ".idp/register")

	jwksURI, ok := metadata["jwks_uri"].(string)
	require.True(t, ok)
	require.Equal(t, "http://localhost:8080/.well-known/jwks.json", jwksURI)

	introspectionEndpoint, ok := metadata["introspection_endpoint"].(string)
	require.True(t, ok)
	require.Contains(t, introspectionEndpoint, ".idp/introspect")

	issSupported, ok := metadata["authorization_response_iss_parameter_supported"].(bool)
	require.True(t, ok)
	require.True(t, issSupported, "RFC 9207 iss support must be advertised")

	responseModes, ok := metadata["response_modes_supported"].([]any)
	require.True(t, ok)
	require.Contains(t, responseModes, "query")
}

func TestOIDCDiscoveryMirror(t *testing.T) {
	// Off by default: the mirror path is not served.
	server, _, _ := setupTestServer(t)
	resp, err := http.Get(server.URL + OIDCDiscoveryEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Enabled: same AS metadata document under the OIDC path (SPEC §1.2).
	mirrorServer, _, _ := setupTestServerMirror(t, true)
	resp, err = http.Get(mirrorServer.URL + OIDCDiscoveryEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var metadata map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&metadata))
	require.Equal(t, "http://localhost:8080", metadata["issuer"])
}

func TestJWKSEndpoint(t *testing.T) {
	server, _, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + JWKSEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	// SPEC §1.8: short cache so rotations propagate quickly.
	require.Equal(t, "max-age=300", resp.Header.Get("Cache-Control"))

	var jwks map[string]any
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	require.NoError(t, err)

	keySet, ok := jwks["keys"].([]any)
	require.True(t, ok)
	require.Len(t, keySet, 1)

	key := keySet[0].(map[string]any)
	require.Equal(t, "RSA", key["kty"])
	require.Equal(t, "sig", key["use"])
	require.Equal(t, "RS256", key["alg"])
	require.NotEmpty(t, key["kid"])
	require.NotEmpty(t, key["n"])
	require.NotEmpty(t, key["e"])
}

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
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

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
	authReturnResp, err = client.Post(server.URL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
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

// registerTestClient is a helper that registers a private OAuth client and returns the registration response.
func registerTestClient(t *testing.T, serverURL string) registrationResponse {
	t.Helper()

	regReq := registrationRequest{
		ClientName:              "Test OAuth Client",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   "test",
		RedirectURIs:            []string{"http://localhost:8080/callback"},
	}

	reqBody, err := json.Marshal(regReq)
	require.NoError(t, err)

	resp, err := http.Post(serverURL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var regResp registrationResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	require.NoError(t, err)

	return regResp
}

// testAuthFlowWithURL performs the OAuth authorization flow given a raw authorization URL
// and returns the callback URL after authorization completes.
func testAuthFlowWithURL(t *testing.T, serverURL, authURL string) *url.URL {
	t.Helper()

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

	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode,
		"expected redirect, got %d", authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)
	require.Contains(t, location, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ""))

	// Step 2: GET renders the authorization confirmation form without granting
	authReturnResp, err := client.Get(serverURL + location)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()
	require.Equal(t, http.StatusOK, authReturnResp.StatusCode)

	// Step 3: POST the confirmation to complete authorization
	authReturnResp, err = client.Post(serverURL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()

	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode,
		"expected redirect with authorization code, got %d", authReturnResp.StatusCode)
	callbackLocation := authReturnResp.Header.Get("Location")
	require.NotEmpty(t, callbackLocation)

	callbackURL, err := url.Parse(callbackLocation)
	require.NoError(t, err)
	require.NotEmpty(t, callbackURL.Query().Get("code"), "callback URL should contain an authorization code")

	return callbackURL
}

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

	authReturnResp, err := client.Post(server.URL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)

	callbackURL, err := url.Parse(authReturnResp.Header.Get("Location"))
	require.NoError(t, err)
	require.Empty(t, callbackURL.Query().Get("code"))
	require.NotEmpty(t, callbackURL.Query().Get("error"))
	// RFC 9207: error redirects identify the issuer, too (SPEC §1.5).
	require.Equal(t, "http://localhost:8080", callbackURL.Query().Get("iss"))
}

func mustCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return jar
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

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResult["access_token"])
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
	tokenReq.Set("resource", "https://other.example.com")

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusBadRequest, tokenResp.StatusCode)
	var tokenErr map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenErr))
	require.Equal(t, "invalid_target", tokenErr["error"])
}

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

// stubResolver satisfies CIMDResolver without network access; the real HTTP
// resolution (SSRF guards, limits, caching) is tested in pkg/cimd.
type stubResolver struct {
	doc *cimd.Client
}

func (s *stubResolver) Resolve(_ context.Context, clientID string) (*cimd.Client, error) {
	if s.doc != nil && s.doc.ClientID == clientID {
		return s.doc, nil
	}
	return nil, cimd.ErrInvalidClientID
}

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

// decodeJWTSegment unmarshals one base64url JWT segment.
func decodeJWTSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}

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
