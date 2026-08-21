package idp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
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

// testPKCEVerifier / testPKCEChallenge are the shared S256 PKCE material.
// Every client now requires PKCE (EnforcePKCE, SPEC §1.5 / F-012b), so the
// confidential-client flows carry it too: testAuthFlowWithURL appends the
// challenge and the token exchanges send the verifier.
const testPKCEVerifier = "pkce-verifier-pkce-verifier-pkce-verifier-01"

func testPKCEChallenge() string {
	sum := sha256.Sum256([]byte(testPKCEVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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

// consentCSRFRE extracts the per-session CSRF token from the consent form.
var consentCSRFRE = regexp.MustCompile(`name="csrf_token" value="([0-9a-f]+)"`)

// postConsent GETs the consent form to read its per-session CSRF token, then
// POSTs the approval carrying it (SPEC §1.5/§1.12).
func postConsent(t *testing.T, client *http.Client, consentURL string) *http.Response {
	t.Helper()
	getResp, err := client.Get(consentURL)
	require.NoError(t, err)
	body, err := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	require.NoError(t, err)
	m := consentCSRFRE.FindSubmatch(body)
	require.NotNil(t, m, "consent form must embed a CSRF token: %s", body)
	resp, err := client.PostForm(consentURL, url.Values{auth.CSRFFieldName: {string(m[1])}})
	require.NoError(t, err)
	return resp
}

// testAuthFlowWithURL performs the OAuth authorization flow given a raw authorization URL
// and returns the callback URL after authorization completes.
func testAuthFlowWithURL(t *testing.T, serverURL, authURL string) *url.URL {
	t.Helper()

	// PKCE is mandatory for every client now (EnforcePKCE, SPEC §1.5).
	// Append the shared test challenge unless the caller already set one
	// (CIMD/public tests supply their own); callers exchange the code with
	// testPKCEVerifier.
	if !strings.Contains(authURL, "code_challenge") {
		authURL += "&code_challenge=" + testPKCEChallenge() + "&code_challenge_method=S256"
	}

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
	formBody, err := io.ReadAll(authReturnResp.Body)
	authReturnResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, authReturnResp.StatusCode)

	// The consent form carries the per-session CSRF token (SPEC §1.5/§1.12);
	// the POST must echo it back.
	csrfMatch := consentCSRFRE.FindSubmatch(formBody)
	require.NotNil(t, csrfMatch, "consent form must embed a CSRF token: %s", formBody)

	// Step 3: POST the confirmation to complete authorization
	authReturnResp, err = client.PostForm(serverURL+location, url.Values{auth.CSRFFieldName: {string(csrfMatch[1])}})
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

// mustGetResp / requireRedirectLocation are tiny helpers for the CSRF test.
func mustGetResp(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err)
	return resp
}

func requireRedirectLocation(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, resp.StatusCode)
	loc := resp.Header.Get("Location")
	require.NotEmpty(t, loc)
	return loc
}

func mustCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return jar
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

// decodeJWTSegment unmarshals one base64url JWT segment.
func decodeJWTSegment(t *testing.T, segment string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded))
	return decoded
}
