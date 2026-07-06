package auth

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	virtualwebauthn "github.com/descope/virtualwebauthn"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"golang.org/x/crypto/bcrypt"
)

const (
	testExternalURL = "http://localhost:8080"
	testPassword    = "test-password"
)

// newWebAuthnTestServer wires an AuthRouter with a real repository and a
// session-gated probe endpoint, mirroring the production setup.
func newWebAuthnTestServer(t *testing.T) (*httptest.Server, repository.Repository) {
	t.Helper()

	repo, err := repository.NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	require.NoError(t, err)

	authRouter, err := NewAuthRouter(Config{
		PasswordHashes: []string{string(hash)},
		Users:          repo,
		ExternalURL:    testExternalURL,
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	secret := sha256.Sum256([]byte("webauthn_test_secret"))
	router.Use(sessions.Sessions("test_session", cookie.NewStore(secret[:])))
	authRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server, repo
}

func newTestClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// passwordLogin performs the form login and returns the final status code.
func passwordLogin(t *testing.T, client *http.Client, serverURL, password string) *http.Response {
	t.Helper()
	resp, err := client.PostForm(serverURL+LoginEndpoint, url.Values{"password": {password}})
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

// enrollPasskey runs the full registration ceremony with the virtual
// authenticator and returns the credential for later logins.
func enrollPasskey(t *testing.T, client *http.Client, serverURL string, rp virtualwebauthn.RelyingParty, authenticator virtualwebauthn.Authenticator, name string) virtualwebauthn.Credential {
	t.Helper()
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	beginResp, err := client.Post(serverURL+WebAuthnRegisterBeginEndpoint, "application/json", nil)
	require.NoError(t, err)
	beginBody, err := io.ReadAll(beginResp.Body)
	beginResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, beginResp.StatusCode, "register begin: %s", beginBody)

	options, err := virtualwebauthn.ParseAttestationOptions(string(beginBody))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *options)

	finishResp, err := client.Post(serverURL+WebAuthnRegisterFinishEndpoint+"?name="+url.QueryEscape(name), "application/json", strings.NewReader(attestation))
	require.NoError(t, err)
	finishBody, err := io.ReadAll(finishResp.Body)
	finishResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, finishResp.StatusCode, "register finish: %s", finishBody)

	authenticator.AddCredential(credential)
	return credential
}

// passkeyLogin runs the assertion ceremony; it returns the finish response
// so callers can assert success or denial.
func passkeyLogin(t *testing.T, client *http.Client, serverURL string, rp virtualwebauthn.RelyingParty, authenticator virtualwebauthn.Authenticator, credential virtualwebauthn.Credential) *http.Response {
	t.Helper()
	beginResp, err := client.Post(serverURL+WebAuthnLoginBeginEndpoint, "application/json", nil)
	require.NoError(t, err)
	beginBody, err := io.ReadAll(beginResp.Body)
	beginResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, beginResp.StatusCode, "login begin: %s", beginBody)

	options, err := virtualwebauthn.ParseAssertionOptions(string(beginBody))
	require.NoError(t, err)
	assertion := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *options)

	finishResp, err := client.Post(serverURL+WebAuthnLoginFinishEndpoint, "application/json", strings.NewReader(assertion))
	require.NoError(t, err)
	return finishResp
}

func TestPasskeyEnrollmentAndLoginRoundTrip(t *testing.T) {
	server, repo := newWebAuthnTestServer(t)
	rp := virtualwebauthn.RelyingParty{Name: "mcp-oauth-gateway", ID: "localhost", Origin: testExternalURL}
	authenticator := virtualwebauthn.NewAuthenticator()

	// Bootstrap: the first password login creates the operator account.
	client := newTestClient(t)
	resp := passwordLogin(t, client, server.URL, testPassword)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	user, err := repo.GetUser(t.Context())
	require.NoError(t, err, "first password login must bootstrap the user")
	require.Equal(t, "admin", user.Username)

	// Enroll a passkey on the session-gated settings surface.
	credential := enrollPasskey(t, client, server.URL, rp, authenticator, "Test Key")
	stored, err := repo.ListWebAuthnCredentials(t.Context(), user.ID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	require.Equal(t, "Test Key", stored[0].Name)

	// The login page now offers the passkey button.
	pageResp, err := client.Get(server.URL + LoginEndpoint)
	require.NoError(t, err)
	page, err := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	require.NoError(t, err)
	require.Contains(t, string(page), "passkey-button")

	// Fresh browser: log in with the passkey alone.
	freshClient := newTestClient(t)
	finishResp := passkeyLogin(t, freshClient, server.URL, rp, authenticator, credential)
	defer finishResp.Body.Close()
	require.Equal(t, http.StatusOK, finishResp.StatusCode)
	var result map[string]string
	require.NoError(t, json.NewDecoder(finishResp.Body).Decode(&result))
	require.Equal(t, "/", result["redirect"])

	// The session is authorized as the persisted user: the settings page
	// (requireOwnUser) is reachable, proving sub == user.ID.
	settingsResp, err := freshClient.Get(server.URL + SettingsEndpoint)
	require.NoError(t, err)
	settingsResp.Body.Close()
	require.Equal(t, http.StatusOK, settingsResp.StatusCode)

	// The ceremony updated the credential's last-used state.
	stored, err = repo.ListWebAuthnCredentials(t.Context(), user.ID)
	require.NoError(t, err)
	require.False(t, stored[0].LastUsedAt.IsZero(), "login must stamp LastUsedAt")

	// Replay: the consumed ceremony state must not allow a second finish.
	replayResp, err := freshClient.Post(server.URL+WebAuthnLoginFinishEndpoint, "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	replayResp.Body.Close()
	require.Equal(t, http.StatusUnauthorized, replayResp.StatusCode)
}

func TestPasskeyLoginUnavailableBeforeEnrollment(t *testing.T) {
	server, _ := newWebAuthnTestServer(t)
	client := newTestClient(t)

	resp, err := client.Post(server.URL+WebAuthnLoginBeginEndpoint, "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// The login page does not offer the passkey button yet.
	pageResp, err := client.Get(server.URL + LoginEndpoint)
	require.NoError(t, err)
	page, err := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	require.NoError(t, err)
	require.NotContains(t, string(page), "passkey-button")
}

func TestPasswordFallbackDisableSemantics(t *testing.T) {
	server, repo := newWebAuthnTestServer(t)
	rp := virtualwebauthn.RelyingParty{Name: "mcp-oauth-gateway", ID: "localhost", Origin: testExternalURL}
	authenticator := virtualwebauthn.NewAuthenticator()

	client := newTestClient(t)
	passwordLogin(t, client, server.URL, testPassword)

	// Disabling the password without a passkey is refused (lockout guard).
	resp, err := client.PostForm(server.URL+SettingsPasswordEndpoint, url.Values{"disabled": {"true"}})
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), "msg=need_passkey")
	user, err := repo.GetUser(t.Context())
	require.NoError(t, err)
	require.False(t, user.PasswordLoginDisabled)

	// With a passkey enrolled, disabling works.
	credential := enrollPasskey(t, client, server.URL, rp, authenticator, "Key")
	resp, err = client.PostForm(server.URL+SettingsPasswordEndpoint, url.Values{"disabled": {"true"}})
	require.NoError(t, err)
	resp.Body.Close()
	require.Contains(t, resp.Header.Get("Location"), "msg=saved")

	// Password login now fails with the same body as a wrong password
	// (uniform error, SR-6 — no state enumeration).
	freshClient := newTestClient(t)
	disabledResp := passwordLogin(t, freshClient, server.URL, testPassword)
	require.Equal(t, http.StatusBadRequest, disabledResp.StatusCode)
	wrongResp := passwordLogin(t, newTestClient(t), server.URL, "wrong-password")
	require.Equal(t, disabledResp.StatusCode, wrongResp.StatusCode)

	// The passkey still logs in.
	finishResp := passkeyLogin(t, freshClient, server.URL, rp, authenticator, credential)
	finishResp.Body.Close()
	require.Equal(t, http.StatusOK, finishResp.StatusCode)

	// Deleting the last passkey re-activates the password fallback
	// (lockout rescue) even though the stored flag stays disabled.
	user, err = repo.GetUser(t.Context())
	require.NoError(t, err)
	stored, err := repo.ListWebAuthnCredentials(t.Context(), user.ID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	resp, err = freshClient.PostForm(server.URL+SettingsCredentialDeleteEndpoint, url.Values{"id": {stored[0].ID}})
	require.NoError(t, err)
	resp.Body.Close()
	require.Contains(t, resp.Header.Get("Location"), "msg=deleted")

	rescueResp := passwordLogin(t, newTestClient(t), server.URL, testPassword)
	require.Equal(t, http.StatusFound, rescueResp.StatusCode, "password fallback must re-activate when no passkeys remain")
}

func TestSettingsRequireOwnUserSession(t *testing.T) {
	server, _ := newWebAuthnTestServer(t)

	// Unauthenticated: the settings page redirects to the login.
	client := newTestClient(t)
	resp, err := client.Get(server.URL + SettingsEndpoint)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), LoginEndpoint)

	// Registration ceremonies are session-gated the same way.
	resp, err = client.Post(server.URL+WebAuthnRegisterBeginEndpoint, "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
}

func TestSettingsRejectForeignSession(t *testing.T) {
	repo, err := repository.NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	authRouter, err := NewAuthRouter(Config{
		PasswordHashes: []string{"dummy"},
		Users:          repo,
		ExternalURL:    testExternalURL,
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	secret := sha256.Sum256([]byte("webauthn_test_secret"))
	router.Use(sessions.Sessions("test_session", cookie.NewStore(secret[:])))
	// Simulate an OIDC-provider session: authorized, but with a provider
	// identity instead of the persisted operator account.
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(SessionKeyAuthorized, true)
		session.Set(SessionKeyUserID, "someone@idp.example.com")
		require.NoError(t, session.Save())
		c.Next()
	})
	authRouter.SetupRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	// No operator account exists (and the session is foreign): 403.
	resp, err := http.Get(server.URL + SettingsEndpoint)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, err = http.Post(server.URL+WebAuthnRegisterBeginEndpoint, "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}
