package auth

// Revoking access from the operator's settings page (F-024b): what each action
// takes, and the negative cases that matter most on this surface — it is the one
// place where a stolen session could hand someone else's access away. Fixtures
// live in clients_test.go beside the listing tests they are shared with.

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
)

// -- Revocation ---------------------------------------------------------

func TestSettingsClientRevokeEndsAccessAtOnce(t *testing.T) {
	server, repo := newClientsTestServer(t, nil)
	seedGrant(t, repo, testCIMDClient, "victim")
	seedGrant(t, repo, testDCRClient, "bystander")

	client := loggedInOperator(t, server)
	token := fetchCSRFToken(t, client, server.URL+SettingsEndpoint)
	resp := postFormWithCSRF(t, client, server.URL+SettingsClientRevokeEndpoint, token,
		url.Values{"client_id": {testCIMDClient}})
	resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), "msg=revoked")
	require.False(t, hasAccessToken(t, repo, "victim-access"), "the record is gone, so /mcp fails on the next request")
	require.True(t, hasAccessToken(t, repo, "bystander-access"), "another client keeps its access")

	_, body := getBody(t, client, server.URL+SettingsEndpoint)
	require.NotContains(t, body, testCIMDClient)
	require.Contains(t, body, testDCRClient)
}

func TestSettingsGrantRevokeLeavesTheClientsOtherGrant(t *testing.T) {
	server, repo := newClientsTestServer(t, nil)
	seedGrant(t, repo, testCIMDClient, "first")
	seedGrant(t, repo, testCIMDClient, "second")

	client := loggedInOperator(t, server)
	token := fetchCSRFToken(t, client, server.URL+SettingsEndpoint)
	resp := postFormWithCSRF(t, client, server.URL+SettingsGrantRevokeEndpoint, token,
		url.Values{"request_id": {"first"}})
	resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.False(t, hasAccessToken(t, repo, "first-access"))
	require.True(t, hasAccessToken(t, repo, "second-access"), "the client itself keeps its other authorization")

	_, body := getBody(t, client, server.URL+SettingsEndpoint)
	require.Contains(t, body, testCIMDClient, "the client is still listed for its remaining grant")
}

// The panic button takes two deliberate actions: the list offers a link, and
// only the confirmation panel carries the POST.
func TestSettingsRevokeAllIsBehindAConfirmation(t *testing.T) {
	server, repo := newClientsTestServer(t, nil)
	seedGrant(t, repo, testCIMDClient, "grant")
	client := loggedInOperator(t, server)

	_, listBody := getBody(t, client, server.URL+SettingsEndpoint)
	require.Contains(t, listBody, "confirm=revoke_all", "the list offers the panic button")
	require.NotContains(t, listBody, "Yes, revoke everything", "but not the confirmed action itself")

	_, panelBody := getBody(t, client, server.URL+SettingsEndpoint+"?confirm=revoke_all")
	require.Contains(t, panelBody, "Yes, revoke everything")

	token := fetchCSRFToken(t, client, server.URL+SettingsEndpoint)
	resp := postFormWithCSRF(t, client, server.URL+SettingsRevokeAllEndpoint, token, url.Values{})
	resp.Body.Close()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), "msg=revoked_all")
	require.False(t, hasAccessToken(t, repo, "grant-access"))

	// The operator is still logged in and still has an account: the panic
	// button revokes clients, never the person answering the incident.
	status, body := getBody(t, client, server.URL+SettingsEndpoint)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, "No client currently holds access.")
}

// -- Negative cases -----------------------------------------------------

func TestSettingsRevokeRejectsMissingOrWrongCSRF(t *testing.T) {
	for name, token := range map[string]string{"missing": "", "wrong": "0000deadbeef"} {
		t.Run(name, func(t *testing.T) {
			server, repo := newClientsTestServer(t, nil)
			seedGrant(t, repo, testCIMDClient, "grant")
			client := loggedInOperator(t, server)
			// Establish the session's own token first, so the request differs
			// from a valid one only in what it submits.
			fetchCSRFToken(t, client, server.URL+SettingsEndpoint)

			resp, err := client.PostForm(server.URL+SettingsClientRevokeEndpoint,
				url.Values{"client_id": {testCIMDClient}, CSRFFieldName: {token}})
			require.NoError(t, err)
			resp.Body.Close()

			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.True(t, hasAccessToken(t, repo, "grant-access"), "a rejected POST must change nothing")
		})
	}
}

func TestSettingsRevokeRejectsForeignSession(t *testing.T) {
	repo, err := repository.NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })
	seedGrant(t, repo, testCIMDClient, "grant")

	authRouter, err := NewAuthRouter(Config{
		PasswordHashes: []string{"dummy"},
		Users:          repo,
		Clients:        repo,
		ExternalURL:    testExternalURL,
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	secret := sha256.Sum256([]byte("clients_test_secret"))
	router.Use(sessions.Sessions("test_session", cookie.NewStore(secret[:])))
	// An OIDC-provider session: authorized, but not the persisted operator.
	const foreignCSRF = "foreignsessioncsrftoken"
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(SessionKeyAuthorized, true)
		session.Set(SessionKeyUserID, "someone@idp.example.com")
		session.Set(SessionKeyCSRF, foreignCSRF)
		require.NoError(t, session.Save())
		c.Next()
	})
	authRouter.SetupRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	// A client that does NOT follow redirects: the handlers answer a rejected
	// revoke with 403, but a redirect chased to the settings page would 403 as
	// well and make this assertion pass without the gate under test.
	client := newTestClient(t)
	for _, endpoint := range []string{SettingsClientRevokeEndpoint, SettingsGrantRevokeEndpoint, SettingsRevokeAllEndpoint} {
		resp := postWithCSRF(t, client, server.URL+endpoint, foreignCSRF, "", nil)
		resp.Body.Close()
		require.Equal(t, http.StatusForbidden, resp.StatusCode, endpoint)
	}
	require.True(t, hasAccessToken(t, repo, "grant-access"), "a foreign session revokes nothing")
}

// An unknown client id answers exactly like a successful revoke: the operator's
// own page has nothing to gain from an existence oracle.
func TestSettingsRevokeUnknownClientAnswersLikeSuccess(t *testing.T) {
	server, repo := newClientsTestServer(t, nil)
	seedGrant(t, repo, testCIMDClient, "grant")

	client := loggedInOperator(t, server)
	token := fetchCSRFToken(t, client, server.URL+SettingsEndpoint)

	known := postFormWithCSRF(t, client, server.URL+SettingsClientRevokeEndpoint, token,
		url.Values{"client_id": {testCIMDClient}})
	known.Body.Close()
	unknown := postFormWithCSRF(t, client, server.URL+SettingsClientRevokeEndpoint, token,
		url.Values{"client_id": {"no-such-client"}})
	unknown.Body.Close()

	require.Equal(t, known.StatusCode, unknown.StatusCode)
	require.Equal(t, known.Header.Get("Location"), unknown.Header.Get("Location"),
		"an unknown client must not be distinguishable from a revoked one")
}

// failingInventory reports every enumeration as broken.
type failingInventory struct {
	repository.InventoryStorage
}

func (failingInventory) ListClientGrants(context.Context) ([]repository.ClientGrants, error) {
	return nil, errors.New("store unavailable")
}

// A page that renders an empty list because the store could not be read would
// tell the operator that nobody holds access — the opposite of the truth.
func TestSettingsFailsClosedWhenTheClientListCannotBeRead(t *testing.T) {
	server, _ := newClientsTestServer(t, failingInventory{})

	status, body := getBody(t, loggedInOperator(t, server), server.URL+SettingsEndpoint)

	require.Equal(t, http.StatusInternalServerError, status)
	require.NotContains(t, body, "No client currently holds access.")
	require.NotContains(t, body, "store unavailable", "the cause stays in the log (§6)")
}

// The client list is part of the settings page, not a separately switchable
// feature — so a user store without an inventory is a misconfiguration that
// has to fail at construction, not at the operator's first visit.
func TestNewAuthRouterRequiresClientsWhenUsersIsSet(t *testing.T) {
	repo, err := repository.NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	_, err = NewAuthRouter(Config{Users: repo, ExternalURL: testExternalURL})
	require.Error(t, err)

	// Without a user store there is no settings page at all, so no inventory
	// is needed either — the existing visibility rule, unchanged.
	_, err = NewAuthRouter(Config{PasswordHashes: []string{"dummy"}})
	require.NoError(t, err)
}
