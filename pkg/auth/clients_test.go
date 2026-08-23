package auth

// The operator's client list and kill switch (F-024b). The negative cases are
// the point on this surface: it is the one place where a stolen session could
// hand someone else's access away, and the one place where a broken store
// could claim nobody has access at all.

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"golang.org/x/crypto/bcrypt"
)

const (
	testCIMDClient   = "https://client.example.com/metadata"
	testDCRClient    = "dcr-client-id"
	testClientSecret = "placeholder-client-secret-hash"
	testRedirectURI  = "https://client.example.com/callback"
)

// newClientsTestServer wires the settings surface against a real repository.
// Passing a clients store overrides the inventory the page reads, which is how
// the fail-closed path is reached.
func newClientsTestServer(t *testing.T, clients repository.InventoryStorage) (*httptest.Server, repository.Repository) {
	t.Helper()

	repo, err := repository.NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	if clients == nil {
		clients = repo
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	require.NoError(t, err)

	authRouter, err := NewAuthRouter(Config{
		PasswordHashes: []string{string(hash)},
		Users:          repo,
		Clients:        clients,
		ExternalURL:    testExternalURL,
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	secret := sha256.Sum256([]byte("clients_test_secret"))
	router.Use(sessions.Sessions("test_session", cookie.NewStore(secret[:])))
	authRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server, repo
}

// seedGrant writes one authorization's token records. The client snapshot
// carries a secret on purpose: the page must never render it.
func seedGrant(t *testing.T, repo repository.Repository, clientID, requestID string) {
	t.Helper()
	req := &fosite.Request{
		ID:          requestID,
		RequestedAt: time.Now().UTC(),
		Client: &fosite.DefaultClient{
			ID:           clientID,
			Secret:       []byte(testClientSecret),
			RedirectURIs: []string{testRedirectURI},
		},
		GrantedScope: fosite.Arguments{"mcp"},
	}
	ctx := t.Context()
	require.NoError(t, repo.CreateAccessTokenSession(ctx, requestID+"-access", req))
	require.NoError(t, repo.CreateRefreshTokenSession(ctx, requestID+"-refresh", requestID+"-access", req))
}

func getBody(t *testing.T, client *http.Client, rawURL string) (int, string) {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// loggedInOperator performs the password login that bootstraps the operator
// account, and returns a client whose session is that account's.
func loggedInOperator(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	client := newTestClient(t)
	resp := passwordLogin(t, client, server.URL, testPassword)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	return client
}

func hasAccessToken(t *testing.T, repo repository.Repository, signature string) bool {
	t.Helper()
	_, err := repo.GetAccessTokenSession(t.Context(), signature, nil)
	return err == nil
}

// -- The list -----------------------------------------------------------

func TestSettingsListsClientsWithoutTheirSecret(t *testing.T) {
	server, repo := newClientsTestServer(t, nil)
	seedGrant(t, repo, testCIMDClient, "cimd-grant")
	require.NoError(t, repo.RegisterClient(t.Context(), &fosite.DefaultClient{
		ID:           testDCRClient,
		Secret:       []byte(testClientSecret),
		RedirectURIs: []string{testRedirectURI},
	}, time.Now().UTC().Add(time.Hour), 0))

	// The store really does hold the secret, so the assertion below has
	// something to catch: a token record keeps a full client snapshot.
	stored, err := repo.GetAccessTokenSession(t.Context(), "cimd-grant-access", nil)
	require.NoError(t, err)
	require.Equal(t, testClientSecret, string(stored.GetClient().(*fosite.DefaultClient).Secret))

	status, body := getBody(t, loggedInOperator(t, server), server.URL+SettingsEndpoint)

	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, testCIMDClient, "the CIMD client holds access and must be listed")
	require.Contains(t, body, testDCRClient, "a registration without tokens must be listed too")
	require.Contains(t, body, "client.example.com", "the redirect host is what makes a DCR client recognisable")
	require.NotContains(t, body, testClientSecret, "the client secret must never reach the page")
	require.Contains(t, body, "not per device", "the page must say what an entry actually is")

	// The two destructive actions must not read as duplicates. Live
	// verification found them indistinguishable: a client with a single
	// authorization makes both buttons do the same thing, so only the wording
	// tells the operator that one also takes the registration and every other
	// authorization.
	require.Contains(t, body, "Revoke client")
	require.Contains(t, body, "Revoke this authorization")
}

func TestSettingsSaysWhenNoClientHoldsAccess(t *testing.T) {
	server, _ := newClientsTestServer(t, nil)

	status, body := getBody(t, loggedInOperator(t, server), server.URL+SettingsEndpoint)

	require.Equal(t, http.StatusOK, status)
	require.Contains(t, body, "No client currently holds access.")
}

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
