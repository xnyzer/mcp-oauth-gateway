package auth

// The operator's client list and kill switch (F-024b). The negative cases are
// the point on this surface: it is the one place where a stolen session could
// hand someone else's access away, and the one place where a broken store
// could claim nobody has access at all.

import (
	"crypto/sha256"
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
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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
	return newClientsTestServerWith(t, clients, nil)
}

// newClientsTestServerWith adds a logger, so the SR-8 auth events this surface
// emits can be asserted (mirrors setupTestServerWith in pkg/idp).
func newClientsTestServerWith(t *testing.T, clients repository.InventoryStorage, logger *zap.Logger) (*httptest.Server, repository.Repository) {
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
		Logger:         logger,
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

// labeledSession mirrors the shape pkg/idp's session has: it carries the
// operator's name, which models.FromFositeReq lifts onto the stored request.
type labeledSession struct {
	*fosite.DefaultSession
	label string
}

func (s *labeledSession) GetLabel() string { return s.label }

// seedNamedGrant writes one authorization that carries the operator's name.
func seedNamedGrant(t *testing.T, repo repository.Repository, clientID, requestID, label string) {
	t.Helper()
	req := &fosite.Request{
		ID:          requestID,
		RequestedAt: time.Now().UTC(),
		Client: &fosite.DefaultClient{
			ID:           clientID,
			RedirectURIs: []string{testRedirectURI},
		},
		GrantedScope: fosite.Arguments{"mcp"},
	}
	req.SetSession(&labeledSession{DefaultSession: &fosite.DefaultSession{}, label: label})
	require.NoError(t, repo.CreateAccessTokenSession(t.Context(), requestID+"-access", req))
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
	require.NoError(t, repo.RegisterClient(t.Context(), repository.ClientRegistration{
		Client: &fosite.DefaultClient{
			ID:           testDCRClient,
			Secret:       []byte(testClientSecret),
			RedirectURIs: []string{testRedirectURI},
		},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}))

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

// The name the operator gave at consent time (F-025) is what identifies the row;
// the client id stays visible beneath it, because the name is a label and the id
// is the verifiable identity.
func TestSettingsShowsTheOperatorsName(t *testing.T) {
	server, repo := newClientsTestServer(t, nil)
	seedNamedGrant(t, repo, testCIMDClient, "named-grant", "Claude web")

	status, body := getBody(t, loggedInOperator(t, server), server.URL+SettingsEndpoint)

	require.Equal(t, http.StatusOK, status)
	// The row's *primary* rendering, not merely the name somewhere on the page:
	// the name also appears in the per-authorization table, so a loose Contains
	// would pass even if the row fell back to the bare client id.
	require.Contains(t, body, "<strong>Claude web</strong>",
		"the operator's name identifies the row")
	require.Contains(t, body, testCIMDClient, "the verifiable client id stays visible")
}

// SR-8: an operator kill reads in the operator's own words.
func TestRevokeEventCarriesTheOperatorsName(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	server, repo := newClientsTestServerWith(t, nil, zap.New(core))
	seedNamedGrant(t, repo, testCIMDClient, "named-grant", "Claude web")

	client := loggedInOperator(t, server)
	token := fetchCSRFToken(t, client, server.URL+SettingsEndpoint)
	resp := postFormWithCSRF(t, client, server.URL+SettingsClientRevokeEndpoint, token,
		url.Values{"client_id": {testCIMDClient}})
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	entries := logs.FilterField(zap.String("event", "revoked")).All()
	require.NotEmpty(t, entries, "a revoked event must be emitted")
	require.Equal(t, "Claude web", entries[len(entries)-1].ContextMap()["label"])
}
