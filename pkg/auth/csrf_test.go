package auth

// Anti-CSRF token coverage (F-012c): every state-changing POST on the login
// surface is rejected without a matching per-session token, and the
// discoverable passkey-login ceremony never enumerates credential IDs to an
// anonymous caller. Defence-in-depth on top of SameSite=Lax (SPEC §1.12).

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	virtualwebauthn "github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/require"
)

func TestLoginPostRejectsMissingOrWrongCSRF(t *testing.T) {
	server, _ := newWebAuthnTestServer(t)
	client := newTestClient(t)

	// Establish a session (and mint its token) by loading the login page.
	token := fetchCSRFToken(t, client, server.URL+LoginEndpoint)

	// No token -> rejected before the password is ever checked.
	missing, err := client.PostForm(server.URL+LoginEndpoint, url.Values{"password": {testPassword}})
	require.NoError(t, err)
	missing.Body.Close()
	require.Equal(t, http.StatusForbidden, missing.StatusCode)

	// Wrong token -> rejected.
	wrong, err := client.PostForm(server.URL+LoginEndpoint, url.Values{
		"password":    {testPassword},
		CSRFFieldName: {"deadbeef"},
	})
	require.NoError(t, err)
	wrong.Body.Close()
	require.Equal(t, http.StatusForbidden, wrong.StatusCode)

	// Correct token on the same session -> the login proceeds.
	ok, err := client.PostForm(server.URL+LoginEndpoint, url.Values{
		"password":    {testPassword},
		CSRFFieldName: {token},
	})
	require.NoError(t, err)
	ok.Body.Close()
	require.Equal(t, http.StatusFound, ok.StatusCode)
}

func TestSettingsPostRejectsMissingCSRF(t *testing.T) {
	server, _ := newWebAuthnTestServer(t)
	client := newTestClient(t)

	// Authenticate (bootstraps the operator account).
	passwordLogin(t, client, server.URL, testPassword)

	// A session-gated settings POST without the token is refused (the session
	// is authorized, so this is the CSRF guard, not RequireAuth).
	resp, err := client.PostForm(server.URL+SettingsPasswordEndpoint, url.Values{"disabled": {"true"}})
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestWebAuthnLoginBeginRejectsMissingCSRF(t *testing.T) {
	server, repo := newWebAuthnTestServer(t)
	rp := virtualwebauthn.RelyingParty{Name: "mcp-oauth-gateway", ID: "localhost", Origin: testExternalURL}
	authenticator := virtualwebauthn.NewAuthenticator()

	client := newTestClient(t)
	passwordLogin(t, client, server.URL, testPassword)
	user, err := repo.GetUser(t.Context())
	require.NoError(t, err)
	authenticator.Options.UserHandle = []byte(user.ID)
	enrollPasskey(t, client, server.URL, rp, authenticator, "Key")

	// A fresh (anonymous) caller must still fetch a token first; a begin POST
	// without the header is rejected before any ceremony state is created.
	fresh := newTestClient(t)
	fetchCSRFToken(t, fresh, server.URL+LoginEndpoint) // establish a session
	resp, err := fresh.Post(server.URL+WebAuthnLoginBeginEndpoint, "application/json", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestDiscoverableLoginBeginOmitsCredentialDescriptors(t *testing.T) {
	server, repo := newWebAuthnTestServer(t)
	rp := virtualwebauthn.RelyingParty{Name: "mcp-oauth-gateway", ID: "localhost", Origin: testExternalURL}
	authenticator := virtualwebauthn.NewAuthenticator()

	client := newTestClient(t)
	passwordLogin(t, client, server.URL, testPassword)
	user, err := repo.GetUser(t.Context())
	require.NoError(t, err)
	authenticator.Options.UserHandle = []byte(user.ID)
	enrollPasskey(t, client, server.URL, rp, authenticator, "Key")

	// The public begin response must not disclose the operator's credential IDs
	// to an anonymous caller (discoverable login, empty allow-list).
	fresh := newTestClient(t)
	token := fetchCSRFToken(t, fresh, server.URL+LoginEndpoint)
	resp := postWithCSRF(t, fresh, server.URL+WebAuthnLoginBeginEndpoint, token, "application/json", nil)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "begin: %s", body)
	require.NotContains(t, strings.ToLower(string(body)), "allowcredentials",
		"discoverable login must not enumerate credential descriptors")
}
