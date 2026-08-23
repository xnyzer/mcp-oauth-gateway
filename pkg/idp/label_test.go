package idp

// The operator's name for a connection (F-025a): taken at consent time, stored
// with the grant, and carried wherever the grant appears. The load-bearing test
// is the one that follows the name through the token exchange — fosite clones
// the session there, and a field left out of Clone would vanish without error.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const testRedirectURI = "http://localhost:8080/callback"

// -- Sanitizing ---------------------------------------------------------

func TestSanitizeLabel(t *testing.T) {
	long := strings.Repeat("a", maxLabelLength+20)
	multibyte := strings.Repeat("ä", maxLabelLength+5)

	for name, tc := range map[string]struct{ in, want string }{
		"plain":                    {"Claude web", "Claude web"},
		"trimmed":                  {"  Claude web  ", "Claude web"},
		"control characters go":    {"Claude\x00 web\x1b", "Claude web"},
		"newline is a control too": {"Claude\nweb", "Claudeweb"},
		"empty stays empty":        {"", ""},
		"whitespace only":          {"   ", ""},
		"capped":                   {long, strings.Repeat("a", maxLabelLength)},
		"capped by runes":          {multibyte, strings.Repeat("ä", maxLabelLength)},
	} {
		t.Run(name, func(t *testing.T) {
			got := sanitizeLabel(tc.in)
			require.Equal(t, tc.want, got)
			require.LessOrEqual(t, len([]rune(got)), maxLabelLength)
		})
	}
}

// -- The flow -----------------------------------------------------------

// authorizeNamed drives authorize + consent to completion, submitting name in
// the consent form's connection_name field, and returns the authorization code.
func authorizeNamed(t *testing.T, serverURL, clientID, name string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=consent-name-state&code_challenge=%s&code_challenge_method=S256",
		serverURL, AuthorizationEndpoint, url.QueryEscape(clientID),
		url.QueryEscape(testRedirectURI), testPKCEChallenge())

	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	authResp.Body.Close()
	consentPath := authResp.Header.Get("Location")
	require.NotEmpty(t, consentPath)

	formResp, err := client.Get(serverURL + consentPath)
	require.NoError(t, err)
	form, err := io.ReadAll(formResp.Body)
	formResp.Body.Close()
	require.NoError(t, err)
	require.Contains(t, string(form), `name="connection_name"`, "the consent form must offer the field")
	csrf := consentCSRFRE.FindSubmatch(form)
	require.NotNil(t, csrf)

	approve, err := client.PostForm(serverURL+consentPath, url.Values{
		auth.CSRFFieldName: {string(csrf[1])},
		"connection_name":  {name},
	})
	require.NoError(t, err)
	approve.Body.Close()
	callback, err := url.Parse(approve.Header.Get("Location"))
	require.NoError(t, err)
	code := callback.Query().Get("code")
	require.NotEmpty(t, code, "consent must return an authorization code")
	return code
}

// exchange trades the code for tokens and returns the decoded response.
func exchange(t *testing.T, serverURL string, reg registrationResponse, code string) map[string]any {
	t.Helper()
	resp, err := http.PostForm(serverURL+TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {reg.ClientID},
		"client_secret": {reg.ClientSecret},
		"code_verifier": {testPKCEVerifier},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// storedLabel reads the name off the record of *this* access token, by its
// signature. Deliberately not via ListClientGrants: that aggregates every
// record of the grant, so an older record still carrying the name would mask a
// newer one that lost it.
func storedLabel(t *testing.T, repo repository.Repository, accessToken string) string {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3, "access token must be a JWS")
	sess := &Session{}
	req, err := repo.GetAccessTokenSession(t.Context(), parts[2], sess)
	require.NoError(t, err, "the access token must have a server-side record")
	require.NotNil(t, req)
	restored, ok := req.GetSession().(*Session)
	require.True(t, ok, "the restored session must be the gateway's own type")
	return restored.Label
}

func onlyRow(t *testing.T, repo repository.Repository) repository.ClientGrants {
	t.Helper()
	rows, err := repo.ListClientGrants(t.Context())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	return rows[0]
}

// The name is typed at consent, but the records that carry it are written at
// the token exchange — with a session fosite cloned in between. This is the
// test that goes red if Clone drops the field.
func TestConnectionNameSurvivesTheTokenExchange(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	reg := registerTestClient(t, server.URL)

	code := authorizeNamed(t, server.URL, reg.ClientID, "Claude web")
	tokens := exchange(t, server.URL, reg, code)
	require.NotEmpty(t, tokens["access_token"])

	require.Equal(t, "Claude web", storedLabel(t, repo, tokens["access_token"].(string)),
		"the record of the issued token must carry the operator's name")

	row := onlyRow(t, repo)
	require.Equal(t, "Claude web", row.Label, "and the operator's list must show it")
	require.Len(t, row.Grants, 1)
	require.Equal(t, "Claude web", row.Grants[0].Label)
}

// Every refresh clones the session again, so the name has to survive rotation
// too — otherwise a long-lived connection loses its name silently.
func TestConnectionNameSurvivesARefresh(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	reg := registerTestClient(t, server.URL)

	code := authorizeNamed(t, server.URL, reg.ClientID, "Claude iOS")
	tokens := exchange(t, server.URL, reg, code)
	refreshToken, _ := tokens["refresh_token"].(string)
	require.NotEmpty(t, refreshToken, "the refresh grant must be enabled for this test to mean anything")

	resp, err := http.PostForm(server.URL+TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {reg.ClientID},
		"client_secret": {reg.ClientSecret},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var refreshed map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&refreshed))

	// The record of the *newly minted* token, not the aggregate: the first
	// token's record still exists and would answer for it.
	require.Equal(t, "Claude iOS", storedLabel(t, repo, refreshed["access_token"].(string)),
		"the name must survive refresh-token rotation")
}

// An unnamed connection stays unnamed — the field is optional, and an empty
// submission must not store whitespace.
func TestConnectionNameIsOptional(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	reg := registerTestClient(t, server.URL)

	code := authorizeNamed(t, server.URL, reg.ClientID, "   ")
	exchange(t, server.URL, reg, code)

	require.Empty(t, onlyRow(t, repo).Label)
}

// The cap and the control-character strip apply to what is stored, not only to
// what sanitizeLabel returns in isolation.
func TestConnectionNameIsSanitizedOnTheWayIn(t *testing.T) {
	server, repo, _ := setupTestServer(t)
	reg := registerTestClient(t, server.URL)

	code := authorizeNamed(t, server.URL, reg.ClientID, "Claude\x00 web"+strings.Repeat("!", maxLabelLength))
	exchange(t, server.URL, reg, code)

	stored := onlyRow(t, repo).Label
	require.NotContains(t, stored, "\x00")
	require.LessOrEqual(t, len([]rune(stored)), maxLabelLength)
	require.True(t, strings.HasPrefix(stored, "Claude web"), "got %q", stored)
}

// SR-8: the log reads in the operator's words, not only in client ids.
func TestTokenIssuedEventCarriesTheName(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	server, _, _ := setupTestServerWith(t, func(cfg *Config) { cfg.Logger = zap.New(core) })
	reg := registerTestClient(t, server.URL)

	code := authorizeNamed(t, server.URL, reg.ClientID, "Claude web")
	exchange(t, server.URL, reg, code)

	entries := logs.FilterField(zap.String("event", "token_issued")).All()
	require.NotEmpty(t, entries, "a token_issued event must be emitted")
	require.Equal(t, "Claude web", entries[len(entries)-1].ContextMap()["label"])
}
