package auth

// What go-webauthn 0.18 changed for the gateway (F-031e): which EXTERNAL_URL
// hosts can carry a passkey, whether a passkey stored by 0.17 still logs in,
// and the stricter checks on what a client sends back.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	virtualwebauthn "github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
)

var testRelyingParty = virtualwebauthn.RelyingParty{Name: "mcp-oauth-gateway", ID: "localhost", Origin: testExternalURL}

// -- The EXTERNAL_URL host -----------------------------------------------------

func TestNewWebAuthnAcceptsDomainNamesAndLocalhost(t *testing.T) {
	for _, externalURL := range []string{
		"https://mcp.example.com",
		"https://mcp.example.com:8443",
		"https://gateway.lan",
		"http://localhost",
		"http://localhost:8080",
	} {
		t.Run(externalURL, func(t *testing.T) {
			_, err := newWebAuthn(externalURL)
			require.NoError(t, err)
		})
	}
}

// A passkey is bound to a domain name. 0.17 let an IP address through and left
// the failure to the browser; 0.18 refuses it where it is configured, and so
// does the gateway — in terms of the setting the operator has to change.
func TestNewWebAuthnRefusesHostsThatCannotCarryAPasskey(t *testing.T) {
	for _, tc := range []struct {
		externalURL string
		host        string
		reason      string
	}{
		{"http://192.0.2.10:8080", "192.0.2.10", "is an IP address"},
		{"http://127.0.0.1:8080", "127.0.0.1", "is an IP address"},
		{"http://[2001:db8::1]:8080", "2001:db8::1", "is an IP address"},
		// A single label that is not localhost: the library's own reason.
		{"http://gateway:8080", "gateway", "not a valid domain string"},
	} {
		t.Run(tc.externalURL, func(t *testing.T) {
			_, err := newWebAuthn(tc.externalURL)

			require.ErrorIs(t, err, ErrInvalidRelyingPartyHost)
			require.Contains(t, err.Error(), "EXTERNAL_URL", "the message names the setting")
			require.Contains(t, err.Error(), `"`+tc.host+`"`, "and the host it objects to")
			require.Contains(t, err.Error(), tc.reason, "and why")
			require.Contains(t, err.Error(), "localhost", "and what works instead")
		})
	}
}

// -- Passkeys stored by 0.17 ---------------------------------------------------

// passkeyFlags is the part of a stored record the authenticator has to agree
// with on every login.
type passkeyFlags struct {
	Flags struct {
		UserVerified   bool `json:"userVerified"`
		BackupEligible bool `json:"backupEligible"`
		BackupState    bool `json:"backupState"`
	} `json:"flags"`
}

// asWrittenBy017 returns a 0.17.4 record carrying another credential's key: the
// fixture with its `id` and `publicKey` replaced. Everything else — the field
// set, the flags, the authenticator data — is what 0.17.4 wrote.
func asWrittenBy017(t *testing.T, golden []byte, fresh json.RawMessage) json.RawMessage {
	t.Helper()
	var record, freshFields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(golden, &record))
	require.NoError(t, json.Unmarshal(fresh, &freshFields))
	record["id"], record["publicKey"] = freshFields["id"], freshFields["publicKey"]
	transplanted, err := json.Marshal(record)
	require.NoError(t, err)
	return transplanted
}

// The fixtures under testdata/ are records go-webauthn 0.17.4 stored, generated
// before the move to 0.18 — one for a synced passkey (backup-eligible, backed
// up, user-verified) and one for a device-bound key without user verification.
//
// A fixture cannot bring its private key (CODING-STANDARDS §7: none in the
// repository), so the test enrolls a fresh key, rewrites the stored record into
// the 0.17.4 one with that key's id and public key, and logs in. The operator's
// own passkey on the live deployment is the check this cannot replace.
func TestPasskeyStoredBy017StillLogsIn(t *testing.T) {
	for _, fixture := range []string{
		"testdata/passkey-record-v0.17.4-synced.json",
		"testdata/passkey-record-v0.17.4-device-bound.json",
	} {
		t.Run(fixture, func(t *testing.T) {
			golden, err := os.ReadFile(fixture)
			require.NoError(t, err)
			var flags passkeyFlags
			require.NoError(t, json.Unmarshal(golden, &flags))

			server, repo := newWebAuthnTestServer(t)
			authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
				BackupEligible:  flags.Flags.BackupEligible,
				BackupState:     flags.Flags.BackupState,
				UserNotVerified: !flags.Flags.UserVerified,
			})
			client := newTestClient(t)
			require.Equal(t, http.StatusFound, passwordLogin(t, client, server.URL, testPassword).StatusCode)
			user, err := repo.GetUser(t.Context())
			require.NoError(t, err)
			authenticator.Options.UserHandle = []byte(user.ID)
			credential := enrollPasskey(t, client, server.URL, testRelyingParty, authenticator, "from 0.17")

			record := onlyStoredPasskey(t, repo, user.ID)
			record.Credential = asWrittenBy017(t, golden, record.Credential)
			require.NoError(t, repo.UpdateWebAuthnCredential(t.Context(), &record))
			require.NotContains(t, string(onlyStoredPasskey(t, repo, user.ID).Credential), `"extensions"`,
				"the stored record is in the 0.17 shape, which has no extensions member")

			finish := passkeyLogin(t, newTestClient(t), server.URL, testRelyingParty, authenticator, credential)
			body, err := io.ReadAll(finish.Body)
			finish.Body.Close()
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, finish.StatusCode, "login with a 0.17.4 record: %s", body)

			require.False(t, onlyStoredPasskey(t, repo, user.ID).LastUsedAt.IsZero(), "and the record was written back")
		})
	}
}

// What 0.17.4 stored decodes under 0.18 and encodes back to the same document:
// no member lost, none invented.
func TestPasskeyRecordFrom017RoundTripsUnchanged(t *testing.T) {
	for _, fixture := range []string{
		"testdata/passkey-record-v0.17.4-synced.json",
		"testdata/passkey-record-v0.17.4-device-bound.json",
	} {
		t.Run(fixture, func(t *testing.T) {
			golden, err := os.ReadFile(fixture)
			require.NoError(t, err)

			var credential webauthn.Credential
			require.NoError(t, json.Unmarshal(golden, &credential))
			encoded, err := json.Marshal(credential)
			require.NoError(t, err)

			require.JSONEq(t, string(golden), string(encoded))
		})
	}
}

func onlyStoredPasskey(t *testing.T, repo repository.Repository, userID string) models.WebAuthnCredential {
	t.Helper()
	stored, err := repo.ListWebAuthnCredentials(t.Context(), userID)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	return stored[0]
}

// -- What a client sends back --------------------------------------------------

// operatorWithPasskey bootstraps the operator account and enrolls one passkey.
func operatorWithPasskey(t *testing.T) (serverURL string, authenticator virtualwebauthn.Authenticator, credential virtualwebauthn.Credential) {
	t.Helper()
	server, repo := newWebAuthnTestServer(t)
	authenticator = virtualwebauthn.NewAuthenticator()
	client := newTestClient(t)
	require.Equal(t, http.StatusFound, passwordLogin(t, client, server.URL, testPassword).StatusCode)
	user, err := repo.GetUser(t.Context())
	require.NoError(t, err)
	authenticator.Options.UserHandle = []byte(user.ID)
	credential = enrollPasskey(t, client, server.URL, testRelyingParty, authenticator, "Key")
	return server.URL, authenticator, credential
}

// The gateway requests no WebAuthn extension. A client that returns an
// extension output anyway is refused — the strict policy, set explicitly in
// newWebAuthn. An empty object, which is what a browser sends, is fine.
func TestPasskeyLoginRefusesAnExtensionOutputNobodyAskedFor(t *testing.T) {
	serverURL, authenticator, credential := operatorWithPasskey(t)

	authenticator.Options.ClientExtensionResults = map[string]any{}
	accepted := passkeyLogin(t, newTestClient(t), serverURL, testRelyingParty, authenticator, credential)
	accepted.Body.Close()
	require.Equal(t, http.StatusOK, accepted.StatusCode, "an empty extension object is no output")

	authenticator.Options.ClientExtensionResults = map[string]any{"credProps": map[string]any{"rk": true}}
	refused := passkeyLogin(t, newTestClient(t), serverURL, testRelyingParty, authenticator, credential)
	refused.Body.Close()
	require.Equal(t, http.StatusUnauthorized, refused.StatusCode, "an unsolicited output fails the login")
}

// registerPasskey runs the registration ceremony and returns the finish
// response; mutate may rewrite the client's reply before it is sent.
func registerPasskey(t *testing.T, client *http.Client, serverURL string, authenticator virtualwebauthn.Authenticator, mutate func(reply string) string) *http.Response {
	t.Helper()
	token := fetchCSRFToken(t, client, serverURL+SettingsEndpoint)
	begin := postWithCSRF(t, client, serverURL+WebAuthnRegisterBeginEndpoint, token, "application/json", nil)
	beginBody, err := io.ReadAll(begin.Body)
	begin.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, begin.StatusCode, "register begin: %s", beginBody)
	options, err := virtualwebauthn.ParseAttestationOptions(string(beginBody))
	require.NoError(t, err)

	reply := virtualwebauthn.CreateAttestationResponse(testRelyingParty, authenticator, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *options)
	if mutate != nil {
		reply = mutate(reply)
	}
	return postWithCSRF(t, client, serverURL+WebAuthnRegisterFinishEndpoint+"?name="+url.QueryEscape("Key"), token, "application/json", strings.NewReader(reply))
}

func loggedInOperatorClient(t *testing.T) (client *http.Client, serverURL string, userID string) {
	t.Helper()
	server, repo := newWebAuthnTestServer(t)
	client = newTestClient(t)
	require.Equal(t, http.StatusFound, passwordLogin(t, client, server.URL, testPassword).StatusCode)
	user, err := repo.GetUser(t.Context())
	require.NoError(t, err)
	return client, server.URL, user.ID
}

func TestPasskeyRegistrationRefusesAnExtensionOutputNobodyAskedFor(t *testing.T) {
	client, serverURL, userID := loggedInOperatorClient(t)
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = []byte(userID)
	authenticator.Options.ClientExtensionResults = map[string]any{"credProps": map[string]any{"rk": true}}

	refused := registerPasskey(t, client, serverURL, authenticator, nil)
	refused.Body.Close()
	require.Equal(t, http.StatusBadRequest, refused.StatusCode)
}

// 0.18 requires the reply's `id` and `rawId` to agree. 0.17 accepted a reply
// where they did not, because it built the record from the attested id alone.
func TestPasskeyRegistrationRefusesAReplyWhoseIDsDisagree(t *testing.T) {
	client, serverURL, userID := loggedInOperatorClient(t)
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = []byte(userID)

	accepted := registerPasskey(t, client, serverURL, authenticator, nil)
	accepted.Body.Close()
	require.Equal(t, http.StatusOK, accepted.StatusCode, "the unmodified reply registers")

	refused := registerPasskey(t, client, serverURL, authenticator, func(reply string) string {
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(reply), &fields))
		fields["id"] = json.RawMessage(`"bm90LXRoZS1yYXctaWQ"`)
		tampered, err := json.Marshal(fields)
		require.NoError(t, err)
		return string(tampered)
	})
	refused.Body.Close()
	require.Equal(t, http.StatusBadRequest, refused.StatusCode)
}
