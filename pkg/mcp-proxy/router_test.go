package mcpproxy

// The optional OIDC login backend, as the start-up path builds it.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
)

// newOIDCDiscoveryServer serves the one document NewOIDCProvider fetches.
func newOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "http://localhost/auth",
			"token_endpoint":         "http://localhost/token",
			"userinfo_endpoint":      "http://localhost/userinfo",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func oidcConfig(t *testing.T) resolvedConfig {
	t.Helper()
	return resolvedConfig{
		Config: Config{
			OIDCConfigurationURL: newOIDCDiscoveryServer(t).URL,
			OIDCClientID:         "client-id",
			OIDCClientSecret:     "placeholder-client-secret",
			OIDCUserIDField:      "/email",
			OIDCProviderName:     "OIDC",
		},
		issuer: e2eIssuer,
	}
}

// oidcConfigWithAllowList is a start-up configuration that passes the allow-list
// requirement, for tests about something else.
func oidcConfigWithAllowList(t *testing.T) resolvedConfig {
	t.Helper()
	rc := oidcConfig(t)
	rc.OIDCAllowedUsers = []string{"operator@example.com"}
	return rc
}

// OIDC without an allow-list would admit every account of the provider. The
// gateway refuses to start, and says which settings to use — including how to
// ask for "everyone" on purpose.
func TestBuildOIDCProvidersRefusesOIDCWithoutAnAllowList(t *testing.T) {
	_, err := buildOIDCProviders(oidcConfig(t))

	require.ErrorIs(t, err, auth.ErrNoAllowList)
	for _, setting := range []string{"OIDC_ALLOWED_USERS", "OIDC_ALLOWED_USERS_GLOB", "OIDC_ALLOWED_ATTRIBUTES", "OIDC_ALLOWED_ATTRIBUTES_GLOB"} {
		require.Contains(t, err.Error(), setting)
	}
	require.Contains(t, err.Error(), "OIDC_ALLOWED_USERS_GLOB=*", "the message shows the explicit way to admit everyone")
}

func TestBuildOIDCProvidersStartsWithAnAllowList(t *testing.T) {
	providers, err := buildOIDCProviders(oidcConfigWithAllowList(t))

	require.NoError(t, err)
	require.Len(t, providers, 1)
}

func TestBuildOIDCProvidersIsOffWithoutItsThreeSettings(t *testing.T) {
	providers, err := buildOIDCProviders(resolvedConfig{})
	require.NoError(t, err)
	require.Empty(t, providers)
}

// `{alice,bob}` written without escaping its comma reaches the provider as two
// halves, and the library's "unclosed {" alone would send the operator looking
// for a typo that is not there. The start-up message names the real cause.
func TestBuildOIDCProvidersExplainsASplitPattern(t *testing.T) {
	rc := oidcConfig(t)
	rc.OIDCAllowedUsersGlob = []string{"{alice", "bob}@example.com"}

	_, err := buildOIDCProviders(rc)

	require.ErrorIs(t, err, auth.ErrInvalidGlobPattern)
	require.Contains(t, err.Error(), `"{alice"`, "the message names the pattern as it arrived")
	require.Contains(t, err.Error(), `\,`, "and says how a comma inside a pattern is written")
}

func TestBuildOIDCProvidersAcceptsAnEscapedPattern(t *testing.T) {
	rc := oidcConfig(t)
	rc.OIDCAllowedUsersGlob = []string{"{alice,bob}@example.com"}

	providers, err := buildOIDCProviders(rc)

	require.NoError(t, err)
	require.Len(t, providers, 1)
}
