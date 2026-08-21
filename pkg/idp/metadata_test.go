package idp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
)

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

	// Always present, so clients can decide between CIMD and the deprecated
	// DCR fallback without guessing. This harness configures no resolver, so
	// the honest answer here is false — see TestASMetadataAdvertisesCIMD.
	cimdSupported, ok := metadata["client_id_metadata_document_supported"].(bool)
	require.True(t, ok, "client_id_metadata_document_supported must always be emitted")
	require.False(t, cimdSupported, "no CIMD resolver configured, so it must not be advertised")
}

// TestASMetadataAdvertisesCIMD pins the advertisement to the resolver that
// actually implements it (SPEC §1.2/§1.3). Clients select CIMD only when the
// metadata says so and offers "none" auth, and otherwise fall back to DCR —
// so a wrong answer here silently routes every client down the deprecated path.
func TestASMetadataAdvertisesCIMD(t *testing.T) {
	readFlag := func(t *testing.T, server *httptest.Server) (bool, map[string]any) {
		t.Helper()
		resp, err := http.Get(server.URL + OauthAuthorizationServerEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&metadata))
		flag, ok := metadata["client_id_metadata_document_supported"].(bool)
		require.True(t, ok, "field must be present in both states")
		return flag, metadata
	}

	t.Run("advertised when a resolver is configured", func(t *testing.T) {
		server, _, _ := setupTestServerWith(t, func(cfg *Config) {
			cfg.CIMDResolver = &stubResolver{doc: &cimd.Client{
				ClientID:     "https://client.example.com/oauth/client-metadata.json",
				ClientName:   "CIMD Test Client",
				RedirectURIs: []string{"https://client.example.com/callback"},
			}}
		})
		flag, metadata := readFlag(t, server)
		require.True(t, flag)

		// Both halves are required before a client picks CIMD, so assert the
		// pair rather than the flag alone.
		authMethods, ok := metadata["token_endpoint_auth_methods_supported"].([]any)
		require.True(t, ok)
		require.Contains(t, authMethods, "none", "CIMD clients authenticate as public clients")
	})

	t.Run("not advertised without a resolver", func(t *testing.T) {
		server, _, _ := setupTestServerWith(t, func(cfg *Config) { cfg.CIMDResolver = nil })
		flag, _ := readFlag(t, server)
		require.False(t, flag)
	})

	t.Run("mirrored onto the OIDC discovery path", func(t *testing.T) {
		server, _, _ := setupTestServerWith(t, func(cfg *Config) {
			cfg.OIDCDiscoveryMirror = true
			cfg.CIMDResolver = &stubResolver{}
		})
		resp, err := http.Get(server.URL + OIDCDiscoveryEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&metadata))
		require.Equal(t, true, metadata["client_id_metadata_document_supported"])
	})
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
