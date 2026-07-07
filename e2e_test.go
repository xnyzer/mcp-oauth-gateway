package main

// End-to-end flows over the assembled gateway (F-006a). See
// e2e_harness_test.go for the harness. Each test drives real HTTP against a
// full gateway (session + auth + idp + proxy + keys + repo) and a mock
// upstream.

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/idp"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/proxy"
)

// authCodeURL builds an /.idp/auth request URL.
func (g *e2eGateway) authCodeURL(clientID, redirectURI, challenge string) string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {"e2e-state-value"},
	}
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	return g.server.URL + idp.AuthorizationEndpoint + "?" + q.Encode()
}

// TestE2EDiscoveryValidAndSelfConsistent verifies the discovery surface (PRM,
// AS metadata, OIDC mirror, JWKS) is complete and internally consistent.
func TestE2EDiscoveryValidAndSelfConsistent(t *testing.T) {
	gw := newE2EGateway(t, e2eOpts{oidcMirror: true})

	// -- Protected Resource Metadata (RFC 9728) --
	prm := decodeJSON(t, gw.get(t, proxy.OauthProtectedResourceEndpoint))
	require.Equal(t, gw.issuer, prm["resource"])
	require.Contains(t, prm["authorization_servers"], gw.issuer)
	require.Equal(t, gw.issuer+idp.JWKSEndpoint, prm["jwks_uri"])
	require.Equal(t, []any{"header"}, prm["bearer_methods_supported"])

	// -- AS metadata (RFC 8414) --
	as := decodeJSON(t, gw.get(t, idp.OauthAuthorizationServerEndpoint))
	require.Equal(t, gw.issuer, as["issuer"])
	require.Equal(t, gw.issuer+idp.AuthorizationEndpoint, as["authorization_endpoint"])
	require.Equal(t, gw.issuer+idp.TokenEndpoint, as["token_endpoint"])
	require.Equal(t, gw.issuer+idp.RegistrationEndpoint, as["registration_endpoint"])
	require.Equal(t, gw.issuer+idp.JWKSEndpoint, as["jwks_uri"])
	require.Equal(t, gw.issuer+idp.RevocationEndpoint, as["revocation_endpoint"])
	require.Equal(t, gw.issuer+idp.IntrospectionEndpoint, as["introspection_endpoint"])
	require.Equal(t, []any{"S256"}, as["code_challenge_methods_supported"], "plain MUST NOT be offered")
	require.Equal(t, true, as["authorization_response_iss_parameter_supported"], "RFC 9207 iss must be advertised")
	require.Contains(t, as["response_types_supported"], "code")

	// -- OIDC Discovery mirror serves the same document --
	mirror := decodeJSON(t, gw.get(t, idp.OIDCDiscoveryEndpoint))
	require.Equal(t, as["issuer"], mirror["issuer"])
	require.Equal(t, as["token_endpoint"], mirror["token_endpoint"])

	// -- JWKS advertises the active signing key --
	jwks := decodeJSON(t, gw.get(t, idp.JWKSEndpoint))
	keyList, ok := jwks["keys"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, keyList)
	first := keyList[0].(map[string]any)
	require.Equal(t, "RSA", first["kty"])
	require.Equal(t, "RS256", first["alg"])
	require.Equal(t, gw.keys.Active().Kid, first["kid"], "JWKS must expose the active kid")
}

// TestE2EAuthCodeProxyAndRevocation drives the full confidential-client flow —
// DCR, real login + consent, token, a proxied upstream call — then the
// fail-closed negatives (no/tampered/replayed/revoked token).
func TestE2EAuthCodeProxyAndRevocation(t *testing.T) {
	gw := newE2EGateway(t, e2eOpts{})
	clientID, clientSecret := gw.registerClient(t, "client_secret_basic")

	// Authorize + real password login + consent.
	client := newFlowClient(t)
	callback := gw.driveAuthCode(t, client, gw.authCodeURL(clientID, e2eRedirectURI, ""))
	require.Equal(t, gw.issuer, callback.Query().Get("iss"), "RFC 9207 iss must be in the redirect")
	require.Equal(t, "e2e-state-value", callback.Query().Get("state"))
	code := callback.Query().Get("code")
	require.NotEmpty(t, code)

	// Token exchange (client_secret_post).
	tokenResp := gw.exchangeCode(t, code, url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	tokens := decodeJSON(t, tokenResp)
	accessToken, _ := tokens["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// The published JWKS verifies the token; claims are audience/issuer bound.
	claims := gw.verifyAgainstJWKS(t, accessToken)
	require.Equal(t, gw.issuer, claims["iss"])
	require.Contains(t, claims["aud"], gw.issuer)
	require.Equal(t, clientID, claims["client_id"])
	require.NotEmpty(t, claims["jti"])

	// -- Happy path: the token proxies to the upstream --
	proxyResp := gw.proxyGet(t, "/mcp", accessToken)
	require.Equal(t, http.StatusOK, proxyResp.StatusCode)
	proxyResp.Body.Close()
	hits, upstreamAuth, path := gw.upstream.snapshot()
	require.Equal(t, 1, hits)
	require.Equal(t, "/mcp", path)
	require.Equal(t, "Bearer "+upstreamSecret, upstreamAuth, "upstream sees the injected credential, never the client token")
	require.NotContains(t, upstreamAuth, accessToken)

	// -- Negative: missing token -> 401 + WWW-Authenticate pointing at PRM --
	t.Run("missing token is denied", func(t *testing.T) {
		resp := gw.proxyGet(t, "/mcp", "")
		defer resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		challenge := resp.Header.Get("WWW-Authenticate")
		require.Contains(t, challenge, "resource_metadata=")
		require.Contains(t, challenge, gw.issuer+proxy.OauthProtectedResourceEndpoint)
	})

	// -- Negative: tampered signature -> 401 --
	t.Run("tampered token is denied", func(t *testing.T) {
		tampered := flipLastChar(accessToken)
		resp := gw.proxyGet(t, "/mcp", tampered)
		defer resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// -- Negative: replaying the consumed authorization code -> rejected --
	t.Run("authorization code replay is denied", func(t *testing.T) {
		resp := gw.exchangeCode(t, code, url.Values{
			"client_id":     {clientID},
			"client_secret": {clientSecret},
		})
		defer resp.Body.Close()
		require.NotEqual(t, http.StatusOK, resp.StatusCode)
		body := decodeJSON(t, resp)
		require.Equal(t, "invalid_grant", body["error"])
	})

	// -- Revocation (RFC 7009): revoke, then the proxy denies the token --
	t.Run("revoked token is denied at the proxy", func(t *testing.T) {
		revoke, err := http.NewRequest(http.MethodPost, gw.server.URL+idp.RevocationEndpoint,
			strings.NewReader(url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}.Encode()))
		require.NoError(t, err)
		revoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		revoke.SetBasicAuth(clientID, clientSecret)
		revokeResp, err := http.DefaultClient.Do(revoke)
		require.NoError(t, err)
		defer revokeResp.Body.Close()
		require.Equal(t, http.StatusOK, revokeResp.StatusCode)

		resp := gw.proxyGet(t, "/mcp", accessToken)
		defer resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "revoked token must be fail-closed")
	})
}

// TestE2EPublicClientPKCE drives a public client identified via CIMD (injected
// resolver stub) through PKCE/S256, and asserts PKCE is mandatory.
func TestE2EPublicClientPKCE(t *testing.T) {
	const cimdClientID = "https://client.example.com/oauth/client-metadata.json"
	const cimdRedirect = "https://client.example.com/callback"
	gw := newE2EGateway(t, e2eOpts{
		cimd: &stubCIMDResolver{doc: &cimd.Client{
			ClientID:     cimdClientID,
			ClientName:   "CIMD E2E Client",
			RedirectURIs: []string{cimdRedirect},
		}},
	})

	verifier, challenge := pkcePair("e2e")

	// authCodeURL builds redirect_uri from the CIMD document's registered URI.
	authURL := gw.server.URL + idp.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {cimdClientID},
		"redirect_uri":          {cimdRedirect},
		"state":                 {"e2e-state-value"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	client := newFlowClient(t)
	callback := gw.driveAuthCode(t, client, authURL)
	require.Equal(t, gw.issuer, callback.Query().Get("iss"))
	code := callback.Query().Get("code")
	require.NotEmpty(t, code)

	// Token exchange presents the verifier instead of a client secret.
	resp, err := http.PostForm(gw.server.URL+idp.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cimdRedirect},
		"client_id":     {cimdClientID},
		"code_verifier": {verifier},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tokens := decodeJSON(t, resp)
	accessToken, _ := tokens["access_token"].(string)
	require.NotEmpty(t, accessToken)

	claims := gw.verifyAgainstJWKS(t, accessToken)
	require.Equal(t, cimdClientID, claims["client_id"], "the CIMD URL is the client_id claim")

	// The public client's token proxies upstream.
	proxyResp := gw.proxyGet(t, "/mcp", accessToken)
	require.Equal(t, http.StatusOK, proxyResp.StatusCode)
	proxyResp.Body.Close()

	// -- PKCE is mandatory for public clients (downgrade is rejected) --
	t.Run("public client without PKCE is rejected", func(t *testing.T) {
		noPKCE := gw.server.URL + idp.AuthorizationEndpoint + "?" + url.Values{
			"response_type": {"code"},
			"client_id":     {cimdClientID},
			"redirect_uri":  {cimdRedirect},
			"state":         {"e2e-state-value"},
		}.Encode()
		noPKCEClient := newFlowClient(t)
		callback := gw.driveAuthCode(t, noPKCEClient, noPKCE)
		require.Empty(t, callback.Query().Get("code"))
		require.NotEmpty(t, callback.Query().Get("error"), "missing PKCE must produce an OAuth error")
		require.Equal(t, gw.issuer, callback.Query().Get("iss"))
	})
}

// TestE2ERateLimit verifies the per-IP token bucket on /.idp/register fires.
func TestE2ERateLimit(t *testing.T) {
	gw := newE2EGateway(t, e2eOpts{registerLimit: "1/m"})

	body := strings.NewReader(`{"client_name":"rl","redirect_uris":["` + e2eRedirectURI + `"]}`)
	first, err := http.Post(gw.server.URL+idp.RegistrationEndpoint, "application/json", body)
	require.NoError(t, err)
	defer first.Body.Close()
	require.Equal(t, http.StatusCreated, first.StatusCode)

	second, err := http.Post(gw.server.URL+idp.RegistrationEndpoint, "application/json",
		strings.NewReader(`{"client_name":"rl","redirect_uris":["`+e2eRedirectURI+`"]}`))
	require.NoError(t, err)
	defer second.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, second.StatusCode)
	require.Equal(t, "temporarily_unavailable", decodeJSON(t, second)["error"])
}

// TestE2EKeyRotationContinuity proves a rotation keeps outstanding tokens valid
// (SPEC §2.3, no abrupt invalidation): a token minted under the old key still
// proxies after the key rotates, and the retiring key stays in the JWKS.
func TestE2EKeyRotationContinuity(t *testing.T) {
	gw := newE2EGateway(t, e2eOpts{})
	clientID, clientSecret := gw.registerClient(t, "client_secret_basic")

	client := newFlowClient(t)
	callback := gw.driveAuthCode(t, client, gw.authCodeURL(clientID, e2eRedirectURI, ""))
	tokenResp := gw.exchangeCode(t, callback.Query().Get("code"), url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)
	oldToken, _ := decodeJSON(t, tokenResp)["access_token"].(string)
	require.NotEmpty(t, oldToken)

	oldKid := gw.keys.Active().Kid
	require.Equal(t, http.StatusOK, gw.proxyGet(t, "/mcp", oldToken).StatusCode)

	// Rotate: active -> retiring, a fresh key becomes active.
	require.NoError(t, gw.keys.Rotate(time.Now()))
	require.NotEqual(t, oldKid, gw.keys.Active().Kid, "rotation must install a new active key")

	// The JWKS now advertises both the new and the retiring key.
	jwks := decodeJSON(t, gw.get(t, idp.JWKSEndpoint))
	kids := map[string]bool{}
	for _, k := range jwks["keys"].([]any) {
		kids[k.(map[string]any)["kid"].(string)] = true
	}
	require.True(t, kids[oldKid], "the retiring key must still be published")
	require.True(t, kids[gw.keys.Active().Kid], "the new active key must be published")

	// Continuity: the pre-rotation token still verifies and proxies.
	resp := gw.proxyGet(t, "/mcp", oldToken)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "a token from the retiring key must remain valid")
}

// TestE2EReservedNamespaceNotProxied confirms an unmatched path inside a
// reserved namespace returns 404 and is never forwarded upstream (SPEC §0).
func TestE2EReservedNamespaceNotProxied(t *testing.T) {
	gw := newE2EGateway(t, e2eOpts{})
	clientID, clientSecret := gw.registerClient(t, "client_secret_basic")
	client := newFlowClient(t)
	callback := gw.driveAuthCode(t, client, gw.authCodeURL(clientID, e2eRedirectURI, ""))
	tokenResp := gw.exchangeCode(t, callback.Query().Get("code"), url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	})
	token, _ := decodeJSON(t, tokenResp)["access_token"].(string)

	// Even with a valid token, a disabled/unknown reserved path is 404, not proxied.
	resp := gw.proxyGet(t, "/.idp/does-not-exist", token)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	hits, _, _ := gw.upstream.snapshot()
	require.Zero(t, hits, "reserved paths must never reach the upstream")
}

// flipLastChar mutates a token's final character to invalidate its signature.
func flipLastChar(token string) string {
	if token == "" {
		return token
	}
	last := token[len(token)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	return fmt.Sprintf("%s%c", token[:len(token)-1], replacement)
}
