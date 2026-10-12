package mcpproxy

// Where the build version is visible on the assembled gateway (F-030). The
// settings footer is covered in pkg/auth; what only this suite can show is
// that the binary's own wiring hands the version to that page — and to no
// public endpoint.

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/idp"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/proxy"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/version"
)

// e2eBuildVersion is unlike anything else the gateway serves, so its presence
// or absence in a body is unambiguous.
const e2eBuildVersion = "v9.9.9-e2e"

var e2eVersionFooterRE = regexp.MustCompile(
	`<div[^>]*id="gateway-version"[^>]*>\s*mcp-oauth-gateway ` + regexp.QuoteMeta(e2eBuildVersion) + `\s*</div>`)

// setBuildVersion stands in for the linker flag a release build sets. The
// package runs no parallel tests, so swapping the global is safe.
func setBuildVersion(t *testing.T, buildVersion string) {
	t.Helper()
	previous := version.Version
	version.Version = buildVersion
	t.Cleanup(func() { version.Version = previous })
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	return string(body)
}

func TestE2EBuildVersionReachesOnlyTheSettingsPage(t *testing.T) {
	setBuildVersion(t, e2eBuildVersion)
	gw := newE2EGateway(t, e2eOpts{oidcMirror: true})

	// SPEC §1.13: the health endpoint answers exactly this, and nothing more.
	health := gw.get(t, "/healthz")
	require.Equal(t, http.StatusOK, health.StatusCode)
	require.JSONEq(t, `{"status":"ok"}`, readBody(t, health))

	// SR-10: no public endpoint names the build.
	publicPaths := []string{
		auth.LoginEndpoint,
		idp.OauthAuthorizationServerEndpoint,
		proxy.OauthProtectedResourceEndpoint,
		idp.OIDCDiscoveryEndpoint,
		idp.JWKSEndpoint,
	}
	for _, path := range publicPaths {
		resp := gw.get(t, path)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.NotContains(t, readBody(t, resp), e2eBuildVersion, "%s must not name the build", path)
	}

	// The page that does show it turns an anonymous caller away, and the
	// redirect itself carries nothing (the client does not follow it).
	turnedAway := mustGet(t, newFlowClient(t), gw.server.URL+auth.SettingsEndpoint)
	require.Equal(t, http.StatusFound, turnedAway.StatusCode, "settings is session-gated")
	require.NotContains(t, readBody(t, turnedAway), e2eBuildVersion)

	// Behind the operator's session the footer shows it.
	operator := newFlowClient(t)
	loginToken := extractCSRFToken(t, operator, gw.server.URL+auth.LoginEndpoint)
	loginResp, err := operator.PostForm(gw.server.URL+auth.LoginEndpoint,
		url.Values{"password": {e2ePassword}, auth.CSRFFieldName: {loginToken}})
	require.NoError(t, err)
	requireRedirect(t, loginResp)

	settings := mustGet(t, operator, gw.server.URL+auth.SettingsEndpoint)
	require.Equal(t, http.StatusOK, settings.StatusCode)
	require.Regexp(t, e2eVersionFooterRE, readBody(t, settings))
}
