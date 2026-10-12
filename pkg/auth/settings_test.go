package auth

// The build version in the settings footer (F-030). What matters here is the
// boundary, not the rendering: the version tells an attacker which advisories
// apply, so it may appear behind the operator's session and nowhere else.

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"golang.org/x/crypto/bcrypt"
)

// testBuildVersion is deliberately unlike anything else on the pages, so
// finding it — or not — means the footer and nothing else.
const testBuildVersion = "v9.9.9-test"

// versionFooterRE matches the footer element itself. A bare Contains on the
// version would also pass if the value leaked into some other element.
var versionFooterRE = regexp.MustCompile(
	`<div[^>]*id="gateway-version"[^>]*>\s*mcp-oauth-gateway ` + regexp.QuoteMeta(testBuildVersion) + `\s*</div>`)

// newVersionTestServer wires the settings surface with the given build
// version (mirrors newClientsTestServerWith, which has no use for one).
func newVersionTestServer(t *testing.T, buildVersion string) *httptest.Server {
	t.Helper()

	repo, err := repository.NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	require.NoError(t, err)

	authRouter, err := NewAuthRouter(Config{
		PasswordHashes: []string{string(hash)},
		Users:          repo,
		Clients:        repo,
		ExternalURL:    testExternalURL,
		Version:        buildVersion,
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	secret := sha256.Sum256([]byte("settings_test_secret"))
	router.Use(sessions.Sessions("test_session", cookie.NewStore(secret[:])))
	authRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

func TestSettingsFooterShowsTheBuildVersion(t *testing.T) {
	server := newVersionTestServer(t, testBuildVersion)

	status, body := getBody(t, loggedInOperator(t, server), server.URL+SettingsEndpoint)

	require.Equal(t, http.StatusOK, status)
	require.Regexp(t, versionFooterRE, body, "the footer names the running build")
}

// A build without a version renders no footer line rather than an empty one.
func TestSettingsFooterIsAbsentWithoutAVersion(t *testing.T) {
	server := newVersionTestServer(t, "")

	status, body := getBody(t, loggedInOperator(t, server), server.URL+SettingsEndpoint)

	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, body, `id="gateway-version"`)
}

// SPEC §1.13 / SR-10: no version disclosure to an anonymous caller. The client
// does not follow redirects, so the settings assertion reads the redirect
// itself, not the login page it points to.
func TestVersionIsNotDisclosedWithoutASession(t *testing.T) {
	server := newVersionTestServer(t, testBuildVersion)
	anonymous := newTestClient(t)

	status, body := getBody(t, anonymous, server.URL+LoginEndpoint)
	require.Equal(t, http.StatusOK, status)
	require.NotContains(t, body, testBuildVersion, "the public login page must not name the build")

	status, body = getBody(t, anonymous, server.URL+SettingsEndpoint)
	require.Equal(t, http.StatusFound, status, "settings is session-gated")
	require.NotContains(t, body, testBuildVersion, "the redirect must not carry the page")
}
