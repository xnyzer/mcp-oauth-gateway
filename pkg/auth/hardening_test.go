package auth

// Login-surface hardening from the F-006b audit (F-012b): uniform
// empty-password handling, full session clearing on logout, and the
// same-origin guard on the stored post-login redirect target.

import (
	"crypto/sha256"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// TestSafeRedirectTarget covers the open-redirect guard: only same-origin
// local paths survive; scheme-relative and absolute URLs fall back to "/".
func TestSafeRedirectTarget(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/mcp", "/mcp"},
		{"/app/callback?x=1", "/app/callback?x=1"},
		{"/", "/"},
		{"", "/"},
		{"//evil.example.com", "/"},
		{`/\evil.example.com`, "/"},
		{"https://evil.example.com", "/"},
		{"http://evil.example.com", "/"},
		{"javascript:alert(1)", "/"},
		{"evil.example.com", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, safeRedirectTarget(tc.in))
		})
	}
}

// TestEmptyPasswordAnswersLikeWrongPassword covers the SR-6 uniformity fix:
// an empty password must take the same bcrypt path and return a
// byte-identical response to a wrong one (no distinct pre-bcrypt body).
func TestEmptyPasswordAnswersLikeWrongPassword(t *testing.T) {
	server, _ := newAbuseTestServer(t, nil)

	// One session so the embedded CSRF token — and thus the rendered page — is
	// identical; only the password-verification outcome may differ.
	client := newTestClient(t)
	wrongResp, wrongBody := postLoginClient(t, client, server.URL, "wrong")
	emptyResp, emptyBody := postLoginClient(t, client, server.URL, "")

	require.Equal(t, http.StatusBadRequest, emptyResp.StatusCode)
	require.Equal(t, wrongResp.StatusCode, emptyResp.StatusCode)
	require.Equal(t, wrongBody, emptyBody, "empty password must not be distinguishable from a wrong one")
}

// newLoginTestServer wires an AuthRouter with password login and a protected
// route, so the full login → protected → logout lifecycle is observable.
func newLoginTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	repo, err := repository.NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	require.NoError(t, err)

	authRouter, err := NewAuthRouter(Config{
		PasswordHashes: []string{string(hash)},
		Users:          repo,
		ExternalURL:    testExternalURL,
		Logger:         zap.NewNop(),
	})
	require.NoError(t, err)

	router := gin.New()
	secret := sha256.Sum256([]byte("hardening_test_secret"))
	router.Use(sessions.Sessions("test_session", cookie.NewStore(secret[:])))
	router.GET("/app", authRouter.RequireAuth(), func(c *gin.Context) {
		c.String(http.StatusOK, "authenticated")
	})
	authRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

// TestLogoutClearsSession verifies logout drops the whole session — the
// protected route is inaccessible again — and expires the cookie client-side.
func TestLogoutClearsSession(t *testing.T) {
	server := newLoginTestServer(t)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Log in, then confirm the protected route is reachable.
	loginResp := passwordLogin(t, client, server.URL, testPassword)
	require.Equal(t, http.StatusFound, loginResp.StatusCode)

	appResp, err := client.Get(server.URL + "/app")
	require.NoError(t, err)
	appResp.Body.Close()
	require.Equal(t, http.StatusOK, appResp.StatusCode, "session authorises the protected route")

	// Log out: the cookie is expired (MaxAge -1) and the session dropped.
	logoutResp, err := client.Get(server.URL + LogoutEndpoint)
	require.NoError(t, err)
	logoutResp.Body.Close()
	require.Equal(t, http.StatusFound, logoutResp.StatusCode)
	var expired bool
	for _, c := range logoutResp.Cookies() {
		if c.Name == "test_session" && c.MaxAge < 0 {
			expired = true
		}
	}
	require.True(t, expired, "logout must expire the session cookie")

	// The protected route redirects to login again — the session is gone.
	afterResp, err := client.Get(server.URL + "/app")
	require.NoError(t, err)
	afterResp.Body.Close()
	require.Equal(t, http.StatusFound, afterResp.StatusCode)
	require.Equal(t, LoginEndpoint, afterResp.Header.Get("Location"))
}

// TestLoginReturnsToRequestedPath verifies the normal redirect flow still
// returns to the originally requested local path (the guard does not break it).
func TestLoginReturnsToRequestedPath(t *testing.T) {
	server := newLoginTestServer(t)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Unauthenticated access records /app as the post-login target.
	resp, err := client.Get(server.URL + "/app")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, LoginEndpoint, resp.Header.Get("Location"))

	// A successful login returns to it.
	loginResp := passwordLogin(t, client, server.URL, testPassword)
	require.Equal(t, http.StatusFound, loginResp.StatusCode)
	require.Equal(t, "/app", loginResp.Header.Get("Location"))
}
