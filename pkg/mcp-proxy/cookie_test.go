package mcpproxy

// Session-cookie key separation (F-012d): the operator session cookie is signed
// AND encrypted with HKDF-derived subkeys distinct from fosite's raw secret, so
// its contents are opaque on the wire (SPEC §1.12/§2.2).

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestDeriveCookieKeys(t *testing.T) {
	secret := []byte("this-is-a-32-byte-long-secret!!!")

	authKey, encKey, err := deriveCookieKeys(secret)
	require.NoError(t, err)
	require.Len(t, authKey, cookieKeyLen)
	require.Len(t, encKey, cookieKeyLen, "encryption key must be an AES-usable length")
	require.NotEqual(t, authKey, encKey, "auth and encryption subkeys must be independent")

	// Deterministic: the same secret always yields the same keys (so a restart
	// keeps validating outstanding cookies).
	authKey2, encKey2, err := deriveCookieKeys(secret)
	require.NoError(t, err)
	require.Equal(t, authKey, authKey2)
	require.Equal(t, encKey, encKey2)

	// A different secret yields different keys.
	otherAuth, _, err := deriveCookieKeys([]byte("a-completely-different-32-byte!!!"))
	require.NoError(t, err)
	require.NotEqual(t, authKey, otherAuth)
}

func TestSessionCookieIsEncrypted(t *testing.T) {
	const marker = "PLAINTEXT_SESSION_MARKER"
	secret := []byte("this-is-a-32-byte-long-secret!!!")

	authKey, encKey, err := deriveCookieKeys(secret)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(sessions.Sessions("session", cookie.NewStore(authKey, encKey)))
	router.GET("/set", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set("marker", marker)
		require.NoError(t, session.Save())
		c.Status(http.StatusOK)
	})

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/set")
	require.NoError(t, err)
	resp.Body.Close()

	var cookieValue string
	for _, ck := range resp.Cookies() {
		if ck.Name == "session" {
			cookieValue = ck.Value
		}
	}
	require.NotEmpty(t, cookieValue, "a session cookie must be set")
	require.NotContains(t, cookieValue, marker,
		"the encrypted cookie must not expose session values in plaintext")
}
