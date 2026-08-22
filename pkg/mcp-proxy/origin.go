package mcpproxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// requireSameOrigin rejects a request whose Origin header names anything other
// than the gateway's own origin (SR-9). The Streamable HTTP transport has
// required this since protocol version 2025-03-26, to stop a DNS-rebinding
// attacker from driving the gateway from a page the victim's browser loaded
// elsewhere.
//
// A request **without** an Origin header passes. That is deliberate and is what
// the specification asks for: server-side MCP clients send none at all — Claude
// connects from a vendor cloud, not from the user's browser — so treating
// absence as a violation would reject every real client and turn a hardening
// measure into an outage. Browsers, meanwhile, attach Origin to every POST even
// same-origin, which is what makes the check bite where it matters: the
// operator's login and consent surface.
//
// Origin: null counts as present and invalid. Browsers send it from sandboxed
// iframes, file:// documents and some redirect chains, and none of those should
// be able to act on the gateway.
func requireSameOrigin(expected string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}
		// The empty check matters: normalizeOrigin returns "" for anything
		// unusable, so comparing the two normalized values alone would let
		// Origin: null match an expected origin that is itself unusable, and
		// the guard would silently become a wildcard. Requiring a non-empty
		// match keeps it closed in that case. EXTERNAL_URL is validated at
		// startup, so this should be unreachable — which is the point.
		if got := normalizeOrigin(origin); got != "" && got == expected {
			c.Next()
			return
		}
		// Logged with the expected value alongside it: a mismatch here is
		// otherwise indistinguishable from any other 403, and the usual cause
		// is an EXTERNAL_URL that does not match what the browser shows.
		logger.Warn("rejected request with a foreign Origin",
			zap.String("origin", origin),
			zap.String("expected", expected),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", c.ClientIP()))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	}
}

// normalizeOrigin reduces an origin to "scheme://host[:port]" for comparison:
// scheme and host lower-cased, and the port dropped when it is the default for
// the scheme. Without this, https://example.com and https://EXAMPLE.COM:443
// would read as different origins even though a browser treats them as one.
//
// It returns "" for anything that is not a usable origin — Origin: null and
// malformed values included — which never equals a normalized expected origin
// and therefore fails closed.
func normalizeOrigin(raw string) string {
	if raw == "" || raw == "null" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	// url.Hostname strips the brackets from an IPv6 literal, so they have to
	// go back on before a port can be appended — otherwise [::1]:8080 would
	// normalize to the unparseable ::1:8080.
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}
