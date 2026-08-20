package idp

import (
	"net"
	"net/url"
	"strings"
)

// loopbackHost is the one hostname whose port this gateway lets vary.
//
// RFC 8252 §7.3 requires an authorization server to accept any port on a
// loopback redirect URI, because a native client gets its port from the
// operating system per session and cannot pre-register it. Fosite implements
// that rule, but only for the IP literals 127.0.0.1 and [::1] — its
// isLoopbackAddress() tests net.ParseIP(host).IsLoopback(), which the name
// "localhost" never satisfies.
//
// RFC 8252 §8.3 discourages the hostname form for exactly that ambiguity, yet
// native clients use it anyway: Claude Code registers http://localhost/callback
// in its Client ID Metadata Document and then redirects to
// http://localhost:<ephemeral>/callback. The tolerance is therefore extended to
// this exact name and nothing else — notably not to "*.localhost", which would
// widen the rule without a caller that needs it.
const loopbackHost = "localhost"

// matchesLoopbackHostPort reports whether requested is registered with a
// different port and nothing else changed.
//
// Every component other than the port must be identical, so this cannot become
// an open redirect: it admits only the one part a loopback client provably
// cannot pre-register. The registered URI's own port is ignored, matching how
// fosite treats the IP-literal form.
func matchesLoopbackHostPort(registered, requested string) bool {
	reg, err := url.Parse(registered)
	if err != nil {
		return false
	}
	req, err := url.Parse(requested)
	if err != nil {
		return false
	}
	// http only — the same restriction fosite puts on the IP-literal rule.
	// A loopback redirect is plain HTTP by construction (no certificate can
	// be issued for it), so an https URI here is never a loopback client.
	if reg.Scheme != "http" || req.Scheme != "http" {
		return false
	}
	if !strings.EqualFold(reg.Hostname(), loopbackHost) || !strings.EqualFold(req.Hostname(), loopbackHost) {
		return false
	}
	// Path and query are what identify the callback endpoint; letting either
	// vary would hand a local attacker a different landing point on the same
	// port they already had to win.
	return reg.Path == req.Path && reg.RawQuery == req.RawQuery
}

// expandLoopbackRedirects returns registered plus requested when requested is
// a port variant of one of the registered URIs, and registered unchanged
// otherwise. The result is always a fresh slice, so callers can hand it to a
// client struct without aliasing whatever the store owns.
func expandLoopbackRedirects(registered []string, requested string) []string {
	if requested == "" {
		return registered
	}
	for _, candidate := range registered {
		// An exact match needs no help; fosite already accepts it.
		if candidate == requested {
			return registered
		}
	}
	for _, candidate := range registered {
		if matchesLoopbackHostPort(candidate, requested) {
			expanded := make([]string, len(registered), len(registered)+1)
			copy(expanded, registered)
			return append(expanded, requested)
		}
	}
	return registered
}

// isLoopbackRedirect reports whether raw points at this machine, covering both
// the IP literals fosite matches port-agnostically and the "localhost"
// hostname added in F-016.
func isLoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, loopbackHost) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// allRedirectsLoopback reports whether every registered redirect URI is a
// loopback address. Keyed on "all", not "any": a web client that also offers a
// local callback is not a native client, and warning there would train the
// operator to click through the warning that matters.
func allRedirectsLoopback(redirectURIs []string) bool {
	if len(redirectURIs) == 0 {
		return false
	}
	for _, raw := range redirectURIs {
		if !isLoopbackRedirect(raw) {
			return false
		}
	}
	return true
}
