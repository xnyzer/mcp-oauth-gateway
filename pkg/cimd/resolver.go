// Package cimd resolves Client ID Metadata Documents (SPEC §1.3): OAuth
// client IDs that are HTTPS URLs pointing at a JSON document describing the
// client. Resolution is SSRF-guarded, size- and time-limited, and cached.
package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"
)

// Client is a validated Client ID Metadata Document.
type Client struct {
	ClientID      string   `json:"client_id"`
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scope         string   `json:"scope"`
	// TokenEndpointAuthMethod MUST be "none" (or absent): CIMD clients are
	// public; PKCE is their proof of possession (SPEC §1.3).
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
}

// Config bounds the resolution (SPEC §1.3; defaults in ResolverDefaults).
type Config struct {
	FetchTimeout time.Duration
	MaxSize      int64
	CacheTTL     time.Duration
	NegativeTTL  time.Duration
}

const (
	DefaultFetchTimeout = 5 * time.Second
	DefaultMaxSize      = 64 * 1024
	DefaultCacheTTL     = time.Hour
	DefaultNegativeTTL  = time.Minute
	// maxCacheEntries bounds the resolver cache (SPEC §1.3) so unique-client-ID
	// floods to the authorize endpoint cannot exhaust memory.
	maxCacheEntries = 4096
)

// ErrInvalidClientID marks resolution/validation failures; the detail is for
// logs only — clients just see invalid_client (SPEC §1.3.6).
var ErrInvalidClientID = errors.New("invalid CIMD client ID")

type cacheEntry struct {
	client    *Client
	err       error
	expiresAt time.Time
}

type Resolver struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	cache      map[string]cacheEntry
	// allowPrivateHosts disables the SSRF address checks; used only by
	// in-package tests against httptest servers. Never exposed via Config.
	allowPrivateHosts bool
	now               func() time.Time
}

func NewResolver(cfg Config) *Resolver {
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = DefaultFetchTimeout
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxSize
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = DefaultNegativeTTL
	}

	r := &Resolver{
		cfg:   cfg,
		cache: map[string]cacheEntry{},
		now:   time.Now,
	}

	// The address check runs at dial time (net.Dialer.Control), so DNS
	// rebinding cannot bypass it: whatever IP is actually connected to is
	// the IP that gets checked.
	dialer := &net.Dialer{
		Timeout: cfg.FetchTimeout,
		Control: func(network, address string, _ syscall.RawConn) error {
			return r.checkDialAddress(address)
		},
	}
	r.httpClient = &http.Client{
		Timeout: cfg.FetchTimeout,
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("%w: redirects are not followed", ErrInvalidClientID)
		},
	}
	return r
}

// Resolve fetches and validates the metadata document for clientID,
// serving from cache when possible (SPEC §1.3).
func (r *Resolver) Resolve(ctx context.Context, clientID string) (*Client, error) {
	r.mu.Lock()
	if entry, ok := r.cache[clientID]; ok && r.now().Before(entry.expiresAt) {
		r.mu.Unlock()
		return entry.client, entry.err
	}
	r.mu.Unlock()

	client, err := r.fetch(ctx, clientID)

	entry := cacheEntry{client: client, err: err}
	if err != nil {
		entry.expiresAt = r.now().Add(r.cfg.NegativeTTL)
	} else {
		entry.expiresAt = r.now().Add(r.cfg.CacheTTL)
	}
	r.store(clientID, entry)

	return client, err
}

// store inserts entry, bounding the cache so an attacker streaming unique
// client IDs to the (unauthenticated) authorize endpoint cannot grow the map
// without limit (memory DoS, SPEC §1.3). Expired entries are purged first, and
// if the cache is still full an arbitrary entry is evicted to make room.
func (r *Resolver) store(clientID string, entry cacheEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.cache[clientID]; !exists && len(r.cache) >= maxCacheEntries {
		now := r.now()
		for key, existing := range r.cache {
			if !now.Before(existing.expiresAt) {
				delete(r.cache, key)
			}
		}
		for key := range r.cache {
			if len(r.cache) < maxCacheEntries {
				break
			}
			delete(r.cache, key)
		}
	}
	r.cache[clientID] = entry
}

func (r *Resolver) fetch(ctx context.Context, clientID string) (*Client, error) {
	if err := r.validateClientIDURL(clientID); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientID, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch failed: %v", ErrInvalidClientID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status %d", ErrInvalidClientID, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, r.cfg.MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read failed: %v", ErrInvalidClientID, err)
	}
	if int64(len(body)) > r.cfg.MaxSize {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrInvalidClientID, r.cfg.MaxSize)
	}

	var client Client
	if err := json.Unmarshal(body, &client); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrInvalidClientID, err)
	}
	if err := r.validateDocument(clientID, &client); err != nil {
		return nil, err
	}
	return &client, nil
}

// validateClientIDURL enforces the URL shape rules (SPEC §1.3.2).
func (r *Resolver) validateClientIDURL(clientID string) error {
	u, err := url.Parse(clientID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidClientID, err)
	}
	if !r.allowPrivateHosts && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be https", ErrInvalidClientID)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidClientID)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo is not allowed", ErrInvalidClientID)
	}
	if !r.allowPrivateHosts {
		if port := u.Port(); port != "" && port != "443" {
			return fmt.Errorf("%w: non-default port is not allowed", ErrInvalidClientID)
		}
	}
	return nil
}

// validateDocument enforces the metadata rules (SPEC §1.3.3/§1.3.4).
func (r *Resolver) validateDocument(clientID string, client *Client) error {
	if client.ClientID != clientID {
		return fmt.Errorf("%w: document client_id does not match its URL", ErrInvalidClientID)
	}
	if len(client.RedirectURIs) == 0 {
		return fmt.Errorf("%w: redirect_uris must not be empty", ErrInvalidClientID)
	}
	for _, redirectURI := range client.RedirectURIs {
		if err := ValidateRedirectURI(redirectURI); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidClientID, err)
		}
	}
	// Absent auth method defaults to "none" for CIMD (public client).
	if client.TokenEndpointAuthMethod != "" && client.TokenEndpointAuthMethod != "none" {
		return fmt.Errorf("%w: token_endpoint_auth_method must be none", ErrInvalidClientID)
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code"}
	}
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}
	return nil
}

// checkDialAddress rejects connections to non-public addresses (SSRF guard,
// SPEC §1.3.2). It runs at dial time, after DNS resolution.
func (r *Resolver) checkDialAddress(address string) error {
	if r.allowPrivateHosts {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidClientID, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: could not parse dial address", ErrInvalidClientID)
	}
	if isDisallowedIP(ip) {
		return fmt.Errorf("%w: resolves to a non-public address", ErrInvalidClientID)
	}
	return nil
}

// disallowedPrefixes are non-public ranges the net.Addr predicates below do
// not already cover (SPEC §1.3.2). Notably 100.64.0.0/10 (CGNAT) contains the
// Alibaba Cloud metadata service 100.100.100.200, and the NAT64 prefixes embed
// IPv4 addresses that a NAT64 gateway would translate to internal hosts.
var disallowedPrefixes = mustParsePrefixes(
	"100.64.0.0/10",   // CGNAT (RFC 6598) — incl. Alibaba metadata 100.100.100.200
	"192.0.0.0/24",    // IETF protocol assignments (RFC 6890)
	"192.0.2.0/24",    // TEST-NET-1 (documentation, RFC 5737)
	"198.18.0.0/15",   // benchmarking (RFC 2544)
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved/future use, incl. 255.255.255.255 broadcast
	"2001:db8::/32",   // IPv6 documentation (RFC 3849)
	"64:ff9b::/96",    // NAT64 well-known prefix (RFC 6052)
	"64:ff9b:1::/48",  // NAT64 local-use (RFC 8215)
	"100::/64",        // IPv6 discard-only (RFC 6666)
)

func mustParsePrefixes(raw ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	return prefixes
}

// isDisallowedIP reports whether ip is any non-public address: loopback,
// private, CGNAT, link-local (incl. cloud metadata services), ULA, unspecified,
// multicast, or one of the reserved/documentation/NAT64 ranges above. An
// address that cannot be parsed is treated as disallowed (fail closed).
func isDisallowedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	// Normalize IPv4-mapped IPv6 (and leave pure v6 as-is) so v4 prefixes and
	// predicates match regardless of the address's wire form.
	addr = addr.Unmap()
	if !addr.IsValid() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return true
	}
	for _, prefix := range disallowedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ValidateRedirectURI enforces the redirect URI scheme rules shared by CIMD
// and DCR (SPEC §1.3.3): https, custom/native schemes, or http strictly for
// loopback literals (RFC 8252 §7.3).
func ValidateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid redirect URI %q: %v", raw, err)
	}
	switch u.Scheme {
	case "":
		return fmt.Errorf("redirect URI %q must be absolute", raw)
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return fmt.Errorf("redirect URI %q: http is only allowed for loopback", raw)
	case "javascript", "data", "file", "vbscript":
		return fmt.Errorf("redirect URI %q: scheme is not allowed", raw)
	default:
		// Custom/native app schemes (RFC 8252).
		return nil
	}
}
