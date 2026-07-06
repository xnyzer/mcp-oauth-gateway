// Package ratelimit provides the in-memory abuse protections (SR-5/SR-6):
// per-client-IP token buckets for the public OAuth endpoints and a
// per-account login lockout. State is process-local by design — the
// gateway targets single-instance deployments (GR-3).
package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limit is a parsed rate expression such as "10/m" (SPEC §3.2). The zero
// value (Events == 0) means "disabled".
type Limit struct {
	Events int
	Window time.Duration
}

// Enabled reports whether the limit actually restricts anything.
func (l Limit) Enabled() bool { return l.Events > 0 }

func (l Limit) String() string {
	if !l.Enabled() {
		return "0"
	}
	return fmt.Sprintf("%d per %s", l.Events, l.Window)
}

// windowUnits maps the supported "/s", "/m", "/h" suffixes.
var windowUnits = map[string]time.Duration{
	"s": time.Second,
	"m": time.Minute,
	"h": time.Hour,
}

// ParseLimit parses "N/unit" (e.g. "10/m", "1/s", "100/h"); "0" disables
// the limit. Anything else fails fast (CODING-STANDARDS §7).
func ParseLimit(s string) (Limit, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "0" {
		return Limit{}, nil
	}
	events, unit, found := strings.Cut(trimmed, "/")
	if !found {
		return Limit{}, fmt.Errorf("invalid rate limit %q: expected N/s, N/m, N/h, or 0", s)
	}
	count, err := strconv.Atoi(events)
	if err != nil || count <= 0 {
		return Limit{}, fmt.Errorf("invalid rate limit %q: event count must be a positive integer", s)
	}
	window, ok := windowUnits[unit]
	if !ok {
		return Limit{}, fmt.Errorf("invalid rate limit %q: unit must be s, m, or h", s)
	}
	return Limit{Events: count, Window: window}, nil
}

// Limiter is a keyed token-bucket set: each key (client IP) gets a bucket
// of Limit.Events tokens refilled evenly over Limit.Window.
type Limiter struct {
	limit    Limit
	mu       sync.Mutex
	visitors map[string]*visitor
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewLimiter returns nil for a disabled limit — a nil *Limiter allows
// everything, so call sites need no special-casing.
func NewLimiter(limit Limit) *Limiter {
	if !limit.Enabled() {
		return nil
	}
	return &Limiter{
		limit:    limit,
		visitors: make(map[string]*visitor),
	}
}

// Allow reports whether the key may proceed and consumes a token if so.
func (l *Limiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.visitors[key]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rate.Every(l.limit.Window/time.Duration(l.limit.Events)), l.limit.Events)}
		l.visitors[key] = v
	}
	v.lastSeen = time.Now()
	return v.limiter.Allow()
}

// Sweep drops buckets idle for at least one full window (fully refilled —
// indistinguishable from a fresh one). Called by the periodic sweeper.
func (l *Limiter) Sweep(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, v := range l.visitors {
		if now.Sub(v.lastSeen) >= l.limit.Window {
			delete(l.visitors, key)
		}
	}
}
