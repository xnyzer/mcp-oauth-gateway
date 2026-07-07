package ratelimit

import (
	"sync"
	"time"
)

// Lockout tracks consecutive failures per account key and locks the
// account after Threshold of them for Duration (SR-6). The caller answers
// with the same uniform error whether locked or merely wrong — the lockout
// only hardens brute force, it must not become an oracle.
type Lockout struct {
	threshold int
	duration  time.Duration
	mu        sync.Mutex
	entries   map[string]*lockoutEntry
}

type lockoutEntry struct {
	failures    int
	lockedUntil time.Time
	lastFailure time.Time
}

// NewLockout returns nil when threshold is 0 (disabled) — a nil *Lockout
// never locks, so call sites need no special-casing.
func NewLockout(threshold int, duration time.Duration) *Lockout {
	if threshold <= 0 {
		return nil
	}
	return &Lockout{
		threshold: threshold,
		duration:  duration,
		entries:   make(map[string]*lockoutEntry),
	}
}

// Locked reports whether the account is currently locked out.
func (l *Lockout) Locked(key string, now time.Time) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	return ok && now.Before(entry.lockedUntil)
}

// Fail records a failed attempt; the threshold-th consecutive failure starts
// the lockout window. The window is armed only on the transition that first
// reaches the threshold — never re-extended by later failures — and a streak
// whose window has fully expired is reset before counting. Otherwise an
// attacker could send one wrong password per window to keep the account
// locked indefinitely (a permanent-lockout DoS on the sole operator).
func (l *Lockout) Fail(key string, now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok {
		entry = &lockoutEntry{}
		l.entries[key] = entry
	}
	// A prior lock that has fully elapsed ends the streak: start counting
	// afresh so the expired window cannot be perpetually re-armed.
	if !entry.lockedUntil.IsZero() && !now.Before(entry.lockedUntil) {
		entry.failures = 0
		entry.lockedUntil = time.Time{}
	}
	entry.failures++
	entry.lastFailure = now
	if entry.failures == l.threshold {
		entry.lockedUntil = now.Add(l.duration)
	}
}

// Reset clears the failure counter after a successful login.
func (l *Lockout) Reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Sweep drops entries whose lockout has expired and whose last failure is
// older than the lockout duration (the consecutive-failure streak is over).
func (l *Lockout) Sweep(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, entry := range l.entries {
		if now.Before(entry.lockedUntil) {
			continue
		}
		if now.Sub(entry.lastFailure) >= l.duration {
			delete(l.entries, key)
		}
	}
}
