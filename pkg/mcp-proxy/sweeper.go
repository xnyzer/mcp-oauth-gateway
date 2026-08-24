package mcpproxy

import (
	"context"
	"time"

	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"go.uber.org/zap"
)

// limiters holds the per-IP token buckets and the login lockout. In-memory by
// design (GR-3); they are swept alongside the expired records.
type limiters struct {
	register  *ratelimit.Limiter
	token     *ratelimit.Limiter
	login     *ratelimit.Limiter
	authorize *ratelimit.Limiter
	lockout   *ratelimit.Lockout
}

// newLimiters builds the abuse-protection buckets and the login lockout
// (SR-5/SR-6). The rate expressions are already validated, so parseLimit
// cannot fail here.
func newLimiters(cfg Config) limiters {
	return limiters{
		register:  ratelimit.NewLimiter(parseLimit(cfg.RateLimitRegister)),
		token:     ratelimit.NewLimiter(parseLimit(cfg.RateLimitToken)),
		login:     ratelimit.NewLimiter(parseLimit(cfg.RateLimitLogin)),
		authorize: ratelimit.NewLimiter(parseLimit(cfg.RateLimitAuthorize)),
		lockout:   ratelimit.NewLockout(cfg.LoginLockoutThreshold, cfg.LoginLockoutDuration),
	}
}

// startSweeper runs the expiry sweep until ctx is done: session records past
// their TTL (SPEC §2.1), expired client registrations, key maintenance —
// interval rotation and retiring-key cleanup (SPEC §2.3) — and the in-memory
// limiter state. Lookups already treat expired records as invalid; the record
// sweep only reclaims storage.
func (d *dependencies) startSweeper(ctx context.Context, rc resolvedConfig) {
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.sweep(ctx, rc, time.Now().UTC())
			}
		}
	}()
}

// sweep is one pass of the expiry sweeper. Every failure is logged and the
// pass continues: a sweep is maintenance, so one failing store call must not
// stop the others or kill the goroutine.
func (d *dependencies) sweep(ctx context.Context, rc resolvedConfig, now time.Time) {
	margin := rc.ClockSkew
	if err := d.repo.DeleteExpiredSessions(ctx,
		now.Add(-rc.AccessTokenTTL-margin),
		now.Add(-rc.refreshSweepTTL()-margin),
		now.Add(-rc.AuthCodeTTL-margin),
	); err != nil {
		d.logger.Warn("failed to sweep expired session records", zap.Error(err))
	}
	if err := d.repo.DeleteExpiredClients(ctx, now); err != nil {
		d.logger.Warn("failed to sweep expired client registrations", zap.Error(err))
	}
	if err := d.keys.Maintain(now); err != nil {
		d.logger.Warn("failed to maintain signing keys", zap.Error(err))
	}
	d.limiters.register.Sweep(now)
	d.limiters.token.Sweep(now)
	d.limiters.login.Sweep(now)
	d.limiters.authorize.Sweep(now)
	d.limiters.lockout.Sweep(now)
}
