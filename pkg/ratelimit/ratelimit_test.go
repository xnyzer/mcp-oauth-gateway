package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestParseLimit(t *testing.T) {
	cases := []struct {
		input   string
		want    Limit
		wantErr bool
	}{
		{input: "10/m", want: Limit{Events: 10, Window: time.Minute}},
		{input: "60/m", want: Limit{Events: 60, Window: time.Minute}},
		{input: "1/s", want: Limit{Events: 1, Window: time.Second}},
		{input: "100/h", want: Limit{Events: 100, Window: time.Hour}},
		{input: "0", want: Limit{}},
		{input: " 10/m ", want: Limit{Events: 10, Window: time.Minute}},
		{input: "", wantErr: true},
		{input: "10", wantErr: true},
		{input: "10/d", wantErr: true},
		{input: "-5/m", wantErr: true},
		{input: "0/m", wantErr: true},
		{input: "x/m", wantErr: true},
	}
	for _, tt := range cases {
		t.Run(tt.input, func(t *testing.T) {
			limit, err := ParseLimit(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, limit)
		})
	}
}

func TestLimiter_AllowsBurstThenDenies(t *testing.T) {
	limiter := NewLimiter(Limit{Events: 3, Window: time.Hour})

	for i := 0; i < 3; i++ {
		require.True(t, limiter.Allow("ip-1"), "request %d within the burst must pass", i+1)
	}
	require.False(t, limiter.Allow("ip-1"), "request beyond the burst must be denied")

	// Other keys have their own bucket.
	require.True(t, limiter.Allow("ip-2"))
}

func TestLimiter_NilAllowsEverything(t *testing.T) {
	var limiter *Limiter
	require.Nil(t, NewLimiter(Limit{}))
	for i := 0; i < 100; i++ {
		require.True(t, limiter.Allow("ip"))
	}
	limiter.Sweep(time.Now()) // must not panic
}

func TestLimiter_SweepDropsIdleBuckets(t *testing.T) {
	limiter := NewLimiter(Limit{Events: 1, Window: time.Minute})
	require.True(t, limiter.Allow("ip-1"))
	require.False(t, limiter.Allow("ip-1"))

	// Not yet idle for a full window: the empty bucket stays.
	limiter.Sweep(time.Now())
	require.False(t, limiter.Allow("ip-1"))

	// Idle for a full window: the bucket is dropped (fully refilled).
	limiter.Sweep(time.Now().Add(2 * time.Minute))
	require.True(t, limiter.Allow("ip-1"))
}

func TestLockout_LocksAfterThresholdAndExpires(t *testing.T) {
	lockout := NewLockout(3, 15*time.Minute)
	now := time.Now().UTC()

	require.False(t, lockout.Locked("acct", now))
	lockout.Fail("acct", now)
	lockout.Fail("acct", now)
	require.False(t, lockout.Locked("acct", now), "below the threshold nothing locks")
	lockout.Fail("acct", now)
	require.True(t, lockout.Locked("acct", now), "the threshold-th failure locks")

	// The lock expires after the duration.
	require.False(t, lockout.Locked("acct", now.Add(16*time.Minute)))

	// Further failures while locked extend the window.
	lockout.Fail("acct", now.Add(time.Minute))
	require.True(t, lockout.Locked("acct", now.Add(15*time.Minute)))
}

func TestLockout_ResetClearsTheStreak(t *testing.T) {
	lockout := NewLockout(2, 15*time.Minute)
	now := time.Now().UTC()

	lockout.Fail("acct", now)
	lockout.Reset("acct")
	lockout.Fail("acct", now)
	require.False(t, lockout.Locked("acct", now), "reset must clear the consecutive-failure streak")
}

func TestLockout_NilNeverLocks(t *testing.T) {
	var lockout *Lockout
	require.Nil(t, NewLockout(0, time.Minute))
	lockout.Fail("acct", time.Now())
	require.False(t, lockout.Locked("acct", time.Now()))
	lockout.Reset("acct")
	lockout.Sweep(time.Now())
}

func TestLockout_SweepDropsExpiredEntries(t *testing.T) {
	lockout := NewLockout(2, time.Minute)
	now := time.Now().UTC()
	lockout.Fail("acct", now)
	lockout.Fail("acct", now)
	require.True(t, lockout.Locked("acct", now))

	// While locked the entry stays.
	lockout.Sweep(now)
	require.True(t, lockout.Locked("acct", now))

	// After expiry + idle duration the entry is dropped entirely.
	later := now.Add(3 * time.Minute)
	lockout.Sweep(later)
	lockout.Fail("acct", later)
	require.False(t, lockout.Locked("acct", later), "the old streak must not carry over after the sweep")
}

func TestMiddleware_Returns429AndEmitsEvent(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	limiter := NewLimiter(Limit{Events: 1, Window: time.Hour})
	router.POST("/limited", Middleware(limiter, "token", logger), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	do := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/limited", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		router.ServeHTTP(w, req)
		return w
	}

	require.Equal(t, http.StatusOK, do().Code)
	limited := do()
	require.Equal(t, http.StatusTooManyRequests, limited.Code)
	require.Contains(t, limited.Body.String(), "temporarily_unavailable")

	// Exactly one rate_limited event, carrying endpoint + client IP.
	entries := logs.FilterField(zap.String("event", "rate_limited")).All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	require.Equal(t, "token", fields["endpoint"])
	require.Equal(t, "203.0.113.7", fields["client_ip"])
}

func TestMiddleware_HonoursTrustedProxiesForClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// The proxy at 203.0.113.7 is trusted: X-Forwarded-For decides the key.
	require.NoError(t, router.SetTrustedProxies([]string{"203.0.113.7"}))
	limiter := NewLimiter(Limit{Events: 1, Window: time.Hour})
	router.POST("/limited", Middleware(limiter, "login", zap.NewNop()), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	do := func(forwardedFor string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/limited", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		req.Header.Set("X-Forwarded-For", forwardedFor)
		router.ServeHTTP(w, req)
		return w.Code
	}

	// Two different forwarded clients get independent buckets.
	require.Equal(t, http.StatusOK, do("198.51.100.1"))
	require.Equal(t, http.StatusOK, do("198.51.100.2"))
	// The same forwarded client hits its limit.
	require.Equal(t, http.StatusTooManyRequests, do("198.51.100.1"))
}

func TestMiddleware_NilLimiterYieldsNilHandler(t *testing.T) {
	require.Nil(t, Middleware(nil, "token", zap.NewNop()))
}
