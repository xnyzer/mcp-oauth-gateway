package ratelimit

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/authevent"
	"go.uber.org/zap"
)

// Middleware rejects over-limit requests with 429 and a `rate_limited`
// event (SPEC §3.2, SR-5/SR-6). Requests are keyed by client IP; gin's
// ClientIP honours the engine's trusted proxies (GR-1). A disabled limiter
// yields nil so routes register without an extra hop.
func Middleware(limiter *Limiter, endpoint string, logger *zap.Logger) gin.HandlerFunc {
	if limiter == nil {
		return nil
	}
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		if limiter.Allow(clientIP) {
			c.Next()
			return
		}
		authevent.Log(logger, authevent.RateLimited,
			zap.String("endpoint", endpoint),
			zap.String("client_ip", clientIP))
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error":             "temporarily_unavailable",
			"error_description": "too many requests",
		})
	}
}
