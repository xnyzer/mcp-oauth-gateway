// Package authevent emits the structured security events required by SR-8:
// one fixed message with a generic `event` field (GR-4), never carrying
// secrets (no passwords, tokens, codes, or keys).
package authevent

import "go.uber.org/zap"

// Event names (SPEC §3.3). Fixed strings — alerting matches on them.
const (
	LoginOK     = "login_ok"
	LoginFail   = "login_fail"
	TokenIssued = "token_issued"
	Register    = "register"
	RateLimited = "rate_limited"
	Revoked     = "revoked"
)

// message is the fixed log line; the event and context live in fields so
// log pipelines can filter without parsing prose.
const message = "auth event"

// Log emits one auth event. Callers pass only non-secret context fields
// (client IDs, IPs, endpoints, methods — never credentials).
func Log(logger *zap.Logger, event string, fields ...zap.Field) {
	logger.Info(message, append([]zap.Field{zap.String("event", event)}, fields...)...)
}
