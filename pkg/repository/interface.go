package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

// SchemaVersion is the current data-store schema version (SPEC §2.5).
const SchemaVersion = 1

type Repository interface {
	fosite.Storage
	oauth2.CoreStorage
	oauth2.TokenRevocationStorage
	pkce.PKCERequestStorage
	DynamicClientStorage
	AuthorizeRequestStorage
	MaintenanceStorage
	Close() error
}

// MaintenanceStorage covers garbage collection and schema versioning
// (SPEC §2.1/§2.5).
type MaintenanceStorage interface {
	// DeleteExpiredSessions removes token/code/PKCE/authorize-request
	// records created before the respective cutoff.
	DeleteExpiredSessions(ctx context.Context, accessBefore, refreshBefore, codeBefore time.Time) error
	// EnsureSchemaVersion records the schema version on first run and
	// fails when the store stems from a newer gateway version.
	EnsureSchemaVersion(ctx context.Context, version int) error
}

type DynamicClientStorage interface {
	RegisterClient(ctx context.Context, client fosite.Client) error
}

type AuthorizeRequestStorage interface {
	CreateAuthorizeRequest(ctx context.Context, request fosite.AuthorizeRequester) error
	GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error)
	DeleteAuthorizeRequest(ctx context.Context, requestID string) error
}

func restoreSession(req *fosite.Request, sessionData json.RawMessage, sess fosite.Session) error {
	if len(sessionData) > 0 && sess != nil {
		if err := json.Unmarshal(sessionData, sess); err != nil {
			return fmt.Errorf("failed to unmarshal session data: %w", err)
		}
		req.SetSession(sess)
	}
	return nil
}
