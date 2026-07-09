package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
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
	UserStorage
	MaintenanceStorage
	Close() error
}

// UserStorage persists the gateway's single operator account and their
// passkey credentials (FR-4, SPEC §1.12/§2.1).
type UserStorage interface {
	// GetUser returns the single user record, or fosite.ErrNotFound before
	// the first password login has bootstrapped it.
	GetUser(ctx context.Context) (*models.User, error)
	CreateUser(ctx context.Context, user *models.User) error
	UpdateUser(ctx context.Context, user *models.User) error
	// AddWebAuthnCredential stores a newly registered passkey.
	AddWebAuthnCredential(ctx context.Context, credential *models.WebAuthnCredential) error
	// ListWebAuthnCredentials returns the user's passkeys, oldest first.
	ListWebAuthnCredentials(ctx context.Context, userID string) ([]models.WebAuthnCredential, error)
	// UpdateWebAuthnCredential persists ceremony state changes (sign count,
	// last-used timestamp).
	UpdateWebAuthnCredential(ctx context.Context, credential *models.WebAuthnCredential) error
	DeleteWebAuthnCredential(ctx context.Context, id string) error
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
	// DeleteExpiredClients removes DCR registrations whose expiry passed.
	DeleteExpiredClients(ctx context.Context, now time.Time) error
}

// ErrClientCapReached is returned by RegisterClient when the registration
// would exceed maxClients (SR-5). The count and the insert happen in one write
// transaction, so this is the atomic cap decision — no TOCTOU window.
var ErrClientCapReached = errors.New("dynamic client registration cap reached")

// DynamicClientStorage manages DCR client registrations (SPEC §1.4).
// Expired registrations are treated as absent by GetClient (fail-closed).
type DynamicClientStorage interface {
	// RegisterClient stores a registration; a zero expiresAt never expires.
	// When maxClients > 0 the count of non-expired registrations and the
	// insert run in a single write transaction; if the store already holds
	// maxClients non-expired clients it returns ErrClientCapReached and stores
	// nothing (SR-5, no TOCTOU). maxClients <= 0 means unlimited.
	RegisterClient(ctx context.Context, client fosite.Client, expiresAt time.Time, maxClients int) error
	// TouchClient extends a registration's expiry (refresh-on-use, SR-5).
	TouchClient(ctx context.Context, id string, expiresAt time.Time) error
	// CountClients returns the number of stored, non-expired registrations.
	CountClients(ctx context.Context) (int, error)
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
