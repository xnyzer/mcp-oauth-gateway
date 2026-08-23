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

// Repository is the gateway's whole persistence surface: everything fosite
// needs to run the flows, plus the gateway's own entities (SPEC §2.1). Both
// backends — bbolt and SQLite — implement it in full; nothing bypasses it.
type Repository interface {
	fosite.Storage
	oauth2.CoreStorage
	oauth2.TokenRevocationStorage
	pkce.PKCERequestStorage
	DynamicClientStorage
	AuthorizeRequestStorage
	UserStorage
	MaintenanceStorage
	InventoryStorage
	Close() error
}

// InventoryStorage lets the operator see which clients hold access and take
// it away again (SPEC §1.12). It is the only storage interface written for a
// human rather than for fosite: fosite revokes a grant a client asks about
// (RFC 7009, client-authenticated), never someone else's.
type InventoryStorage interface {
	// ListClientGrants returns one row per client that holds access, newest
	// activity first. The listing is built from token records rather than
	// from stored registrations, because a CIMD client has no registration
	// at all — it is re-resolved from its URL on every use (SPEC §1.3), so
	// enumerating registrations would miss exactly the clients that matter.
	// Non-expired registrations join as a second source so a registration
	// without tokens still shows.
	ListClientGrants(ctx context.Context) ([]ClientGrants, error)
	// RevokeClient deletes every record of the client — access and refresh
	// tokens, authorization codes, PKCE sessions, pending authorize requests
	// and the DCR registration where one exists — and returns the number of
	// deleted records. Access and refresh tokens must go together: a refresh
	// token left behind mints a new access token immediately.
	RevokeClient(ctx context.Context, clientID string) (int, error)
	// RevokeGrant deletes one authorization's records, leaving the client's
	// other authorizations and its registration intact.
	RevokeGrant(ctx context.Context, requestID string) (int, error)
	// RevokeAll deletes every client's records in one transaction — the
	// panic case, where looping over RevokeClient could fail halfway and
	// leave some clients with access while reporting a kill.
	RevokeAll(ctx context.Context) (int, error)
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

// ClientRegistration is what RegisterClient stores. A struct rather than four
// parameters (§3), which also names the optional fields at the call site.
type ClientRegistration struct {
	// Client is the fosite client to persist.
	Client fosite.Client
	// Name is the client's self-declared `client_name` (RFC 7591 §2). Kept for
	// the consent page (SPEC §1.5); display text only, never a decision input.
	Name string
	// ExpiresAt is the registration TTL (SR-5); a zero value never expires.
	ExpiresAt time.Time
	// MaxClients caps stored non-expired registrations; <= 0 means unlimited.
	MaxClients int
}

// DynamicClientStorage manages DCR client registrations (SPEC §1.4).
// Expired registrations are treated as absent by GetClient (fail-closed).
type DynamicClientStorage interface {
	// RegisterClient stores a registration. When MaxClients > 0 the count of
	// non-expired registrations and the insert run in a single write
	// transaction; if the store already holds that many non-expired clients it
	// returns ErrClientCapReached and stores nothing (SR-5, no TOCTOU).
	RegisterClient(ctx context.Context, registration ClientRegistration) error
	// GetClientName returns the name a DCR client declared at registration, or
	// an empty string when the client is unknown, expired, or never named
	// itself. It exists because fosite's client type has nowhere to carry a
	// name, so GetClient cannot return one.
	GetClientName(ctx context.Context, id string) (string, error)
	// TouchClient extends a registration's expiry (refresh-on-use, SR-5).
	TouchClient(ctx context.Context, id string, expiresAt time.Time) error
	// CountClients returns the number of stored, non-expired registrations.
	CountClients(ctx context.Context) (int, error)
}

// AuthorizeRequestStorage parks an authorize request between the redirect to
// the login/consent page and the operator's approval, keyed by the ar_id the
// session carries (SPEC §1.5).
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
