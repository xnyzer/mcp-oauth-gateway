package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"gorm.io/gorm"
)

// -- Listing ------------------------------------------------------------

// ListClientGrants aggregates the store into one row per client (SPEC §1.12).
// The token tables carry no client column — the client lives inside the
// serialized request — so the rows are decoded in Go rather than grouped in
// SQL. That keeps the schema at version 1: adding an indexed client_id column
// would need a migration and would break a downgrade, and the tables are
// bounded by the DCR cap and the token TTLs anyway.
func (r *sqlRepository) ListClientGrants(ctx context.Context) ([]ClientGrants, error) {
	inv := newInventory()
	db := r.db.WithContext(ctx)

	accessTokens, err := allRequests(db, "access token", func(row accessTokenSession) []byte { return row.Request })
	if err != nil {
		return nil, err
	}
	for i := range accessTokens {
		inv.addToken(accessTokenKind, &accessTokens[i])
	}

	refreshTokens, err := allRequests(db, "refresh token", func(row refreshTokenSession) []byte { return row.Request })
	if err != nil {
		return nil, err
	}
	for i := range refreshTokens {
		inv.addToken(refreshTokenKind, &refreshTokens[i])
	}

	var records []clientRecord
	if err := db.Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to load client records: %w", err)
	}
	for _, record := range records {
		var client models.Client
		// Strict, unlike allClientModels: a registration that cannot be
		// decoded would silently drop a client from the operator's list, and
		// a list that hides a client is worse than no list at all.
		if err := json.Unmarshal(record.Client, &client); err != nil {
			return nil, fmt.Errorf("failed to decode a client record: %w", err)
		}
		inv.addRegistration(&client)
	}

	return inv.rows(time.Now().UTC()), nil
}

// -- Revocation ---------------------------------------------------------

// revokeScope says which registrations a sweep deletes alongside the session
// records.
type revokeScope struct {
	// clientID names a single registration to delete; empty deletes none.
	clientID string
	// all deletes every registration — the panic case.
	all bool
}

// RevokeClient deletes everything the client holds, registration included.
func (r *sqlRepository) RevokeClient(ctx context.Context, clientID string) (int, error) {
	return r.revoke(ctx, func(req *models.Request) bool {
		return req.Client != nil && req.Client.ID == clientID
	}, revokeScope{clientID: clientID})
}

// RevokeGrant deletes one authorization, leaving the client itself in place.
func (r *sqlRepository) RevokeGrant(ctx context.Context, requestID string) (int, error) {
	return r.revoke(ctx, func(req *models.Request) bool { return req.ID == requestID }, revokeScope{})
}

// RevokeAll deletes every client's records and every registration.
func (r *sqlRepository) RevokeAll(ctx context.Context) (int, error) {
	return r.revoke(ctx, func(*models.Request) bool { return true }, revokeScope{all: true})
}

// sweep is one table's share of a revoke: the rows to delete, named by the
// column that addresses them.
type sweep struct {
	model  any
	column string
	keys   []string
}

// revoke deletes every session record the matcher accepts, plus the
// registrations the scope names, inside one transaction — so a failure
// part-way through rolls the whole sweep back and never leaves a client with a
// refresh token that mints a fresh access token.
func (r *sqlRepository) revoke(ctx context.Context, match func(*models.Request) bool, scope revokeScope) (int, error) {
	deleted := 0
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		sweeps, err := collectSweeps(tx, match)
		if err != nil {
			return err
		}
		for _, table := range sweeps {
			if len(table.keys) == 0 {
				continue
			}
			if err := tx.Delete(table.model, table.column+" IN ?", table.keys).Error; err != nil {
				return fmt.Errorf("failed to revoke session records: %w", err)
			}
			deleted += len(table.keys)
		}
		clients, err := deleteRegistrations(tx, scope)
		if err != nil {
			return err
		}
		deleted += clients
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// collectSweeps decodes every session table and returns the rows to delete.
//
// All four tables are swept the same way: load, decode, address by primary
// key. The two token tables could be narrowed by their indexed request_id, but
// only for RevokeGrant — RevokeClient has to decode the request blobs
// regardless, because no column holds the client. One path for all four is one
// chance to be wrong instead of two.
func collectSweeps(tx *gorm.DB, match func(*models.Request) bool) ([]sweep, error) {
	accessTokens, err := staleKeys(tx, "access token",
		func(row accessTokenSession) (string, []byte) { return row.Signature, row.Request }, match)
	if err != nil {
		return nil, err
	}
	refreshTokens, err := staleKeys(tx, "refresh token",
		func(row refreshTokenSession) (string, []byte) { return row.Signature, row.Request }, match)
	if err != nil {
		return nil, err
	}
	authorizeCodes, err := staleKeys(tx, "authorize code",
		func(row authorizeCodeSession) (string, []byte) { return row.Code, row.Request }, match)
	if err != nil {
		return nil, err
	}
	pkceRequests, err := staleKeys(tx, "PKCE",
		func(row pkceRequestSession) (string, []byte) { return row.Signature, row.Request }, match)
	if err != nil {
		return nil, err
	}
	authorizeRequests, err := staleAuthorizeRequests(tx, match)
	if err != nil {
		return nil, err
	}
	return []sweep{
		{&accessTokenSession{}, "signature", accessTokens},
		{&refreshTokenSession{}, "signature", refreshTokens},
		{&authorizeCodeSession{}, "code", authorizeCodes},
		{&pkceRequestSession{}, "signature", pkceRequests},
		{&authorizeRequestRecord{}, "request_id", authorizeRequests},
	}, nil
}

// deleteRegistrations removes the registrations the scope names and reports
// how many rows went, so the caller's count covers the whole sweep.
func deleteRegistrations(tx *gorm.DB, scope revokeScope) (int, error) {
	var result *gorm.DB
	switch {
	case scope.all:
		// gorm refuses a Delete without a WHERE clause; "1 = 1" is the
		// deliberate everything-goes case.
		result = tx.Delete(&clientRecord{}, "1 = 1")
	case scope.clientID != "":
		result = tx.Delete(&clientRecord{}, "id = ?", scope.clientID)
	default:
		return 0, nil
	}
	if result.Error != nil {
		return 0, fmt.Errorf("failed to delete client registration: %w", result.Error)
	}
	return int(result.RowsAffected), nil
}

// -- Scanning -----------------------------------------------------------

// staleKeys decodes every row's request blob and returns the primary keys of
// the rows the matcher accepts. An undecodable record is an error rather than
// a skip: a revoke that quietly steps over a record it cannot read would
// report a kill that did not happen.
func staleKeys[T any](tx *gorm.DB, kind string, fields func(T) (string, []byte), match func(*models.Request) bool) ([]string, error) {
	var rows []T
	if err := tx.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to load %s records: %w", kind, err)
	}
	var stale []string
	for _, row := range rows {
		key, blob := fields(row)
		var req models.Request
		if err := json.Unmarshal(blob, &req); err != nil {
			return nil, fmt.Errorf("failed to decode a %s record: %w", kind, err)
		}
		if match(&req) {
			stale = append(stale, key)
		}
	}
	return stale, nil
}

// staleAuthorizeRequests is staleKeys for the pending-authorize table, whose
// blob wraps the request in a models.AuthorizeRequest.
func staleAuthorizeRequests(tx *gorm.DB, match func(*models.Request) bool) ([]string, error) {
	var rows []authorizeRequestRecord
	if err := tx.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to load authorize request records: %w", err)
	}
	var stale []string
	for _, row := range rows {
		var ar models.AuthorizeRequest
		if err := json.Unmarshal(row.Request, &ar); err != nil {
			return nil, fmt.Errorf("failed to decode an authorize request record: %w", err)
		}
		if ar.Request != nil && match(ar.Request) {
			stale = append(stale, row.RequestID)
		}
	}
	return stale, nil
}

// allRequests loads and decodes every row of a table whose blob is a plain
// models.Request.
func allRequests[T any](db *gorm.DB, kind string, blob func(T) []byte) ([]models.Request, error) {
	var rows []T
	if err := db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to load %s records: %w", kind, err)
	}
	requests := make([]models.Request, 0, len(rows))
	for _, row := range rows {
		var req models.Request
		if err := json.Unmarshal(blob(row), &req); err != nil {
			return nil, fmt.Errorf("failed to decode a %s record: %w", kind, err)
		}
		requests = append(requests, req)
	}
	return requests, nil
}
