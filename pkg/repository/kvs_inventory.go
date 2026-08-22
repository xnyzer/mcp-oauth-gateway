package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"go.etcd.io/bbolt"
)

// -- Key prefixes -------------------------------------------------------

// The bbolt key prefixes the inventory reads and a revoke sweeps. They repeat
// the literals kvs.go builds its keys from; F-022 will put both on one
// definition when it splits that file.
const (
	accessTokenPrefix      = "access_token-"
	refreshTokenPrefix     = "refresh_token-"
	authorizeCodePrefix    = "authorize_code-"
	pkceRequestPrefix      = "pkce_request-"
	authorizeRequestPrefix = "authorize_request-"
	clientPrefix           = "client-"
)

// sessionPrefixes are the prefixes whose stored value is a models.Request.
// All four have to go on a revoke: an authorization code or a PKCE session
// left behind completes into a fresh token the moment the client redeems it.
var sessionPrefixes = []string{
	accessTokenPrefix,
	refreshTokenPrefix,
	authorizeCodePrefix,
	pkceRequestPrefix,
}

// -- Listing ------------------------------------------------------------

// ListClientGrants aggregates the store into one row per client (SPEC §1.12).
func (r *kvsRepository) ListClientGrants(ctx context.Context) ([]ClientGrants, error) {
	inv := newInventory()
	tokenSources := []struct {
		prefix string
		kind   tokenKind
	}{
		{accessTokenPrefix, accessTokenKind},
		{refreshTokenPrefix, refreshTokenKind},
	}
	err := r.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		for _, source := range tokenSources {
			if err := scanRequests(bucket, source.prefix, func(_ []byte, req *models.Request) error {
				inv.addToken(source.kind, req)
				return nil
			}); err != nil {
				return err
			}
		}
		return scanClients(bucket, func(_ []byte, client *models.Client) error {
			inv.addRegistration(client)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return inv.rows(time.Now().UTC()), nil
}

// -- Revocation ---------------------------------------------------------

// RevokeClient deletes everything the client holds, registration included.
func (r *kvsRepository) RevokeClient(ctx context.Context, clientID string) (int, error) {
	return r.revoke(
		func(req *models.Request) bool {
			return req.Client != nil && req.Client.ID == clientID
		},
		func(bucket *bbolt.Bucket) ([][]byte, error) {
			key := []byte(clientPrefix + clientID)
			if bucket.Get(key) == nil {
				return nil, nil
			}
			return [][]byte{key}, nil
		},
	)
}

// RevokeGrant deletes one authorization, leaving the client itself in place.
func (r *kvsRepository) RevokeGrant(ctx context.Context, requestID string) (int, error) {
	return r.revoke(func(req *models.Request) bool { return req.ID == requestID }, nil)
}

// RevokeAll deletes every client's records and every registration.
func (r *kvsRepository) RevokeAll(ctx context.Context) (int, error) {
	return r.revoke(func(*models.Request) bool { return true }, allClientKeys)
}

// revoke deletes every session record the matcher accepts, plus the client
// records selectClients picks, in a single write transaction. bbolt commits a
// transaction whole, so a failure part-way through leaves the store exactly as
// it was — the operator never sees a half-revoked client.
func (r *kvsRepository) revoke(
	match func(*models.Request) bool,
	selectClients func(*bbolt.Bucket) ([][]byte, error),
) (int, error) {
	deleted := 0
	err := r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		stale, err := staleRecords(bucket, match, selectClients)
		if err != nil {
			return err
		}
		for _, key := range stale {
			if err := bucket.Delete(key); err != nil {
				return err
			}
		}
		deleted = len(stale)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// staleRecords collects the keys a revoke has to delete. Collecting first and
// deleting second keeps the cursor walk apart from the mutation, which is the
// same shape kvs.go's sweeper uses.
func staleRecords(
	bucket *bbolt.Bucket,
	match func(*models.Request) bool,
	selectClients func(*bbolt.Bucket) ([][]byte, error),
) ([][]byte, error) {
	var stale [][]byte
	collect := func(key []byte) {
		stale = append(stale, append([]byte(nil), key...))
	}

	for _, prefix := range sessionPrefixes {
		if err := scanRequests(bucket, prefix, func(key []byte, req *models.Request) error {
			if match(req) {
				collect(key)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	// Authorize requests wrap the request in a different value type.
	if err := scanAuthorizeRequests(bucket, func(key []byte, ar *models.AuthorizeRequest) error {
		if ar.Request != nil && match(ar.Request) {
			collect(key)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if selectClients == nil {
		return stale, nil
	}
	keys, err := selectClients(bucket)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		collect(key)
	}
	return stale, nil
}

// allClientKeys selects every stored registration, expired or not — the panic
// button is not the moment to be selective.
func allClientKeys(bucket *bbolt.Bucket) ([][]byte, error) {
	var keys [][]byte
	err := scanClients(bucket, func(key []byte, _ *models.Client) error {
		keys = append(keys, append([]byte(nil), key...))
		return nil
	})
	return keys, err
}

// -- Scanning -----------------------------------------------------------

// scanRequests walks every record under prefix and hands the decoded request
// to fn. Unlike the sweeper, an undecodable record is an **error** here rather
// than something to skip: this path decides both what the operator sees and
// what a revoke deletes, so skipping would either hide a client that holds
// access or report a kill that did not happen. The record's key is a token
// signature and never appears in the error.
func scanRequests(bucket *bbolt.Bucket, prefix string, fn func(key []byte, req *models.Request) error) error {
	return scanPrefix(bucket, prefix, func(key, value []byte) error {
		var req models.Request
		if err := json.Unmarshal(value, &req); err != nil {
			return fmt.Errorf("failed to decode a %s record: %w", prefix, err)
		}
		return fn(key, &req)
	})
}

func scanAuthorizeRequests(bucket *bbolt.Bucket, fn func(key []byte, ar *models.AuthorizeRequest) error) error {
	return scanPrefix(bucket, authorizeRequestPrefix, func(key, value []byte) error {
		var ar models.AuthorizeRequest
		if err := json.Unmarshal(value, &ar); err != nil {
			return fmt.Errorf("failed to decode an %s record: %w", authorizeRequestPrefix, err)
		}
		return fn(key, &ar)
	})
}

func scanClients(bucket *bbolt.Bucket, fn func(key []byte, client *models.Client) error) error {
	return scanPrefix(bucket, clientPrefix, func(key, value []byte) error {
		var client models.Client
		if err := json.Unmarshal(value, &client); err != nil {
			return fmt.Errorf("failed to decode a %s record: %w", clientPrefix, err)
		}
		return fn(key, &client)
	})
}

func scanPrefix(bucket *bbolt.Bucket, prefix string, fn func(key, value []byte) error) error {
	cursor := bucket.Cursor()
	raw := []byte(prefix)
	for key, value := cursor.Seek(raw); key != nil && bytes.HasPrefix(key, raw); key, value = cursor.Next() {
		if err := fn(key, value); err != nil {
			return err
		}
	}
	return nil
}
