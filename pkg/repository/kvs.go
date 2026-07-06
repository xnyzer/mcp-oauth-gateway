package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	time "time"

	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"go.etcd.io/bbolt"
)

type kvsRepository struct {
	db         *bbolt.DB
	bucketName string
}

var RefreshTokenGracePeriod = 1 * time.Hour

func NewKVSRepository(path string, bucketName string) (Repository, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}
	return &kvsRepository{
		db:         db,
		bucketName: bucketName,
	}, nil
}

func (r *kvsRepository) create(ctx context.Context, key string, value any) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		return bucket.Put([]byte(key), data)
	})
}

func (r *kvsRepository) get(ctx context.Context, key string, value any) error {
	return r.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		data := bucket.Get([]byte(key))
		if data == nil {
			return fosite.ErrNotFound
		}
		return json.Unmarshal(data, value)
	})
}

func (r *kvsRepository) delete(ctx context.Context, key string) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		return bucket.Delete([]byte(key))
	})
}

func (r *kvsRepository) update(ctx context.Context, key string, value any) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		if bucket.Get([]byte(key)) == nil {
			return fosite.ErrNotFound
		}
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		return bucket.Put([]byte(key), data)
	})
}

func (r *kvsRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, fositeReq fosite.Requester) error {
	return r.create(ctx, "authorize_code-"+code, models.FromFositeReq(fositeReq))
}

func (r *kvsRepository) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "authorize_code-"+code, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func (r *kvsRepository) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return r.delete(ctx, "authorize_code-"+code)
}

func (r *kvsRepository) CreateAccessTokenSession(ctx context.Context, signature string, fositeReq fosite.Requester) error {
	return r.create(ctx, "access_token-"+signature, models.FromFositeReq(fositeReq))
}

func (r *kvsRepository) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "access_token-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func (r *kvsRepository) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "access_token-"+signature)
}

func (r *kvsRepository) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, req fosite.Requester) (err error) {
	return r.create(ctx, "refresh_token-"+signature, models.FromFositeReq(req))
}

func (r *kvsRepository) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "refresh_token-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func (r *kvsRepository) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "refresh_token-"+signature)
}

func (r *kvsRepository) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	var req models.Request
	if err := r.get(ctx, "refresh_token-"+signature, &req); err != nil {
		return err
	}
	req.RotatedAt = time.Now()
	return r.update(ctx, "refresh_token-"+signature, req)
}

// deleteMatching removes every record under prefix whose decoded request
// matches. Runs in a single bbolt write transaction.
func (r *kvsRepository) deleteMatching(prefix string, match func(models.Request) bool) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		cursor := bucket.Cursor()
		var stale [][]byte
		for k, v := cursor.Seek([]byte(prefix)); k != nil && bytes.HasPrefix(k, []byte(prefix)); k, v = cursor.Next() {
			var req models.Request
			if err := json.Unmarshal(v, &req); err != nil {
				continue // undecodable records are reclaimed by the sweeper, not revocation
			}
			if match(req) {
				stale = append(stale, append([]byte(nil), k...))
			}
		}
		for _, k := range stale {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeRefreshToken revokes a refresh token as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
// fosite passes the grant's request ID; records are keyed by signature, so
// the matching records are found by their stored request ID.
func (r *kvsRepository) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return r.deleteMatching("refresh_token-", func(req models.Request) bool { return req.ID == requestID })
}

// RevokeAccessToken revokes all access tokens of the grant as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
func (r *kvsRepository) RevokeAccessToken(ctx context.Context, requestID string) error {
	return r.deleteMatching("access_token-", func(req models.Request) bool { return req.ID == requestID })
}

// DeleteExpiredSessions garbage-collects session records past their cutoff
// (SPEC §2.1). Expiry on use is enforced by fosite; this reclaims storage.
func (r *kvsRepository) DeleteExpiredSessions(ctx context.Context, accessBefore, refreshBefore, codeBefore time.Time) error {
	cutoffs := []struct {
		prefix string
		before time.Time
	}{
		{"access_token-", accessBefore},
		{"refresh_token-", refreshBefore},
		{"authorize_code-", codeBefore},
		{"pkce_request-", codeBefore},
	}
	for _, c := range cutoffs {
		before := c.before
		if err := r.deleteMatching(c.prefix, func(req models.Request) bool {
			return req.RequestedAt.Before(before)
		}); err != nil {
			return fmt.Errorf("failed to sweep %s records: %w", c.prefix, err)
		}
	}
	// Authorize requests use a different value type (models.AuthorizeRequest).
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		cursor := bucket.Cursor()
		prefix := []byte("authorize_request-")
		var stale [][]byte
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var ar models.AuthorizeRequest
			if err := json.Unmarshal(v, &ar); err != nil || ar.Request == nil || ar.Request.RequestedAt.Before(codeBefore) {
				stale = append(stale, append([]byte(nil), k...))
			}
		}
		for _, k := range stale {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

const kvsSchemaVersionKey = "meta-schema_version"

// EnsureSchemaVersion writes the schema version on first run and fails fast
// when the store was written by a newer gateway (SPEC §2.5).
func (r *kvsRepository) EnsureSchemaVersion(ctx context.Context, version int) error {
	var stored int
	err := r.get(ctx, kvsSchemaVersionKey, &stored)
	if errors.Is(err, fosite.ErrNotFound) {
		return r.create(ctx, kvsSchemaVersionKey, version)
	}
	if err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}
	if stored > version {
		return fmt.Errorf("data store schema version %d is newer than supported version %d — downgrades are unsupported", stored, version)
	}
	if stored < version {
		return r.update(ctx, kvsSchemaVersionKey, version)
	}
	return nil
}

func (r *kvsRepository) RegisterClient(ctx context.Context, fositeClient fosite.Client, expiresAt time.Time) error {
	client := models.FromFositeClient(fositeClient)
	client.CreatedAt = time.Now().UTC()
	client.ExpiresAt = expiresAt
	return r.create(ctx, "client-"+fositeClient.GetID(), client)
}

// GetClient loads the client by its ID. Expired registrations are treated
// as absent (SPEC §1.4, fail-closed — no reliance on the sweeper).
func (r *kvsRepository) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var client models.Client
	if err := r.get(ctx, "client-"+id, &client); err != nil {
		return nil, err
	}
	if !client.ExpiresAt.IsZero() && client.ExpiresAt.Before(time.Now().UTC()) {
		return nil, fosite.ErrNotFound
	}
	return client.ToFositeClient(), nil
}

// TouchClient extends a registration's expiry (refresh-on-use, SR-5).
func (r *kvsRepository) TouchClient(ctx context.Context, id string, expiresAt time.Time) error {
	var client models.Client
	if err := r.get(ctx, "client-"+id, &client); err != nil {
		return err
	}
	if client.ExpiresAt.IsZero() {
		return nil // registration without expiry stays permanent
	}
	client.ExpiresAt = expiresAt
	return r.update(ctx, "client-"+id, client)
}

// CountClients counts stored, non-expired DCR registrations (cap, SR-5).
func (r *kvsRepository) CountClients(ctx context.Context) (int, error) {
	now := time.Now().UTC()
	count := 0
	err := r.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		cursor := bucket.Cursor()
		prefix := []byte("client-")
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var client models.Client
			if err := json.Unmarshal(v, &client); err != nil {
				continue
			}
			if client.ExpiresAt.IsZero() || client.ExpiresAt.After(now) {
				count++
			}
		}
		return nil
	})
	return count, err
}

// DeleteExpiredClients garbage-collects expired DCR registrations.
func (r *kvsRepository) DeleteExpiredClients(ctx context.Context, now time.Time) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		cursor := bucket.Cursor()
		prefix := []byte("client-")
		var stale [][]byte
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var client models.Client
			if err := json.Unmarshal(v, &client); err != nil {
				continue
			}
			if !client.ExpiresAt.IsZero() && client.ExpiresAt.Before(now) {
				stale = append(stale, append([]byte(nil), k...))
			}
		}
		for _, k := range stale {
			if err := bucket.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (r *kvsRepository) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return errors.New("not implemented")
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (r *kvsRepository) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("not implemented")
}

func (r *kvsRepository) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	return r.create(ctx, "pkce_request-"+signature, models.FromFositeReq(req))
}

func (r *kvsRepository) GetPKCERequestSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "pkce_request-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func (r *kvsRepository) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "pkce_request-"+signature)
}

func (r *kvsRepository) CreateAuthorizeRequest(ctx context.Context, fositeAR fosite.AuthorizeRequester) error {
	return r.create(ctx, "authorize_request-"+fositeAR.GetID(), models.FromFositeAuthorizeRequest(fositeAR))
}

func (r *kvsRepository) GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error) {
	var ar models.AuthorizeRequest
	if err := r.get(ctx, "authorize_request-"+requestID, &ar); err != nil {
		return nil, err
	}
	return ar.ToFositeAuthorizeRequest(), nil
}

func (r *kvsRepository) DeleteAuthorizeRequest(ctx context.Context, requestID string) error {
	return r.delete(ctx, "authorize_request-"+requestID)
}

// kvsUserKey is the fixed key of the single operator account (FR-4).
const kvsUserKey = "user-record"

func (r *kvsRepository) GetUser(ctx context.Context) (*models.User, error) {
	var user models.User
	if err := r.get(ctx, kvsUserKey, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *kvsRepository) CreateUser(ctx context.Context, user *models.User) error {
	return r.create(ctx, kvsUserKey, user)
}

func (r *kvsRepository) UpdateUser(ctx context.Context, user *models.User) error {
	return r.update(ctx, kvsUserKey, user)
}

func (r *kvsRepository) AddWebAuthnCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	return r.create(ctx, "webauthn_credential-"+credential.ID, credential)
}

// ListWebAuthnCredentials returns the user's passkeys, oldest first.
func (r *kvsRepository) ListWebAuthnCredentials(ctx context.Context, userID string) ([]models.WebAuthnCredential, error) {
	var credentials []models.WebAuthnCredential
	err := r.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		cursor := bucket.Cursor()
		prefix := []byte("webauthn_credential-")
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var credential models.WebAuthnCredential
			if err := json.Unmarshal(v, &credential); err != nil {
				return fmt.Errorf("failed to decode passkey credential: %w", err)
			}
			if credential.UserID == userID {
				credentials = append(credentials, credential)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(credentials, func(i, j int) bool {
		return credentials[i].CreatedAt.Before(credentials[j].CreatedAt)
	})
	return credentials, nil
}

func (r *kvsRepository) UpdateWebAuthnCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	return r.update(ctx, "webauthn_credential-"+credential.ID, credential)
}

func (r *kvsRepository) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	return r.delete(ctx, "webauthn_credential-"+id)
}

func (r *kvsRepository) Close() error {
	return r.db.Close()
}
