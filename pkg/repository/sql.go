package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type sqlRepository struct {
	db *gorm.DB
}

type authorizeCodeSession struct {
	Code      string `gorm:"primaryKey;size:512"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type accessTokenSession struct {
	Signature string `gorm:"primaryKey;size:512"`
	RequestID string `gorm:"size:512;index"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type refreshTokenSession struct {
	Signature       string `gorm:"primaryKey;size:512"`
	AccessSignature string `gorm:"size:512"`
	RequestID       string `gorm:"size:512;index"`
	Request         []byte `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type clientRecord struct {
	ID        string `gorm:"primaryKey;size:512"`
	Client    []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type pkceRequestSession struct {
	Signature string `gorm:"primaryKey;size:512"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type authorizeRequestRecord struct {
	RequestID string `gorm:"primaryKey;size:512"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type userRecord struct {
	ID        string `gorm:"primaryKey;size:512"`
	User      []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type webauthnCredentialRecord struct {
	ID         string `gorm:"primaryKey;size:1024"`
	UserID     string `gorm:"size:512;index"`
	Credential []byte `gorm:"not null"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func NewSQLRepository(driver string, dsn string) (Repository, error) {
	if driver == "" {
		return nil, fmt.Errorf("driver must not be empty")
	}
	if dsn == "" {
		return nil, fmt.Errorf("dsn must not be empty")
	}

	var dialector gorm.Dialector
	switch strings.ToLower(driver) {
	case "sqlite":
		dialector = sqlite.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported driver: %s", driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	if err := configureSQLite(db); err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(
		&authorizeCodeSession{},
		&accessTokenSession{},
		&refreshTokenSession{},
		&clientRecord{},
		&pkceRequestSession{},
		&authorizeRequestRecord{},
		&schemaVersionRecord{},
		&userRecord{},
		&webauthnCredentialRecord{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	return &sqlRepository{db: db}, nil
}

// configureSQLite serialises writes and applies durability/concurrency
// pragmas (SPEC §2.2). SQLite is a single-writer engine: SetMaxOpenConns(1)
// keeps every statement on one connection so the DCR-cap transaction cannot
// race a concurrent writer, and WAL + a busy timeout avoid "database is
// locked" errors under the read-heavy proxy path.
func configureSQLite(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to access database handle: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	} {
		if err := db.Exec(pragma).Error; err != nil {
			return fmt.Errorf("failed to apply %q: %w", pragma, err)
		}
	}
	return nil
}

func (r *sqlRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, fositeReq fosite.Requester) error {
	data, err := marshalRequest(fositeReq)
	if err != nil {
		return err
	}

	session := authorizeCodeSession{
		Code:    code,
		Request: data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	var session authorizeCodeSession
	if err := r.db.WithContext(ctx).First(&session, "code = ?", code).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load authorize code session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return r.db.WithContext(ctx).Delete(&authorizeCodeSession{}, "code = ?", code).Error
}

func (r *sqlRepository) CreateAccessTokenSession(ctx context.Context, signature string, fositeReq fosite.Requester) error {
	data, err := marshalRequest(fositeReq)
	if err != nil {
		return err
	}

	session := accessTokenSession{
		Signature: signature,
		RequestID: fositeReq.GetID(),
		Request:   data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var session accessTokenSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load access token session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return r.db.WithContext(ctx).Delete(&accessTokenSession{}, "signature = ?", signature).Error
}

func (r *sqlRepository) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return err
	}

	session := refreshTokenSession{
		Signature:       signature,
		AccessSignature: accessSignature,
		RequestID:       req.GetID(),
		Request:         data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var session refreshTokenSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load refresh token session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return r.db.WithContext(ctx).Delete(&refreshTokenSession{}, "signature = ?", signature).Error
}

func (r *sqlRepository) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	var session refreshTokenSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fosite.ErrNotFound
		}
		return fmt.Errorf("failed to load refresh token session: %w", err)
	}

	var req models.Request
	if err := json.Unmarshal(session.Request, &req); err != nil {
		return fmt.Errorf("failed to decode refresh token session: %w", err)
	}
	req.RotatedAt = time.Now().UTC()

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to encode refresh token session: %w", err)
	}

	return r.db.WithContext(ctx).
		Model(&refreshTokenSession{}).
		Where("signature = ?", signature).
		Update("request", data).Error
}

// RevokeRefreshToken deletes all refresh-token sessions of the grant —
// fosite passes the request ID, records are keyed by signature (RFC 7009).
func (r *sqlRepository) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).Delete(&refreshTokenSession{}, "request_id = ?", requestID).Error
}

// RevokeAccessToken deletes all access-token sessions of the grant.
func (r *sqlRepository) RevokeAccessToken(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).Delete(&accessTokenSession{}, "request_id = ?", requestID).Error
}

// DeleteExpiredSessions garbage-collects session records past their cutoff
// (SPEC §2.1). Expiry on use is enforced by fosite; this reclaims storage.
func (r *sqlRepository) DeleteExpiredSessions(ctx context.Context, accessBefore, refreshBefore, codeBefore time.Time) error {
	sweeps := []struct {
		model  any
		before time.Time
	}{
		{&accessTokenSession{}, accessBefore},
		{&refreshTokenSession{}, refreshBefore},
		{&authorizeCodeSession{}, codeBefore},
		{&pkceRequestSession{}, codeBefore},
		{&authorizeRequestRecord{}, codeBefore},
	}
	for _, s := range sweeps {
		// julianday() compares datetimes regardless of their stored UTC
		// offset (SQLite stores time.Time values as strings).
		if err := r.db.WithContext(ctx).Delete(s.model, "julianday(created_at) < julianday(?)", s.before).Error; err != nil {
			return fmt.Errorf("failed to sweep expired records: %w", err)
		}
	}
	return nil
}

type schemaVersionRecord struct {
	ID      int `gorm:"primaryKey"`
	Version int `gorm:"not null"`
}

// EnsureSchemaVersion writes the schema version on first run and fails fast
// when the store was written by a newer gateway (SPEC §2.5).
func (r *sqlRepository) EnsureSchemaVersion(ctx context.Context, version int) error {
	var record schemaVersionRecord
	err := r.db.WithContext(ctx).First(&record, "id = ?", 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.WithContext(ctx).Create(&schemaVersionRecord{ID: 1, Version: version}).Error
	}
	if err != nil {
		return fmt.Errorf("failed to read schema version: %w", err)
	}
	if record.Version > version {
		return fmt.Errorf("data store schema version %d is newer than supported version %d — downgrades are unsupported", record.Version, version)
	}
	if record.Version < version {
		return r.db.WithContext(ctx).Model(&schemaVersionRecord{}).Where("id = ?", 1).Update("version", version).Error
	}
	return nil
}

func (r *sqlRepository) RegisterClient(ctx context.Context, fositeClient fosite.Client, expiresAt time.Time, maxClients int) error {
	client := models.FromFositeClient(fositeClient)
	client.CreatedAt = time.Now().UTC()
	client.ExpiresAt = expiresAt
	data, err := json.Marshal(client) //nolint:gosec // G117: persisting the DCR client secret server-side is the repository's purpose (SPEC §2.1)
	if err != nil {
		return fmt.Errorf("failed to encode client: %w", err)
	}

	record := clientRecord{
		ID:     fositeClient.GetID(),
		Client: data,
	}

	// Count and insert in one transaction. With SetMaxOpenConns(1) writes run
	// on a single connection, so the cap check cannot race a concurrent
	// registration (SR-5, no TOCTOU).
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if maxClients > 0 {
			var existing clientRecord
			err := tx.First(&existing, "id = ?", fositeClient.GetID()).Error
			isNew := errors.Is(err, gorm.ErrRecordNotFound)
			if err != nil && !isNew {
				return fmt.Errorf("failed to check existing client: %w", err)
			}
			// A re-registration replaces in place and must not count against
			// the cap; only a genuinely new ID does.
			if isNew {
				count, err := countNonExpiredClientRecords(tx, time.Now().UTC())
				if err != nil {
					return err
				}
				if count >= maxClients {
					return ErrClientCapReached
				}
			}
		}
		return tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&record).Error
	})
}

// countNonExpiredClientRecords counts the client registrations whose expiry
// has not passed (a zero expiry never expires), scoped to the given
// DB/transaction handle.
func countNonExpiredClientRecords(db *gorm.DB, now time.Time) (int, error) {
	var records []clientRecord
	if err := db.Find(&records).Error; err != nil {
		return 0, fmt.Errorf("failed to load clients: %w", err)
	}
	count := 0
	for _, record := range records {
		var client models.Client
		if err := json.Unmarshal(record.Client, &client); err != nil {
			continue
		}
		if client.ExpiresAt.IsZero() || client.ExpiresAt.After(now) {
			count++
		}
	}
	return count, nil
}

// getClientModel loads and decodes a stored client registration.
func (r *sqlRepository) getClientModel(ctx context.Context, id string) (*models.Client, error) {
	var record clientRecord
	if err := r.db.WithContext(ctx).First(&record, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load client: %w", err)
	}
	var client models.Client
	if err := json.Unmarshal(record.Client, &client); err != nil {
		return nil, fmt.Errorf("failed to decode client: %w", err)
	}
	return &client, nil
}

// GetClient loads the client by its ID. Expired registrations are treated
// as absent (SPEC §1.4, fail-closed — no reliance on the sweeper).
func (r *sqlRepository) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	client, err := r.getClientModel(ctx, id)
	if err != nil {
		return nil, err
	}
	if !client.ExpiresAt.IsZero() && client.ExpiresAt.Before(time.Now().UTC()) {
		return nil, fosite.ErrNotFound
	}
	return client.ToFositeClient(), nil
}

// TouchClient extends a registration's expiry (refresh-on-use, SR-5).
func (r *sqlRepository) TouchClient(ctx context.Context, id string, expiresAt time.Time) error {
	client, err := r.getClientModel(ctx, id)
	if err != nil {
		return err
	}
	if client.ExpiresAt.IsZero() {
		return nil // registration without expiry stays permanent
	}
	client.ExpiresAt = expiresAt
	data, err := json.Marshal(client) //nolint:gosec // G117: persisting the DCR client secret server-side is the repository's purpose (SPEC §2.1)
	if err != nil {
		return fmt.Errorf("failed to encode client: %w", err)
	}
	return r.db.WithContext(ctx).
		Model(&clientRecord{}).
		Where("id = ?", id).
		Update("client", data).Error
}

// CountClients counts stored, non-expired DCR registrations (cap, SR-5).
func (r *sqlRepository) CountClients(ctx context.Context) (int, error) {
	return countNonExpiredClientRecords(r.db.WithContext(ctx), time.Now().UTC())
}

// DeleteExpiredClients garbage-collects expired DCR registrations.
func (r *sqlRepository) DeleteExpiredClients(ctx context.Context, now time.Time) error {
	clients, err := r.allClientModels(ctx)
	if err != nil {
		return err
	}
	for _, client := range clients {
		if !client.ExpiresAt.IsZero() && client.ExpiresAt.Before(now) {
			if err := r.db.WithContext(ctx).Delete(&clientRecord{}, "id = ?", client.ID).Error; err != nil {
				return fmt.Errorf("failed to delete expired client: %w", err)
			}
		}
	}
	return nil
}

// allClientModels loads every stored registration (the table is bounded by
// the DCR client cap, SPEC §1.4).
func (r *sqlRepository) allClientModels(ctx context.Context) ([]models.Client, error) {
	var records []clientRecord
	if err := r.db.WithContext(ctx).Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to load clients: %w", err)
	}
	clients := make([]models.Client, 0, len(records))
	for _, record := range records {
		var client models.Client
		if err := json.Unmarshal(record.Client, &client); err != nil {
			continue
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func (r *sqlRepository) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return errors.New("not implemented")
}

func (r *sqlRepository) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("not implemented")
}

func (r *sqlRepository) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return err
	}

	session := pkceRequestSession{
		Signature: signature,
		Request:   data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetPKCERequestSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var session pkceRequestSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load pkce request session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return r.db.WithContext(ctx).Delete(&pkceRequestSession{}, "signature = ?", signature).Error
}

func (r *sqlRepository) CreateAuthorizeRequest(ctx context.Context, fositeAR fosite.AuthorizeRequester) error {
	data, err := marshalAuthorizeRequest(fositeAR)
	if err != nil {
		return err
	}

	record := authorizeRequestRecord{
		RequestID: fositeAR.GetID(),
		Request:   data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&record).Error
}

func (r *sqlRepository) GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error) {
	var record authorizeRequestRecord
	if err := r.db.WithContext(ctx).First(&record, "request_id = ?", requestID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load authorize request: %w", err)
	}

	return unmarshalAuthorizeRequest(record.Request)
}

func (r *sqlRepository) DeleteAuthorizeRequest(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).Delete(&authorizeRequestRecord{}, "request_id = ?", requestID).Error
}

// GetUser returns the single operator account (FR-4); the table never holds
// more than one row.
func (r *sqlRepository) GetUser(ctx context.Context) (*models.User, error) {
	var record userRecord
	if err := r.db.WithContext(ctx).First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load user: %w", err)
	}
	var user models.User
	if err := json.Unmarshal(record.User, &user); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}
	return &user, nil
}

func (r *sqlRepository) CreateUser(ctx context.Context, user *models.User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to encode user: %w", err)
	}
	return r.db.WithContext(ctx).Create(&userRecord{ID: user.ID, User: data}).Error
}

func (r *sqlRepository) UpdateUser(ctx context.Context, user *models.User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to encode user: %w", err)
	}
	result := r.db.WithContext(ctx).
		Model(&userRecord{}).
		Where("id = ?", user.ID).
		Update("user", data)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

func (r *sqlRepository) AddWebAuthnCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	data, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("failed to encode passkey credential: %w", err)
	}
	record := webauthnCredentialRecord{
		ID:         credential.ID,
		UserID:     credential.UserID,
		Credential: data,
	}
	return r.db.WithContext(ctx).Create(&record).Error
}

// ListWebAuthnCredentials returns the user's passkeys, oldest first.
func (r *sqlRepository) ListWebAuthnCredentials(ctx context.Context, userID string) ([]models.WebAuthnCredential, error) {
	var records []webauthnCredentialRecord
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at").
		Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to load passkey credentials: %w", err)
	}
	credentials := make([]models.WebAuthnCredential, 0, len(records))
	for _, record := range records {
		var credential models.WebAuthnCredential
		if err := json.Unmarshal(record.Credential, &credential); err != nil {
			return nil, fmt.Errorf("failed to decode passkey credential: %w", err)
		}
		credentials = append(credentials, credential)
	}
	return credentials, nil
}

func (r *sqlRepository) UpdateWebAuthnCredential(ctx context.Context, credential *models.WebAuthnCredential) error {
	data, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("failed to encode passkey credential: %w", err)
	}
	result := r.db.WithContext(ctx).
		Model(&webauthnCredentialRecord{}).
		Where("id = ?", credential.ID).
		Update("credential", data)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

func (r *sqlRepository) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&webauthnCredentialRecord{}, "id = ?", id).Error
}

func (r *sqlRepository) Close() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql db: %w", err)
	}
	return sqlDB.Close()
}

func marshalRequest(req fosite.Requester) ([]byte, error) {
	data, err := json.Marshal(models.FromFositeReq(req))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	return data, nil
}

func unmarshalRequest(data []byte, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	fositeReq := req.ToFositeReq()
	if err := restoreSession(fositeReq, req.SessionData, sess); err != nil {
		return nil, err
	}
	return fositeReq, nil
}

func marshalAuthorizeRequest(req fosite.AuthorizeRequester) ([]byte, error) {
	data, err := json.Marshal(models.FromFositeAuthorizeRequest(req))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authorize request: %w", err)
	}
	return data, nil
}

func unmarshalAuthorizeRequest(data []byte) (fosite.AuthorizeRequester, error) {
	var req models.AuthorizeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorize request: %w", err)
	}
	return req.ToFositeAuthorizeRequest(), nil
}
