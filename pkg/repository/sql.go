package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type sqlRepository struct {
	db *gorm.DB
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
