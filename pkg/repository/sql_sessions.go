package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

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
