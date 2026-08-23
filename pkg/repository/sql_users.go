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
)

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
