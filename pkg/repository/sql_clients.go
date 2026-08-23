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

type clientRecord struct {
	ID        string `gorm:"primaryKey;size:512"`
	Client    []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (r *sqlRepository) RegisterClient(ctx context.Context, registration ClientRegistration) error {
	fositeClient, expiresAt, maxClients := registration.Client, registration.ExpiresAt, registration.MaxClients
	client := models.FromFositeClient(fositeClient)
	client.Name = registration.Name
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

// GetClientName returns the name a DCR client declared at registration.
// An expired registration answers empty, like GetClient treats it as absent.
func (r *sqlRepository) GetClientName(ctx context.Context, id string) (string, error) {
	client, err := r.getClientModel(ctx, id)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	if !client.ExpiresAt.IsZero() && client.ExpiresAt.Before(time.Now().UTC()) {
		return "", nil
	}
	return client.Name, nil
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
