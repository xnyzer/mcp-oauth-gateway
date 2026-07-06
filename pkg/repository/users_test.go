package repository

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
)

func TestUserLifecycle(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()

			// Before bootstrap there is no user (fail-closed lookup).
			_, err := repo.GetUser(ctx)
			require.ErrorIs(t, err, fosite.ErrNotFound)

			user := &models.User{
				ID:        "user-id-1",
				Username:  "admin",
				CreatedAt: time.Now().UTC(),
			}
			require.NoError(t, repo.CreateUser(ctx, user))

			loaded, err := repo.GetUser(ctx)
			require.NoError(t, err)
			require.Equal(t, user.ID, loaded.ID)
			require.Equal(t, "admin", loaded.Username)
			require.False(t, loaded.PasswordLoginDisabled)

			// The password-fallback flag round-trips through UpdateUser.
			loaded.PasswordLoginDisabled = true
			require.NoError(t, repo.UpdateUser(ctx, loaded))
			loaded, err = repo.GetUser(ctx)
			require.NoError(t, err)
			require.True(t, loaded.PasswordLoginDisabled)
		})
	}
}

func TestWebAuthnCredentialLifecycle(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			now := time.Now().UTC()

			first := &models.WebAuthnCredential{
				ID:         "cred-a",
				UserID:     "user-1",
				Name:       "MacBook",
				Credential: json.RawMessage(`{"id":"cred-a"}`),
				CreatedAt:  now.Add(-time.Hour),
			}
			second := &models.WebAuthnCredential{
				ID:         "cred-b",
				UserID:     "user-1",
				Name:       "iPhone",
				Credential: json.RawMessage(`{"id":"cred-b"}`),
				CreatedAt:  now,
			}
			foreign := &models.WebAuthnCredential{
				ID:         "cred-c",
				UserID:     "user-2",
				Credential: json.RawMessage(`{"id":"cred-c"}`),
				CreatedAt:  now,
			}
			require.NoError(t, repo.AddWebAuthnCredential(ctx, first))
			require.NoError(t, repo.AddWebAuthnCredential(ctx, second))
			require.NoError(t, repo.AddWebAuthnCredential(ctx, foreign))

			// Listing is per-user and ordered oldest first.
			credentials, err := repo.ListWebAuthnCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.Len(t, credentials, 2)
			require.Equal(t, "cred-a", credentials[0].ID)
			require.Equal(t, "cred-b", credentials[1].ID)

			// Ceremony state updates (sign count / last used) persist.
			first.LastUsedAt = now
			first.Credential = json.RawMessage(`{"id":"cred-a","signCount":7}`)
			require.NoError(t, repo.UpdateWebAuthnCredential(ctx, first))
			credentials, err = repo.ListWebAuthnCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.JSONEq(t, `{"id":"cred-a","signCount":7}`, string(credentials[0].Credential))
			require.False(t, credentials[0].LastUsedAt.IsZero())

			// Deleting removes exactly the addressed credential.
			require.NoError(t, repo.DeleteWebAuthnCredential(ctx, "cred-a"))
			credentials, err = repo.ListWebAuthnCredentials(ctx, "user-1")
			require.NoError(t, err)
			require.Len(t, credentials, 1)
			require.Equal(t, "cred-b", credentials[0].ID)

			// Updating a deleted credential fails instead of resurrecting it.
			require.ErrorIs(t, repo.UpdateWebAuthnCredential(ctx, first), fosite.ErrNotFound)
		})
	}
}
