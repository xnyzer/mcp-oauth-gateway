package repository

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

// testRepos returns one instance per backend so the maintenance contract is
// verified for bbolt and SQLite alike.
func testRepos(t *testing.T) map[string]Repository {
	t.Helper()

	kvs, err := NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { kvs.Close() })

	sql, err := NewSQLRepository("sqlite", fmt.Sprintf("file:%s?_busy_timeout=5000", filepath.Join(t.TempDir(), "test.sqlite")))
	require.NoError(t, err)
	t.Cleanup(func() { sql.Close() })

	return map[string]Repository{"kvs": kvs, "sql": sql}
}

func testRequest(id string) *fosite.Request {
	return &fosite.Request{
		ID:          id,
		RequestedAt: time.Now().UTC(),
		Client:      &fosite.DefaultClient{ID: "test-client"},
	}
}

func TestRevokeByRequestID(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			grant := testRequest("grant-1")
			other := testRequest("grant-2")

			// Two access tokens + one refresh token in the same grant,
			// plus an unrelated grant that must survive.
			require.NoError(t, repo.CreateAccessTokenSession(ctx, "sig-a", grant))
			require.NoError(t, repo.CreateAccessTokenSession(ctx, "sig-b", grant))
			require.NoError(t, repo.CreateRefreshTokenSession(ctx, "sig-r", "sig-a", grant))
			require.NoError(t, repo.CreateAccessTokenSession(ctx, "sig-other", other))

			// RFC 7009 cascade: revocation is keyed by the grant's request ID.
			require.NoError(t, repo.RevokeAccessToken(ctx, "grant-1"))
			require.NoError(t, repo.RevokeRefreshToken(ctx, "grant-1"))

			_, err := repo.GetAccessTokenSession(ctx, "sig-a", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
			_, err = repo.GetAccessTokenSession(ctx, "sig-b", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
			_, err = repo.GetRefreshTokenSession(ctx, "sig-r", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)

			_, err = repo.GetAccessTokenSession(ctx, "sig-other", nil)
			require.NoError(t, err, "other grants must be untouched")
		})
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			require.NoError(t, repo.CreateAccessTokenSession(ctx, "sig-1", testRequest("req-1")))
			require.NoError(t, repo.CreateRefreshTokenSession(ctx, "sig-2", "sig-1", testRequest("req-1")))
			require.NoError(t, repo.CreateAuthorizeCodeSession(ctx, "code-1", testRequest("req-1")))
			require.NoError(t, repo.CreatePKCERequestSession(ctx, "sig-3", testRequest("req-1")))

			// Cutoffs in the past: everything is fresh and must stay.
			past := time.Now().UTC().Add(-time.Hour)
			require.NoError(t, repo.DeleteExpiredSessions(ctx, past, past, past))
			_, err := repo.GetAccessTokenSession(ctx, "sig-1", nil)
			require.NoError(t, err)

			// Cutoffs in the future: everything is expired and must go.
			future := time.Now().UTC().Add(time.Hour)
			require.NoError(t, repo.DeleteExpiredSessions(ctx, future, future, future))
			_, err = repo.GetAccessTokenSession(ctx, "sig-1", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
			_, err = repo.GetRefreshTokenSession(ctx, "sig-2", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
			_, err = repo.GetAuthorizeCodeSession(ctx, "code-1", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
			_, err = repo.GetPKCERequestSession(ctx, "sig-3", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
		})
	}
}

func TestEnsureSchemaVersion(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			// First run writes the version; repeating it is a no-op.
			require.NoError(t, repo.EnsureSchemaVersion(ctx, SchemaVersion))
			require.NoError(t, repo.EnsureSchemaVersion(ctx, SchemaVersion))
			// Upgrades move the marker forward.
			require.NoError(t, repo.EnsureSchemaVersion(ctx, SchemaVersion+1))
			// Downgrades fail fast (SPEC §2.5).
			err := repo.EnsureSchemaVersion(ctx, SchemaVersion)
			require.Error(t, err)
			require.Contains(t, err.Error(), "downgrades are unsupported")
		})
	}
}
