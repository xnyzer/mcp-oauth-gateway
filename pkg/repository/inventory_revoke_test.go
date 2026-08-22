package repository

// The kill switch (F-024a): what a revoke deletes, what it must leave alone,
// and how it behaves on a record it cannot read. Fixtures live in
// inventory_test.go beside the listing tests they are shared with.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
	"go.etcd.io/bbolt"
)

// -- Revocation ---------------------------------------------------------

func TestRevokeClientRemovesEveryRecordKindAndSparesOthers(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			registerTestClient(t, ctx, repo, dcrClientID, time.Now().UTC().Add(time.Hour))
			victim := writeGrant(t, ctx, repo, dcrClientID, "victim-grant", time.Now().UTC())
			bystander := writeGrant(t, ctx, repo, cimdClientID, "bystander-grant", time.Now().UTC())

			deleted, err := repo.RevokeClient(ctx, dcrClientID)
			require.NoError(t, err)
			require.Equal(t, 6, deleted, "five record kinds plus the registration")

			require.Equal(t, allGone(), victim.presence(t, ctx, repo))
			require.Equal(t, allPresent(), bystander.presence(t, ctx, repo), "another client's records must not be touched")

			_, err = repo.GetClient(ctx, dcrClientID)
			require.Error(t, err, "the registration goes with the client")

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Equal(t, cimdClientID, rows[0].ClientID)
		})
	}
}

// A CIMD client has no registration, so the count covers records only — and
// the revoke must still work rather than failing on the missing client record.
func TestRevokeClientWithoutRegistration(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			fixture := writeGrant(t, ctx, repo, cimdClientID, "cimd-grant", time.Now().UTC())

			deleted, err := repo.RevokeClient(ctx, cimdClientID)
			require.NoError(t, err)
			require.Equal(t, 5, deleted)
			require.Equal(t, allGone(), fixture.presence(t, ctx, repo))
		})
	}
}

func TestRevokeGrantLeavesTheClientsOtherGrants(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			registerTestClient(t, ctx, repo, dcrClientID, time.Now().UTC().Add(time.Hour))
			first := writeGrant(t, ctx, repo, dcrClientID, "first-grant", time.Now().UTC())
			second := writeGrant(t, ctx, repo, dcrClientID, "second-grant", time.Now().UTC())

			deleted, err := repo.RevokeGrant(ctx, "first-grant")
			require.NoError(t, err)
			require.Equal(t, 5, deleted, "a grant revoke never takes the registration")

			require.Equal(t, allGone(), first.presence(t, ctx, repo))
			require.Equal(t, allPresent(), second.presence(t, ctx, repo))

			_, err = repo.GetClient(ctx, dcrClientID)
			require.NoError(t, err, "the client itself survives a single grant revoke")
		})
	}
}

func TestRevokeAllEmptiesTheStore(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			registerTestClient(t, ctx, repo, dcrClientID, time.Now().UTC().Add(time.Hour))
			first := writeGrant(t, ctx, repo, dcrClientID, "first-grant", time.Now().UTC())
			second := writeGrant(t, ctx, repo, cimdClientID, "second-grant", time.Now().UTC())

			deleted, err := repo.RevokeAll(ctx)
			require.NoError(t, err)
			require.Equal(t, 11, deleted, "ten records plus the one registration")

			require.Equal(t, allGone(), first.presence(t, ctx, repo))
			require.Equal(t, allGone(), second.presence(t, ctx, repo))

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Empty(t, rows)
		})
	}
}

// The panic button revokes clients — it must not touch the operator's own
// account or passkeys. Wiping those would answer a compromise by locking the
// only person who can respond out of the gateway.
func TestRevokeAllKeepsTheOperatorAccount(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			require.NoError(t, repo.CreateUser(ctx, &models.User{ID: "operator", Username: "admin"}))
			require.NoError(t, repo.AddWebAuthnCredential(ctx, &models.WebAuthnCredential{
				ID:         "passkey-1",
				UserID:     "operator",
				Name:       "laptop",
				Credential: json.RawMessage(`{}`),
			}))
			writeGrant(t, ctx, repo, cimdClientID, "grant", time.Now().UTC())

			_, err := repo.RevokeAll(ctx)
			require.NoError(t, err)

			user, err := repo.GetUser(ctx)
			require.NoError(t, err, "the operator account survives the panic button")
			require.Equal(t, "operator", user.ID)
			credentials, err := repo.ListWebAuthnCredentials(ctx, "operator")
			require.NoError(t, err)
			require.Len(t, credentials, 1, "the passkey survives too — it is the way back in")
			require.NoError(t, repo.EnsureSchemaVersion(ctx, SchemaVersion), "the schema marker survives")
		})
	}
}

// -- Fail-closed --------------------------------------------------------

// corruptRecord writes an undecodable access-token record straight into the
// backing store. White-box on purpose: no public path can produce one, and the
// behaviour on a record that cannot be read is the whole point of the test.
func corruptRecord(t *testing.T, repo Repository, signature string) {
	t.Helper()
	switch backend := repo.(type) {
	case *kvsRepository:
		require.NoError(t, backend.db.Update(func(tx *bbolt.Tx) error {
			return tx.Bucket([]byte(backend.bucketName)).Put([]byte(accessTokenPrefix+signature), []byte("{not json"))
		}))
	case *sqlRepository:
		require.NoError(t, backend.db.Create(&accessTokenSession{
			Signature: signature,
			RequestID: "unreadable",
			Request:   []byte("{not json"),
		}).Error)
	default:
		t.Fatalf("unknown repository implementation %T", repo)
	}
}

// A revoke that steps over a record it cannot read would report a kill that
// did not happen. It has to fail instead — and leave the store untouched, so
// the operator can retry rather than face a half-revoked client.
func TestRevokeFailsClosedAndAtomicallyOnUnreadableRecord(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			registerTestClient(t, ctx, repo, dcrClientID, time.Now().UTC().Add(time.Hour))
			fixture := writeGrant(t, ctx, repo, dcrClientID, "victim-grant", time.Now().UTC())
			corruptRecord(t, repo, "unreadable-record")

			deleted, err := repo.RevokeClient(ctx, dcrClientID)
			require.Error(t, err)
			require.Zero(t, deleted)

			require.Equal(t, allPresent(), fixture.presence(t, ctx, repo), "the transaction rolled back whole")
			_, err = repo.GetClient(ctx, dcrClientID)
			require.NoError(t, err, "the registration survived too")
		})
	}
}

// The listing fails the same way: a client hidden by an unreadable record is
// worse than an error the operator can see.
func TestListClientGrantsFailsClosedOnUnreadableRecord(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			writeGrant(t, ctx, repo, cimdClientID, "grant", time.Now().UTC())
			corruptRecord(t, repo, "unreadable-record")

			rows, err := repo.ListClientGrants(ctx)
			require.Error(t, err)
			require.Nil(t, rows)
		})
	}
}

// -- Storage compatibility ----------------------------------------------

// The inventory adds no entity and no column, so a store written before it
// must read without a migration. A bumped SchemaVersion would mean the
// opposite, hence the explicit guard.
func TestInventoryNeedsNoMigration(t *testing.T) {
	require.Equal(t, 1, SchemaVersion, "the inventory introduces no new entity — a bump would force a migration")

	dir := t.TempDir()
	backends := []struct {
		name string
		open func() (Repository, error)
	}{
		{"kvs", func() (Repository, error) { return NewKVSRepository(filepath.Join(dir, "test.db"), "test") }},
		{"sql", func() (Repository, error) {
			return NewSQLRepository("sqlite", fmt.Sprintf("file:%s?_busy_timeout=5000", filepath.Join(dir, "test.sqlite")))
		}},
	}
	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			ctx := t.Context()
			first, err := backend.open()
			require.NoError(t, err)
			require.NoError(t, first.EnsureSchemaVersion(ctx, SchemaVersion))
			writeGrant(t, ctx, first, cimdClientID, "grant", time.Now().UTC())
			require.NoError(t, first.Close())

			second, err := backend.open()
			require.NoError(t, err)
			t.Cleanup(func() { second.Close() })
			require.NoError(t, second.EnsureSchemaVersion(ctx, SchemaVersion))

			rows, err := second.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Equal(t, cimdClientID, rows[0].ClientID)
		})
	}
}
