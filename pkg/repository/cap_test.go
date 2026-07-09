package repository

// DCR registration cap (SR-5, F-012d): the count and the insert happen in one
// write transaction, so concurrent registrations can never push the store past
// the cap. Run under -race to exercise the concurrent path.

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestRegisterClientCapIsAtomicUnderConcurrency(t *testing.T) {
	const (
		maxClients = 5
		registrars = 40
	)
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()

			var (
				wg        sync.WaitGroup
				mu        sync.Mutex
				succeeded int
				capErrors int
			)
			for i := 0; i < registrars; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					client := &fosite.DefaultClient{
						ID:           fmt.Sprintf("client-%d", i),
						RedirectURIs: []string{"https://app.example.com/cb"},
					}
					err := repo.RegisterClient(ctx, client, time.Time{}, maxClients)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						succeeded++
					case errors.Is(err, ErrClientCapReached):
						capErrors++
					default:
						t.Errorf("unexpected error: %v", err)
					}
				}(i)
			}
			wg.Wait()

			require.Equal(t, maxClients, succeeded, "exactly the cap may be registered")
			require.Equal(t, registrars-maxClients, capErrors, "every excess registration is capped")

			count, err := repo.CountClients(ctx)
			require.NoError(t, err)
			require.Equal(t, maxClients, count, "the store never exceeds the cap")
		})
	}
}

// TestRegisterClientCapAllowsReRegistration verifies a re-registration of an
// existing client ID replaces in place and does not count against the cap.
func TestRegisterClientCapAllowsReRegistration(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			client := &fosite.DefaultClient{ID: "client-1", RedirectURIs: []string{"https://app.example.com/cb"}}

			require.NoError(t, repo.RegisterClient(ctx, client, time.Time{}, 1))
			// Cap is 1 and one client exists, but re-registering the same ID
			// updates in place rather than being rejected.
			require.NoError(t, repo.RegisterClient(ctx, client, time.Time{}, 1))

			// A different ID is rejected — the cap is full.
			other := &fosite.DefaultClient{ID: "client-2", RedirectURIs: []string{"https://app.example.com/cb"}}
			require.ErrorIs(t, repo.RegisterClient(ctx, other, time.Time{}, 1), ErrClientCapReached)

			count, err := repo.CountClients(ctx)
			require.NoError(t, err)
			require.Equal(t, 1, count)
		})
	}
}
