package repository

// Operator inventory and kill switch (F-024a). Every test runs against both
// backends through testRepos, because the two implementations share nothing
// but the contract: bbolt scans key prefixes, SQL decodes request blobs.

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
)

const (
	// cimdClientID is shaped like a Client ID Metadata Document URL, which is
	// what makes it a CIMD client — the same https:// rule clientSource uses.
	cimdClientID = "https://client.example.com/metadata"
	dcrClientID  = "dcr-client-id"
	testRedirect = "https://client.example.com/callback"
)

// -- Fixtures -----------------------------------------------------------

func grantRequest(requestID, clientID string, requestedAt time.Time) *fosite.Request {
	return &fosite.Request{
		ID:          requestID,
		RequestedAt: requestedAt,
		Client: &fosite.DefaultClient{
			ID:           clientID,
			Secret:       []byte("hashed-secret"),
			RedirectURIs: []string{testRedirect},
		},
		RequestedScope: fosite.Arguments{"mcp"},
		GrantedScope:   fosite.Arguments{"mcp"},
	}
}

// grantFixture is one authorization with a record of every kind, so a revoke
// can be asserted per record kind rather than on tokens alone.
type grantFixture struct {
	clientID   string
	requestID  string
	accessSig  string
	refreshSig string
	code       string
	pkceSig    string
}

func writeGrant(t *testing.T, ctx context.Context, repo Repository, clientID, requestID string, at time.Time) grantFixture {
	t.Helper()
	fixture := grantFixture{
		clientID:   clientID,
		requestID:  requestID,
		accessSig:  requestID + "-access",
		refreshSig: requestID + "-refresh",
		code:       requestID + "-code",
		pkceSig:    requestID + "-pkce",
	}
	req := grantRequest(requestID, clientID, at)
	require.NoError(t, repo.CreateAccessTokenSession(ctx, fixture.accessSig, req))
	require.NoError(t, repo.CreateRefreshTokenSession(ctx, fixture.refreshSig, fixture.accessSig, req))
	require.NoError(t, repo.CreateAuthorizeCodeSession(ctx, fixture.code, req))
	require.NoError(t, repo.CreatePKCERequestSession(ctx, fixture.pkceSig, req))
	require.NoError(t, repo.CreateAuthorizeRequest(ctx, &fosite.AuthorizeRequest{
		ResponseTypes: fosite.Arguments{"code"},
		RedirectURI:   models.Must(url.Parse(testRedirect)),
		Request:       *req,
	}))
	return fixture
}

// presence reports, per record kind, whether the fixture's record still
// exists. A revoke is judged on this map: "the tokens are gone" is not the
// same claim as "nothing of this grant survived".
func (f grantFixture) presence(t *testing.T, ctx context.Context, repo Repository) map[string]bool {
	t.Helper()
	exists := func(err error) bool { return err == nil }
	_, accessErr := repo.GetAccessTokenSession(ctx, f.accessSig, nil)
	_, refreshErr := repo.GetRefreshTokenSession(ctx, f.refreshSig, nil)
	_, codeErr := repo.GetAuthorizeCodeSession(ctx, f.code, nil)
	_, pkceErr := repo.GetPKCERequestSession(ctx, f.pkceSig, nil)
	_, authorizeErr := repo.GetAuthorizeRequest(ctx, f.requestID)
	return map[string]bool{
		"access_token":      exists(accessErr),
		"refresh_token":     exists(refreshErr),
		"authorize_code":    exists(codeErr),
		"pkce_request":      exists(pkceErr),
		"authorize_request": exists(authorizeErr),
	}
}

func allGone() map[string]bool {
	return map[string]bool{"access_token": false, "refresh_token": false, "authorize_code": false, "pkce_request": false, "authorize_request": false}
}

func allPresent() map[string]bool {
	return map[string]bool{"access_token": true, "refresh_token": true, "authorize_code": true, "pkce_request": true, "authorize_request": true}
}

func registerTestClient(t *testing.T, ctx context.Context, repo Repository, clientID string, expiresAt time.Time) {
	t.Helper()
	require.NoError(t, repo.RegisterClient(ctx, &fosite.DefaultClient{
		ID:           clientID,
		RedirectURIs: []string{testRedirect},
	}, expiresAt, 0))
}

func rowFor(rows []ClientGrants, clientID string) (ClientGrants, bool) {
	for _, row := range rows {
		if row.ClientID == clientID {
			return row, true
		}
	}
	return ClientGrants{}, false
}

// labeledSession is a session carrying the operator's name for its grant, the
// way pkg/idp's real session does. models.FromFositeReq lifts the name onto the
// stored request through the models.Labeled interface.
type labeledSession struct {
	*fosite.DefaultSession
	label string
}

func (s *labeledSession) GetLabel() string { return s.label }

func writeNamedGrant(t *testing.T, ctx context.Context, repo Repository, clientID, requestID, label string, at time.Time) {
	t.Helper()
	req := grantRequest(requestID, clientID, at)
	req.SetSession(&labeledSession{DefaultSession: &fosite.DefaultSession{}, label: label})
	require.NoError(t, repo.CreateAccessTokenSession(ctx, requestID+"-access", req))
}

// -- Listing ------------------------------------------------------------

// A CIMD client has no stored registration at all — it is re-resolved from its
// URL on every use. Enumerating client records would therefore miss exactly
// the client the operator wants to see, which is the finding this whole task
// turns on.
func TestListClientGrantsFindsCIMDClientWithoutRegistration(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			writeGrant(t, ctx, repo, cimdClientID, "cimd-grant", time.Now().UTC())

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1)

			row := rows[0]
			require.Equal(t, cimdClientID, row.ClientID)
			require.Equal(t, OriginCIMD, row.Origin)
			require.False(t, row.Registered, "a CIMD client has no registration to revoke")
			require.Equal(t, []string{testRedirect}, row.RedirectURIs, "the client snapshot on the token record carries the redirect URI")
			require.Equal(t, []string{"mcp"}, row.Scopes)
			require.Len(t, row.Grants, 1)
			require.Equal(t, "cimd-grant", row.Grants[0].RequestID)
		})
	}
}

// Rotation leaves one refresh-token record per rotation. F-017d found 58 for a
// single client, so the listing has to aggregate rather than show a row per
// record.
// The operator's name (F-025) rides the grant's session, so the listing must
// surface it per grant and per row without a separate store.
func TestListClientGrantsCarriesTheOperatorsName(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			older := time.Now().UTC().Add(-time.Hour)
			writeNamedGrant(t, ctx, repo, cimdClientID, "older-grant", "Claude web", older)
			writeNamedGrant(t, ctx, repo, cimdClientID, "newer-grant", "Claude iOS", time.Now().UTC())

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Len(t, rows[0].Grants, 2)

			// Grants come newest first, and the row takes that one's name:
			// re-authorizing renames the connection.
			require.Equal(t, "Claude iOS", rows[0].Grants[0].Label)
			require.Equal(t, "Claude web", rows[0].Grants[1].Label)
			require.Equal(t, "Claude iOS", rows[0].Label)
		})
	}
}

// The name has no store of its own, so revoking the authorization takes it —
// there is no cleanup path to forget.
func TestRevokeTakesTheOperatorsNameWithIt(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			writeNamedGrant(t, ctx, repo, cimdClientID, "grant", "Claude web", time.Now().UTC())
			require.Equal(t, "Claude web", func() string {
				rows, err := repo.ListClientGrants(ctx)
				require.NoError(t, err)
				require.Len(t, rows, 1)
				return rows[0].Label
			}())

			_, err := repo.RevokeClient(ctx, cimdClientID)
			require.NoError(t, err)

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Empty(t, rows, "the name goes with the records that carried it")
		})
	}
}

func TestListClientGrantsAggregatesRotationHistory(t *testing.T) {
	const rotations = 58
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			at := time.Now().UTC().Add(-time.Hour)
			req := grantRequest("rotating-grant", cimdClientID, at)
			require.NoError(t, repo.CreateAccessTokenSession(ctx, "access", req))
			for i := 0; i < rotations; i++ {
				require.NoError(t, repo.CreateRefreshTokenSession(ctx, fmt.Sprintf("refresh-%d", i), "access", req))
			}

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1, "58 refresh records are one client, not 58")
			require.Len(t, rows[0].Grants, 1, "and one grant, not 58")
			require.Equal(t, rotations, rows[0].RefreshTokens)
			require.Equal(t, 1, rows[0].AccessTokens)
			require.Equal(t, rotations, rows[0].Grants[0].RefreshTokens)
		})
	}
}

func TestListClientGrantsReportsRegistrationAndRotationTimes(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			issued := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
			expiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
			registerTestClient(t, ctx, repo, dcrClientID, expiry)
			req := grantRequest("dcr-grant", dcrClientID, issued)
			require.NoError(t, repo.CreateRefreshTokenSession(ctx, "refresh", "access", req))
			require.NoError(t, repo.RotateRefreshToken(ctx, "dcr-grant", "refresh"))

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			row, ok := rowFor(rows, dcrClientID)
			require.True(t, ok)

			require.Equal(t, OriginDCR, row.Origin)
			require.True(t, row.Registered)
			require.WithinDuration(t, expiry, row.ExpiresAt, time.Second)
			require.WithinDuration(t, issued, row.FirstActivity, time.Second)
			require.True(t, row.LastActivity.After(issued), "rotation is newer activity than the original request")
		})
	}
}

// A registration with no tokens still has to show: it is a client that can
// come back with a refresh, and the operator may want it gone first.
func TestListClientGrantsIncludesRegistrationWithoutTokens(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			registerTestClient(t, ctx, repo, dcrClientID, time.Now().UTC().Add(time.Hour))

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.True(t, rows[0].Registered)
			require.Empty(t, rows[0].Grants)
		})
	}
}

// An expired registration without tokens grants nothing — GetClient already
// treats it as absent — so offering the operator a kill switch for it would be
// theatre.
func TestListClientGrantsDropsExpiredRegistrationWithoutTokens(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			registerTestClient(t, ctx, repo, dcrClientID, time.Now().UTC().Add(-time.Hour))

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Empty(t, rows)
		})
	}
}

// The same registration, expired but still holding a live access token, must
// show — the access check is record presence, not the registration.
func TestListClientGrantsKeepsExpiredRegistrationThatStillHoldsTokens(t *testing.T) {
	for name, repo := range testRepos(t) {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			registerTestClient(t, ctx, repo, dcrClientID, time.Now().UTC().Add(-time.Hour))
			writeGrant(t, ctx, repo, dcrClientID, "stale-grant", time.Now().UTC())

			rows, err := repo.ListClientGrants(ctx)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			require.Equal(t, 1, rows[0].AccessTokens)
		})
	}
}
