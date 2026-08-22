package repository

import (
	"sort"
	"strings"
	"time"

	"github.com/xnyzer/mcp-oauth-gateway/pkg/models"
)

// -- The operator's view of a client -----------------------------------

// ClientOrigin records how a client identifies itself, which decides what a
// revoke can actually take away (SPEC §1.3/§1.4): a DCR client has a stored
// registration to delete, while a CIMD client is re-resolved from its URL on
// every use and can therefore return through a fresh authorization.
type ClientOrigin string

const (
	// OriginCIMD is a client identified by an https:// Client ID Metadata
	// Document URL.
	OriginCIMD ClientOrigin = "cimd"
	// OriginDCR is a client that registered dynamically (SPEC §1.4).
	OriginDCR ClientOrigin = "dcr"
)

// ClientGrants is one row of the operator's client list (SPEC §1.12): a
// client and everything it currently holds. It is a projection of the stored
// records, never the records themselves — the client secret a token record
// carries in its client snapshot stays in the store.
type ClientGrants struct {
	ClientID string
	Origin   ClientOrigin
	// Registered reports whether a DCR registration is stored. A CIMD client
	// never has one, and an expired DCR registration can still have live
	// tokens — the access check is record presence, not the registration
	// (SPEC §2.4).
	Registered   bool
	RegisteredAt time.Time
	// ExpiresAt is the registration's expiry. Zero means the registration
	// never expires, or that there is none.
	ExpiresAt time.Time
	// RedirectURIs come from the stored registration where one exists, and
	// otherwise from the most recent token record's client snapshot. They are
	// what makes a DCR client recognisable, whose client ID is random.
	RedirectURIs []string
	// Scopes is the union of the scopes granted across Grants.
	Scopes []string
	Grants []Grant
	// AccessTokens and RefreshTokens count stored records rather than grants:
	// refresh-token rotation leaves one record per rotation, so a single
	// long-lived grant can hold dozens.
	AccessTokens  int
	RefreshTokens int
	FirstActivity time.Time
	LastActivity  time.Time
}

// Grant is one authorization a client holds — what the operator revokes when
// they want to cut one authorization rather than the client itself.
type Grant struct {
	RequestID   string
	RequestedAt time.Time
	// LastActivity is the newest timestamp on the grant's records: the
	// request time, or the rotation time where a refresh token was rotated.
	LastActivity  time.Time
	Scopes        []string
	AccessTokens  int
	RefreshTokens int
}

// originOf classifies a client ID the same way clientSource.lookupClient
// does — an https:// prefix means the ID is a CIMD document URL. Keeping the
// rule identical matters: a row that claims DCR for a client fosite resolves
// via CIMD would promise the operator a registration that revoking cannot
// find.
func originOf(clientID string) ClientOrigin {
	if strings.HasPrefix(clientID, "https://") {
		return OriginCIMD
	}
	return OriginDCR
}

// -- Aggregation, shared by both backends -------------------------------

// tokenKind names the two record kinds that carry access.
type tokenKind int

const (
	accessTokenKind tokenKind = iota
	refreshTokenKind
)

// inventory turns a stream of token records and stored registrations into the
// per-client rows the operator list shows. Both backends feed this one
// aggregator, so the two listings cannot drift apart.
type inventory struct {
	clients map[string]*clientAccumulator
}

type clientAccumulator struct {
	row    ClientGrants
	grants map[string]*Grant
	scopes map[string]struct{}
	// snapshotAt is the request time of the token record whose client
	// snapshot currently fills RedirectURIs; a newer record replaces it.
	snapshotAt time.Time
}

func newInventory() *inventory {
	return &inventory{clients: make(map[string]*clientAccumulator)}
}

func (i *inventory) accumulator(clientID string) *clientAccumulator {
	if acc, ok := i.clients[clientID]; ok {
		return acc
	}
	acc := &clientAccumulator{
		row:    ClientGrants{ClientID: clientID, Origin: originOf(clientID)},
		grants: make(map[string]*Grant),
		scopes: make(map[string]struct{}),
	}
	i.clients[clientID] = acc
	return acc
}

// addToken folds one access- or refresh-token record into its client's row.
// Records without a client snapshot are ignored rather than grouped under an
// empty ID — they cannot be attributed, and inventing a row for them would
// offer the operator a revoke that revokes nothing.
func (i *inventory) addToken(kind tokenKind, req *models.Request) {
	if req == nil || req.Client == nil || req.Client.ID == "" {
		return
	}
	acc := i.accumulator(req.Client.ID)
	acc.takeSnapshot(req)
	grant := acc.grantFor(req)
	for _, scope := range grantedScopes(req) {
		acc.scopes[scope] = struct{}{}
	}
	acc.count(kind, grant)
	acc.recordActivity(grant, req)
}

// takeSnapshot fills the row's redirect URIs from a token record's copy of the
// client, the newest record winning. A stored registration outranks every
// snapshot: it is the live record, while a snapshot is whatever the client
// looked like when the token was issued.
func (acc *clientAccumulator) takeSnapshot(req *models.Request) {
	if acc.row.Registered || req.RequestedAt.Before(acc.snapshotAt) {
		return
	}
	acc.row.RedirectURIs = append([]string(nil), req.Client.RedirectURIs...)
	acc.snapshotAt = req.RequestedAt
}

// grantFor returns the row's grant for this request, creating it on first
// sight and keeping the earliest request time seen for it.
func (acc *clientAccumulator) grantFor(req *models.Request) *Grant {
	grant, ok := acc.grants[req.ID]
	if !ok {
		grant = &Grant{RequestID: req.ID, RequestedAt: req.RequestedAt}
		acc.grants[req.ID] = grant
		return grant
	}
	if req.RequestedAt.Before(grant.RequestedAt) {
		grant.RequestedAt = req.RequestedAt
	}
	return grant
}

// count adds one record of the kind to the grant and to the row.
func (acc *clientAccumulator) count(kind tokenKind, grant *Grant) {
	switch kind {
	case accessTokenKind:
		grant.AccessTokens++
		acc.row.AccessTokens++
	case refreshTokenKind:
		grant.RefreshTokens++
		acc.row.RefreshTokens++
	}
}

// recordActivity folds a record's timestamps into the grant and the row. A
// rotated refresh token is newer activity than the request that created it,
// which is what makes a long-lived connection look alive in the list.
func (acc *clientAccumulator) recordActivity(grant *Grant, req *models.Request) {
	activity := req.RequestedAt
	if req.RotatedAt.After(activity) {
		activity = req.RotatedAt
	}
	if activity.After(grant.LastActivity) {
		grant.LastActivity = activity
	}
	if activity.After(acc.row.LastActivity) {
		acc.row.LastActivity = activity
	}
	if acc.row.FirstActivity.IsZero() || req.RequestedAt.Before(acc.row.FirstActivity) {
		acc.row.FirstActivity = req.RequestedAt
	}
}

// addRegistration folds a stored DCR registration into its row. The
// registration is the live record, so its redirect URIs outrank the snapshot
// any token record carries.
func (i *inventory) addRegistration(client *models.Client) {
	if client == nil || client.ID == "" {
		return
	}
	acc := i.accumulator(client.ID)
	acc.row.Registered = true
	acc.row.RegisteredAt = client.CreatedAt
	acc.row.ExpiresAt = client.ExpiresAt
	acc.row.RedirectURIs = append([]string(nil), client.RedirectURIs...)
}

// rows returns the finished list, newest activity first. A registration that
// has expired and holds no tokens is dropped: it grants nothing (GetClient
// treats it as absent) and is the sweeper's to remove, so listing it would
// offer the operator a kill switch for something already dead.
func (i *inventory) rows(now time.Time) []ClientGrants {
	rows := make([]ClientGrants, 0, len(i.clients))
	for _, acc := range i.clients {
		if len(acc.grants) == 0 && acc.isExpiredRegistration(now) {
			continue
		}
		row := acc.row
		row.Grants = sortedGrants(acc.grants)
		row.Scopes = sortedKeys(acc.scopes)
		rows = append(rows, row)
	}
	sort.Slice(rows, func(a, b int) bool {
		if !rows[a].LastActivity.Equal(rows[b].LastActivity) {
			return rows[a].LastActivity.After(rows[b].LastActivity)
		}
		return rows[a].ClientID < rows[b].ClientID
	})
	return rows
}

func (acc *clientAccumulator) isExpiredRegistration(now time.Time) bool {
	return acc.row.Registered && !acc.row.ExpiresAt.IsZero() && acc.row.ExpiresAt.Before(now)
}

// grantedScopes prefers what was granted and falls back to what was
// requested, which is what a record carries before the grant completes.
func grantedScopes(req *models.Request) []string {
	if len(req.GrantedScope) > 0 {
		return req.GrantedScope
	}
	return req.RequestedScope
}

func sortedGrants(grants map[string]*Grant) []Grant {
	out := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		out = append(out, *grant)
	}
	sort.Slice(out, func(a, b int) bool {
		if !out[a].LastActivity.Equal(out[b].LastActivity) {
			return out[a].LastActivity.After(out[b].LastActivity)
		}
		return out[a].RequestID < out[b].RequestID
	})
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
