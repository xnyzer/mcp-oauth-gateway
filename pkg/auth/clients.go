package auth

// The operator's client list and its kill switch (SPEC §1.12, F-024). This is
// the only place access can be taken away: `/.idp/revoke` is RFC 7009 and
// client-authenticated, so it lets a client drop its *own* token, never the
// operator drop someone else's.

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/authevent"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
)

// -- View model ---------------------------------------------------------

// grantView is one authorization as the settings page shows it.
type grantView struct {
	RequestID string
	// Label is the operator's name for this authorization (F-025).
	Label         string
	RequestedAt   time.Time
	LastActivity  time.Time
	Scopes        []string
	AccessTokens  int
	RefreshTokens int
}

// clientView is one row of the client list. It is a projection by
// construction: the stored records carry the client's hashed secret and this
// type has nowhere to put it, so no later template change can leak one.
type clientView struct {
	ClientID string
	// Label is the operator's name for the connection, taken at consent time
	// (F-025). Empty for a client authorized before the field existed, or for
	// one the operator chose not to name.
	Label string
	// IsCIMD marks a client identified by a metadata document URL. It decides
	// the wording rather than the layout: a CIMD client keeps no registration,
	// so revoking destroys its tokens and it may return through a fresh
	// authorization — it is not banned.
	IsCIMD bool
	// Registered reports a stored DCR registration. An expired one can still
	// hold live tokens, because access is decided by record presence
	// (SPEC §2.4).
	Registered bool
	ExpiresAt  time.Time
	// RedirectHosts are the distinct hosts of the client's redirect URIs —
	// the recognisable part for a DCR client, whose client ID is random.
	RedirectHosts []string
	Scopes        []string
	Grants        []grantView
	AccessTokens  int
	RefreshTokens int
	FirstActivity time.Time
	LastActivity  time.Time
}

// clientViews loads the client list for the settings page. An error is
// returned rather than an empty list: a page reading "no clients" because
// enumeration failed would tell the operator that nobody holds access, which
// is the opposite of the truth (fail-closed, §6).
func (a *AuthRouter) clientViews(ctx context.Context) ([]clientView, error) {
	rows, err := a.clients.ListClientGrants(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]clientView, 0, len(rows))
	for _, row := range rows {
		views = append(views, clientView{
			ClientID:      row.ClientID,
			Label:         row.Label,
			IsCIMD:        row.Origin == repository.OriginCIMD,
			Registered:    row.Registered,
			ExpiresAt:     row.ExpiresAt,
			RedirectHosts: redirectHosts(row.RedirectURIs),
			Scopes:        row.Scopes,
			Grants:        grantViews(row.Grants),
			AccessTokens:  row.AccessTokens,
			RefreshTokens: row.RefreshTokens,
			FirstActivity: row.FirstActivity,
			LastActivity:  row.LastActivity,
		})
	}
	return views, nil
}

func grantViews(grants []repository.Grant) []grantView {
	views := make([]grantView, 0, len(grants))
	for _, grant := range grants {
		views = append(views, grantView{
			RequestID:     grant.RequestID,
			Label:         grant.Label,
			RequestedAt:   grant.RequestedAt,
			LastActivity:  grant.LastActivity,
			Scopes:        grant.Scopes,
			AccessTokens:  grant.AccessTokens,
			RefreshTokens: grant.RefreshTokens,
		})
	}
	return views
}

// redirectHosts reduces redirect URIs to their distinct hosts, sorted. A URI
// that does not parse contributes nothing rather than being shown raw — the
// value comes from the client, and the host is the only part of it worth
// putting in front of the operator.
func redirectHosts(uris []string) []string {
	seen := make(map[string]struct{}, len(uris))
	for _, raw := range uris {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			continue
		}
		seen[parsed.Host] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

// -- Revocation handlers ------------------------------------------------

// handleSettingsClientRevoke deletes one client's registration and every token
// issued to it. Access ends at once: `/mcp` requires the token's record to
// still exist (SPEC §2.4), so nothing waits out ACCESS_TOKEN_TTL.
func (a *AuthRouter) handleSettingsClientRevoke(c *gin.Context) {
	if _, _, ok := a.requireOwnUser(c); !ok {
		return
	}
	clientID := c.PostForm("client_id")
	if clientID == "" {
		c.Redirect(http.StatusFound, SettingsEndpoint)
		return
	}
	// Read the name before the records go, since that is where it lives.
	label := a.labelOf(c.Request.Context(), clientID, "")
	deleted, err := a.clients.RevokeClient(c.Request.Context(), clientID)
	if err != nil {
		a.logger.Error("Failed to revoke client", zap.Error(err))
		c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=revoke_failed")
		return
	}
	a.logRevoke(c, revokeEvent{scope: "client", subject: clientID, label: label, records: deleted})
	// The same answer whether or not the client existed: the operator's own
	// page gains nothing from an existence oracle, and a mistyped ID should
	// not read differently from a successful kill.
	c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=revoked")
}

// handleSettingsGrantRevoke deletes one authorization, leaving the client's
// other authorizations and its registration in place.
func (a *AuthRouter) handleSettingsGrantRevoke(c *gin.Context) {
	if _, _, ok := a.requireOwnUser(c); !ok {
		return
	}
	requestID := c.PostForm("request_id")
	if requestID == "" {
		c.Redirect(http.StatusFound, SettingsEndpoint)
		return
	}
	label := a.labelOf(c.Request.Context(), "", requestID)
	deleted, err := a.clients.RevokeGrant(c.Request.Context(), requestID)
	if err != nil {
		a.logger.Error("Failed to revoke grant", zap.Error(err))
		c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=revoke_failed")
		return
	}
	a.logRevoke(c, revokeEvent{scope: "grant", subject: requestID, label: label, records: deleted})
	c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=revoked")
}

// handleSettingsRevokeAll is the panic button: every client's records in one
// transaction. The operator's own account and passkeys are untouched — an
// answer to a compromise that locked out the only person who can respond
// would be the wrong reflex.
//
// It is reached from the confirmation panel the settings page renders for
// `?confirm=revoke_all`, so the destructive step needs two deliberate actions.
// That guards against a slip, not against an attacker: the CSRF token and the
// session are what make the POST authentic.
func (a *AuthRouter) handleSettingsRevokeAll(c *gin.Context) {
	if _, _, ok := a.requireOwnUser(c); !ok {
		return
	}
	deleted, err := a.clients.RevokeAll(c.Request.Context())
	if err != nil {
		a.logger.Error("Failed to revoke every client", zap.Error(err))
		c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=revoke_failed")
		return
	}
	a.logRevoke(c, revokeEvent{scope: "all", records: deleted})
	c.Redirect(http.StatusFound, SettingsEndpoint+"?msg=revoked_all")
}

// revokeEvent is what the auth log records about one operator revocation.
// A struct rather than four parameters (§3), which also makes the optional
// fields optional at the call site.
type revokeEvent struct {
	// scope is "client", "grant" or "all".
	scope string
	// subject is the client or request ID the revoke named; empty for "all".
	subject string
	// label is the operator's own name for the connection (F-025), when it
	// has one.
	label   string
	records int
}

// logRevoke emits the SR-8 auth event, so an operator kill is visible in the
// log next to the client-initiated RFC 7009 revocations that share its name.
// Only non-secret context travels: a client or request ID and the operator's
// own label, never a token.
func (a *AuthRouter) logRevoke(c *gin.Context, event revokeEvent) {
	fields := []zap.Field{
		zap.String("actor", "operator"),
		zap.String("scope", event.scope),
		zap.Int("records", event.records),
		zap.String("client_ip", c.ClientIP()),
	}
	if event.subject != "" {
		fields = append(fields, zap.String("subject", event.subject))
	}
	if event.label != "" {
		fields = append(fields, zap.String("label", event.label))
	}
	authevent.Log(a.logger, authevent.Revoked, fields...)
}

// labelOf resolves the operator's name for a client or a grant so the auth
// event can carry it. Best-effort by design: a revoke must never fail because
// a display name could not be read, so an error yields no label rather than an
// aborted kill.
func (a *AuthRouter) labelOf(ctx context.Context, clientID, requestID string) string {
	rows, err := a.clients.ListClientGrants(ctx)
	if err != nil {
		return ""
	}
	for _, row := range rows {
		if clientID != "" && row.ClientID == clientID {
			return row.Label
		}
		for _, grant := range row.Grants {
			if requestID != "" && grant.RequestID == requestID {
				return grant.Label
			}
		}
	}
	return ""
}
