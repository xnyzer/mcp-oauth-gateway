package idp

import (
	"context"
	"strings"

	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
)

// CIMDResolver resolves a Client ID Metadata Document for an https://
// client ID (implemented by *cimd.Resolver; an interface for testability).
type CIMDResolver interface {
	Resolve(ctx context.Context, clientID string) (*cimd.Client, error)
}

// clientSource resolves CIMD client IDs first and falls back to the DCR
// store (SPEC §1.3); fosite uses it for every client lookup, so CIMD works
// at the authorize and token endpoints alike.
type clientSource struct {
	repository.Repository
	resolver    CIMDResolver
	externalURL string
	logger      *zap.Logger
}

// requestedRedirectURIKey carries the authorize request's raw redirect_uri
// down to GetClient. Fosite looks the client up itself and does not pass the
// request along, so the context is the only channel available.
type requestedRedirectURIKey struct{}

// withRequestedRedirectURI stashes the raw redirect_uri for GetClient.
func withRequestedRedirectURI(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, requestedRedirectURIKey{}, raw)
}

// requestedRedirectURI returns the stashed redirect_uri, or "" outside the
// authorize path — where GetClient then behaves exactly as it always has.
func requestedRedirectURI(ctx context.Context) string {
	raw, _ := ctx.Value(requestedRedirectURIKey{}).(string)
	return raw
}

func (s *clientSource) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	client, err := s.lookupClient(ctx, id)
	if err != nil {
		return nil, err
	}
	// Fosite matches the requested redirect URI against this list and ignores
	// the port for loopback IP literals only. Admit the "localhost" hostname
	// on the same terms by adding the requested URI when it differs from a
	// registered one in nothing but the port (SPEC §1.3.3).
	raw := requestedRedirectURI(ctx)
	if raw == "" {
		return client, nil
	}
	// Only DefaultClient exposes a redirect list to extend. Anything else is
	// returned untouched rather than asserted — models.FromFositeClient type-
	// asserts without checking, so a foreign client type must never appear.
	def, ok := client.(*fosite.DefaultClient)
	if !ok {
		return client, nil
	}
	expanded := expandLoopbackRedirects(def.RedirectURIs, raw)
	if len(expanded) == len(def.RedirectURIs) {
		return client, nil
	}
	// Copy before handing it back: today both paths build a fresh client per
	// call, but mutating a store-owned object would be a latent aliasing bug.
	clone := *def
	clone.RedirectURIs = expanded
	return &clone, nil
}

func (s *clientSource) lookupClient(ctx context.Context, id string) (fosite.Client, error) {
	if s.resolver == nil || !strings.HasPrefix(id, "https://") {
		return s.Repository.GetClient(ctx, id)
	}
	doc, err := s.resolver.Resolve(ctx, id)
	if err != nil {
		// Resolution detail stays in the logs (SR-8); the client only
		// sees invalid_client (SPEC §1.3.6, fail-closed).
		s.logger.Warn("CIMD resolution failed", zap.String("client_id", id), zap.Error(err))
		return nil, fosite.ErrNotFound
	}
	return &fosite.DefaultClient{
		ID:            doc.ClientID,
		RedirectURIs:  doc.RedirectURIs,
		GrantTypes:    doc.GrantTypes,
		ResponseTypes: doc.ResponseTypes,
		Scopes:        strings.Fields(doc.Scope),
		Audience:      []string{s.externalURL},
		Public:        true, // CIMD clients are public; PKCE is enforced
	}, nil
}
