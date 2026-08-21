package idp

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	foauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type IDPRouter struct {
	repo                repository.Repository
	keys                *keys.Manager
	logger              *zap.Logger
	externalURL         string
	hasher              fosite.Hasher
	provider            fosite.OAuth2Provider
	authRouter          *auth.AuthRouter
	oidcDiscoveryMirror bool
	refreshEnabled      bool
	cimdEnabled         bool
	dcrEnabled          bool
	dcrClientTTL        time.Duration
	dcrMaxClients       int
	tokenRateLimit      gin.HandlerFunc
	registerRateLimit   gin.HandlerFunc
	authorizeRateLimit  gin.HandlerFunc
}

// Config carries all options for the OAuth authorization-server surface
// (SPEC §1.2–§1.10).
type Config struct {
	Repo repository.Repository
	// Keys manages the signing key set (SPEC §2.2/§2.3): tokens are signed
	// with the active key and validated against active + retiring keys.
	Keys   *keys.Manager
	Logger *zap.Logger
	// ExternalURL is the normalized issuer (no trailing slash, SPEC §0).
	ExternalURL string
	Secret      []byte
	AuthRouter  *auth.AuthRouter
	// OIDCDiscoveryMirror additionally serves the AS metadata under
	// /.well-known/openid-configuration (SPEC §1.2, off by default).
	OIDCDiscoveryMirror bool
	// AccessTokenTTL and AuthCodeTTL default to 1h / 10m when zero.
	// RefreshTokenTTL of 0 disables the refresh grant (SPEC §3.2).
	AccessTokenTTL  time.Duration
	AuthCodeTTL     time.Duration
	RefreshTokenTTL time.Duration
	// CIMDResolver resolves https:// client IDs (SPEC §1.3). nil disables
	// CIMD; only stored DCR registrations are accepted then.
	CIMDResolver CIMDResolver
	// DCREnabled serves POST /.idp/register and advertises it in the AS
	// metadata (SPEC §1.4). CIMD is unaffected.
	DCREnabled bool
	// DCRClientTTL expires DCR registrations (refreshed on token issuance);
	// 0 disables expiry. DCRMaxClients caps stored registrations; 0 means
	// unlimited (SR-5).
	DCRClientTTL  time.Duration
	DCRMaxClients int
	// TokenRateLimit / RegisterRateLimit / AuthorizeRateLimit guard the public
	// token, registration and authorize endpoints (SR-5); nil disables. The
	// authorize limit also bounds CIMD-resolution fetches driven by unique
	// client IDs (SPEC §1.3).
	TokenRateLimit     gin.HandlerFunc
	RegisterRateLimit  gin.HandlerFunc
	AuthorizeRateLimit gin.HandlerFunc
}

const (
	defaultAccessTokenTTL = time.Hour
	defaultAuthCodeTTL    = 10 * time.Minute
)

func NewIDPRouter(cfg Config) (*IDPRouter, error) {
	hasher := &fosite.BCrypt{
		Config: &fosite.Config{
			HashCost: bcrypt.DefaultCost,
		},
	}
	accessTokenTTL := cfg.AccessTokenTTL
	if accessTokenTTL == 0 {
		accessTokenTTL = defaultAccessTokenTTL
	}
	authCodeTTL := cfg.AuthCodeTTL
	if authCodeTTL == 0 {
		authCodeTTL = defaultAuthCodeTTL
	}
	refreshEnabled := cfg.RefreshTokenTTL > 0
	fositeConfig := &fosite.Config{
		GlobalSecret:          cfg.Secret,
		AccessTokenLifespan:   accessTokenTTL,
		AuthorizeCodeLifespan: authCodeTTL,
		RefreshTokenLifespan:  cfg.RefreshTokenTTL,
		RefreshTokenScopes:    []string{},
		AccessTokenIssuer:     cfg.ExternalURL,
		// PKCE is REQUIRED for every client (SPEC §1.5) — confidential DCR
		// clients included, not only public/CIMD ones. The public-client
		// flag stays set as defence-in-depth should EnforcePKCE ever change.
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy:                  fosite.HierarchicScopeStrategy,
		MinParameterEntropy:            fosite.MinParameterEntropy,
		ClientSecretsHasher:            hasher,
		// Space-separated scope claim (SPEC §1.7).
		JWTScopeClaimKey: jwt.JWTScopeFieldString,
	}
	storage := &clientSource{
		Repository:  cfg.Repo,
		resolver:    cfg.CIMDResolver,
		externalURL: cfg.ExternalURL,
		logger:      cfg.Logger,
	}
	provider := customCompose(fositeConfig, storage, cfg.Keys, refreshEnabled)

	return &IDPRouter{
		repo:                cfg.Repo,
		keys:                cfg.Keys,
		logger:              cfg.Logger,
		externalURL:         cfg.ExternalURL,
		hasher:              hasher,
		provider:            provider,
		authRouter:          cfg.AuthRouter,
		oidcDiscoveryMirror: cfg.OIDCDiscoveryMirror,
		refreshEnabled:      refreshEnabled,
		// The resolver's presence is what makes CIMD work, so it is also
		// what the metadata advertises — the two cannot drift apart.
		cimdEnabled:        cfg.CIMDResolver != nil,
		dcrEnabled:         cfg.DCREnabled,
		dcrClientTTL:       cfg.DCRClientTTL,
		dcrMaxClients:      cfg.DCRMaxClients,
		tokenRateLimit:     cfg.TokenRateLimit,
		registerRateLimit:  cfg.RegisterRateLimit,
		authorizeRateLimit: cfg.AuthorizeRateLimit,
	}, nil
}

// withRateLimit prepends a rate-limit middleware when configured.
func withRateLimit(limit gin.HandlerFunc, handlers ...gin.HandlerFunc) []gin.HandlerFunc {
	if limit == nil {
		return handlers
	}
	return append([]gin.HandlerFunc{limit}, handlers...)
}

func customCompose(config *fosite.Config, storage any, keyManager *keys.Manager, refreshEnabled bool) fosite.OAuth2Provider {
	// The multi-key signer keeps fosite's own JWT validation (introspection)
	// working across key rotations (SPEC §2.3.3); jwt.DefaultSigner would
	// only ever verify against the active key.
	signer := &keys.FositeSigner{Keys: keyManager}
	keyGetter := func(context.Context) (any, error) { return keyManager.Active().Key, nil }

	factories := []compose.Factory{
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenRevocationFactory,
	}
	if refreshEnabled {
		factories = append(factories, compose.OAuth2RefreshTokenGrantFactory)
	}

	return compose.Compose(
		config,
		storage,
		&compose.CommonStrategy{
			CoreStrategy: &foauth2.DefaultJWTStrategy{
				Signer:          signer,
				HMACSHAStrategy: compose.NewOAuth2HMACStrategy(config),
				Config:          config,
			},
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     signer,
		},
		factories...,
	)
}

const (
	AuthorizationEndpoint            = "/.idp/auth"
	AuthorizationReturnEndpoint      = "/.idp/auth/:ar_id"
	TokenEndpoint                    = "/.idp/token"
	IntrospectionEndpoint            = "/.idp/introspect"
	RevocationEndpoint               = "/.idp/revoke"
	RegistrationEndpoint             = "/.idp/register"
	OauthAuthorizationServerEndpoint = "/.well-known/oauth-authorization-server"
	OIDCDiscoveryEndpoint            = "/.well-known/openid-configuration"
	JWKSEndpoint                     = "/.well-known/jwks.json"
	sessionKeyAuthorizeRequestIDs    = "idp_authorize_request_ids"
)

func (a *IDPRouter) SetupRoutes(router gin.IRouter) {
	router.GET(AuthorizationEndpoint, withRateLimit(a.authorizeRateLimit, a.handleAuth)...)
	router.GET(AuthorizationReturnEndpoint, a.authRouter.RequireAuth(), a.handleAuthorizationReturnForm)
	router.POST(AuthorizationReturnEndpoint, a.authRouter.RequireAuth(), a.authRouter.RequireCSRF(), a.handleAuthorizationReturn)
	router.POST(TokenEndpoint, withRateLimit(a.tokenRateLimit, a.handleToken)...)
	router.POST(IntrospectionEndpoint, a.handleIntrospect)
	router.POST(RevocationEndpoint, a.handleRevoke)
	if a.dcrEnabled {
		router.POST(RegistrationEndpoint, withRateLimit(a.registerRateLimit, a.handleRegister)...)
	}
	router.GET(OauthAuthorizationServerEndpoint, a.handleOauthAuthorizationServer)
	if a.oidcDiscoveryMirror {
		router.GET(OIDCDiscoveryEndpoint, a.handleOauthAuthorizationServer)
	}
	router.GET(JWKSEndpoint, a.handleJWKS)
}
