package mcpproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/idp"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/proxy"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/version"
	"golang.org/x/crypto/bcrypt"
)

// buildRouter assembles the whole gateway onto one gin engine and returns it
// **without listening**. Serving is the caller's business, which is what lets
// the end-to-end tests drive the real wiring through httptest instead of
// rebuilding it — a second construction of the same thing drifts, and this one
// had (F-022e).
//
// The order of the middleware is contract, not taste: /healthz is registered
// before the origin check so a health probe stays reachable, and the origin
// check sits ahead of the session store so a rebinding attempt is turned away
// before it can touch session or auth state (SPEC §0).
func buildRouter(ctx context.Context, rc resolvedConfig, deps *dependencies) (*gin.Engine, error) {
	authRouter, err := newAuthRouter(ctx, rc, deps)
	if err != nil {
		return nil, err
	}
	idpRouter, err := newIDPRouter(rc, deps, authRouter)
	if err != nil {
		return nil, err
	}
	proxyRouter, err := newProxySurface(rc, deps)
	if err != nil {
		return nil, err
	}

	router := gin.New()
	if err := router.SetTrustedProxies(rc.trustedProxies); err != nil {
		return nil, fmt.Errorf("failed to set trusted proxies: %w", err)
	}

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router.Use(ginzap.Ginzap(deps.logger, time.RFC3339, true))
	router.Use(ginzap.CustomRecoveryWithZap(deps.logger, true, func(c *gin.Context, err any) {
		if err == http.ErrAbortHandler {
			c.Abort()
			return
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	}))

	// Ahead of the session store and every route, so a rebinding attempt is
	// turned away before it can touch session or auth state. /healthz is
	// registered above this line and therefore stays reachable regardless.
	if rc.OriginCheckEnabled {
		router.Use(requireSameOrigin(normalizeOrigin(rc.issuer), deps.logger))
	} else {
		deps.logger.Warn("Origin validation is disabled (ORIGIN_CHECK_ENABLED=false); " +
			"the gateway will accept requests from any origin (SR-9)")
	}

	store, err := newSessionStore(rc, deps.secret)
	if err != nil {
		return nil, err
	}
	router.Use(sessions.Sessions("session", store))

	authRouter.SetupRoutes(router)
	idpRouter.SetupRoutes(router)
	proxyRouter.SetupRoutes(router)
	return router, nil
}

// newSessionStore builds the operator session cookie with distinct
// authentication and encryption subkeys, so it is signed **and** encrypted
// (SPEC §1.12/§2.2). fosite keeps the raw secret as its GlobalSecret, so issued
// tokens are unaffected; only the short-lived operator session cookie has this
// format.
func newSessionStore(rc resolvedConfig, secret []byte) (cookie.Store, error) {
	authKey, encKey, err := deriveCookieKeys(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive session cookie keys: %w", err)
	}
	store := cookie.NewStore(authKey, encKey)
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   sessionCookieSecure(rc.issuerURL, rc.manualTLS || rc.TLSHost != ""),
		SameSite: http.SameSiteLaxMode,
	})
	return store, nil
}

// newAuthRouter builds the operator login surface and refuses to start when no
// backend could ever log the operator in (SPEC §3.1).
func newAuthRouter(ctx context.Context, rc resolvedConfig, deps *dependencies) (*auth.AuthRouter, error) {
	providers, err := buildOIDCProviders(rc)
	if err != nil {
		return nil, err
	}
	passwordHashes, err := buildPasswordHashes(rc)
	if err != nil {
		return nil, err
	}

	// At least one auth backend must be able to log the operator in
	// (SPEC §3.1): a password, an OIDC provider, or an already-enrolled
	// passkey. Otherwise every login would dead-end — fail fast instead.
	if len(passwordHashes) == 0 && len(providers) == 0 {
		if !hasEnrolledPasskey(ctx, deps.repo) {
			return nil, fmt.Errorf("no authentication backend configured: set PASSWORD or PASSWORD_HASH (or configure OIDC); passkeys require a bootstrap login first")
		}
		deps.logger.Info("No password or OIDC provider configured; relying on enrolled passkeys for login")
	}

	return auth.NewAuthRouter(auth.Config{
		PasswordHashes:       passwordHashes,
		NoProviderAutoSelect: rc.NoProviderAutoSelect,
		// Only the top-level userinfo keys that are actually needed, so the
		// session cookie doesn't store the entire provider response.
		UserInfoFields: userInfoFieldsFromConfig(rc.OIDCUserIDField, rc.HeaderMapping),
		Providers:      providers,
		Users:          deps.repo,
		Clients:        deps.repo,
		ExternalURL:    rc.issuer,
		Logger:         deps.logger,
		LoginRateLimit: ratelimit.Middleware(deps.limiters.login, "login", deps.logger),
		Lockout:        deps.limiters.lockout,
		Version:        version.Version,
	})
}

// buildOIDCProviders returns the optional generic OIDC login backend, active
// only when URL, client ID and secret are all set.
func buildOIDCProviders(rc resolvedConfig) ([]auth.Provider, error) {
	if rc.OIDCConfigurationURL == "" || rc.OIDCClientID == "" || rc.OIDCClientSecret == "" {
		return nil, nil
	}
	provider, err := auth.NewOIDCProvider(
		rc.OIDCConfigurationURL,
		rc.OIDCScopes,
		rc.OIDCUserIDField,
		rc.OIDCProviderName,
		rc.issuer,
		rc.OIDCClientID,
		rc.OIDCClientSecret,
		rc.OIDCAllowedUsers,
		rc.OIDCAllowedUsersGlob,
		rc.OIDCAllowedAttributes,
		rc.OIDCAllowedAttributesGlob,
	)
	if errors.Is(err, auth.ErrNoAllowList) {
		return nil, fmt.Errorf("failed to create OIDC provider: %w — set at least one of OIDC_ALLOWED_USERS, OIDC_ALLOWED_USERS_GLOB, OIDC_ALLOWED_ATTRIBUTES, OIDC_ALLOWED_ATTRIBUTES_GLOB; to admit every account of the provider, say so with OIDC_ALLOWED_USERS_GLOB=*", err)
	}
	if errors.Is(err, auth.ErrInvalidGlobPattern) {
		// The likeliest cause is not a typo but the list syntax: the setting
		// is split at commas before a pattern is read, so `{a,b}` arrives in
		// two halves unless its comma is escaped.
		return nil, fmt.Errorf("failed to create OIDC provider: %w — in OIDC_ALLOWED_USERS_GLOB and OIDC_ALLOWED_ATTRIBUTES_GLOB a comma separates patterns, so write a comma inside one as \\,", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}
	return []auth.Provider{provider}, nil
}

// buildPasswordHashes turns the configured password and/or hash into the list
// the login surface checks against. A plain password is hashed at startup so
// it never sits in memory in the clear beyond that point.
func buildPasswordHashes(rc resolvedConfig) ([]string, error) {
	var hashes []string
	if rc.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(rc.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to generate password hash: %w", err)
		}
		hashes = append(hashes, string(hash))
	}
	if rc.PasswordHash != "" {
		hashes = append(hashes, rc.PasswordHash)
	}
	return hashes, nil
}

// newIDPRouter builds the OAuth surface (SPEC §1.1–§1.10).
func newIDPRouter(rc resolvedConfig, deps *dependencies, authRouter *auth.AuthRouter) (*idp.IDPRouter, error) {
	router, err := idp.NewIDPRouter(idp.Config{
		Repo:                deps.repo,
		Keys:                deps.keys,
		Logger:              deps.logger,
		ExternalURL:         rc.issuer,
		Secret:              deps.secret,
		AuthRouter:          authRouter,
		OIDCDiscoveryMirror: rc.OIDCDiscoveryMirror,
		AccessTokenTTL:      rc.AccessTokenTTL,
		AuthCodeTTL:         rc.AuthCodeTTL,
		RefreshTokenTTL:     rc.RefreshTokenTTL,
		CIMDResolver:        deps.cimdResolver,
		DCREnabled:          rc.DCREnabled,
		DCRClientTTL:        rc.DCRClientTTL,
		DCRMaxClients:       rc.DCRMaxClients,
		TokenRateLimit:      ratelimit.Middleware(deps.limiters.token, "token", deps.logger),
		RegisterRateLimit:   ratelimit.Middleware(deps.limiters.register, "register", deps.logger),
		AuthorizeRateLimit:  ratelimit.Middleware(deps.limiters.authorize, "authorize", deps.logger),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create IDP router: %w", err)
	}
	return router, nil
}

// newProxySurface builds the protected proxy surface (SPEC §1.11).
func newProxySurface(rc resolvedConfig, deps *dependencies) (*proxy.ProxyRouter, error) {
	router, err := newProxyRouter(proxy.Config{
		ExternalURL:                rc.issuer,
		Proxy:                      deps.upstream,
		VerificationKey:            deps.keys.VerificationKey,
		ProxyHeaders:               deps.proxyHeaders,
		HTTPStreamingOnly:          rc.HTTPStreamingOnly,
		ForwardAuthorizationHeader: rc.ForwardAuthorizationHeader,
		HeaderMapping:              rc.HeaderMapping,
		HeaderMappingBase:          rc.HeaderMappingBase,
		ClockSkew:                  rc.ClockSkew,
		TokenActive:                tokenActiveChecker(deps),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy router: %w", err)
	}
	return router, nil
}

// tokenActiveChecker implements the revocation check the proxy performs
// (SPEC §2.4): a token is active while its server-side record exists. fosite
// keys access-token records by the JWT's signature segment.
func tokenActiveChecker(deps *dependencies) func(context.Context, string) error {
	return func(ctx context.Context, rawToken string) error {
		parts := strings.Split(rawToken, ".")
		if len(parts) != 3 {
			return proxy.ErrTokenInactive
		}
		if _, err := deps.repo.GetAccessTokenSession(ctx, parts[2], nil); err != nil {
			if errors.Is(err, fosite.ErrNotFound) {
				return proxy.ErrTokenInactive
			}
			return err
		}
		return nil
	}
}
