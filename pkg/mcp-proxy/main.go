package mcpproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/cimd"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/idp"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/proxy"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/ratelimit"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/tlsreload"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

var ServerShutdownTimeout = 5 * time.Second

var newProxyRouter = proxy.NewProxyRouter

// Config carries the full gateway configuration (SPEC §3). Field names
// mirror the CLI flags / env vars defined in main.go.
type Config struct {
	Listen          string
	TLSListen       string
	AutoTLS         bool
	TLSHost         string
	TLSDirectoryURL string
	TLSAcceptTOS    bool
	TLSCertFile     string
	TLSKeyFile      string

	DataPath          string
	RepositoryBackend string
	RepositoryDSN     string

	// ExternalURL is the public base URL; Run normalizes it to the issuer
	// form — absolute, http(s), no path/query/fragment, no trailing slash
	// (SPEC §0) — and fails fast otherwise.
	ExternalURL string

	OIDCConfigurationURL      string
	OIDCClientID              string
	OIDCClientSecret          string
	OIDCScopes                []string
	OIDCUserIDField           string
	OIDCProviderName          string
	OIDCAllowedUsers          []string
	OIDCAllowedUsersGlob      []string
	OIDCAllowedAttributes     map[string][]string
	OIDCAllowedAttributesGlob map[string][]string

	NoProviderAutoSelect bool
	Password             string
	PasswordHash         string

	TrustedProxies             []string
	ProxyHeaders               []string
	ProxyBearerToken           string
	ForwardAuthorizationHeader bool
	ProxyTargets               []string
	HTTPStreamingOnly          bool
	HeaderMapping              map[string]string
	HeaderMappingBase          string

	// OriginCheckEnabled rejects a request whose Origin header names a
	// foreign origin (SR-9, on by default in main.go). A request without an
	// Origin header always passes — see requireSameOrigin.
	OriginCheckEnabled bool
	// OIDCDiscoveryMirror serves the AS metadata additionally under
	// /.well-known/openid-configuration (SPEC §1.2, off by default).
	OIDCDiscoveryMirror bool
	// ClockSkew is the leeway for token time-claim validation
	// (SPEC §1.11.1; 0–5m, default set in main.go).
	ClockSkew time.Duration
	// Token lifetimes (SPEC §3.2). AccessTokenTTL 1m–24h, AuthCodeTTL
	// 30s–1h; RefreshTokenTTL 0 disables the refresh grant.
	AccessTokenTTL  time.Duration
	AuthCodeTTL     time.Duration
	RefreshTokenTTL time.Duration

	// CIMD client identification (SPEC §1.3; on by default in main.go).
	CIMDEnabled      bool
	CIMDFetchTimeout time.Duration
	CIMDMaxSize      int64
	CIMDCacheTTL     time.Duration
	// DCR fallback (SPEC §1.4; on by default in main.go).
	DCREnabled    bool
	DCRClientTTL  time.Duration
	DCRMaxClients int

	// Signing keys (SPEC §2.2/§2.3). KeyAlg is RS256 (default) or ES256;
	// switching triggers a rotation at startup. KeyRotationInterval of 0
	// disables automatic rotation.
	KeyAlg              string
	KeyRotationInterval time.Duration

	// Abuse protection (SPEC §3.2, SR-5/SR-6). Rate limits are per-client-
	// IP expressions like "10/m"; "0" or empty disables one. The lockout
	// locks the operator account after LoginLockoutThreshold consecutive
	// failed password logins for LoginLockoutDuration; threshold 0
	// disables it.
	RateLimitRegister     string
	RateLimitToken        string
	RateLimitLogin        string
	RateLimitAuthorize    string
	LoginLockoutThreshold int
	LoginLockoutDuration  time.Duration
}

const (
	maxClockSkew = 5 * time.Minute
	// sweepInterval is how often expired session records are garbage-
	// collected (SPEC §2.1).
	sweepInterval = 5 * time.Minute
	// readHeaderTimeout bounds the request-header read on every listener
	// (Slowloris; gosec G112). Header-phase only — SSE / streamable-HTTP
	// responses are unaffected.
	readHeaderTimeout = 10 * time.Second
)

// validateTTLs enforces the SPEC §3.2 ranges (fail-fast at startup).
func validateTTLs(cfg Config) error {
	if cfg.AccessTokenTTL < time.Minute || cfg.AccessTokenTTL > 24*time.Hour {
		return fmt.Errorf("access token TTL must be between 1m and 24h, got: %s", cfg.AccessTokenTTL)
	}
	if cfg.AuthCodeTTL < 30*time.Second || cfg.AuthCodeTTL > time.Hour {
		return fmt.Errorf("auth code TTL must be between 30s and 1h, got: %s", cfg.AuthCodeTTL)
	}
	if cfg.RefreshTokenTTL != 0 && (cfg.RefreshTokenTTL < time.Hour || cfg.RefreshTokenTTL > 365*24*time.Hour) {
		return fmt.Errorf("refresh token TTL must be 0 (disabled) or between 1h and 8760h, got: %s", cfg.RefreshTokenTTL)
	}
	if cfg.CIMDEnabled {
		if cfg.CIMDFetchTimeout < time.Second || cfg.CIMDFetchTimeout > time.Minute {
			return fmt.Errorf("CIMD fetch timeout must be between 1s and 1m, got: %s", cfg.CIMDFetchTimeout)
		}
		if cfg.CIMDMaxSize < 1024 || cfg.CIMDMaxSize > 1024*1024 {
			return fmt.Errorf("CIMD max document size must be between 1KiB and 1MiB, got: %d", cfg.CIMDMaxSize)
		}
		if cfg.CIMDCacheTTL < time.Minute || cfg.CIMDCacheTTL > 24*time.Hour {
			return fmt.Errorf("CIMD cache TTL must be between 1m and 24h, got: %s", cfg.CIMDCacheTTL)
		}
	}
	if !cfg.CIMDEnabled && !cfg.DCREnabled {
		return fmt.Errorf("at least one client registration mechanism (CIMD or DCR) must be enabled")
	}
	if cfg.DCRClientTTL != 0 && cfg.DCRClientTTL < time.Hour {
		return fmt.Errorf("DCR client TTL must be 0 (no expiry) or at least 1h, got: %s", cfg.DCRClientTTL)
	}
	if cfg.DCRMaxClients < 0 {
		return fmt.Errorf("DCR client cap must not be negative, got: %d", cfg.DCRMaxClients)
	}
	if _, err := keys.ParseAlg(cfg.KeyAlg); err != nil {
		return err
	}
	if cfg.KeyRotationInterval != 0 && cfg.KeyRotationInterval < time.Hour {
		return fmt.Errorf("key rotation interval must be 0 (disabled) or at least 1h, got: %s", cfg.KeyRotationInterval)
	}
	for name, value := range map[string]string{
		"register rate limit":  cfg.RateLimitRegister,
		"token rate limit":     cfg.RateLimitToken,
		"login rate limit":     cfg.RateLimitLogin,
		"authorize rate limit": cfg.RateLimitAuthorize,
	} {
		if value == "" {
			continue // empty means disabled (programmatic use)
		}
		if _, err := ratelimit.ParseLimit(value); err != nil {
			return fmt.Errorf("invalid %s: %w", name, err)
		}
	}
	if cfg.LoginLockoutThreshold < 0 {
		return fmt.Errorf("login lockout threshold must not be negative, got: %d", cfg.LoginLockoutThreshold)
	}
	if cfg.LoginLockoutThreshold > 0 && (cfg.LoginLockoutDuration < time.Minute || cfg.LoginLockoutDuration > 24*time.Hour) {
		return fmt.Errorf("login lockout duration must be between 1m and 24h, got: %s", cfg.LoginLockoutDuration)
	}
	return nil
}

// parseLimit re-parses an already-validated rate expression; empty means
// disabled.
func parseLimit(value string) ratelimit.Limit {
	if value == "" {
		return ratelimit.Limit{}
	}
	limit, err := ratelimit.ParseLimit(value)
	if err != nil {
		return ratelimit.Limit{} // unreachable: validateTTLs ran first
	}
	return limit
}

func Run(cfg Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	rc, err := resolveConfig(cfg)
	if err != nil {
		return err
	}
	cfg = rc.Config

	deps, err := openDependencies(ctx, rc)
	if err != nil {
		return err
	}
	defer func() {
		if err := deps.repo.Close(); err != nil {
			deps.logger.Warn("failed to close repository", zap.Error(err))
		}
	}()
	deps.startSweeper(ctx, rc)

	// Names the wiring below still reads. F-022e extracts that wiring next
	// and these go with it.
	listen, tlsListen := rc.Listen, rc.TLSListen
	autoTLS, tlsHost := rc.AutoTLS, rc.TLSHost
	tlsDirectoryURL, tlsAcceptTOS := rc.TLSDirectoryURL, rc.TLSAcceptTOS
	tlsCertFile, tlsKeyFile := rc.TLSCertFile, rc.TLSKeyFile
	dataPath, headerMapping := rc.DataPath, rc.HeaderMapping
	parsedExternalURL, externalURL := rc.issuerURL, rc.issuer
	trustedProxy, manualTLS := rc.trustedProxies, rc.manualTLS
	logger, secret, repo, keyManager := deps.logger, deps.secret, deps.repo, deps.keys
	beHandler, proxyHeadersMap := deps.upstream, deps.proxyHeaders
	be := deps.upstreamBackend
	registerLimiter, tokenLimiter := deps.limiters.register, deps.limiters.token
	loginLimiter, authorizeLimiter := deps.limiters.login, deps.limiters.authorize
	loginLockout := deps.limiters.lockout

	var providers []auth.Provider

	// Add OIDC provider if configured
	if cfg.OIDCConfigurationURL != "" && cfg.OIDCClientID != "" && cfg.OIDCClientSecret != "" {
		oidcProvider, err := auth.NewOIDCProvider(
			cfg.OIDCConfigurationURL,
			cfg.OIDCScopes,
			cfg.OIDCUserIDField,
			cfg.OIDCProviderName,
			externalURL,
			cfg.OIDCClientID,
			cfg.OIDCClientSecret,
			cfg.OIDCAllowedUsers,
			cfg.OIDCAllowedUsersGlob,
			cfg.OIDCAllowedAttributes,
			cfg.OIDCAllowedAttributesGlob,
		)
		if err != nil {
			return fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		providers = append(providers, oidcProvider)
	}

	var passwordHashes []string

	// Handle password argument - generate bcrypt hash if provided
	if cfg.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(cfg.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to generate password hash: %w", err)
		}
		passwordHashes = append(passwordHashes, string(hash))
	}

	// Handle password-hash argument - use directly if provided
	if cfg.PasswordHash != "" {
		passwordHashes = append(passwordHashes, cfg.PasswordHash)
	}

	// At least one auth backend must be able to log the operator in
	// (SPEC §3.1): a password, an OIDC provider, or an already-enrolled
	// passkey. Otherwise every login would dead-end — fail fast instead.
	if len(passwordHashes) == 0 && len(providers) == 0 {
		if !hasEnrolledPasskey(ctx, repo) {
			return fmt.Errorf("no authentication backend configured: set PASSWORD or PASSWORD_HASH (or configure OIDC); passkeys require a bootstrap login first")
		}
		logger.Info("No password or OIDC provider configured; relying on enrolled passkeys for login")
	}

	// Collect the top-level userinfo keys that are actually needed so the
	// session cookie doesn't store the entire provider response.
	userInfoFields := userInfoFieldsFromConfig(cfg.OIDCUserIDField, headerMapping)

	authRouter, err := auth.NewAuthRouter(auth.Config{
		PasswordHashes:       passwordHashes,
		NoProviderAutoSelect: cfg.NoProviderAutoSelect,
		UserInfoFields:       userInfoFields,
		Providers:            providers,
		Users:                repo,
		Clients:              repo,
		ExternalURL:          externalURL,
		Logger:               logger,
		LoginRateLimit:       ratelimit.Middleware(loginLimiter, "login", logger),
		Lockout:              loginLockout,
	})
	if err != nil {
		return fmt.Errorf("failed to create auth router: %w", err)
	}
	// Assigned only when enabled: a typed-nil *cimd.Resolver in the
	// interface field would defeat the nil check in the client source.
	var cimdResolver idp.CIMDResolver
	if cfg.CIMDEnabled {
		cimdResolver = cimd.NewResolver(cimd.Config{
			FetchTimeout: cfg.CIMDFetchTimeout,
			MaxSize:      cfg.CIMDMaxSize,
			CacheTTL:     cfg.CIMDCacheTTL,
		})
	}

	idpRouter, err := idp.NewIDPRouter(idp.Config{
		Repo:                repo,
		Keys:                keyManager,
		Logger:              logger,
		ExternalURL:         externalURL,
		Secret:              secret,
		AuthRouter:          authRouter,
		OIDCDiscoveryMirror: cfg.OIDCDiscoveryMirror,
		AccessTokenTTL:      cfg.AccessTokenTTL,
		AuthCodeTTL:         cfg.AuthCodeTTL,
		RefreshTokenTTL:     cfg.RefreshTokenTTL,
		CIMDResolver:        cimdResolver,
		DCREnabled:          cfg.DCREnabled,
		DCRClientTTL:        cfg.DCRClientTTL,
		DCRMaxClients:       cfg.DCRMaxClients,
		TokenRateLimit:      ratelimit.Middleware(tokenLimiter, "token", logger),
		RegisterRateLimit:   ratelimit.Middleware(registerLimiter, "register", logger),
		AuthorizeRateLimit:  ratelimit.Middleware(authorizeLimiter, "authorize", logger),
	})
	if err != nil {
		return fmt.Errorf("failed to create IDP router: %w", err)
	}

	// Revocation check for the proxy (SPEC §2.4): a token is active while
	// its server-side record exists. fosite keys access-token records by
	// the JWT's signature segment.
	tokenActive := func(ctx context.Context, rawToken string) error {
		parts := strings.Split(rawToken, ".")
		if len(parts) != 3 {
			return proxy.ErrTokenInactive
		}
		if _, err := repo.GetAccessTokenSession(ctx, parts[2], nil); err != nil {
			if errors.Is(err, fosite.ErrNotFound) {
				return proxy.ErrTokenInactive
			}
			return err
		}
		return nil
	}

	proxyRouter, err := newProxyRouter(proxy.Config{
		ExternalURL:                externalURL,
		Proxy:                      beHandler,
		VerificationKey:            keyManager.VerificationKey,
		ProxyHeaders:               proxyHeadersMap,
		HTTPStreamingOnly:          cfg.HTTPStreamingOnly,
		ForwardAuthorizationHeader: cfg.ForwardAuthorizationHeader,
		HeaderMapping:              headerMapping,
		HeaderMappingBase:          cfg.HeaderMappingBase,
		ClockSkew:                  cfg.ClockSkew,
		TokenActive:                tokenActive,
	})
	if err != nil {
		return fmt.Errorf("failed to create proxy router: %w", err)
	}

	router := gin.New()
	if err := router.SetTrustedProxies(trustedProxy); err != nil {
		return fmt.Errorf("failed to set trusted proxies: %w", err)
	}

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))
	router.Use(ginzap.CustomRecoveryWithZap(logger, true, func(c *gin.Context, err any) {
		if err == http.ErrAbortHandler {
			c.Abort()
			return
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	}))
	// Ahead of the session store and every route, so a rebinding attempt is
	// turned away before it can touch session or auth state. /healthz is
	// registered above this line and therefore stays reachable regardless.
	if cfg.OriginCheckEnabled {
		router.Use(requireSameOrigin(normalizeOrigin(parsedExternalURL.String()), logger))
	} else {
		logger.Warn("Origin validation is disabled (ORIGIN_CHECK_ENABLED=false); " +
			"the gateway will accept requests from any origin (SR-9)")
	}

	// Derive distinct authentication and encryption subkeys for the operator
	// session cookie so it is signed AND encrypted (SPEC §1.12/§2.2). fosite
	// keeps the raw secret as its GlobalSecret, so issued tokens are
	// unaffected; only the short-lived (MaxAge 600s) operator session cookie
	// changes format and is re-issued on the next login.
	cookieAuthKey, cookieEncKey, err := deriveCookieKeys(secret)
	if err != nil {
		return fmt.Errorf("failed to derive session cookie keys: %w", err)
	}
	store := cookie.NewStore(cookieAuthKey, cookieEncKey)
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   sessionCookieSecure(parsedExternalURL, manualTLS || tlsHost != ""),
		SameSite: http.SameSiteLaxMode,
	})
	router.Use(sessions.Sessions("session", store))
	authRouter.SetupRoutes(router)
	idpRouter.SetupRoutes(router)
	proxyRouter.SetupRoutes(router)

	var tlsHostDetected bool
	if autoTLS && !manualTLS &&
		tlsHost == "" &&
		parsedExternalURL.Scheme == "https" &&
		parsedExternalURL.Host != "localhost" {
		tlsHost = parsedExternalURL.Host
		tlsHostDetected = true
	}

	exit := make(chan struct{}, 3)
	var wg sync.WaitGroup
	errs := []error{}
	lock := sync.Mutex{}

	if manualTLS {
		certReloader, err := tlsreload.NewFileReloader(tlsCertFile, tlsKeyFile, logger)
		if err != nil {
			return fmt.Errorf("failed to prepare TLS certificate reloader: %w", err)
		}

		logger.Info("Starting server with provided TLS certificate")
		httpServer := &http.Server{
			Addr:              listen,
			Handler:           httpFallbackHandler(),
			ReadHeaderTimeout: readHeaderTimeout,
		}
		httpsServer := &http.Server{
			Addr:              tlsListen,
			Handler:           router,
			TLSConfig:         &tls.Config{GetCertificate: certReloader.GetCertificate},
			ReadHeaderTimeout: readHeaderTimeout,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTP server closed")
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpsServer.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTPS server closed")
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpsServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTPS server shutdown error", zap.Error(shutdownErr))
			}
		}()
	} else if tlsHost != "" {
		if !tlsAcceptTOS {
			if tlsHostDetected {
				return errors.New("TLS host is auto-detected, but tlsAcceptTOS is not set to true. Please agree to the TOS or set noAutoTLS to true")
			}
			return errors.New("TLS is enabled, but tlsAcceptTOS is not set to true. Please explicitly agree to the TOS")
		}

		m := autocert.Manager{
			Prompt: func(tosURL string) bool {
				return tlsAcceptTOS
			},
			HostPolicy: autocert.HostWhitelist(tlsHost),
			Cache:      autocert.DirCache(path.Join(dataPath, "certs")),
			Client: &acme.Client{
				DirectoryURL: tlsDirectoryURL,
			},
		}

		httpServer := &http.Server{
			Addr:              listen,
			Handler:           m.HTTPHandler(httpFallbackHandler()),
			ReadHeaderTimeout: readHeaderTimeout,
		}
		httpsServer := &http.Server{
			Addr:              tlsListen,
			Handler:           router,
			TLSConfig:         m.TLSConfig(),
			ReadHeaderTimeout: readHeaderTimeout,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTP server closed")
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpsServer.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTPS server closed")
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpsServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTPS server shutdown error", zap.Error(shutdownErr))
			}
		}()
	} else {
		httpServer := &http.Server{
			Addr:              listen,
			Handler:           router,
			ReadHeaderTimeout: readHeaderTimeout,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()
	}

	if be != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := be.Wait(); err != nil && !errors.Is(ctx.Err(), context.Canceled) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("proxy backend closed")
			exit <- struct{}{}
		}()
	}

	if manualTLS || tlsHost != "" {
		logger.Info("Starting server", zap.Strings("listen", []string{listen, tlsListen}))
	} else {
		logger.Info("Starting server", zap.Strings("listen", []string{listen}))
	}
	<-exit
	stop()
	wg.Wait()
	return errors.Join(errs...)
}

// httpFallbackHandler serves the plain-HTTP listener while TLS carries the
// real traffic: /healthz stays reachable for local container health probes
// (SPEC §1.13 — the healthcheck subcommand probes LISTEN in every mode),
// everything else redirects to https.
func httpFallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		//nolint:gosec // G710: same-host http→https upgrade, no cross-origin target
		http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
	})
}

// sessionCookieSecure decides the operator session cookie's Secure flag:
// set for an https issuer, and also when the gateway itself terminates TLS
// while the issuer says http (a misconfiguration — the §3.1 warning fires,
// but the cookie must not travel unprotected either; audit M7).
func sessionCookieSecure(externalURL *url.URL, servesTLS bool) bool {
	return externalURL.Scheme == "https" || servesTLS
}

// warnPlainHTTPIssuer emits the SPEC §3.1 startup WARNING: an http issuer
// on a non-loopback host sends tokens and cookies over the network
// unencrypted (audit M7). Loopback stays silent — local development.
func warnPlainHTTPIssuer(logger *zap.Logger, externalURL *url.URL) {
	if externalURL.Scheme != "http" || isLoopbackHost(externalURL.Hostname()) {
		return
	}
	logger.Warn("EXTERNAL_URL uses plain http on a non-loopback host — tokens and session cookies are exposed in transit; use https, or keep http strictly behind a TLS-terminating reverse proxy",
		zap.String("external_url", externalURL.String()))
}

// isLoopbackHost reports whether the issuer host is loopback ("localhost",
// "*.localhost", 127.0.0.0/8, ::1) — the only hosts where a plain-http
// issuer needs no warning (SPEC §3.1).
func isLoopbackHost(hostname string) bool {
	lower := strings.ToLower(hostname)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(hostname)
	return err == nil && addr.Unmap().IsLoopback()
}

// hasEnrolledPasskey reports whether the operator account exists and has at
// least one registered passkey (SPEC §3.1 auth-backend check).
func hasEnrolledPasskey(ctx context.Context, repo repository.Repository) bool {
	user, err := repo.GetUser(ctx)
	if err != nil {
		return false
	}
	credentials, err := repo.ListWebAuthnCredentials(ctx, user.ID)
	return err == nil && len(credentials) > 0
}

// userInfoFieldsFromConfig extracts the top-level userinfo keys referenced
// by the OIDC user-ID field and the header mapping. JSON pointers like
// "/email" or "/preferred_username" yield "email" or "preferred_username".
func userInfoFieldsFromConfig(oidcUserIDField string, headerMapping map[string]string) []string {
	seen := map[string]struct{}{}
	add := func(pointer string) {
		pointer = strings.TrimPrefix(pointer, "/")
		if i := strings.IndexByte(pointer, '/'); i != -1 {
			pointer = pointer[:i]
		}
		if pointer != "" {
			seen[pointer] = struct{}{}
		}
	}
	add(oidcUserIDField)
	for pointer := range headerMapping {
		add(pointer)
	}
	fields := make([]string, 0, len(seen))
	for k := range seen {
		fields = append(fields, k)
	}
	return fields
}
