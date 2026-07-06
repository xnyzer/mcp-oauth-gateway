package mcpproxy

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/blendle/zapdriver"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/auth"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/backend"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/idp"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/proxy"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/tlsreload"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
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

	// OIDCDiscoveryMirror serves the AS metadata additionally under
	// /.well-known/openid-configuration (SPEC §1.2, off by default).
	OIDCDiscoveryMirror bool
	// ClockSkew is the leeway for token time-claim validation
	// (SPEC §1.11.1; 0–5m, default set in main.go).
	ClockSkew time.Duration
}

const maxClockSkew = 5 * time.Minute

func Run(cfg Config) error {
	listen := cfg.Listen
	tlsListen := cfg.TLSListen
	autoTLS := cfg.AutoTLS
	tlsHost := cfg.TLSHost
	tlsDirectoryURL := cfg.TLSDirectoryURL
	tlsAcceptTOS := cfg.TLSAcceptTOS
	tlsCertFile := cfg.TLSCertFile
	tlsKeyFile := cfg.TLSKeyFile
	dataPath := cfg.DataPath
	repositoryBackend := cfg.RepositoryBackend
	repositoryDSN := cfg.RepositoryDSN
	externalURL := cfg.ExternalURL
	trustedProxy := cfg.TrustedProxies
	proxyHeaders := cfg.ProxyHeaders
	proxyBearerToken := cfg.ProxyBearerToken
	proxyTarget := cfg.ProxyTargets
	headerMapping := cfg.HeaderMapping

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	parsedExternalURL, err := url.Parse(externalURL)
	if err != nil {
		return fmt.Errorf("failed to parse external URL: %w", err)
	}
	if parsedExternalURL.Scheme != "http" && parsedExternalURL.Scheme != "https" {
		return fmt.Errorf("external URL must use http or https, got: %q", parsedExternalURL.Scheme)
	}
	if parsedExternalURL.Host == "" {
		return fmt.Errorf("external URL must be absolute, got: %s", externalURL)
	}
	if parsedExternalURL.Path != "" && parsedExternalURL.Path != "/" {
		return fmt.Errorf("external URL must not have a path, got: %s", parsedExternalURL.Path)
	}
	if parsedExternalURL.RawQuery != "" || parsedExternalURL.Fragment != "" {
		return fmt.Errorf("external URL must not have a query or fragment, got: %s", externalURL)
	}
	// SPEC §0: the issuer is the external URL without a trailing slash; the
	// same form is used in metadata, token iss/aud, and the RFC 9207 iss.
	parsedExternalURL.Path = ""
	externalURL = parsedExternalURL.String()

	if cfg.ClockSkew < 0 || cfg.ClockSkew > maxClockSkew {
		return fmt.Errorf("clock skew must be between 0 and %s, got: %s", maxClockSkew, cfg.ClockSkew)
	}

	if (tlsCertFile == "") != (tlsKeyFile == "") {
		return fmt.Errorf("both TLS certificate and key files must be provided together")
	}
	var manualTLS bool
	if tlsCertFile != "" && tlsKeyFile != "" {
		manualTLS = true
	}
	if manualTLS && tlsHost != "" {
		return fmt.Errorf("tlsHost cannot be used when TLS certificate and key files are provided")
	}
	if !manualTLS && !autoTLS && tlsHost != "" {
		return fmt.Errorf("tlsHost requires automatic TLS; remove noAutoTLS or provide certificate files instead")
	}

	if err := os.MkdirAll(dataPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	var secret []byte
	if envSecret := os.Getenv("AUTH_HMAC_SECRET"); envSecret != "" {
		secret, err = utils.SecretFromBase64(envSecret)
		if err != nil {
			return fmt.Errorf("failed to parse AUTH_HMAC_SECRET environment variable: %w", err)
		}
	} else {
		secret, err = utils.LoadOrGenerateSecret(path.Join(dataPath, "secret"))
		if err != nil {
			return fmt.Errorf("failed to load or generate secret: %w", err)
		}
	}

	var config zap.Config
	if os.Getenv("MODE") == "debug" {
		gin.SetMode(gin.DebugMode)
		config = zap.NewDevelopmentConfig()
	} else {
		gin.SetMode(gin.ReleaseMode)
		config = zapdriver.NewProductionConfig()
	}
	logger, err := config.Build()
	if err != nil {
		return fmt.Errorf("failed to build logger: %w", err)
	}

	if len(proxyTarget) == 0 {
		return fmt.Errorf("proxy target must be specified")
	}
	var be backend.Backend
	var beHandler http.Handler
	if proxyURL, err := url.Parse(proxyTarget[0]); err == nil && (proxyURL.Scheme == "http" || proxyURL.Scheme == "https") {
		var err error
		be, err = backend.NewTransparentBackend(logger, proxyURL, trustedProxy)
		if err != nil {
			return fmt.Errorf("failed to create transparent backend: %w", err)
		}
		beHandler, err = be.Run(ctx)
		if err != nil {
			return fmt.Errorf("failed to create transparent backend: %w", err)
		}
	} else {
		be = backend.NewProxyBackend(logger, proxyTarget)
		beHandler, err = be.Run(ctx)
		if err != nil {
			return fmt.Errorf("failed to create proxy backend: %w", err)
		}
	}

	// Convert headers slice to map and integrate bearer token
	proxyHeadersMap := http.Header{}
	for _, header := range proxyHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("invalid proxy header format: %s", header)
		}
		proxyHeadersMap.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	// Add bearer token as Authorization header if provided
	if proxyBearerToken != "" {
		if proxyHeadersMap.Get("Authorization") != "" {
			logger.Warn("Authorization header already set, overwriting with bearer token")
		}
		proxyHeadersMap.Set("Authorization", "Bearer "+proxyBearerToken)
	}

	var repo repository.Repository
	switch backend := strings.ToLower(repositoryBackend); backend {
	case "", "local":
		repo, err = repository.NewKVSRepository(path.Join(dataPath, "db"), "mcp-oauth-gateway")
		if err != nil {
			return fmt.Errorf("failed to create repository: %w", err)
		}
	case "sqlite":
		if repositoryDSN == "" {
			return fmt.Errorf("repository DSN must be provided for sqlite backend")
		}
		repo, err = repository.NewSQLRepository("sqlite", repositoryDSN)
		if err != nil {
			return fmt.Errorf("failed to create repository: %w", err)
		}
	default:
		return fmt.Errorf("unsupported repository backend: %s", repositoryBackend)
	}
	defer func() {
		if err := repo.Close(); err != nil {
			logger.Warn("failed to close repository", zap.Error(err))
		}
	}()

	var privKey *rsa.PrivateKey
	if envKey := os.Getenv("JWT_PRIVATE_KEY"); envKey != "" {
		privKey, err = utils.PrivateKeyFromPEM(envKey)
		if err != nil {
			return fmt.Errorf("failed to parse JWT_PRIVATE_KEY environment variable: %w", err)
		}
	} else {
		privKey, err = utils.LoadOrGeneratePrivateKey(path.Join(dataPath, "private_key.pem"))
		if err != nil {
			return fmt.Errorf("failed to load or generate private key: %w", err)
		}
	}
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

	// Collect the top-level userinfo keys that are actually needed so the
	// session cookie doesn't store the entire provider response.
	userInfoFields := userInfoFieldsFromConfig(cfg.OIDCUserIDField, headerMapping)

	authRouter, err := auth.NewAuthRouter(passwordHashes, cfg.NoProviderAutoSelect, userInfoFields, providers...)
	if err != nil {
		return fmt.Errorf("failed to create auth router: %w", err)
	}
	idpRouter, err := idp.NewIDPRouter(idp.Config{
		Repo:                repo,
		PrivKey:             privKey,
		Logger:              logger,
		ExternalURL:         externalURL,
		Secret:              secret,
		AuthRouter:          authRouter,
		OIDCDiscoveryMirror: cfg.OIDCDiscoveryMirror,
	})
	if err != nil {
		return fmt.Errorf("failed to create IDP router: %w", err)
	}
	proxyRouter, err := newProxyRouter(proxy.Config{
		ExternalURL:                externalURL,
		Proxy:                      beHandler,
		PublicKey:                  &privKey.PublicKey,
		ProxyHeaders:               proxyHeadersMap,
		HTTPStreamingOnly:          cfg.HTTPStreamingOnly,
		ForwardAuthorizationHeader: cfg.ForwardAuthorizationHeader,
		HeaderMapping:              headerMapping,
		HeaderMappingBase:          cfg.HeaderMappingBase,
		ClockSkew:                  cfg.ClockSkew,
	})
	if err != nil {
		return fmt.Errorf("failed to create proxy router: %w", err)
	}

	router := gin.New()
	router.SetTrustedProxies(trustedProxy)

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
	store := cookie.NewStore(secret)
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   sessionCookieSecure(parsedExternalURL),
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
			Addr: listen,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				if host == "" {
					host = r.URL.Host
				}
				target := "https://" + host + r.RequestURI
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			}),
		}
		httpsServer := &http.Server{
			Addr:      tlsListen,
			Handler:   router,
			TLSConfig: &tls.Config{GetCertificate: certReloader.GetCertificate},
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
			Addr: listen,
			Handler: m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				if host == "" {
					host = r.URL.Host
				}
				target := "https://" + host + r.RequestURI
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})),
		}
		httpsServer := &http.Server{
			Addr:      tlsListen,
			Handler:   router,
			TLSConfig: m.TLSConfig(),
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
			Addr:    listen,
			Handler: router,
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

func sessionCookieSecure(externalURL *url.URL) bool {
	return externalURL.Scheme == "https"
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
