package mcpproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/blendle/zapdriver"
	"github.com/gin-gonic/gin"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/backend"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/repository"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
	"go.uber.org/zap"
)

// dependencies are the long-lived collaborators the routers are built from.
// The caller owns repo and MUST close it; openDependencies closes it itself
// only when a later step fails, so a half-built gateway leaves no open store.
type dependencies struct {
	logger       *zap.Logger
	secret       []byte
	repo         repository.Repository
	keys         *keys.Manager
	limiters     limiters
	proxyHeaders http.Header

	// upstream serves the proxied traffic; upstreamBackend is the process
	// behind it, kept because shutdown waits on it.
	upstream        http.Handler
	upstreamBackend backend.Backend
}

// openDependencies performs every side effect startup needs before any route
// exists: the data directory, the session secret, the logger, the upstream
// backend, the store, and the signing keys.
func openDependencies(ctx context.Context, rc resolvedConfig) (*dependencies, error) {
	// 0700: the data directory holds keys and the token store (SPEC §2.2).
	if err := os.MkdirAll(rc.DataPath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	secret, err := loadSessionSecret(rc.DataPath)
	if err != nil {
		return nil, err
	}

	logger, err := buildLogger()
	if err != nil {
		return nil, err
	}
	warnPlainHTTPIssuer(logger, rc.issuerURL)

	upstreamBackend, upstream, err := openUpstream(ctx, rc, logger)
	if err != nil {
		return nil, err
	}

	proxyHeaders, err := buildProxyHeaders(rc, logger)
	if err != nil {
		return nil, err
	}

	repo, err := openRepository(ctx, rc)
	if err != nil {
		return nil, err
	}

	keyManager, err := openKeyManager(rc, logger)
	if err != nil {
		// The store is already open at this point and nothing else will
		// close it, because the caller only takes ownership on success.
		if closeErr := repo.Close(); closeErr != nil {
			logger.Warn("failed to close repository after a failed start", zap.Error(closeErr))
		}
		return nil, err
	}

	return &dependencies{
		logger:       logger,
		secret:       secret,
		repo:         repo,
		keys:         keyManager,
		limiters:     newLimiters(rc.Config),
		proxyHeaders: proxyHeaders,

		upstream:        upstream,
		upstreamBackend: upstreamBackend,
	}, nil
}

// loadSessionSecret takes the session/HMAC secret from the environment, or
// loads and generates one in the data directory (SPEC §2.2).
func loadSessionSecret(dataPath string) ([]byte, error) {
	if envSecret := os.Getenv("AUTH_HMAC_SECRET"); envSecret != "" {
		secret, err := utils.SecretFromBase64(envSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to parse AUTH_HMAC_SECRET environment variable: %w", err)
		}
		return secret, nil
	}
	secret, err := utils.LoadOrGenerateSecret(path.Join(dataPath, "secret"))
	if err != nil {
		return nil, fmt.Errorf("failed to load or generate secret: %w", err)
	}
	return secret, nil
}

// buildLogger returns the structured stdout logger (GR-4) and puts gin into
// the matching mode.
func buildLogger() (*zap.Logger, error) {
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
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}
	return logger, nil
}

// openUpstream starts the backend for the configured target: the transparent
// HTTP proxy for a URL, the stdio backend for a command (SPEC §3.1).
func openUpstream(ctx context.Context, rc resolvedConfig, logger *zap.Logger) (backend.Backend, http.Handler, error) {
	if len(rc.ProxyTargets) == 0 {
		return nil, nil, fmt.Errorf("proxy target must be specified")
	}

	if proxyURL, err := url.Parse(rc.ProxyTargets[0]); err == nil && (proxyURL.Scheme == "http" || proxyURL.Scheme == "https") {
		be, err := backend.NewTransparentBackend(logger, proxyURL, rc.trustedProxies)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create transparent backend: %w", err)
		}
		handler, err := be.Run(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create transparent backend: %w", err)
		}
		return be, handler, nil
	}

	be := backend.NewProxyBackend(logger, rc.ProxyTargets)
	handler, err := be.Run(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create proxy backend: %w", err)
	}
	return be, handler, nil
}

// buildProxyHeaders turns the configured static headers into the set injected
// toward the upstream, with the bearer token folded in (FR-6, SPEC §1.11.4).
func buildProxyHeaders(rc resolvedConfig, logger *zap.Logger) (http.Header, error) {
	headers := http.Header{}
	for _, header := range rc.ProxyHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid proxy header format: %s", header)
		}
		headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	if rc.ProxyBearerToken != "" {
		if headers.Get("Authorization") != "" {
			logger.Warn("Authorization header already set, overwriting with bearer token")
		}
		headers.Set("Authorization", "Bearer "+rc.ProxyBearerToken)
	}
	return headers, nil
}

// openRepository opens the configured store and refuses one written by a newer
// gateway (SPEC §2.5). The caller owns the returned repository.
func openRepository(ctx context.Context, rc resolvedConfig) (repository.Repository, error) {
	var repo repository.Repository
	var err error

	switch name := strings.ToLower(rc.RepositoryBackend); name {
	case "", "local":
		repo, err = repository.NewKVSRepository(path.Join(rc.DataPath, "db"), "mcp-oauth-gateway")
		if err != nil {
			return nil, fmt.Errorf("failed to create repository: %w", err)
		}
	case "sqlite":
		if rc.RepositoryDSN == "" {
			return nil, fmt.Errorf("repository DSN must be provided for sqlite backend")
		}
		repo, err = repository.NewSQLRepository("sqlite", rc.RepositoryDSN)
		if err != nil {
			return nil, fmt.Errorf("failed to create repository: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported repository backend: %s", rc.RepositoryBackend)
	}

	// Fail fast when the store stems from a newer gateway (SPEC §2.5).
	if err := repo.EnsureSchemaVersion(ctx, repository.SchemaVersion); err != nil {
		if closeErr := repo.Close(); closeErr != nil {
			err = fmt.Errorf("%w (and closing the store failed: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("schema version check failed: %w", err)
	}
	return repo, nil
}

// openKeyManager builds the signing-key manager (SPEC §2.2/§2.3): a key
// directory with a manifest and rotation, adopting the legacy single-key file
// on first start. A key from the environment stays static — no directory, no
// rotation.
func openKeyManager(rc resolvedConfig, logger *zap.Logger) (*keys.Manager, error) {
	keyAlg, err := keys.ParseAlg(rc.KeyAlg) // already validated in validateTTLs
	if err != nil {
		return nil, err
	}

	if envKey := os.Getenv("JWT_PRIVATE_KEY"); envKey != "" {
		envSigner, err := keys.ParsePrivateKeyPEM(envKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWT_PRIVATE_KEY environment variable: %w", err)
		}
		manager, err := keys.NewStaticManager(envSigner, keyAlg)
		if err != nil {
			return nil, err
		}
		if rc.KeyRotationInterval > 0 {
			logger.Warn("JWT_PRIVATE_KEY is set; automatic key rotation is disabled")
		}
		return manager, nil
	}

	manager, err := keys.NewManager(keys.Config{
		Dir:              path.Join(rc.DataPath, "keys"),
		Alg:              keyAlg,
		LegacyKeyPath:    path.Join(rc.DataPath, "private_key.pem"),
		RotationInterval: rc.KeyRotationInterval,
		RetireWindow:     rc.AccessTokenTTL + 2*rc.ClockSkew,
		Logger:           logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing keys: %w", err)
	}
	return manager, nil
}
