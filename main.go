package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	mcpproxy "github.com/xnyzer/mcp-oauth-gateway/pkg/mcp-proxy"
)

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return strings.EqualFold(value, "true") || value == "1"
	}
	return defaultValue
}

// getEnvDurationWithDefault fails fast on a malformed duration instead of
// silently falling back (config validation, CODING-STANDARDS §7).
func getEnvDurationWithDefault(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		panic(fmt.Sprintf("invalid duration in %s: %q", key, value))
	}
	return parsed
}

// getEnvIntWithDefault fails fast on a malformed integer (CODING-STANDARDS §7).
func getEnvIntWithDefault(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Sprintf("invalid integer in %s: %q", key, value))
	}
	return parsed
}

// getEnvInt64WithDefault fails fast on a malformed integer (CODING-STANDARDS §7).
func getEnvInt64WithDefault(key string, defaultValue int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("invalid integer in %s: %q", key, value))
	}
	return parsed
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// splitWithEscapes splits a string by delimiter, respecting escape sequences
// e.g., "a,b\,c,d" with delimiter "," returns ["a", "b,c", "d"]
func splitWithEscapes(s, delimiter string) []string {
	if s == "" {
		return []string{}
	}

	var result []string
	var current strings.Builder
	escaped := false

	for i := 0; i < len(s); i++ {
		if escaped {
			current.WriteByte(s[i])
			escaped = false
		} else if s[i] == '\\' && i+1 < len(s) {
			// Check if next character is the delimiter
			if strings.HasPrefix(s[i+1:], delimiter) {
				// Skip the backslash and add the delimiter character
				escaped = true
			} else {
				// Not escaping delimiter, keep the backslash
				current.WriteByte(s[i])
			}
		} else if strings.HasPrefix(s[i:], delimiter) {
			// Found unescaped delimiter
			result = append(result, strings.TrimSpace(current.String()))
			current.Reset()
			i += len(delimiter) - 1 // -1 because loop will increment
		} else {
			current.WriteByte(s[i])
		}
	}

	// Add the last part
	result = append(result, strings.TrimSpace(current.String()))
	return result
}

// parseAttributeMap parses a comma-separated string of key=value pairs into a map
// where each key can have multiple values. Format: /key1=value1,/key1=value2,/key2=value3
// Keys are JSON pointers to attributes in the userinfo response.
func parseAttributeMap(s string) map[string][]string {
	result := make(map[string][]string)
	if s == "" {
		return result
	}
	parts := splitWithEscapes(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eqIdx := strings.Index(part, "=")
		if eqIdx == -1 {
			continue
		}
		key := strings.TrimSpace(part[:eqIdx])
		value := strings.TrimSpace(part[eqIdx+1:])
		if key != "" && value != "" {
			result[key] = append(result[key], value)
		}
	}
	return result
}

func parseHeaderMapping(s string) map[string]string {
	result := make(map[string]string)
	if s == "" {
		return result
	}
	parts := splitWithEscapes(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		colonIdx := strings.LastIndex(part, ":")
		if colonIdx == -1 {
			continue
		}
		pointer := strings.TrimSpace(part[:colonIdx])
		header := strings.TrimSpace(part[colonIdx+1:])
		if pointer != "" && header != "" {
			result[pointer] = header
		}
	}
	return result
}

type proxyRunnerFunc func(cfg mcpproxy.Config) error

func main() {
	if err := newRootCommand(mcpproxy.Run).Execute(); err != nil {
		panic(err)
	}
}

func newRootCommand(run proxyRunnerFunc) *cobra.Command {
	var listen string
	var tlsListen string
	var noAutoTLS bool
	var tlsHost string
	var tlsDirectoryURL string
	var tlsAcceptTOS bool
	var tlsCertFile string
	var tlsKeyFile string
	var dataPath string
	var repositoryBackend string
	var repositoryDSN string
	var externalURL string
	var oidcConfigurationURL string
	var oidcClientID string
	var oidcClientSecret string
	var oidcScopes string
	var oidcUserIDField string
	var oidcProviderName string
	var oidcAllowedUsers string
	var oidcAllowedUsersGlob string
	var oidcAllowedAttributes string
	var oidcAllowedAttributesGlob string
	var noProviderAutoSelect bool
	var password string
	var passwordHash string
	var proxyBearerToken string
	var forwardAuthorizationHeader bool
	var proxyHeaders string
	var headerMapping string
	var headerMappingBase string
	var httpStreamingOnly bool
	var trustedProxies string
	var oidcDiscoveryMirror bool
	var clockSkew time.Duration
	var accessTokenTTL time.Duration
	var authCodeTTL time.Duration
	var refreshTokenTTL time.Duration
	var cimdEnabled bool
	var cimdFetchTimeout time.Duration
	var cimdMaxSize int64
	var cimdCacheTTL time.Duration
	var dcrEnabled bool
	var dcrClientTTL time.Duration
	var dcrMaxClients int
	var keyAlg string
	var keyRotationInterval time.Duration
	var rateLimitRegister string
	var rateLimitToken string
	var rateLimitLogin string
	var loginLockoutThreshold int
	var loginLockoutDuration time.Duration

	rootCmd := &cobra.Command{
		Use: "mcp-oauth-gateway",
		Run: func(cmd *cobra.Command, args []string) {
			oidcAllowedUsersList := splitCSV(oidcAllowedUsers)

			var oidcAllowedUsersGlobList []string
			if oidcAllowedUsersGlob != "" {
				oidcAllowedUsersGlobList = splitWithEscapes(oidcAllowedUsersGlob, ",")
			}

			oidcAllowedAttributesMap := parseAttributeMap(oidcAllowedAttributes)
			oidcAllowedAttributesGlobMap := parseAttributeMap(oidcAllowedAttributesGlob)

			oidcScopesList := splitCSV(oidcScopes)
			if len(oidcScopesList) == 0 {
				oidcScopesList = []string{"openid", "profile", "email"}
			}

			trustedProxiesList := splitCSV(trustedProxies)
			proxyHeadersList := splitCSV(proxyHeaders)

			headerMappingMap := parseHeaderMapping(headerMapping)

			if err := run(mcpproxy.Config{
				Listen:          listen,
				TLSListen:       tlsListen,
				AutoTLS:         (!noAutoTLS) || tlsCertFile != "" || tlsKeyFile != "",
				TLSHost:         tlsHost,
				TLSDirectoryURL: tlsDirectoryURL,
				TLSAcceptTOS:    tlsAcceptTOS,
				TLSCertFile:     tlsCertFile,
				TLSKeyFile:      tlsKeyFile,

				DataPath:          dataPath,
				RepositoryBackend: repositoryBackend,
				RepositoryDSN:     repositoryDSN,
				ExternalURL:       externalURL,

				OIDCConfigurationURL:      oidcConfigurationURL,
				OIDCClientID:              oidcClientID,
				OIDCClientSecret:          oidcClientSecret,
				OIDCScopes:                oidcScopesList,
				OIDCUserIDField:           oidcUserIDField,
				OIDCProviderName:          oidcProviderName,
				OIDCAllowedUsers:          oidcAllowedUsersList,
				OIDCAllowedUsersGlob:      oidcAllowedUsersGlobList,
				OIDCAllowedAttributes:     oidcAllowedAttributesMap,
				OIDCAllowedAttributesGlob: oidcAllowedAttributesGlobMap,

				NoProviderAutoSelect: noProviderAutoSelect,
				Password:             password,
				PasswordHash:         passwordHash,

				TrustedProxies:             trustedProxiesList,
				ProxyHeaders:               proxyHeadersList,
				ProxyBearerToken:           proxyBearerToken,
				ForwardAuthorizationHeader: forwardAuthorizationHeader,
				ProxyTargets:               args,
				HTTPStreamingOnly:          httpStreamingOnly,
				HeaderMapping:              headerMappingMap,
				HeaderMappingBase:          headerMappingBase,

				OIDCDiscoveryMirror: oidcDiscoveryMirror,
				ClockSkew:           clockSkew,
				AccessTokenTTL:      accessTokenTTL,
				AuthCodeTTL:         authCodeTTL,
				RefreshTokenTTL:     refreshTokenTTL,

				CIMDEnabled:      cimdEnabled,
				CIMDFetchTimeout: cimdFetchTimeout,
				CIMDMaxSize:      cimdMaxSize,
				CIMDCacheTTL:     cimdCacheTTL,
				DCREnabled:       dcrEnabled,
				DCRClientTTL:     dcrClientTTL,
				DCRMaxClients:    dcrMaxClients,

				KeyAlg:              keyAlg,
				KeyRotationInterval: keyRotationInterval,

				RateLimitRegister:     rateLimitRegister,
				RateLimitToken:        rateLimitToken,
				RateLimitLogin:        rateLimitLogin,
				LoginLockoutThreshold: loginLockoutThreshold,
				LoginLockoutDuration:  loginLockoutDuration,
			}); err != nil {
				panic(err)
			}
		},
	}

	rootCmd.Flags().StringVar(&listen, "listen", getEnvWithDefault("LISTEN", ":80"), "Address to listen on")
	rootCmd.Flags().StringVar(&tlsListen, "tls-listen", getEnvWithDefault("TLS_LISTEN", ":443"), "Address to listen on for TLS")
	rootCmd.Flags().BoolVar(&noAutoTLS, "no-auto-tls", getEnvBoolWithDefault("NO_AUTO_TLS", false), "Disable automatic TLS host detection from externalURL")
	rootCmd.Flags().StringVarP(&tlsHost, "tls-host", "H", getEnvWithDefault("TLS_HOST", ""), "Host name for automatic TLS certificate provisioning")
	rootCmd.Flags().StringVar(&tlsDirectoryURL, "tls-directory-url", getEnvWithDefault("TLS_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"), "ACME directory URL for TLS certificates")
	rootCmd.Flags().BoolVar(&tlsAcceptTOS, "tls-accept-tos", getEnvBoolWithDefault("TLS_ACCEPT_TOS", false), "Accept TLS terms of service")
	rootCmd.Flags().StringVar(&tlsCertFile, "tls-cert-file", getEnvWithDefault("TLS_CERT_FILE", ""), "Path to TLS certificate file (PEM). Requires --tls-key-file")
	rootCmd.Flags().StringVar(&tlsKeyFile, "tls-key-file", getEnvWithDefault("TLS_KEY_FILE", ""), "Path to TLS private key file (PEM). Requires --tls-cert-file")
	rootCmd.Flags().StringVarP(&dataPath, "data-path", "d", getEnvWithDefault("DATA_PATH", "./data"), "Path to the data directory")
	rootCmd.Flags().StringVar(&repositoryBackend, "repository-backend", getEnvWithDefault("REPOSITORY_BACKEND", "local"), "Repository backend to use: local (embedded bbolt, default) or sqlite")
	rootCmd.Flags().StringVar(&repositoryDSN, "repository-dsn", getEnvWithDefault("REPOSITORY_DSN", ""), "DSN passed directly to the SQL driver (required when repository-backend is sqlite)")
	rootCmd.Flags().StringVarP(&externalURL, "external-url", "e", getEnvWithDefault("EXTERNAL_URL", "http://localhost"), "External URL for the proxy")

	// OIDC configuration
	rootCmd.Flags().StringVar(&oidcConfigurationURL, "oidc-configuration-url", getEnvWithDefault("OIDC_CONFIGURATION_URL", ""), "OIDC configuration URL")
	rootCmd.Flags().StringVar(&oidcClientID, "oidc-client-id", getEnvWithDefault("OIDC_CLIENT_ID", ""), "OIDC client ID")
	rootCmd.Flags().StringVar(&oidcClientSecret, "oidc-client-secret", getEnvWithDefault("OIDC_CLIENT_SECRET", ""), "OIDC client secret")
	rootCmd.Flags().StringVar(&oidcScopes, "oidc-scopes", getEnvWithDefault("OIDC_SCOPES", "openid,profile,email"), "Comma-separated list of OIDC scopes")
	rootCmd.Flags().StringVar(&oidcUserIDField, "oidc-user-id-field", getEnvWithDefault("OIDC_USER_ID_FIELD", "/email"), "JSON pointer to user ID field in userinfo endpoint response")
	rootCmd.Flags().StringVar(&oidcProviderName, "oidc-provider-name", getEnvWithDefault("OIDC_PROVIDER_NAME", "OIDC"), "Display name for OIDC provider")
	rootCmd.Flags().StringVar(&oidcAllowedUsers, "oidc-allowed-users", getEnvWithDefault("OIDC_ALLOWED_USERS", ""), "Comma-separated list of allowed OIDC users")
	rootCmd.Flags().StringVar(&oidcAllowedUsersGlob, "oidc-allowed-users-glob", getEnvWithDefault("OIDC_ALLOWED_USERS_GLOB", ""), "Comma-separated list of glob patterns for allowed OIDC users")
	rootCmd.Flags().StringVar(&oidcAllowedAttributes, "oidc-allowed-attributes", getEnvWithDefault("OIDC_ALLOWED_ATTRIBUTES", ""), "Comma-separated list of allowed attribute key=value pairs (e.g., /groups=admin,/roles=editor). Keys are JSON pointers.")
	rootCmd.Flags().StringVar(&oidcAllowedAttributesGlob, "oidc-allowed-attributes-glob", getEnvWithDefault("OIDC_ALLOWED_ATTRIBUTES_GLOB", ""), "Comma-separated list of attribute key=pattern pairs for glob matching (e.g., /groups=*-admins,/email=*@example.com). Keys are JSON pointers.")

	// Discovery & token validation
	rootCmd.Flags().BoolVar(&oidcDiscoveryMirror, "oidc-discovery-mirror", getEnvBoolWithDefault("OIDC_DISCOVERY_MIRROR", false), "Additionally serve the AS metadata under /.well-known/openid-configuration")
	rootCmd.Flags().DurationVar(&clockSkew, "clock-skew", getEnvDurationWithDefault("CLOCK_SKEW", 30*time.Second), "Leeway for token time-claim validation (0-5m)")

	// Token lifetimes
	rootCmd.Flags().DurationVar(&accessTokenTTL, "access-token-ttl", getEnvDurationWithDefault("ACCESS_TOKEN_TTL", time.Hour), "Access token lifetime (1m-24h)")
	rootCmd.Flags().DurationVar(&authCodeTTL, "auth-code-ttl", getEnvDurationWithDefault("AUTH_CODE_TTL", 10*time.Minute), "Authorization code lifetime (30s-1h)")
	rootCmd.Flags().DurationVar(&refreshTokenTTL, "refresh-token-ttl", getEnvDurationWithDefault("REFRESH_TOKEN_TTL", 720*time.Hour), "Refresh token lifetime (1h-8760h; 0 disables the refresh grant)")

	// Client registration: CIMD (primary) + DCR (deprecated fallback)
	rootCmd.Flags().BoolVar(&cimdEnabled, "cimd-enabled", getEnvBoolWithDefault("CIMD_ENABLED", true), "Accept CIMD client IDs (HTTPS URLs resolving to a Client ID Metadata Document)")
	rootCmd.Flags().DurationVar(&cimdFetchTimeout, "cimd-fetch-timeout", getEnvDurationWithDefault("CIMD_FETCH_TIMEOUT", 5*time.Second), "Timeout for fetching a CIMD document (1s-1m)")
	rootCmd.Flags().Int64Var(&cimdMaxSize, "cimd-max-size", getEnvInt64WithDefault("CIMD_MAX_SIZE", 65536), "Maximum CIMD document size in bytes (1KiB-1MiB)")
	rootCmd.Flags().DurationVar(&cimdCacheTTL, "cimd-cache-ttl", getEnvDurationWithDefault("CIMD_CACHE_TTL", time.Hour), "Cache lifetime for resolved CIMD documents (1m-24h)")
	rootCmd.Flags().BoolVar(&dcrEnabled, "dcr-enabled", getEnvBoolWithDefault("DCR_ENABLED", true), "Serve the deprecated RFC 7591 dynamic client registration endpoint")
	rootCmd.Flags().DurationVar(&dcrClientTTL, "dcr-client-ttl", getEnvDurationWithDefault("DCR_CLIENT_TTL", 720*time.Hour), "DCR registration lifetime, refreshed on token issuance (0 disables expiry)")
	rootCmd.Flags().IntVar(&dcrMaxClients, "dcr-max-clients", getEnvIntWithDefault("DCR_MAX_CLIENTS", 100), "Maximum number of stored DCR registrations (0 = unlimited)")

	// Signing keys
	rootCmd.Flags().StringVar(&keyAlg, "key-alg", getEnvWithDefault("KEY_ALG", "RS256"), "JWS signing algorithm: RS256 or ES256 (switching triggers a key rotation)")
	rootCmd.Flags().DurationVar(&keyRotationInterval, "key-rotation-interval", getEnvDurationWithDefault("KEY_ROTATION_INTERVAL", 2160*time.Hour), "Automatic signing-key rotation interval, at least 1h (0 disables rotation)")

	// Abuse protection: per-client-IP rate limits + login lockout
	rootCmd.Flags().StringVar(&rateLimitRegister, "rate-limit-register", getEnvWithDefault("RATE_LIMIT_REGISTER", "10/m"), "Per-IP rate limit for client registration, format N/s|m|h (0 disables)")
	rootCmd.Flags().StringVar(&rateLimitToken, "rate-limit-token", getEnvWithDefault("RATE_LIMIT_TOKEN", "60/m"), "Per-IP rate limit for the token endpoint, format N/s|m|h (0 disables)")
	rootCmd.Flags().StringVar(&rateLimitLogin, "rate-limit-login", getEnvWithDefault("RATE_LIMIT_LOGIN", "10/m"), "Per-IP rate limit for the login surfaces, format N/s|m|h (0 disables)")
	rootCmd.Flags().IntVar(&loginLockoutThreshold, "login-lockout-threshold", getEnvIntWithDefault("LOGIN_LOCKOUT_THRESHOLD", 10), "Consecutive failed password logins before the account locks (0 disables)")
	rootCmd.Flags().DurationVar(&loginLockoutDuration, "login-lockout-duration", getEnvDurationWithDefault("LOGIN_LOCKOUT_DURATION", 15*time.Minute), "How long the account stays locked (1m-24h)")

	// Password authentication
	rootCmd.Flags().BoolVar(&noProviderAutoSelect, "no-provider-auto-select", getEnvBoolWithDefault("NO_PROVIDER_AUTO_SELECT", false), "Disable auto-redirect when only one OAuth/OIDC provider is configured and no password is set")
	rootCmd.Flags().StringVar(&password, "password", getEnvWithDefault("PASSWORD", ""), "Plain text password for authentication (will be hashed with bcrypt)")
	rootCmd.Flags().StringVar(&passwordHash, "password-hash", getEnvWithDefault("PASSWORD_HASH", ""), "Bcrypt hash of password for authentication")

	// Proxy headers configuration
	rootCmd.Flags().StringVar(&proxyBearerToken, "proxy-bearer-token", getEnvWithDefault("PROXY_BEARER_TOKEN", ""), "Bearer token to add to Authorization header when proxying requests")
	rootCmd.Flags().BoolVar(&forwardAuthorizationHeader, "proxy-forward-authorization", getEnvBoolWithDefault("PROXY_FORWARD_AUTHORIZATION", false), "Forward the incoming Authorization bearer token to the backend after validation")
	rootCmd.Flags().StringVar(&trustedProxies, "trusted-proxies", getEnvWithDefault("TRUSTED_PROXIES", ""), "Comma-separated list of trusted proxies (IP addresses or CIDR ranges)")
	rootCmd.Flags().StringVar(&proxyHeaders, "proxy-headers", getEnvWithDefault("PROXY_HEADERS", ""), "Comma-separated list of headers to add when proxying requests (format: Header1:Value1,Header2:Value2)")
	rootCmd.Flags().BoolVar(&httpStreamingOnly, "http-streaming-only", getEnvBoolWithDefault("HTTP_STREAMING_ONLY", false), "Reject SSE (GET) requests and keep the backend in HTTP streaming-only mode")
	rootCmd.Flags().StringVar(&headerMapping, "header-mapping", getEnvWithDefault("HEADER_MAPPING", ""), "Comma-separated mapping of JSON pointer paths to header names (e.g., /email:X-Forwarded-Email,/preferred_username:X-Forwarded-User)")
	rootCmd.Flags().StringVar(&headerMappingBase, "header-mapping-base", getEnvWithDefault("HEADER_MAPPING_BASE", "/userinfo"), "JSON pointer base path for header mapping claims lookup (e.g., /userinfo or /)")

	return rootCmd
}
