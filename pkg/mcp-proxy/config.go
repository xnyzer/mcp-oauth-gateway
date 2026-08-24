package mcpproxy

import (
	"fmt"
	"net/url"
	"time"

	"github.com/xnyzer/mcp-oauth-gateway/pkg/backend"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/keys"
)

// resolvedConfig is the configuration after startup normalisation: defaults
// applied, values validated, and the derived forms the rest of the assembly
// needs. Producing it is the first thing Run does, and it is the only place
// that may still reject the configuration outright (SPEC §3, fail-fast).
type resolvedConfig struct {
	Config

	// issuerURL is EXTERNAL_URL parsed and stripped of its path, i.e. the
	// issuer in the SPEC §0 sense. issuer holds the same value as a string,
	// which is what most consumers want.
	issuerURL *url.URL
	issuer    string

	// trustedProxies is the normalised TRUSTED_PROXIES list: bare IPs
	// widened to /32 and /128 so gin and the transparent backend see one
	// identical list (SPEC §3.1).
	trustedProxies []string

	// manualTLS reports that a certificate and key file were supplied, as
	// opposed to built-in ACME or TLS terminated by a fronting proxy.
	manualTLS bool
}

// resolveConfig validates and normalises the configuration, or fails.
//
// The order of the checks is part of the contract: the startup error a
// misconfigured deployment sees is the *first* problem found, and the tests
// covering SPEC §3.2 assert on those messages.
func resolveConfig(cfg Config) (resolvedConfig, error) {
	issuerURL, err := url.Parse(cfg.ExternalURL)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("failed to parse external URL: %w", err)
	}
	if issuerURL.Scheme != "http" && issuerURL.Scheme != "https" {
		return resolvedConfig{}, fmt.Errorf("external URL must use http or https, got: %q", issuerURL.Scheme)
	}
	if issuerURL.Host == "" {
		return resolvedConfig{}, fmt.Errorf("external URL must be absolute, got: %s", cfg.ExternalURL)
	}
	if issuerURL.Path != "" && issuerURL.Path != "/" {
		return resolvedConfig{}, fmt.Errorf("external URL must not have a path, got: %s", issuerURL.Path)
	}
	if issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return resolvedConfig{}, fmt.Errorf("external URL must not have a query or fragment, got: %s", cfg.ExternalURL)
	}
	// SPEC §0: the issuer is the external URL without a trailing slash; the
	// same form is used in metadata, token iss/aud, and the RFC 9207 iss.
	issuerURL.Path = ""

	if cfg.ClockSkew < 0 || cfg.ClockSkew > maxClockSkew {
		return resolvedConfig{}, fmt.Errorf("clock skew must be between 0 and %s, got: %s", maxClockSkew, cfg.ClockSkew)
	}
	// Zero TTLs (programmatic use) fall back to the SPEC defaults;
	// RefreshTokenTTL 0 means "refresh grant disabled" and stays as is.
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = time.Hour
	}
	if cfg.AuthCodeTTL == 0 {
		cfg.AuthCodeTTL = 10 * time.Minute
	}
	if cfg.KeyAlg == "" {
		cfg.KeyAlg = string(keys.AlgRS256)
	}
	if err := validateTTLs(cfg); err != nil {
		return resolvedConfig{}, err
	}

	// TRUSTED_PROXIES accepts bare IPs and CIDR ranges (SPEC §3.1, audit
	// M8); normalise once so gin and the transparent backend see the same
	// list and an invalid entry fails fast here.
	trustedProxies, err := backend.NormalizeTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("invalid TRUSTED_PROXIES: %w", err)
	}

	manualTLS, err := resolveTLSMode(cfg)
	if err != nil {
		return resolvedConfig{}, err
	}

	return resolvedConfig{
		Config:         cfg,
		issuerURL:      issuerURL,
		issuer:         issuerURL.String(),
		trustedProxies: trustedProxies,
		manualTLS:      manualTLS,
	}, nil
}

// refreshSweepTTL is the window the expiry sweeper uses for refresh-token
// records. With the refresh grant disabled (RefreshTokenTTL 0) no refresh
// token is ever issued, so the access-token window is the safe stand-in.
func (rc resolvedConfig) refreshSweepTTL() time.Duration {
	if rc.RefreshTokenTTL == 0 {
		return rc.AccessTokenTTL
	}
	return rc.RefreshTokenTTL
}

// resolveTLSMode reports whether the gateway serves a supplied certificate,
// and rejects the flag combinations that cannot be satisfied at once.
func resolveTLSMode(cfg Config) (bool, error) {
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return false, fmt.Errorf("both TLS certificate and key files must be provided together")
	}
	manualTLS := cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
	if manualTLS && cfg.TLSHost != "" {
		return false, fmt.Errorf("tlsHost cannot be used when TLS certificate and key files are provided")
	}
	if !manualTLS && !cfg.AutoTLS && cfg.TLSHost != "" {
		return false, fmt.Errorf("tlsHost requires automatic TLS; remove noAutoTLS or provide certificate files instead")
	}
	return manualTLS, nil
}
