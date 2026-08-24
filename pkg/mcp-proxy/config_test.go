package mcpproxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// validConfig is a configuration that resolves cleanly, so a test can change
// exactly one field and attribute the failure to it.
func validConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Listen:            ":0",
		TLSListen:         ":0",
		DataPath:          t.TempDir(),
		RepositoryBackend: "local",
		ExternalURL:       "http://localhost",
		ProxyTargets:      []string{"http://example.com"},
		HeaderMappingBase: "/userinfo",
		DCREnabled:        true,
	}
}

// TestResolveConfig_RequiresAClientRegistrationMechanism covers the one
// SPEC §3.2 fail-fast that had no test: disabling CIMD and DCR together leaves
// no way for a client to obtain an identity, so the gateway must refuse to
// start rather than come up unusable.
func TestResolveConfig_RequiresAClientRegistrationMechanism(t *testing.T) {
	cfg := validConfig(t)
	cfg.CIMDEnabled = false
	cfg.DCREnabled = false

	_, err := resolveConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one client registration mechanism")

	t.Run("either one on its own is enough", func(t *testing.T) {
		for name, mutate := range map[string]func(*Config){
			"DCR only": func(c *Config) { c.DCREnabled = true },
			"CIMD only": func(c *Config) {
				c.CIMDEnabled = true
				c.CIMDFetchTimeout = 5 * time.Second
				c.CIMDMaxSize = 65536
				c.CIMDCacheTTL = time.Hour
			},
		} {
			t.Run(name, func(t *testing.T) {
				cfg := validConfig(t)
				cfg.CIMDEnabled, cfg.DCREnabled = false, false
				mutate(&cfg)
				_, err := resolveConfig(cfg)
				require.NoError(t, err)
			})
		}
	})
}

// TestResolveConfig_NormalizesIssuer pins the SPEC §0 normalisation the rest of
// the assembly depends on: the issuer carries no trailing slash, and the
// parsed and string forms agree.
func TestResolveConfig_NormalizesIssuer(t *testing.T) {
	cfg := validConfig(t)
	cfg.ExternalURL = "https://gateway.example.com/"

	rc, err := resolveConfig(cfg)
	require.NoError(t, err)
	require.Equal(t, "https://gateway.example.com", rc.issuer)
	require.Equal(t, rc.issuer, rc.issuerURL.String())
	require.Empty(t, rc.issuerURL.Path)
}

// TestResolveTLSMode covers the flag combinations that cannot be satisfied at
// once, plus the two that can.
func TestResolveTLSMode(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*Config)
		manualTLS   bool
		errContains string
	}{
		{name: "no TLS options is reverse-proxy mode"},
		{name: "cert and key together", mutate: func(c *Config) { c.TLSCertFile, c.TLSKeyFile = "cert.pem", "key.pem" }, manualTLS: true},
		{name: "cert without key", mutate: func(c *Config) { c.TLSCertFile = "cert.pem" }, errContains: "must be provided together"},
		{name: "key without cert", mutate: func(c *Config) { c.TLSKeyFile = "key.pem" }, errContains: "must be provided together"},
		{
			name:        "manual cert with tlsHost",
			mutate:      func(c *Config) { c.TLSCertFile, c.TLSKeyFile, c.TLSHost = "cert.pem", "key.pem", "gateway.example.com" },
			errContains: "tlsHost cannot be used",
		},
		{
			name:        "tlsHost without automatic TLS",
			mutate:      func(c *Config) { c.TLSHost = "gateway.example.com" },
			errContains: "tlsHost requires automatic TLS",
		},
		{
			name:      "tlsHost with automatic TLS",
			mutate:    func(c *Config) { c.TLSHost, c.AutoTLS = "gateway.example.com", true },
			manualTLS: false,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}
			manualTLS, err := resolveTLSMode(cfg)
			if tt.errContains != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.manualTLS, manualTLS)
		})
	}
}
