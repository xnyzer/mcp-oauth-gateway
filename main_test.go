package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	mcpproxy "github.com/xnyzer/mcp-oauth-gateway/pkg/mcp-proxy"
)

func TestSplitWithEscapes(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		delimiter string
		expected  []string
	}{
		{
			name:      "simple comma split",
			input:     "a,b,c",
			delimiter: ",",
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "escaped comma",
			input:     "a,b\\,c,d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "email with escaped comma",
			input:     "user@domain.com\\,backup,*@example.org",
			delimiter: ",",
			expected:  []string{"user@domain.com,backup", "*@example.org"},
		},
		{
			name:      "glob pattern with escaped comma",
			input:     "admin.*@company\\,inc.*,*@example.com",
			delimiter: ",",
			expected:  []string{"admin.*@company,inc.*", "*@example.com"},
		},
		{
			name:      "empty string",
			input:     "",
			delimiter: ",",
			expected:  []string{},
		},
		{
			name:      "single item",
			input:     "single",
			delimiter: ",",
			expected:  []string{"single"},
		},
		{
			name:      "no escapes needed",
			input:     "user1@example.com,user2@test.org",
			delimiter: ",",
			expected:  []string{"user1@example.com", "user2@test.org"},
		},
		{
			name:      "multiple escaped commas",
			input:     "a\\,b\\,c,d,e\\,f",
			delimiter: ",",
			expected:  []string{"a,b,c", "d", "e,f"},
		},
		{
			name:      "whitespace trimming",
			input:     "a , b\\,c , d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "different delimiter",
			input:     "a;b\\;c;d",
			delimiter: ";",
			expected:  []string{"a", "b;c", "d"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitWithEscapes(tc.input, tc.delimiter)

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseAttributeMap(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string][]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string][]string{},
		},
		{
			name:  "single key-value pair",
			input: "/groups=admin",
			expected: map[string][]string{
				"/groups": {"admin"},
			},
		},
		{
			name:  "multiple values for same key",
			input: "/groups=admin,/groups=users",
			expected: map[string][]string{
				"/groups": {"admin", "users"},
			},
		},
		{
			name:  "multiple keys",
			input: "/groups=admin,/department=engineering",
			expected: map[string][]string{
				"/groups":     {"admin"},
				"/department": {"engineering"},
			},
		},
		{
			name:  "nested key with JSON pointer",
			input: "/org/team=platform",
			expected: map[string][]string{
				"/org/team": {"platform"},
			},
		},
		{
			name:  "glob pattern value",
			input: "/groups=*-admins,/email=*@example.com",
			expected: map[string][]string{
				"/groups": {"*-admins"},
				"/email":  {"*@example.com"},
			},
		},
		{
			name:  "whitespace trimming",
			input: " /groups = admin , /role = editor ",
			expected: map[string][]string{
				"/groups": {"admin"},
				"/role":   {"editor"},
			},
		},
		{
			name:     "invalid format - no equals sign",
			input:    "invalid",
			expected: map[string][]string{},
		},
		{
			name:     "invalid format - empty key",
			input:    "=value",
			expected: map[string][]string{},
		},
		{
			name:     "invalid format - empty value",
			input:    "/key=",
			expected: map[string][]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseAttributeMap(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseHeaderMapping(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:  "single mapping",
			input: "/email:X-Forwarded-Email",
			expected: map[string]string{
				"/email": "X-Forwarded-Email",
			},
		},
		{
			name:  "multiple mappings",
			input: "/email:X-Forwarded-Email,/preferred_username:X-Forwarded-User",
			expected: map[string]string{
				"/email":              "X-Forwarded-Email",
				"/preferred_username": "X-Forwarded-User",
			},
		},
		{
			name:  "nested JSON pointer",
			input: "/org/team:X-Forwarded-Team",
			expected: map[string]string{
				"/org/team": "X-Forwarded-Team",
			},
		},
		{
			name:  "whitespace trimming",
			input: " /email : X-Forwarded-Email , /sub : X-Forwarded-Sub ",
			expected: map[string]string{
				"/email": "X-Forwarded-Email",
				"/sub":   "X-Forwarded-Sub",
			},
		},
		{
			name:     "no colon - skipped",
			input:    "invalid",
			expected: map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseHeaderMapping(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestGetEnvWithDefault(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		def      string
		expected string
		setEnv   bool
		envValue string
	}{
		{
			name:     "env var not set",
			key:      "TEST_KEY_NOT_SET",
			def:      "default_value",
			expected: "default_value",
			setEnv:   false,
		},
		{
			name:     "env var set",
			key:      "TEST_KEY_SET",
			def:      "default_value",
			expected: "env_value",
			setEnv:   true,
			envValue: "env_value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setEnv {
				t.Setenv(tc.key, tc.envValue)
			}

			// Test
			result := getEnvWithDefault(tc.key, tc.def)

			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestGetEnvBoolWithDefault(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		def      bool
		expected bool
		setEnv   bool
		envValue string
	}{
		{
			name:     "env var not set - default false",
			key:      "TEST_BOOL_NOT_SET",
			def:      false,
			expected: false,
			setEnv:   false,
		},
		{
			name:     "env var not set - default true",
			key:      "TEST_BOOL_NOT_SET2",
			def:      true,
			expected: true,
			setEnv:   false,
		},
		{
			name:     "env var set to 'true'",
			key:      "TEST_BOOL_TRUE",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "true",
		},
		{
			name:     "env var set to 'TRUE'",
			key:      "TEST_BOOL_TRUE_UPPER",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "TRUE",
		},
		{
			name:     "env var set to '1'",
			key:      "TEST_BOOL_ONE",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "1",
		},
		{
			name:     "env var set to 'false'",
			key:      "TEST_BOOL_FALSE",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "false",
		},
		{
			name:     "env var set to '0'",
			key:      "TEST_BOOL_ZERO",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "0",
		},
		{
			name:     "env var set to 'FALSE'",
			key:      "TEST_BOOL_FALSE_UPPER",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "FALSE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setEnv {
				t.Setenv(tc.key, tc.envValue)
			}

			// Test
			result := getEnvBoolWithDefault(tc.key, tc.def)

			if result != tc.expected {
				t.Errorf("Expected %t, got %t", tc.expected, result)
			}
		})
	}
}

// TestGetEnvBoolWithDefault_RejectsMalformedValue covers the fail-fast
// contract (SPEC §3, CODING-STANDARDS §7): a typo like "yes" in a security
// toggle must abort startup instead of silently becoming false.
func TestGetEnvBoolWithDefault_RejectsMalformedValue(t *testing.T) {
	for _, value := range []string{"yes", "on", "enabled", " true"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("TEST_BOOL_MALFORMED", value)
			require.PanicsWithValue(t,
				`invalid boolean in TEST_BOOL_MALFORMED: "`+value+`" (accepted: true, 1, false, 0)`,
				func() { getEnvBoolWithDefault("TEST_BOOL_MALFORMED", false) })
		})
	}
}

func TestSplitCSV(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "trims values",
			input:    " user1@example.com, user2@example.com ",
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "keeps empty values",
			input:    "a,,b",
			expected: []string{"a", "", "b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitCSV(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestHealthURL(t *testing.T) {
	cases := []struct {
		listen  string
		want    string
		wantErr bool
	}{
		{listen: ":8080", want: "http://127.0.0.1:8080/healthz"},
		{listen: "0.0.0.0:8080", want: "http://127.0.0.1:8080/healthz"},
		{listen: "[::]:8080", want: "http://127.0.0.1:8080/healthz"},
		{listen: "10.0.0.5:8080", want: "http://10.0.0.5:8080/healthz"},
		{listen: "127.0.0.1:80", want: "http://127.0.0.1:80/healthz"},
		{listen: "no-port", wantErr: true},
	}
	for _, tt := range cases {
		t.Run(tt.listen, func(t *testing.T) {
			got, err := healthURL(tt.listen)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestHealthcheckCommand drives the container health probe against stub
// servers: only a plain 200 counts as healthy — errors, non-200 and
// redirects (an https-redirecting listener without the /healthz
// passthrough) must fail.
func TestHealthcheckCommand(t *testing.T) {
	runProbe := func(t *testing.T, listen string) error {
		t.Helper()
		cmd := newRootCommand(nil)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"healthcheck", "--listen", listen, "--timeout", "2s"})
		return cmd.Execute()
	}

	t.Run("healthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		require.NoError(t, runProbe(t, strings.TrimPrefix(srv.URL, "http://")))
	})

	t.Run("unhealthy status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		err := runProbe(t, strings.TrimPrefix(srv.URL, "http://"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "503")
	})

	t.Run("redirect is not healthy", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com"+r.RequestURI, http.StatusMovedPermanently)
		}))
		defer srv.Close()
		err := runProbe(t, strings.TrimPrefix(srv.URL, "http://"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "301")
	})

	t.Run("no listener", func(t *testing.T) {
		require.Error(t, runProbe(t, "127.0.0.1:1"))
	})
}

// TestRotateKeyCommand covers the manual key-rotation ops command
// (SPEC §2.3): each run makes a fresh key active and moves the previous
// active key into the retiring set (kid continuity).
func TestRotateKeyCommand(t *testing.T) {
	dataPath := t.TempDir()

	type manifest struct {
		Active   string `json:"active"`
		Retiring []struct {
			Kid string `json:"kid"`
		} `json:"retiring"`
	}
	readManifest := func(t *testing.T) manifest {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dataPath, "keys", "manifest.json"))
		require.NoError(t, err)
		var mf manifest
		require.NoError(t, json.Unmarshal(data, &mf))
		return mf
	}
	runRotate := func(t *testing.T) string {
		t.Helper()
		var out bytes.Buffer
		cmd := newRootCommand(nil)
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"rotate-key", "--data-path", dataPath})
		require.NoError(t, cmd.Execute())
		return out.String()
	}

	output := runRotate(t)
	require.Contains(t, output, "Rotated signing key")
	require.Contains(t, output, "Restart the gateway")

	first := readManifest(t)
	require.NotEmpty(t, first.Active)
	require.Len(t, first.Retiring, 1, "the initial key must retire, not disappear")

	runRotate(t)
	second := readManifest(t)
	require.NotEqual(t, first.Active, second.Active, "each rotation must mint a fresh active key")
	retiringKids := make([]string, 0, len(second.Retiring))
	for _, r := range second.Retiring {
		retiringKids = append(retiringKids, r.Kid)
	}
	require.Contains(t, retiringKids, first.Active,
		"the previously active kid must stay verifiable (retiring)")
}

func TestRotateKeyCommand_RejectsStaticKeyMode(t *testing.T) {
	t.Setenv("JWT_PRIVATE_KEY", "irrelevant")
	cmd := newRootCommand(nil)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"rotate-key", "--data-path", t.TempDir()})
	err := cmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "JWT_PRIVATE_KEY")
}

func TestRotateKeyCommand_ValidatesFlags(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		errContains string
	}{
		{name: "unsupported algorithm", args: []string{"--key-alg", "HS256"}, errContains: "unsupported key algorithm"},
		{name: "access token TTL out of range", args: []string{"--access-token-ttl", "10s"}, errContains: "access token TTL"},
		{name: "clock skew out of range", args: []string{"--clock-skew", "10m"}, errContains: "clock skew"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCommand(nil)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append([]string{"rotate-key", "--data-path", t.TempDir()}, tt.args...))
			err := cmd.Execute()
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestNewRootCommand_HTTPStreamingOnlyFlag(t *testing.T) {
	t.Setenv("HTTP_STREAMING_ONLY", "")

	var streamingOnly bool
	var receivedTargets []string
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		streamingOnly = cfg.HTTPStreamingOnly
		receivedTargets = cfg.ProxyTargets
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"--http-streaming-only", "http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !streamingOnly {
		t.Fatalf("expected httpStreamingOnly to be true when flag is set")
	}
	if len(receivedTargets) != 1 || receivedTargets[0] != "http://backend" {
		t.Fatalf("expected proxyTarget to receive CLI args, got %v", receivedTargets)
	}
}

func TestNewRootCommand_HTTPStreamingOnlyFromEnv(t *testing.T) {
	t.Setenv("HTTP_STREAMING_ONLY", "true")

	var streamingOnly bool
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		streamingOnly = cfg.HTTPStreamingOnly
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !streamingOnly {
		t.Fatalf("expected httpStreamingOnly to default to true from env var")
	}
}

func TestNewRootCommand_ForwardAuthorizationFlag(t *testing.T) {
	t.Setenv("PROXY_FORWARD_AUTHORIZATION", "")

	var forwardAuthorization bool
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		forwardAuthorization = cfg.ForwardAuthorizationHeader
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"--proxy-forward-authorization", "http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !forwardAuthorization {
		t.Fatalf("expected forwardAuthorizationHeader to be true when flag is set")
	}
}

func TestNewRootCommand_ForwardAuthorizationFromEnv(t *testing.T) {
	t.Setenv("PROXY_FORWARD_AUTHORIZATION", "true")

	var forwardAuthorization bool
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		forwardAuthorization = cfg.ForwardAuthorizationHeader
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !forwardAuthorization {
		t.Fatalf("expected forwardAuthorizationHeader to default to true from env var")
	}
}

func TestNewRootCommand_KeyFlagDefaults(t *testing.T) {
	t.Setenv("KEY_ALG", "")
	t.Setenv("KEY_ROTATION_INTERVAL", "")

	var keyAlg string
	var keyRotationInterval time.Duration
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		keyAlg = cfg.KeyAlg
		keyRotationInterval = cfg.KeyRotationInterval
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if keyAlg != "RS256" {
		t.Fatalf("expected KEY_ALG default RS256, got %q", keyAlg)
	}
	if keyRotationInterval != 2160*time.Hour {
		t.Fatalf("expected KEY_ROTATION_INTERVAL default 2160h, got %s", keyRotationInterval)
	}
}

func TestNewRootCommand_KeyFlagsFromEnv(t *testing.T) {
	t.Setenv("KEY_ALG", "ES256")
	t.Setenv("KEY_ROTATION_INTERVAL", "48h")

	var keyAlg string
	var keyRotationInterval time.Duration
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		keyAlg = cfg.KeyAlg
		keyRotationInterval = cfg.KeyRotationInterval
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if keyAlg != "ES256" {
		t.Fatalf("expected KEY_ALG ES256 from env, got %q", keyAlg)
	}
	if keyRotationInterval != 48*time.Hour {
		t.Fatalf("expected KEY_ROTATION_INTERVAL 48h from env, got %s", keyRotationInterval)
	}
}

func TestNewRootCommand_AbuseProtectionDefaults(t *testing.T) {
	for _, key := range []string{"RATE_LIMIT_REGISTER", "RATE_LIMIT_TOKEN", "RATE_LIMIT_LOGIN", "RATE_LIMIT_AUTHORIZE", "LOGIN_LOCKOUT_THRESHOLD", "LOGIN_LOCKOUT_DURATION"} {
		t.Setenv(key, "")
	}

	var received mcpproxy.Config
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		received = cfg
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if received.RateLimitRegister != "10/m" || received.RateLimitToken != "60/m" || received.RateLimitLogin != "10/m" || received.RateLimitAuthorize != "60/m" {
		t.Fatalf("unexpected rate limit defaults: %q %q %q %q", received.RateLimitRegister, received.RateLimitToken, received.RateLimitLogin, received.RateLimitAuthorize)
	}
	if received.LoginLockoutThreshold != 10 || received.LoginLockoutDuration != 15*time.Minute {
		t.Fatalf("unexpected lockout defaults: %d %s", received.LoginLockoutThreshold, received.LoginLockoutDuration)
	}
}

func TestNewRootCommand_AbuseProtectionFromEnv(t *testing.T) {
	t.Setenv("RATE_LIMIT_REGISTER", "5/h")
	t.Setenv("RATE_LIMIT_TOKEN", "0")
	t.Setenv("RATE_LIMIT_LOGIN", "3/m")
	t.Setenv("RATE_LIMIT_AUTHORIZE", "7/m")
	t.Setenv("LOGIN_LOCKOUT_THRESHOLD", "5")
	t.Setenv("LOGIN_LOCKOUT_DURATION", "30m")

	var received mcpproxy.Config
	runner := proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		received = cfg
		return nil
	})

	cmd := newRootCommand(runner)
	cmd.SetArgs([]string{"http://backend"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if received.RateLimitRegister != "5/h" || received.RateLimitToken != "0" || received.RateLimitLogin != "3/m" || received.RateLimitAuthorize != "7/m" {
		t.Fatalf("unexpected rate limits from env: %q %q %q %q", received.RateLimitRegister, received.RateLimitToken, received.RateLimitLogin, received.RateLimitAuthorize)
	}
	if received.LoginLockoutThreshold != 5 || received.LoginLockoutDuration != 30*time.Minute {
		t.Fatalf("unexpected lockout config from env: %d %s", received.LoginLockoutThreshold, received.LoginLockoutDuration)
	}
}
