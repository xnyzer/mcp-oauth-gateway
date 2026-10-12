package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	mcpproxy "github.com/xnyzer/mcp-oauth-gateway/pkg/mcp-proxy"
)

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

// A malformed OIDC allow-list must keep the gateway from starting at all. The
// runner stands in for the gateway: if it is called, start-up went ahead.
func TestNewRootCommand_RejectsMalformedOIDCAllowLists(t *testing.T) {
	testCases := []struct {
		env   string
		value string
	}{
		{"OIDC_ALLOWED_USERS", ","},
		{"OIDC_ALLOWED_USERS_GLOB", " , "},
		{"OIDC_ALLOWED_ATTRIBUTES", "/groups admin"},
		{"OIDC_ALLOWED_ATTRIBUTES_GLOB", "groups=team-*"},
	}
	for _, tc := range testCases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(tc.env, tc.value)

			started := false
			cmd := newRootCommand(proxyRunnerFunc(func(mcpproxy.Config) error {
				started = true
				return nil
			}))
			cmd.SetArgs([]string{"http://backend"})
			cmd.SilenceErrors = true

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected start-up to fail for %s=%q", tc.env, tc.value)
			}
			if started {
				t.Fatalf("the gateway must not start with %s=%q", tc.env, tc.value)
			}
			if !strings.HasPrefix(err.Error(), tc.env+" ") {
				t.Errorf("error %q does not name the setting %s", err, tc.env)
			}
		})
	}
}

func TestNewRootCommand_PassesOIDCAllowListsOn(t *testing.T) {
	t.Setenv("OIDC_ALLOWED_USERS", "alice@example.com, bob@example.com,")
	t.Setenv("OIDC_ALLOWED_USERS_GLOB", `{carol\,dave}@example.com`)
	t.Setenv("OIDC_ALLOWED_ATTRIBUTES", "/groups=admin")
	t.Setenv("OIDC_ALLOWED_ATTRIBUTES_GLOB", "/groups=team-*")

	var got mcpproxy.Config
	cmd := newRootCommand(proxyRunnerFunc(func(cfg mcpproxy.Config) error {
		got = cfg
		return nil
	}))
	cmd.SetArgs([]string{"http://backend"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected command to succeed, got error: %v", err)
	}

	if !reflect.DeepEqual(got.OIDCAllowedUsers, []string{"alice@example.com", "bob@example.com"}) {
		t.Errorf("users: got %q", got.OIDCAllowedUsers)
	}
	if !reflect.DeepEqual(got.OIDCAllowedUsersGlob, []string{"{carol,dave}@example.com"}) {
		t.Errorf("users glob: got %q", got.OIDCAllowedUsersGlob)
	}
	if !reflect.DeepEqual(got.OIDCAllowedAttributes, map[string][]string{"/groups": {"admin"}}) {
		t.Errorf("attributes: got %v", got.OIDCAllowedAttributes)
	}
	if !reflect.DeepEqual(got.OIDCAllowedAttributesGlob, map[string][]string{"/groups": {"team-*"}}) {
		t.Errorf("attributes glob: got %v", got.OIDCAllowedAttributesGlob)
	}
}
