package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
