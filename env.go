package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBoolWithDefault fails fast on a malformed boolean instead of
// silently coercing it to false (config validation, CODING-STANDARDS §7):
// a typo in a security toggle must abort startup, not disable the toggle.
func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	if strings.EqualFold(value, "true") || value == "1" {
		return true
	}
	if strings.EqualFold(value, "false") || value == "0" {
		return false
	}
	panic(fmt.Sprintf("invalid boolean in %s: %q (accepted: true, 1, false, 0)", key, value))
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
