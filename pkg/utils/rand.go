package utils

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateClientID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func GenerateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func GenerateState() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateJTI returns a unique JWT token identifier (SPEC §1.7).
func GenerateJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateUserID returns the operator account ID (SPEC §1.12). 32 random
// bytes hex-encoded yield 64 characters — the full 64-byte WebAuthn user
// handle recommended by the spec.
func GenerateUserID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateCSRFToken returns a per-session anti-CSRF token (SPEC §1.12): 32
// random bytes hex-encoded, embedded in the login/consent/settings forms and
// checked in constant time on state-changing POSTs as defence-in-depth on top
// of the session cookie's SameSite=Lax attribute.
func GenerateCSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
