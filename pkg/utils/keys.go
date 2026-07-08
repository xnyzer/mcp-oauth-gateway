package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

const SecretSize = 32

func LoadOrGenerateSecret(secretPath string) ([]byte, error) {
	_, err := os.Stat(secretPath)
	if os.IsNotExist(err) {
		secret := make([]byte, SecretSize)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate secret: %w", err)
		}
		if err := os.WriteFile(secretPath, secret, 0600); err != nil {
			return nil, fmt.Errorf("failed to save secret: %w", err)
		}
		return secret, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat secret file: %w", err)
	}
	secret, err := os.ReadFile(secretPath) //nolint:gosec // G304: path is inside the gateway's data directory (operator config, SPEC §2.2)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file: %w", err)
	}
	return secret, nil
}

func SecretFromBase64(encoded string) ([]byte, error) {
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 secret: %w", err)
	}
	if len(secret) != SecretSize {
		return nil, fmt.Errorf("decoded secret must be exactly %d bytes, got %d", SecretSize, len(secret))
	}
	return secret, nil
}
