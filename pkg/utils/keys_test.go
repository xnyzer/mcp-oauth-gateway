package utils

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretFromBase64_Valid(t *testing.T) {
	secret := make([]byte, SecretSize)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(secret)
	decoded, err := SecretFromBase64(encoded)
	require.NoError(t, err)
	require.Equal(t, secret, decoded)
}

func TestSecretFromBase64_InvalidBase64(t *testing.T) {
	_, err := SecretFromBase64("not-valid-base64!!!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to decode base64")
}

func TestSecretFromBase64_WrongLength(t *testing.T) {
	short := make([]byte, 16)
	_, err := rand.Read(short)
	require.NoError(t, err)

	encoded := base64.StdEncoding.EncodeToString(short)
	_, err = SecretFromBase64(encoded)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be exactly 32 bytes")
}
