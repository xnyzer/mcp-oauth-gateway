package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWeakRSAKeysAreRefused covers the SPEC §2.2 minimum key size on every
// ingress path for operator-supplied keys: parsing (JWT_PRIVATE_KEY, legacy
// adoption, manifest loads) and the static manager. Keys below 2048 bits
// must fail fast instead of silently signing tokens.
func TestWeakRSAKeysAreRefused(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	t.Run("ParsePrivateKeyPEM rejects 1024-bit RSA", func(t *testing.T) {
		pemBytes, err := MarshalPrivateKeyPEM(weakKey)
		require.NoError(t, err)
		_, err = ParsePrivateKeyPEM(string(pemBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least 2048")
	})

	t.Run("NewStaticManager rejects 1024-bit RSA", func(t *testing.T) {
		_, err := NewStaticManager(weakKey, AlgRS256)
		require.Error(t, err)
		require.Contains(t, err.Error(), "at least 2048")
	})

	t.Run("2048-bit RSA is accepted", func(t *testing.T) {
		key, err := GeneratePrivateKey(AlgRS256)
		require.NoError(t, err)
		alg, err := algForKey(key)
		require.NoError(t, err)
		require.Equal(t, AlgRS256, alg)
	})
}
