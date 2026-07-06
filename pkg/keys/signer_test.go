package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"
)

func testClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "https://example.com",
		"sub": "user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func TestFositeSigner_GenerateSetsActiveKid(t *testing.T) {
	m := newTestManager(t, Config{})
	signer := &FositeSigner{Keys: m}

	token, sig, err := signer.Generate(context.Background(), testClaims(), &jwt.Headers{Extra: map[string]any{}})
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	decoded, err := signer.Decode(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, m.Active().Kid, decoded.Header["kid"])
	require.Equal(t, "RS256", string(decoded.Method))
}

func TestFositeSigner_ValidatesAcrossRotation(t *testing.T) {
	m := newTestManager(t, Config{RetireWindow: time.Hour})
	signer := &FositeSigner{Keys: m}
	ctx := context.Background()

	oldToken, _, err := signer.Generate(ctx, testClaims(), &jwt.Headers{Extra: map[string]any{}})
	require.NoError(t, err)
	oldKid := m.Active().Kid

	require.NoError(t, m.Rotate(time.Now().UTC()))

	// The pre-rotation token still validates (retiring key, SPEC §2.3.3)...
	_, err = signer.Validate(ctx, oldToken)
	require.NoError(t, err)

	// ...and new tokens are signed with the new active key.
	newToken, _, err := signer.Generate(ctx, testClaims(), &jwt.Headers{Extra: map[string]any{}})
	require.NoError(t, err)
	decoded, err := signer.Decode(ctx, newToken)
	require.NoError(t, err)
	require.Equal(t, m.Active().Kid, decoded.Header["kid"])
	require.NotEqual(t, oldKid, decoded.Header["kid"])
}

func TestFositeSigner_RejectsUnknownKidAfterSweep(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	m := newTestManager(t, Config{Dir: dir, RetireWindow: time.Minute})
	signer := &FositeSigner{Keys: m}
	ctx := context.Background()

	token, _, err := signer.Generate(ctx, testClaims(), &jwt.Headers{Extra: map[string]any{}})
	require.NoError(t, err)

	now := time.Now().UTC()
	require.NoError(t, m.Rotate(now))
	require.NoError(t, m.Maintain(now.Add(2*time.Minute)))

	// The signing key is gone from the set: fail closed.
	_, err = signer.Validate(ctx, token)
	require.Error(t, err)
}

func TestFositeSigner_ES256RoundTrip(t *testing.T) {
	m := newTestManager(t, Config{Alg: AlgES256})
	signer := &FositeSigner{Keys: m}
	ctx := context.Background()

	token, _, err := signer.Generate(ctx, testClaims(), &jwt.Headers{Extra: map[string]any{}})
	require.NoError(t, err)

	decoded, err := signer.Decode(ctx, token)
	require.NoError(t, err)
	require.Equal(t, "ES256", string(decoded.Method))
	require.Equal(t, m.Active().Kid, decoded.Header["kid"])
}

func TestFositeSigner_RejectsAlgMismatchForKid(t *testing.T) {
	m := newTestManager(t, Config{Alg: AlgRS256})
	signer := &FositeSigner{Keys: m}
	ctx := context.Background()

	// Forge an ES256 token claiming the RSA active key's kid.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	forgedSigner := &jwt.DefaultSigner{GetPrivateKey: func(context.Context) (any, error) {
		return ecKey, nil
	}}
	header := &jwt.Headers{Extra: map[string]any{"kid": m.Active().Kid}}
	forged, _, err := forgedSigner.Generate(ctx, testClaims(), header)
	require.NoError(t, err)

	_, err = signer.Validate(ctx, forged)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
}
