package keys

import (
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/ory/fosite/token/jwt"
)

// FositeSigner implements fosite's jwt.Signer against the managed key set:
// it signs with the active key and verifies against active + retiring keys
// selected by kid (SPEC §2.3.3). This keeps fosite's own JWT validation
// (introspection) working across rotations, not just the proxy's.
type FositeSigner struct {
	Keys *Manager
}

var _ jwt.Signer = (*FositeSigner)(nil)

// Generate signs with the active key. The kid header is set here, at
// signing time — sessions are created at authorize time and cloned for
// refresh grants, so a session-borne kid could be stale after a rotation.
func (s *FositeSigner) Generate(ctx context.Context, claims jwt.MapClaims, header jwt.Mapper) (string, string, error) {
	active := s.Keys.Active()
	header.Add("kid", active.Kid)
	signer := &jwt.DefaultSigner{GetPrivateKey: func(context.Context) (any, error) {
		return active.Key, nil
	}}
	return signer.Generate(ctx, claims, header)
}

// Validate verifies the token against the key selected by its kid and
// returns its signature segment (mirrors jwt.DefaultSigner.Validate).
func (s *FositeSigner) Validate(ctx context.Context, token string) (string, error) {
	if _, err := s.Decode(ctx, token); err != nil {
		return "", err
	}
	return s.GetSignature(ctx, token)
}

// Decode parses and verifies a token, selecting the verification key by
// the kid header; unknown kids and algorithm mismatches fail closed.
func (s *FositeSigner) Decode(ctx context.Context, token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, jwt.MapClaims{}, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pub, alg, ok := s.Keys.VerificationKey(kid)
		if !ok {
			return nil, fmt.Errorf("token references an unknown signing key")
		}
		if string(t.Method) != alg {
			return nil, fmt.Errorf("token algorithm %q does not match the signing key", t.Method)
		}
		return pub, nil
	})
}

func (s *FositeSigner) GetSignature(ctx context.Context, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("header, body and signature must all be set")
	}
	return parts[2], nil
}

func (s *FositeSigner) Hash(ctx context.Context, in []byte) ([]byte, error) {
	sum := sha256.Sum256(in)
	return sum[:], nil
}

func (s *FositeSigner) GetSigningMethodLength(ctx context.Context) int {
	return crypto.SHA256.Size()
}
