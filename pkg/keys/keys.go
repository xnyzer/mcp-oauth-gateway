// Package keys manages the gateway's JWS signing keys (SPEC §2.2/§2.3):
// a key directory with an atomic manifest, migration from the legacy
// single-key file, interval-based rotation with a retiring window, and a
// fosite-compatible signer that verifies against the full key set.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// Alg is a supported JWS signing algorithm (SPEC §3.2 KEY_ALG).
type Alg string

const (
	AlgRS256 Alg = "RS256" // RSA-2048, the default
	AlgES256 Alg = "ES256" // ECDSA P-256
)

// ParseAlg validates a KEY_ALG value (fail-fast, CODING-STANDARDS §7).
func ParseAlg(s string) (Alg, error) {
	switch strings.ToUpper(s) {
	case string(AlgRS256):
		return AlgRS256, nil
	case string(AlgES256):
		return AlgES256, nil
	default:
		return "", fmt.Errorf("unsupported key algorithm %q (supported: RS256, ES256)", s)
	}
}

// SigningKey is a managed private key. Key's dynamic type is
// *rsa.PrivateKey or *ecdsa.PrivateKey, matching Alg.
type SigningKey struct {
	Kid string
	Alg Alg
	Key crypto.Signer
}

// KeyID derives the kid for a public key: hex-encoded first 8 bytes of the
// SHA-256 fingerprint of the PKIX encoding. This scheme predates F-005d
// (single-key deployments embed it in outstanding token headers), so it
// MUST NOT change — the legacy-key migration relies on adopted keys keeping
// their kid.
func KeyID(publicKey crypto.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:8]), nil
}

// GeneratePrivateKey creates a new private key for the given algorithm.
func GeneratePrivateKey(alg Alg) (crypto.Signer, error) {
	switch alg {
	case AlgRS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	case AlgES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", alg)
	}
}

// algForKey returns the JWS algorithm a private key signs with.
func algForKey(key crypto.Signer) (Alg, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return AlgRS256, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("unsupported ECDSA curve %q (only P-256 is supported)", k.Curve.Params().Name)
		}
		return AlgES256, nil
	default:
		return "", fmt.Errorf("unsupported private key type %T", key)
	}
}

// ParsePrivateKeyPEM parses a PKCS#8 PEM private key (RSA or ECDSA P-256).
func ParsePrivateKeyPEM(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", parsed)
	}
	if _, err := algForKey(key); err != nil {
		return nil, err
	}
	return key, nil
}

// MarshalPrivateKeyPEM encodes a private key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}

// SavePrivateKey writes a private key as PKCS#8 PEM with 0600 permissions
// (SPEC §2.2).
func SavePrivateKey(path string, key crypto.Signer) error {
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, keyPEM, 0600)
}

// JWK is a public JSON Web Key (RFC 7517) as served by the JWKS endpoint
// (SPEC §1.8). RSA keys carry n/e, EC keys crv/x/y.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// publicJWK builds the RFC 7517 representation of a signing key's public
// half.
func publicJWK(key SigningKey) (JWK, error) {
	jwk := JWK{Use: "sig", Kid: key.Kid, Alg: string(key.Alg)}
	switch pub := key.Key.Public().(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		jwk.Crv = "P-256"
		// RFC 7518 §6.2.1: fixed-length big-endian coordinates, sliced
		// from the uncompressed point (0x04 || X || Y).
		raw, err := pub.Bytes()
		if err != nil {
			return JWK{}, fmt.Errorf("failed to encode EC public key: %w", err)
		}
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		if len(raw) != 1+2*byteLen || raw[0] != 4 {
			return JWK{}, fmt.Errorf("unexpected EC point encoding (%d bytes)", len(raw))
		}
		jwk.X = base64.RawURLEncoding.EncodeToString(raw[1 : 1+byteLen])
		jwk.Y = base64.RawURLEncoding.EncodeToString(raw[1+byteLen:])
	default:
		return JWK{}, fmt.Errorf("unsupported public key type %T", pub)
	}
	return jwk, nil
}
