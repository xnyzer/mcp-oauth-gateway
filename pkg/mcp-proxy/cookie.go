package mcpproxy

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// cookieKeyLen is 32 bytes: a full-strength HMAC-SHA256 authentication key and
// an AES-256 encryption key for the gorilla securecookie codec.
const cookieKeyLen = 32

// HKDF context labels keep the two subkeys cryptographically independent even
// though they are expanded from the same input secret (RFC 5869 §3.2).
const (
	cookieAuthInfo = "mcp-oauth-gateway session cookie auth key v1"
	cookieEncInfo  = "mcp-oauth-gateway session cookie encryption key v1"
)

// deriveCookieKeys expands the shared 32-byte secret into distinct
// authentication and encryption subkeys for the operator session cookie
// (SPEC §1.12/§2.2). The raw secret stays fosite's GlobalSecret, so deriving
// here keeps the cookie keys separate from the token-signing secret while
// still needing only one configured value.
func deriveCookieKeys(secret []byte) (authKey, encKey []byte, err error) {
	authKey, err = hkdf.Key(sha256.New, secret, nil, cookieAuthInfo, cookieKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive cookie auth key: %w", err)
	}
	encKey, err = hkdf.Key(sha256.New, secret, nil, cookieEncInfo, cookieKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("derive cookie encryption key: %w", err)
	}
	return authKey, encKey, nil
}
