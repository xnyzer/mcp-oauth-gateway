package idp

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/xnyzer/mcp-oauth-gateway/pkg/utils"
)

// NewJWTSession creates the session fosite carries through a flow and turns
// into the access token's claims. The `jti` is generated here rather than at
// signing time, because revocation is keyed on it (SPEC §1.9): a token that
// reached a client must be identifiable for the rest of its lifetime.
func NewJWTSession(iss string, subject string, clientID string, userInfo map[string]any) (*Session, error) {
	jti, err := utils.GenerateJTI()
	if err != nil {
		return nil, err
	}
	extra := map[string]any{}
	if userInfo != nil {
		extra["userinfo"] = userInfo
	}
	if clientID != "" {
		extra["client_id"] = clientID
	}
	// exp, aud, and scope are set by fosite at issuance time from the
	// session expiry and the granted audience/scopes (SPEC §1.7); the kid
	// header is set by the signer at signing time (SPEC §2.3.3).
	return &Session{
		DefaultSession: &fosite.DefaultSession{
			Username: subject,
			Subject:  subject,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    iss,
			Subject:   subject,
			JTI:       jti,
			IssuedAt:  time.Now(),
			NotBefore: time.Now(),
			Extra:     extra,
		},
		JWTHeader: &jwt.Headers{
			Extra: map[string]any{},
		},
	}, nil
}

// Session extends fosite's default session with the JWT claims and headers
// this gateway issues, so the same object serves fosite's bookkeeping and the
// token's payload (SPEC §1.7).
type Session struct {
	*fosite.DefaultSession
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
}

// GetJWTClaims satisfies fosite's JWT session interface.
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	return s.JWTClaims
}

// GetJWTHeader satisfies fosite's JWT session interface. The `kid` is added by
// the signer at signing time, not here (SPEC §2.3.3).
func (s *Session) GetJWTHeader() *jwt.Headers {
	return s.JWTHeader
}

// Clone deep-copies the session. Fosite clones sessions between the authorize
// and token steps, and a shallow copy would let two requests share one claims
// map — which is how one client's identity ends up in another's token.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	clone := &Session{
		DefaultSession: &fosite.DefaultSession{
			Username:  s.Username,
			Subject:   s.Subject,
			ExpiresAt: s.ExpiresAt,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    s.JWTClaims.Issuer,
			Subject:   s.JWTClaims.Subject,
			JTI:       s.JWTClaims.JTI,
			Audience:  s.JWTClaims.Audience,
			ExpiresAt: s.JWTClaims.ExpiresAt,
			IssuedAt:  s.JWTClaims.IssuedAt,
			NotBefore: s.JWTClaims.NotBefore,
			Extra:     s.JWTClaims.Extra,
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]any),
		},
	}

	// Refresh grants clone the stored session; each issued token gets a
	// fresh jti so token identifiers stay unique (SPEC §1.7).
	if jti, err := utils.GenerateJTI(); err == nil {
		clone.JWTClaims.JTI = jti
	}

	for k, v := range s.JWTHeader.Extra {
		clone.JWTHeader.Extra[k] = v
	}

	return clone
}
