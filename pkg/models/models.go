package models

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/ory/fosite"
)

type Request struct {
	ID                string
	RequestedAt       time.Time
	Client            *Client
	RequestedScope    []string
	GrantedScope      []string
	Form              map[string][]string
	RequestedAudience []string
	GrantedAudience   []string
	RotatedAt         time.Time
	SessionData       json.RawMessage `json:",omitempty"`
}

type Client struct {
	ID             string
	Secret         string
	RotatedSecrets []string
	RedirectURIs   []string
	GrantTypes     []string
	ResponseTypes  []string
	Scopes         []string
	Audience       []string
	Public         bool
	// CreatedAt/ExpiresAt implement the DCR registration TTL (SPEC §1.4).
	// A zero ExpiresAt means the registration never expires.
	CreatedAt time.Time `json:",omitempty"`
	ExpiresAt time.Time `json:",omitempty"`
}

// User is the gateway's single operator account (FR-4), bootstrapped on the
// first successful password login (SPEC §1.12). The password itself stays in
// the env config (decision F-005e) — the record carries identity and the
// passkey-fallback state only, never a password hash.
type User struct {
	ID       string
	Username string
	// PasswordLoginDisabled turns the password fallback off. It is only
	// honoured while at least one passkey exists (lockout rescue,
	// SPEC §1.12).
	PasswordLoginDisabled bool
	CreatedAt             time.Time
}

// WebAuthnCredential is a passkey registered to the user (SPEC §2.1). The
// Credential payload is the marshaled go-webauthn credential (COSE public
// key, sign count, transports, flags); models stays agnostic of that type.
type WebAuthnCredential struct {
	// ID is the base64url-encoded WebAuthn credential ID.
	ID         string
	UserID     string
	Name       string
	Credential json.RawMessage
	CreatedAt  time.Time
	LastUsedAt time.Time `json:",omitempty"`
}

type AuthorizeRequest struct {
	ResponseTypes        []string
	RedirectURI          string
	State                string
	HandledResponseTypes []string
	ResponseMode         string
	DefaultResponseMode  string
	Request              *Request
}

func FromFositeReq(reqester fosite.Requester) *Request {
	req := reqester.(*fosite.Request)
	r := &Request{
		ID:                req.ID,
		RequestedAt:       req.RequestedAt,
		Client:            FromFositeClient(req.Client),
		RequestedScope:    req.RequestedScope,
		GrantedScope:      req.GrantedScope,
		Form:              req.Form,
		RequestedAudience: req.RequestedAudience,
		GrantedAudience:   req.GrantedAudience,
	}
	if sess := req.GetSession(); sess != nil {
		if data, err := json.Marshal(sess); err == nil {
			r.SessionData = data
		}
	}
	return r
}

func (r *Request) ToFositeReq() *fosite.Request {
	return &fosite.Request{
		ID:                r.ID,
		RequestedAt:       r.RequestedAt,
		Client:            r.Client.ToFositeClient(),
		RequestedScope:    r.RequestedScope,
		GrantedScope:      r.GrantedScope,
		Form:              r.Form,
		RequestedAudience: r.RequestedAudience,
		GrantedAudience:   r.GrantedAudience,
	}
}

func FromFositeClient(client fosite.Client) *Client {
	c := client.(*fosite.DefaultClient)

	var rotatedSecrets []string
	for _, rotSecret := range c.RotatedSecrets {
		rotatedSecrets = append(rotatedSecrets, string(rotSecret))
	}

	return &Client{
		ID:             c.ID,
		Secret:         string(c.Secret),
		RotatedSecrets: rotatedSecrets,
		RedirectURIs:   c.RedirectURIs,
		GrantTypes:     c.GrantTypes,
		ResponseTypes:  c.ResponseTypes,
		Scopes:         c.Scopes,
		Audience:       c.Audience,
		Public:         c.Public,
	}
}

func (c *Client) ToFositeClient() *fosite.DefaultClient {
	var rotatedSecrets [][]byte
	for _, rotSecret := range c.RotatedSecrets {
		rotatedSecrets = append(rotatedSecrets, []byte(rotSecret))
	}
	return &fosite.DefaultClient{
		ID:             c.ID,
		Secret:         []byte(c.Secret),
		RotatedSecrets: rotatedSecrets,
		RedirectURIs:   c.RedirectURIs,
		GrantTypes:     c.GrantTypes,
		ResponseTypes:  c.ResponseTypes,
		Scopes:         c.Scopes,
		Audience:       c.Audience,
		Public:         c.Public,
	}
}

func FromFositeAuthorizeRequest(reqester fosite.AuthorizeRequester) *AuthorizeRequest {
	req := reqester.(*fosite.AuthorizeRequest)
	return &AuthorizeRequest{
		ResponseTypes:        req.ResponseTypes,
		RedirectURI:          req.RedirectURI.String(),
		State:                req.State,
		HandledResponseTypes: req.HandledResponseTypes,
		ResponseMode:         string(req.ResponseMode),
		DefaultResponseMode:  string(req.DefaultResponseMode),
		Request:              FromFositeReq(&req.Request),
	}
}

func (ar *AuthorizeRequest) ToFositeAuthorizeRequest() *fosite.AuthorizeRequest {
	return &fosite.AuthorizeRequest{
		ResponseTypes:        ar.ResponseTypes,
		RedirectURI:          Must(url.Parse(ar.RedirectURI)),
		State:                ar.State,
		HandledResponseTypes: ar.HandledResponseTypes,
		ResponseMode:         fosite.ResponseModeType(ar.ResponseMode),
		DefaultResponseMode:  fosite.ResponseModeType(ar.DefaultResponseMode),
		Request:              *ar.Request.ToFositeReq(),
	}
}

func Must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
