package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"github.com/mattn/go-jsonpointer"
	"golang.org/x/oauth2"
)

var (
	// ErrInvalidGlobPattern reports an allow-list pattern that does not parse.
	ErrInvalidGlobPattern = errors.New("invalid glob pattern")
	// ErrNoAllowList reports an OIDC provider configured without a single
	// allow rule.
	ErrNoAllowList = errors.New("OIDC login is configured without an allow-list")
)

type oidcProvider struct {
	oauth2                oauth2.Config
	providerName          string
	userInfoURL           string
	userIDField           string
	allowedUsers          []string
	allowedUsersGlob      []*glob.Pattern
	allowedAttributes     map[string][]string
	allowedAttributesGlob map[string][]*glob.Pattern
}

// NewOIDCProvider builds the generic OIDC login backend. Its allow-list is
// checked before anything is fetched, so a gateway that would let the wrong
// people in is refused whether or not the provider is reachable.
func NewOIDCProvider(
	configurationURL string, scopes []string, userIDField string,
	providerName, externalURL, clientID, clientSecret string, allowedUsers []string, allowedUsersGlob []string,
	allowedAttributes map[string][]string, allowedAttributesGlob map[string][]string,
) (Provider, error) {
	compiledGlobs, err := compileGlobs(allowedUsersGlob)
	if err != nil {
		return nil, err
	}
	compiledAttributeGlobs := make(map[string][]*glob.Pattern)
	for key, patterns := range allowedAttributesGlob {
		compiled, err := compileGlobs(patterns)
		if err != nil {
			return nil, err
		}
		if len(compiled) > 0 {
			compiledAttributeGlobs[key] = compiled
		}
	}
	provider := &oidcProvider{
		providerName:          providerName,
		userIDField:           userIDField,
		allowedUsers:          allowedUsers,
		allowedUsersGlob:      compiledGlobs,
		allowedAttributes:     allowedAttributes,
		allowedAttributesGlob: compiledAttributeGlobs,
	}
	// Without a rule, every account the provider authenticates would be the
	// operator. That has to be asked for with a `*`, never arrived at by
	// leaving the settings out or by an empty variable (§6, fail closed).
	if !provider.hasAllowRule() {
		return nil, ErrNoAllowList
	}

	resp, err := http.Get(configurationURL) //nolint:gosec // G107: fetching the operator-configured OIDC discovery URL is this provider's purpose
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("OIDC configuration request failed: %s", resp.Status)
	}
	var cfg struct {
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
		UserInfo      string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	redirectURL, err := url.JoinPath(externalURL, OIDCCallbackEndpoint)
	if err != nil {
		return nil, err
	}
	provider.userInfoURL = cfg.UserInfo
	provider.oauth2 = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthEndpoint,
			TokenURL: cfg.TokenEndpoint,
		},
	}
	return provider, nil
}

// hasAllowRule reports whether at least one of the four allow-lists holds a
// rule.
func (p *oidcProvider) hasAllowRule() bool {
	if len(p.allowedUsers) > 0 || len(p.allowedUsersGlob) > 0 || len(p.allowedAttributesGlob) > 0 {
		return true
	}
	for _, values := range p.allowedAttributes {
		if len(values) > 0 {
			return true
		}
	}
	return false
}

func (p *oidcProvider) Name() string {
	return p.providerName
}

func (p *oidcProvider) Type() string {
	return "oidc"
}

func (p *oidcProvider) RedirectURL() string {
	return OIDCCallbackEndpoint
}

func (p *oidcProvider) AuthURL() string {
	return OIDCAuthEndpoint
}

func (p *oidcProvider) AuthCodeURL(state string) (string, error) {
	authURL := p.oauth2.AuthCodeURL(state)
	return authURL, nil
}

func (p *oidcProvider) Exchange(c *gin.Context, state string) (*oauth2.Token, error) {
	if c.Query("state") != state {
		return nil, errors.New("invalid OAuth state")
	}
	code := c.Query("code")
	token, err := p.oauth2.Exchange(c, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (p *oidcProvider) Authorization(ctx context.Context, token *oauth2.Token) (bool, string, map[string]any, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return false, "", nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, "", nil, fmt.Errorf("userinfo request failed: %s", resp.Status)
	}
	var obj any
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return false, "", nil, err
	}
	userInfoMap, ok := obj.(map[string]any)
	if !ok {
		return false, "", nil, errors.New("userinfo response is not a JSON object")
	}
	v, err := jsonpointer.Get(obj, p.userIDField)
	if err != nil {
		return false, "", nil, err
	}
	userID, ok := v.(string)
	if !ok {
		return false, "", nil, errors.New("user ID field is not a string")
	}

	return p.isAllowed(obj, userID), userID, userInfoMap, nil
}

// isAllowed applies the allow-list to a verified identity. A login is allowed
// as soon as one rule matches. No rule, no login: NewOIDCProvider refuses to
// build a provider without one, and a provider that has none anyway denies
// rather than admits. An attribute the userinfo response lacks matches nothing.
func (p *oidcProvider) isAllowed(userInfo any, userID string) bool {
	if slices.Contains(p.allowedUsers, userID) {
		return true
	}
	for _, g := range p.allowedUsersGlob {
		if g.Match(userID) {
			return true
		}
	}
	for key, allowedValues := range p.allowedAttributes {
		if attrValue, err := jsonpointer.Get(userInfo, key); err == nil && matchAttributeValue(attrValue, allowedValues) {
			return true
		}
	}
	for key, globs := range p.allowedAttributesGlob {
		if attrValue, err := jsonpointer.Get(userInfo, key); err == nil && matchAttributeGlob(attrValue, globs) {
			return true
		}
	}
	return false
}

// compileGlobs compiles the non-empty patterns of an allow-list. No separator
// is configured, so `*` spans every character — `@`, `.` and `/` included —
// and a pattern is matched against the whole value, never a part of it. A
// pattern that does not compile is an error, which stops start-up rather than
// silently dropping a rule from an authorization decision.
func compileGlobs(patterns []string) ([]*glob.Pattern, error) {
	var compiled []*glob.Pattern
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		g, err := glob.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("%w %q: %w", ErrInvalidGlobPattern, pattern, err)
		}
		compiled = append(compiled, g)
	}
	return compiled, nil
}

// matchAttributeValue checks if an attribute value matches any of the allowed values.
// Supports string values and arrays of strings.
func matchAttributeValue(attrValue any, allowedValues []string) bool {
	switch v := attrValue.(type) {
	case string:
		return slices.Contains(allowedValues, v)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if slices.Contains(allowedValues, s) {
					return true
				}
			}
		}
	}
	return false
}

// matchAttributeGlob checks if an attribute value matches any of the glob patterns.
// Supports string values and arrays of strings.
func matchAttributeGlob(attrValue any, globs []*glob.Pattern) bool {
	switch v := attrValue.(type) {
	case string:
		for _, g := range globs {
			if g.Match(v) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				for _, g := range globs {
					if g.Match(s) {
						return true
					}
				}
			}
		}
	}
	return false
}
