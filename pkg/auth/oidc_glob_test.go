package auth

// What the OIDC allow-list matches (F-031b). The patterns in
// OIDC_ALLOWED_USERS_GLOB and OIDC_ALLOWED_ATTRIBUTES_GLOB decide who may log
// in, so the rows that matter most are the ones that must NOT match.
//
// The table was written against gobwas/glob 0.2.3 and run there before the
// move to 1.0, whose matching engine is a rewrite. Rows marked "0.2.3 got this
// wrong" failed on the old engine; everything else held on both.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestAllowListGlobSemantics(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
		why     string
	}{
		// -- A pattern describes the whole value, never a part of it ------
		{"user@example.com", "user@example.com", true, "a pattern without wildcards is an exact match"},
		{"user@example.com", "user@example.comx", false, "no match on a prefix"},
		{"user@example.com", "xuser@example.com", false, "no match on a suffix"},
		{"*@example.com", "user@example.com", true, "the documented use"},
		{"*@example.com", "user@example.com.evil.example", false, "the domain is anchored at the end"},
		{"*@example.com", "user@sub.example.com", false, "the @ is part of the literal"},
		{"admin@*", "admin@example.com", true, "anchored at the start"},
		{"admin@*", "notadmin@example.com", false, "anchored at the start"},
		{"*@Example.com", "user@example.com", false, "matching is case-sensitive"},

		// -- `*` has no separator: it spans everything, including @ . / ---
		{"*", "anything", true, "a lone star allows every value"},
		{"*", "", true, "including the empty one"},
		{"*@example.com", "attacker@evil.example@example.com", true, "star crosses @ — allow-list on a verified claim"},
		{"*.example.com", "a.b.example.com", true, "star crosses dots"},
		{"*.example.com", "example.com", false, "the dot is part of the literal"},
		{"*/admins", "corp/eu/admins", true, "star crosses slashes"},
		{"**@example.com", "user@example.com", true, "a double star means the same here"},
		{"team-*", "team-", true, "star may match nothing"},
		{"team-*", "team", false, "the dash is part of the literal"},
		{"team-*", "xteam-a", false, "anchored at the start"},

		// -- `?` is exactly one character ---------------------------------
		{"user?@example.com", "user1@example.com", true, "one character"},
		{"user?@example.com", "user@example.com", false, "not zero"},
		{"user?@example.com", "user12@example.com", false, "not two"},
		{"?", "", false, "0.2.3 got this wrong: ? matched the empty value"},
		{"user?@example.com", "userü@example.com", true, "0.2.3 got this wrong: a non-ASCII character is one character"},

		// -- Character classes --------------------------------------------
		{"user[0-9]@example.com", "user5@example.com", true, "in the class"},
		{"user[0-9]@example.com", "userx@example.com", false, "outside the class"},
		{"user[0-9]@example.com", "user@example.com", false, "a class is exactly one character"},
		{"user[!0-9]@example.com", "userx@example.com", true, "negated class"},
		{"user[!0-9]@example.com", "user5@example.com", false, "negated class"},
		{"[!a]", "", false, "0.2.3 got this wrong: a negated class matched the empty value"},

		// -- Alternatives -------------------------------------------------
		{"{alice,bob}@example.com", "alice@example.com", true, "first alternative"},
		{"{alice,bob}@example.com", "bob@example.com", true, "second alternative"},
		{"{alice,bob}@example.com", "carol@example.com", false, "not listed"},
		{"{alice,bob}@example.com", "alice,bob@example.com", false, "the comma separates, it is not matched"},
		{"*@{example.com,example.org}", "user@example.org", true, "alternatives after a star"},
		{"*@{example.com,example.org}", "user@example.net", false, "not listed"},
		{"a{}", "a", true, "0.2.3 got this wrong: empty braces crashed the match"},
		{"team{-eu,}-*", "team-ops", true, "an empty alternative means the part is optional"},
		{"team{-eu,}-*", "team-eu-ops", true, "and may be present"},
		{"{dev,}{ops,}-lead", "-lead", true, "0.2.3 got this wrong: two empty choices in a row were lost"},
		{"*{a,}", "", true, "0.2.3 got this wrong: the empty choice was lost next to a star"},

		// -- Escapes ------------------------------------------------------
		{`user\*@example.com`, "user*@example.com", true, "an escaped star is a literal star"},
		{`user\*@example.com`, "userX@example.com", false, "and nothing else"},

		// -- Non-ASCII ----------------------------------------------------
		{"müller@*", "müller@example.com", true, "non-ASCII literals match themselves"},
		{"müller@*", "muller@example.com", false, "and only themselves"},

		// -- Literals around a star must not share characters -------------
		{"admin*admin", "adminadmin", true, "prefix and suffix side by side"},
		{"admin*admin", "admin", false, "0.2.3 got this wrong: one 'admin' served as both prefix and suffix"},
		{"admin*n@corp.example", "adminxn@corp.example", true, "prefix, something, suffix"},
		{"admin*n@corp.example", "admin@corp.example", false, "0.2.3 got this wrong: the 'n' of admin was counted twice"},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+" vs "+tc.value, func(t *testing.T) {
			globs, err := compileGlobs([]string{tc.pattern})
			require.NoError(t, err)
			require.Equal(t, tc.want, matchAttributeGlob(tc.value, globs), tc.why)
		})
	}
}

// A pattern that does not parse must stop start-up. Dropping it silently
// would remove a rule from an authorization decision; guessing what it meant
// is worse — 0.2.3 read `{alice,bob` as if the brace had been closed.
func TestAllowListRejectsMalformedPatterns(t *testing.T) {
	for _, pattern := range []string{
		"{alice,bob", // unclosed brace — 0.2.3 accepted it
		`user\`,      // trailing backslash — 0.2.3 accepted it
		"user[0-9",   // unclosed class
		"[]",         // empty class
	} {
		t.Run(pattern, func(t *testing.T) {
			_, err := compileGlobs([]string{"*@example.com", pattern})
			require.Error(t, err)
			require.Contains(t, err.Error(), pattern, "the message names the offending pattern")
		})
	}
}

func TestAllowListSkipsEmptyPatterns(t *testing.T) {
	globs, err := compileGlobs([]string{"", "*@example.com", ""})
	require.NoError(t, err)
	require.Len(t, globs, 1, "an empty entry is no pattern; as one it would match only the empty value")

	globs, err = compileGlobs(nil)
	require.NoError(t, err)
	require.Empty(t, globs)
}

// Attribute values arrive as whatever the userinfo JSON holds.
func TestAllowListGlobOnAttributeValues(t *testing.T) {
	globs, err := compileGlobs([]string{"team-*"})
	require.NoError(t, err)

	require.True(t, matchAttributeGlob([]any{"users", "team-platform"}, globs), "one matching entry in a list is enough")
	require.False(t, matchAttributeGlob([]any{"users", "guests"}, globs))
	require.True(t, matchAttributeGlob([]any{42, "team-a"}, globs), "non-strings in a list are skipped, not fatal")
	require.False(t, matchAttributeGlob(42, globs), "a non-string value never matches")
	require.False(t, matchAttributeGlob(nil, globs))
	require.False(t, matchAttributeGlob("team-platform", nil), "no pattern, no match")
}

// The constructor is where a malformed pattern has to surface: it runs at
// start-up, so the gateway refuses to start instead of running without the rule.
func TestNewOIDCProviderFailsOnMalformedGlob(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configServer := gin.New()
	configServer.GET("/.well-known/openid_configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]any{
			"authorization_endpoint": "http://localhost/auth",
			"token_endpoint":         "http://localhost/token",
			"userinfo_endpoint":      "http://localhost/userinfo",
		})
	})
	server := httptest.NewServer(configServer)
	defer server.Close()

	newProvider := func(usersGlob []string, attributesGlob map[string][]string) error {
		_, err := NewOIDCProvider(
			server.URL+"/.well-known/openid_configuration", []string{"openid"}, "/email",
			"TestOIDC", TestOIDCExternalURL, TestOIDCClientID, TestOIDCClientSecret,
			nil, usersGlob, nil, attributesGlob,
		)
		return err
	}

	require.NoError(t, newProvider([]string{"*@example.com"}, map[string][]string{"/groups": {"team-*"}}))
	require.Error(t, newProvider([]string{"*@example.com", "user[0-9"}, nil), "a malformed user pattern")
	require.Error(t, newProvider(nil, map[string][]string{"/groups": {"team-*", "[]"}}), "a malformed attribute pattern")
}

// -- An allow-list is required -------------------------------------------------

// unreachableOIDCConfig is never fetched by a test that expects the allow-list
// check to come first; a provider that did fetch it would fail differently.
const unreachableOIDCConfig = "http://127.0.0.1:1/.well-known/openid_configuration"

// OIDC without a rule would make every account of the provider the operator.
// The constructor refuses that — before it fetches anything, so the refusal
// does not depend on the provider being reachable.
func TestNewOIDCProviderRequiresAnAllowList(t *testing.T) {
	cases := []struct {
		name           string
		users          []string
		usersGlob      []string
		attributes     map[string][]string
		attributesGlob map[string][]string
	}{
		{name: "nothing set"},
		{name: "empty lists", users: []string{}, usersGlob: []string{}, attributes: map[string][]string{}, attributesGlob: map[string][]string{}},
		{name: "only blank patterns", usersGlob: []string{"", ""}},
		{name: "an attribute key without values", attributes: map[string][]string{"/groups": {}}},
		{name: "an attribute key with only blank patterns", attributesGlob: map[string][]string{"/groups": {""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewOIDCProvider(
				unreachableOIDCConfig, []string{"openid"}, "/email",
				"TestOIDC", TestOIDCExternalURL, TestOIDCClientID, TestOIDCClientSecret,
				tc.users, tc.usersGlob, tc.attributes, tc.attributesGlob,
			)
			require.ErrorIs(t, err, ErrNoAllowList)
		})
	}
}

// Any single rule is an allow-list — including the one that admits everyone,
// which is the point: it has to be written down.
func TestNewOIDCProviderAcceptsAnySingleRule(t *testing.T) {
	gin.SetMode(gin.TestMode)
	configServer := gin.New()
	configServer.GET("/.well-known/openid_configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]any{
			"authorization_endpoint": "http://localhost/auth",
			"token_endpoint":         "http://localhost/token",
			"userinfo_endpoint":      "http://localhost/userinfo",
		})
	})
	server := httptest.NewServer(configServer)
	defer server.Close()

	cases := []struct {
		name           string
		users          []string
		usersGlob      []string
		attributes     map[string][]string
		attributesGlob map[string][]string
	}{
		{name: "an exact user", users: []string{"alice@example.com"}},
		{name: "a user pattern", usersGlob: []string{"*@example.com"}},
		{name: "everyone, said explicitly", usersGlob: []string{"*"}},
		{name: "an exact attribute", attributes: map[string][]string{"/groups": {"admins"}}},
		{name: "an attribute pattern", attributesGlob: map[string][]string{"/groups": {"team-*"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewOIDCProvider(
				server.URL+"/.well-known/openid_configuration", []string{"openid"}, "/email",
				"TestOIDC", TestOIDCExternalURL, TestOIDCClientID, TestOIDCClientSecret,
				tc.users, tc.usersGlob, tc.attributes, tc.attributesGlob,
			)
			require.NoError(t, err)
		})
	}
}

// Belt and braces: a provider that holds no rule — which the constructor never
// builds — denies. The old behaviour was to admit everyone.
func TestOIDCProviderWithoutARuleDeniesEveryone(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userinfo := gin.New()
	userinfo.GET("/userinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]any{"sub": "user1", "email": "user@example.com", "groups": []string{"admins"}})
	})
	server := httptest.NewServer(userinfo)
	defer server.Close()

	provider := &oidcProvider{userInfoURL: server.URL + "/userinfo", userIDField: "/email"}

	authorized, userID, _, err := provider.Authorization(context.Background(), &oauth2.Token{AccessToken: "test"})

	require.NoError(t, err)
	require.Equal(t, "user@example.com", userID, "the identity was read")
	require.False(t, authorized, "and refused, because no rule admits it")
}
