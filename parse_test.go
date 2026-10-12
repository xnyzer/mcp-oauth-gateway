package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSplitWithEscapes(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		delimiter string
		expected  []string
	}{
		{
			name:      "simple comma split",
			input:     "a,b,c",
			delimiter: ",",
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "escaped comma",
			input:     "a,b\\,c,d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "email with escaped comma",
			input:     "user@domain.com\\,backup,*@example.org",
			delimiter: ",",
			expected:  []string{"user@domain.com,backup", "*@example.org"},
		},
		{
			name:      "glob pattern with escaped comma",
			input:     "admin.*@company\\,inc.*,*@example.com",
			delimiter: ",",
			expected:  []string{"admin.*@company,inc.*", "*@example.com"},
		},
		{
			name:      "empty string",
			input:     "",
			delimiter: ",",
			expected:  []string{},
		},
		{
			name:      "single item",
			input:     "single",
			delimiter: ",",
			expected:  []string{"single"},
		},
		{
			name:      "no escapes needed",
			input:     "user1@example.com,user2@test.org",
			delimiter: ",",
			expected:  []string{"user1@example.com", "user2@test.org"},
		},
		{
			name:      "multiple escaped commas",
			input:     "a\\,b\\,c,d,e\\,f",
			delimiter: ",",
			expected:  []string{"a,b,c", "d", "e,f"},
		},
		{
			name:      "whitespace trimming",
			input:     "a , b\\,c , d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "different delimiter",
			input:     "a;b\\;c;d",
			delimiter: ";",
			expected:  []string{"a", "b;c", "d"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitWithEscapes(tc.input, tc.delimiter)

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseAttributeMap(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string][]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string][]string{},
		},
		{
			name:  "single key-value pair",
			input: "/groups=admin",
			expected: map[string][]string{
				"/groups": {"admin"},
			},
		},
		{
			name:  "multiple values for same key",
			input: "/groups=admin,/groups=users",
			expected: map[string][]string{
				"/groups": {"admin", "users"},
			},
		},
		{
			name:  "multiple keys",
			input: "/groups=admin,/department=engineering",
			expected: map[string][]string{
				"/groups":     {"admin"},
				"/department": {"engineering"},
			},
		},
		{
			name:  "nested key with JSON pointer",
			input: "/org/team=platform",
			expected: map[string][]string{
				"/org/team": {"platform"},
			},
		},
		{
			name:  "glob pattern value",
			input: "/groups=*-admins,/email=*@example.com",
			expected: map[string][]string{
				"/groups": {"*-admins"},
				"/email":  {"*@example.com"},
			},
		},
		{
			name:  "whitespace trimming",
			input: " /groups = admin , /role = editor ",
			expected: map[string][]string{
				"/groups": {"admin"},
				"/role":   {"editor"},
			},
		},
		{
			name:  "blank entries are dropped",
			input: "/groups=admin,, ,/role=editor,",
			expected: map[string][]string{
				"/groups": {"admin"},
				"/role":   {"editor"},
			},
		},
		{
			name:  "a value may contain an equals sign",
			input: "/claim=a=b",
			expected: map[string][]string{
				"/claim": {"a=b"},
			},
		},
		{
			name:  "an escaped comma stays inside the value",
			input: `/groups={eng\,ops}-*`,
			expected: map[string][]string{
				"/groups": {"{eng,ops}-*"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseAttributeMap(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// An entry that cannot be read as a rule is an error, never a dropped rule:
// dropped, a lone malformed entry used to leave the allow-list empty, and an
// empty allow-list means "no restriction".
func TestParseAttributeMapRejectsMalformedEntries(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantInErr string
	}{
		{"no equals sign", "/groups admin", `"/groups admin"`},
		{"no equals sign beside a valid entry", "/groups=admin,invalid", `"invalid"`},
		{"empty key", "=value", `"=value"`},
		{"key is not a JSON pointer", "groups=admin", `"groups=admin"`},
		{"empty value", "/key=", `"/key="`},
		{"only separators", " , ,", errEmptyAllowList.Error()},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseAttributeMap(tc.input)
			if err == nil {
				t.Fatalf("expected an error, got %v", result)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q does not name %s", err, tc.wantInErr)
			}
		})
	}
}

func TestParseAllowList(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		split    func(string) []string
		expected []string
	}{
		{"unset", "", splitCSV, nil},
		{"plain list", "alice@example.com,bob@example.com", splitCSV, []string{"alice@example.com", "bob@example.com"}},
		{"blank entries are dropped", " alice@example.com ,, ,bob@example.com,", splitCSV, []string{"alice@example.com", "bob@example.com"}},
		{"glob list keeps escaped commas", `{alice\,bob}@example.com,*@example.org`, splitEscapedCSV, []string{"{alice,bob}@example.com", "*@example.org"}},
		{"glob list keeps other escapes", `user\*@example.com`, splitEscapedCSV, []string{`user\*@example.com`}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseAllowList(tc.input, tc.split)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}

	// Set, but nothing in it: the lenient reading would be "no restriction".
	for _, raw := range []string{",", " ", " , ,"} {
		for name, split := range map[string]func(string) []string{"plain": splitCSV, "glob": splitEscapedCSV} {
			if result, err := parseAllowList(raw, split); !errors.Is(err, errEmptyAllowList) {
				t.Errorf("%s list %q: expected errEmptyAllowList, got %v / %v", name, raw, result, err)
			}
		}
	}
}

// Each of the four settings reports its own name, so the start-up message
// tells the operator which variable to look at.
func TestOIDCAllowListSettingsNameTheSettingInErrors(t *testing.T) {
	testCases := []struct {
		settings oidcAllowListSettings
		want     string
	}{
		{oidcAllowListSettings{Users: ","}, "OIDC_ALLOWED_USERS is set"},
		{oidcAllowListSettings{UsersGlob: " "}, "OIDC_ALLOWED_USERS_GLOB is set"},
		{oidcAllowListSettings{Attributes: "/groups admin"}, "OIDC_ALLOWED_ATTRIBUTES has an entry"},
		{oidcAllowListSettings{AttributesGlob: "groups=*"}, "OIDC_ALLOWED_ATTRIBUTES_GLOB has an entry"},
	}
	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			_, err := tc.settings.parse()
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("expected an error starting with %q, got %v", tc.want, err)
			}
		})
	}

	lists, err := oidcAllowListSettings{
		Users:          "alice@example.com",
		UsersGlob:      "*@example.org",
		Attributes:     "/groups=admin",
		AttributesGlob: "/groups=team-*",
	}.parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lists.Users) != 1 || len(lists.UsersGlob) != 1 || len(lists.Attributes) != 1 || len(lists.AttributesGlob) != 1 {
		t.Errorf("every setting should yield its one rule, got %+v", lists)
	}

	if lists, err := (oidcAllowListSettings{}).parse(); err != nil || lists.Users != nil || lists.UsersGlob != nil {
		t.Errorf("unset settings parse to no rules without error, got %+v / %v", lists, err)
	}
}

func TestParseHeaderMapping(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:  "single mapping",
			input: "/email:X-Forwarded-Email",
			expected: map[string]string{
				"/email": "X-Forwarded-Email",
			},
		},
		{
			name:  "multiple mappings",
			input: "/email:X-Forwarded-Email,/preferred_username:X-Forwarded-User",
			expected: map[string]string{
				"/email":              "X-Forwarded-Email",
				"/preferred_username": "X-Forwarded-User",
			},
		},
		{
			name:  "nested JSON pointer",
			input: "/org/team:X-Forwarded-Team",
			expected: map[string]string{
				"/org/team": "X-Forwarded-Team",
			},
		},
		{
			name:  "whitespace trimming",
			input: " /email : X-Forwarded-Email , /sub : X-Forwarded-Sub ",
			expected: map[string]string{
				"/email": "X-Forwarded-Email",
				"/sub":   "X-Forwarded-Sub",
			},
		},
		{
			name:     "no colon - skipped",
			input:    "invalid",
			expected: map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseHeaderMapping(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "trims values",
			input:    " user1@example.com, user2@example.com ",
			expected: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:     "keeps empty values",
			input:    "a,,b",
			expected: []string{"a", "", "b"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitCSV(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}
