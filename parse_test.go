package main

import (
	"reflect"
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
			name:     "invalid format - no equals sign",
			input:    "invalid",
			expected: map[string][]string{},
		},
		{
			name:     "invalid format - empty key",
			input:    "=value",
			expected: map[string][]string{},
		},
		{
			name:     "invalid format - empty value",
			input:    "/key=",
			expected: map[string][]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseAttributeMap(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
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
