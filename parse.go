package main

import (
	"errors"
	"fmt"
	"strings"
)

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// splitWithEscapes splits a string by delimiter, respecting escape sequences
// e.g., "a,b\,c,d" with delimiter "," returns ["a", "b,c", "d"]
func splitWithEscapes(s, delimiter string) []string {
	if s == "" {
		return []string{}
	}

	var result []string
	var current strings.Builder
	escaped := false

	for i := 0; i < len(s); i++ {
		if escaped {
			current.WriteByte(s[i])
			escaped = false
		} else if s[i] == '\\' && i+1 < len(s) {
			// Check if next character is the delimiter
			if strings.HasPrefix(s[i+1:], delimiter) {
				// Skip the backslash and add the delimiter character
				escaped = true
			} else {
				// Not escaping delimiter, keep the backslash
				current.WriteByte(s[i])
			}
		} else if strings.HasPrefix(s[i:], delimiter) {
			// Found unescaped delimiter
			result = append(result, strings.TrimSpace(current.String()))
			current.Reset()
			i += len(delimiter) - 1 // -1 because loop will increment
		} else {
			current.WriteByte(s[i])
		}
	}

	// Add the last part
	result = append(result, strings.TrimSpace(current.String()))
	return result
}

// -- OIDC allow-lists ---------------------------------------------------------
//
// These four settings decide who may log in through OIDC. They are parsed
// strictly: an entry that cannot be read as a rule stops start-up. Dropping it
// silently — what this parser used to do — removes a rule from an authorization
// decision, and when it was the only rule, the allow-list quietly became "no
// restriction" (CODING-STANDARDS §6/§7: fail closed, fail fast).

// errEmptyAllowList reports a setting that is set but names no rule.
var errEmptyAllowList = errors.New("is set but contains no entry")

// oidcAllowListSettings are the raw values of the four allow-list settings.
type oidcAllowListSettings struct {
	Users          string
	UsersGlob      string
	Attributes     string
	AttributesGlob string
}

// oidcAllowLists are the same four settings, parsed.
type oidcAllowLists struct {
	Users          []string
	UsersGlob      []string
	Attributes     map[string][]string
	AttributesGlob map[string][]string
}

// parse reads all four settings; an error names the setting it came from.
func (s oidcAllowListSettings) parse() (oidcAllowLists, error) {
	var lists oidcAllowLists
	var err error
	if lists.Users, err = parseAllowList(s.Users, splitCSV); err != nil {
		return oidcAllowLists{}, fmt.Errorf("OIDC_ALLOWED_USERS %w", err)
	}
	if lists.UsersGlob, err = parseAllowList(s.UsersGlob, splitEscapedCSV); err != nil {
		return oidcAllowLists{}, fmt.Errorf("OIDC_ALLOWED_USERS_GLOB %w", err)
	}
	if lists.Attributes, err = parseAttributeMap(s.Attributes); err != nil {
		return oidcAllowLists{}, fmt.Errorf("OIDC_ALLOWED_ATTRIBUTES %w", err)
	}
	if lists.AttributesGlob, err = parseAttributeMap(s.AttributesGlob); err != nil {
		return oidcAllowLists{}, fmt.Errorf("OIDC_ALLOWED_ATTRIBUTES_GLOB %w", err)
	}
	return lists, nil
}

// splitEscapedCSV splits at commas, reading `\,` as a literal comma — which a
// glob pattern needs for the comma inside `{a,b}`.
func splitEscapedCSV(s string) []string {
	return splitWithEscapes(s, ",")
}

// parseAllowList turns a comma-separated allow-list setting into its entries.
// Blank entries (a trailing comma, stray spaces) are dropped. A setting that is
// set but yields no entry is an error.
func parseAllowList(raw string, split func(string) []string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var entries []string
	for _, entry := range split(raw) {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		return nil, errEmptyAllowList
	}
	return entries, nil
}

// parseAttributeMap parses a comma-separated list of key=value pairs, where a
// key may repeat: /key1=value1,/key1=value2,/key2=value3. Keys are JSON
// pointers into the userinfo response, so each starts with a slash. Blank
// entries are dropped; an entry that is not `/pointer=value` is an error.
func parseAttributeMap(s string) (map[string][]string, error) {
	result := make(map[string][]string)
	if s == "" {
		return result, nil
	}
	for _, part := range splitWithEscapes(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case !found:
			return nil, fmt.Errorf("has an entry without \"=\": %q", part)
		case !strings.HasPrefix(key, "/"):
			return nil, fmt.Errorf("has an entry whose key is not a JSON pointer starting with \"/\": %q", part)
		case value == "":
			return nil, fmt.Errorf("has an entry without a value: %q", part)
		}
		result[key] = append(result[key], value)
	}
	if len(result) == 0 {
		return nil, errEmptyAllowList
	}
	return result, nil
}

func parseHeaderMapping(s string) map[string]string {
	result := make(map[string]string)
	if s == "" {
		return result
	}
	parts := splitWithEscapes(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		colonIdx := strings.LastIndex(part, ":")
		if colonIdx == -1 {
			continue
		}
		pointer := strings.TrimSpace(part[:colonIdx])
		header := strings.TrimSpace(part[colonIdx+1:])
		if pointer != "" && header != "" {
			result[pointer] = header
		}
	}
	return result
}
