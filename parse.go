package main

import (
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

// parseAttributeMap parses a comma-separated string of key=value pairs into a map
// where each key can have multiple values. Format: /key1=value1,/key1=value2,/key2=value3
// Keys are JSON pointers to attributes in the userinfo response.
func parseAttributeMap(s string) map[string][]string {
	result := make(map[string][]string)
	if s == "" {
		return result
	}
	parts := splitWithEscapes(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eqIdx := strings.Index(part, "=")
		if eqIdx == -1 {
			continue
		}
		key := strings.TrimSpace(part[:eqIdx])
		value := strings.TrimSpace(part[eqIdx+1:])
		if key != "" && value != "" {
			result[key] = append(result[key], value)
		}
	}
	return result
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
