package observability

import (
	"regexp"
	"strings"
)

const credentialRedacted = "[CREDENTIAL_REDACTED]"

// credentialPatterns detects common credential formats that must never
// appear in telemetry span attributes or metric labels.
//
// Patterns are aligned with the token regex in cmd/ongoingai/trace_capture.go
// and extended with Bearer header values and connection-string secrets.
var credentialPatterns = []*regexp.Regexp{
	// API key prefixes: sk_, pk_, rk_, xox*_, ghp/gho/ghu/ghs/ghr_, pat_
	regexp.MustCompile(`(?i)\b(?:sk|pk|rk|xox[baprs]|gh[pousr]|pat)_[a-z0-9_-]{8,}\b`),
	// JWT-like tokens (three base64url segments separated by dots)
	regexp.MustCompile(`(?i)eyj[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}`),
	// Bearer token in header-like strings
	regexp.MustCompile(`(?i)\bBearer\s+[a-z0-9_.\-/+=]{8,}\b`),
	// Connection string secrets: password=..., secret=..., token=...
	regexp.MustCompile(`(?i)\b(?:password|secret|token)\s*=\s*\S{4,}`),
}

// ContainsCredential reports whether s matches any known credential pattern.
// Short strings (< 8 chars) are skipped as a fast path since no credential
// pattern can match a string that short.
func ContainsCredential(s string) bool {
	if len(s) < 8 {
		return false
	}
	for _, p := range credentialPatterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}

// ScrubCredentials replaces all detected credential patterns in s with
// [CREDENTIAL_REDACTED]. If no patterns match, s is returned unchanged
// with no allocation.
func ScrubCredentials(s string) string {
	if len(s) < 8 {
		return s
	}
	result := s
	changed := false
	for _, p := range credentialPatterns {
		if p.MatchString(result) {
			result = p.ReplaceAllString(result, credentialRedacted)
			changed = true
		}
	}
	if !changed {
		return s
	}
	return strings.TrimSpace(result)
}
