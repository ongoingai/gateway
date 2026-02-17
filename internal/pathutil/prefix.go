package pathutil

import "strings"

// NormalizePrefix returns a leading-slash prefix without a trailing slash.
func NormalizePrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "/"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if len(prefix) > 1 {
		prefix = strings.TrimRight(prefix, "/")
	}
	return prefix
}

// HasPathPrefix reports whether path equals prefix or is nested under it.
func HasPathPrefix(path, prefix string) bool {
	prefix = NormalizePrefix(prefix)
	if prefix == "/" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// StripPathPrefix removes a normalized prefix from path.
func StripPathPrefix(path, prefix string) string {
	if !HasPathPrefix(path, prefix) {
		return path
	}

	stripped := strings.TrimPrefix(path, NormalizePrefix(prefix))
	if stripped == "" {
		return "/"
	}
	if !strings.HasPrefix(stripped, "/") {
		return "/" + stripped
	}
	return stripped
}
