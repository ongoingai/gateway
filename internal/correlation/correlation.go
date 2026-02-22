package correlation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// HeaderName is the canonical correlation identifier header.
	HeaderName = "X-OngoingAI-Correlation-ID"
	maxIDLen   = 128
)

type contextKey struct{}

var correlationContextKey contextKey

// EnsureRequest guarantees a stable correlation identifier on the request
// context and request headers.
func EnsureRequest(req *http.Request) (*http.Request, string) {
	if req == nil {
		return nil, ""
	}
	if id, ok := FromContext(req.Context()); ok {
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set(HeaderName, id)
		return req, id
	}

	id := FromHeaders(req.Header)
	if id == "" {
		id = NewID()
	}

	req = req.WithContext(WithContext(req.Context(), id))
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set(HeaderName, id)
	return req, id
}

// WithContext stores a normalized correlation identifier in context.
func WithContext(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := normalizeID(id)
	if normalized == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationContextKey, normalized)
}

// FromContext extracts a normalized correlation identifier from context.
func FromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(correlationContextKey).(string)
	if !ok {
		return "", false
	}
	normalized := normalizeID(value)
	if normalized == "" {
		return "", false
	}
	return normalized, true
}

// FromHeaders extracts a normalized correlation identifier from known headers.
func FromHeaders(headers http.Header) string {
	if headers == nil {
		return ""
	}
	candidates := []string{
		HeaderName,
		"X-Request-ID",
		"X-Request-Id",
		"X-Correlation-ID",
		"X-Correlation-Id",
	}
	for _, header := range candidates {
		if id := normalizeID(headers.Get(header)); id != "" {
			return id
		}
	}
	return ""
}

// NewID returns a new gateway correlation identifier.
func NewID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("corr-%d", time.Now().UnixNano())
	}
	return "corr-" + hex.EncodeToString(bytes[:])
}

func normalizeID(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if len(value) > maxIDLen {
		value = value[:maxIDLen]
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return ""
		}
	}
	return value
}
