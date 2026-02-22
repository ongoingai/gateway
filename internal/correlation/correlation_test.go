package correlation

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnsureRequestUsesIncomingHeaderWhenValid(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/openai/v1/chat/completions", nil)
	req.Header.Set("X-Request-ID", "abc-123")

	updated, id := EnsureRequest(req)
	if updated == nil {
		t.Fatal("updated request is nil")
	}
	if id != "abc-123" {
		t.Fatalf("correlation id=%q, want abc-123", id)
	}
	if got := updated.Header.Get(HeaderName); got != "abc-123" {
		t.Fatalf("%s=%q, want abc-123", HeaderName, got)
	}
	if fromCtx, ok := FromContext(updated.Context()); !ok || fromCtx != "abc-123" {
		t.Fatalf("context correlation=%q (ok=%v), want abc-123", fromCtx, ok)
	}
}

func TestEnsureRequestGeneratesIDWhenIncomingHeaderInvalid(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/openai/v1/chat/completions", nil)
	req.Header.Set(HeaderName, "bad value with spaces")

	updated, id := EnsureRequest(req)
	if updated == nil {
		t.Fatal("updated request is nil")
	}
	if id == "" {
		t.Fatal("expected generated correlation id")
	}
	if got := updated.Header.Get(HeaderName); got != id {
		t.Fatalf("%s=%q, want %q", HeaderName, got, id)
	}
	if fromCtx, ok := FromContext(updated.Context()); !ok || fromCtx != id {
		t.Fatalf("context correlation=%q (ok=%v), want %q", fromCtx, ok, id)
	}
}

func TestFromHeadersPrioritizesCanonicalHeader(t *testing.T) {
	t.Parallel()

	headers := make(http.Header)
	headers.Set("X-Request-ID", "request-id")
	headers.Set(HeaderName, "canonical-id")

	if got := FromHeaders(headers); got != "canonical-id" {
		t.Fatalf("FromHeaders()=%q, want canonical-id", got)
	}
}
