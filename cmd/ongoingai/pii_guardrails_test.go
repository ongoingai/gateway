package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/config"
)

func TestPIIGuardrailMiddlewareRedactUpstreamRedactsRequestBody(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.PII.Mode = config.PIIModeRedactUpstream

	var seenBody string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		seenBody = string(data)
		w.WriteHeader(http.StatusOK)
	})

	handler := piiGuardrailMiddleware(cfg, nil, next)
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", strings.NewReader(`{"email":"alice@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusOK)
	}
	if strings.Contains(seenBody, "alice@example.com") {
		t.Fatalf("upstream body still contains raw pii: %q", seenBody)
	}
	if !strings.Contains(seenBody, "_REDACTED:") {
		t.Fatalf("upstream body=%q, want redaction placeholder", seenBody)
	}
}

func TestPIIGuardrailMiddlewareBlockRejectsDetectedPII(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.PII.Mode = config.PIIModeBlock

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := piiGuardrailMiddleware(cfg, nil, next)
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{"phone":"415-555-1212"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusForbidden)
	}
	if nextCalled {
		t.Fatal("next handler called for blocked request")
	}
	if !strings.Contains(rec.Body.String(), "request blocked by pii policy") {
		t.Fatalf("response body=%q, want block message", rec.Body.String())
	}
}

func TestPIIGuardrailMiddlewareBlockAllowsCleanPayload(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.PII.Mode = config.PIIModeBlock

	var seenBody string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		seenBody = string(data)
		w.WriteHeader(http.StatusAccepted)
	})

	handler := piiGuardrailMiddleware(cfg, nil, next)
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", strings.NewReader(`{"prompt":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusAccepted)
	}
	if seenBody != `{"prompt":"hello"}` {
		t.Fatalf("upstream body=%q, want unchanged body", seenBody)
	}
}

func TestPIIGuardrailMiddlewareFailsClosedWhenRequestBodyExceedsInspectionLimit(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.PII.Mode = config.PIIModeRedactUpstream
	cfg.Tracing.BodyMaxSize = 8

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := piiGuardrailMiddleware(cfg, nil, next)
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", strings.NewReader(`{"email":"alice@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if nextCalled {
		t.Fatal("next handler called for oversize inspected body")
	}
	if !strings.Contains(rec.Body.String(), piiGuardrailUncertaintyMessage) {
		t.Fatalf("response body=%q, want uncertainty message", rec.Body.String())
	}
}

func TestPIIGuardrailMiddlewareBlockFailsClosedOnPolicyUncertainty(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.PII.Mode = config.PIIModeBlock
	cfg.Tracing.BodyMaxSize = 8

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := piiGuardrailMiddleware(cfg, nil, next)
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{"phone":"415-555-1212"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if nextCalled {
		t.Fatal("next handler called for policy uncertainty")
	}
	if !strings.Contains(rec.Body.String(), piiGuardrailUncertaintyMessage) {
		t.Fatalf("response body=%q, want uncertainty message", rec.Body.String())
	}
}

func TestPIIGuardrailMiddlewareSkipsNonProviderRoutes(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.PII.Mode = config.PIIModeBlock

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := piiGuardrailMiddleware(cfg, nil, next)
	req := httptest.NewRequest(http.MethodPost, "/api/health", strings.NewReader(`{"email":"alice@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Fatal("next handler not called for non-provider route")
	}
}

func TestPIIGuardrailMiddlewareAppliesScopedPolicyByWorkspaceProviderAndRoute(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.PII.Mode = config.PIIModeOff
	cfg.PII.Scopes = []config.PIIScopeConfig{
		{
			Match: config.PIIScopeMatchConfig{
				WorkspaceID: "workspace-strict",
				Provider:    "openai",
				RoutePrefix: "/openai/v1/chat",
			},
			Mode: config.PIIModeBlock,
		},
	}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := piiGuardrailMiddleware(cfg, nil, next)
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", strings.NewReader(`{"email":"alice@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-default",
		WorkspaceID: "workspace-strict",
		KeyID:       "key-123",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusForbidden)
	}
	if nextCalled {
		t.Fatal("next handler called for scoped blocked request")
	}
	if !strings.Contains(rec.Body.String(), piiGuardrailBlockedMessage) {
		t.Fatalf("response body=%q, want block message", rec.Body.String())
	}
}
