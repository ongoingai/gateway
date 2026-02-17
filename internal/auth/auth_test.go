package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAuthorizerRequiresKeysWhenEnabled(t *testing.T) {
	t.Parallel()

	_, err := NewAuthorizer(Options{
		Enabled: true,
	})
	if err == nil {
		t.Fatal("expected error when auth is enabled without keys")
	}
}

func TestAuthenticateAndRolePermissions(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-dev-1",
				Token: "dev-token",
				Team:  "team-a",
				Role:  "developer",
			},
			{
				ID:    "team-a-viewer-1",
				Token: "viewer-token",
				Team:  "team-a",
				Role:  "viewer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "dev-token")
	identity, err := authorizer.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if identity.KeyID != "team-a-dev-1" {
		t.Fatalf("identity.KeyID=%q, want team-a-dev-1", identity.KeyID)
	}
	if identity.OrgID != "default" {
		t.Fatalf("identity.OrgID=%q, want default", identity.OrgID)
	}
	if identity.WorkspaceID != "team-a" {
		t.Fatalf("identity.WorkspaceID=%q, want team-a (fallback from team)", identity.WorkspaceID)
	}
	if !identity.HasPermission(PermissionProxyWrite) {
		t.Fatal("developer role should include proxy:write")
	}

	req.Header.Set("X-OngoingAI-Gateway-Key", "viewer-token")
	identity, err = authorizer.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() viewer error: %v", err)
	}
	if identity.HasPermission(PermissionProxyWrite) {
		t.Fatal("viewer role should not include proxy:write")
	}
	if !identity.HasPermission(PermissionAnalyticsRead) {
		t.Fatal("viewer role should include analytics:read")
	}
}

func TestAuthenticateWithPreHashedToken(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:        "team-a-owner-1",
				TokenHash: hashToken("owner-token"),
				Team:      "team-a",
				Role:      "owner",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "owner-token")
	identity, err := authorizer.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if identity.KeyID != "team-a-owner-1" {
		t.Fatalf("identity.KeyID=%q, want team-a-owner-1", identity.KeyID)
	}
}

func TestAuthenticateReturnsIndependentIdentityCopy(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-dev-1",
				Token: "dev-token",
				Role:  "developer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "dev-token")

	firstIdentity, err := authorizer.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() first call error: %v", err)
	}
	firstIdentity.OrgID = "mutated-org"
	firstIdentity.permissions[PermissionKeysManage] = struct{}{}

	secondIdentity, err := authorizer.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() second call error: %v", err)
	}
	if secondIdentity.OrgID != "default" {
		t.Fatalf("second identity OrgID=%q, want default", secondIdentity.OrgID)
	}
	if secondIdentity.HasPermission(PermissionKeysManage) {
		t.Fatal("mutating one authenticated identity should not affect future authentications")
	}
}

func TestAuthenticateUnknownRoleHasNoImplicitPermissions(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-custom-1",
				Token: "custom-token",
				Role:  "custom",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "custom-token")
	identity, err := authorizer.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if identity.HasPermission(PermissionProxyWrite) {
		t.Fatal("custom role should not receive proxy:write by default")
	}
	if identity.HasPermission(PermissionAnalyticsRead) {
		t.Fatal("custom role should not receive analytics:read by default")
	}
}

func TestAuthenticateUnknownRoleRespectsExplicitPermissions(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:          "team-a-custom-2",
				Token:       "custom-token-2",
				Role:        "custom",
				Permissions: []string{"analytics:read"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "custom-token-2")
	identity, err := authorizer.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if !identity.HasPermission(PermissionAnalyticsRead) {
		t.Fatal("explicit permission should be granted")
	}
	if identity.HasPermission(PermissionProxyWrite) {
		t.Fatal("ungranted permission should remain denied")
	}
}

func TestMiddlewareProtectsProxyAndPassesThroughProviderCredential(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-owner-1",
				Token: "owner-token",
				Team:  "team-a",
				Role:  "owner",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	var seenAuthHeader string
	var seenGatewayHeader string
	var seenIdentityKeyID string
	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthHeader = r.Header.Get("Authorization")
		seenGatewayHeader = r.Header.Get("X-OngoingAI-Gateway-Key")
		identity, ok := IdentityFromContext(r.Context())
		if !ok {
			t.Fatal("expected identity in context")
		}
		seenIdentityKeyID = identity.KeyID
		w.WriteHeader(http.StatusAccepted)
	}))

	// Client sends gateway key in custom header + provider key in Authorization
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "owner-token")
	req.Header.Set("Authorization", "Bearer sk-openai-user-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusAccepted)
	}
	if seenAuthHeader != "Bearer sk-openai-user-key" {
		t.Fatalf("authorization=%q, want client's provider key passed through", seenAuthHeader)
	}
	if seenGatewayHeader != "" {
		t.Fatalf("gateway header=%q, want stripped", seenGatewayHeader)
	}
	if seenIdentityKeyID != "team-a-owner-1" {
		t.Fatalf("identity key id=%q, want team-a-owner-1", seenIdentityKeyID)
	}
}

func TestMiddlewareRejectsMissingProviderCredential(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-owner-1",
				Token: "owner-token",
				Team:  "team-a",
				Role:  "owner",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Client sends gateway key but no provider key
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "owner-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d (missing provider key)", rec.Code, http.StatusForbidden)
	}
}

func TestMiddlewareRequiresGatewayTokenInConfiguredHeader(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-owner-1",
				Token: "owner-token",
				Team:  "team-a",
				Role:  "owner",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	// Gateway token in Authorization is not accepted. Must use configured gateway header.
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer owner-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d (gateway key missing header)", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareBlocksProxyForViewer(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-viewer-1",
				Token: "viewer-token",
				Team:  "team-a",
				Role:  "viewer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "viewer-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestMiddlewareAllowsAPIReadForViewerAndHealthWithoutAuth(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-viewer-1",
				Token: "viewer-token",
				Team:  "team-a",
				Role:  "viewer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	apiReq := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	apiReq.Header.Set("X-OngoingAI-Gateway-Key", "viewer-token")
	apiRec := httptest.NewRecorder()
	handler.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusOK {
		t.Fatalf("api status=%d, want %d", apiRec.Code, http.StatusOK)
	}

	keysReq := httptest.NewRequest(http.MethodGet, "/api/gateway-keys", nil)
	keysReq.Header.Set("X-OngoingAI-Gateway-Key", "viewer-token")
	keysRec := httptest.NewRecorder()
	handler.ServeHTTP(keysRec, keysReq)
	if keysRec.Code != http.StatusForbidden {
		t.Fatalf("gateway keys status=%d, want %d", keysRec.Code, http.StatusForbidden)
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health status=%d, want %d", healthRec.Code, http.StatusOK)
	}
}

func TestMiddlewareRequiresGatewayKeyOnProtectedRoutes(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-dev-1",
				Token: "dev-token",
				Team:  "team-a",
				Role:  "developer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMiddlewareDeniesUnmappedAPIActionByDefault(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-owner-1",
				Token: "owner-token",
				Role:  "owner",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	var called bool
	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/internal/debug", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "owner-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("next handler should not be called for unmapped action")
	}
}

func TestMiddlewareAllowsPreflightWithoutAuth(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-owner-1",
				Token: "owner-token",
				Role:  "owner",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/traces", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestMiddlewareAllowsTraceReplayAndForkWithAnalyticsPermission(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-viewer-1",
				Token: "viewer-token",
				Role:  "viewer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	replayReq := httptest.NewRequest(http.MethodGet, "/api/traces/trace-1/replay", nil)
	replayReq.Header.Set("X-OngoingAI-Gateway-Key", "viewer-token")
	replayRec := httptest.NewRecorder()
	handler.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusNoContent {
		t.Fatalf("replay status=%d, want %d", replayRec.Code, http.StatusNoContent)
	}

	forkReq := httptest.NewRequest(http.MethodPost, "/api/traces/trace-1/fork", nil)
	forkReq.Header.Set("X-OngoingAI-Gateway-Key", "viewer-token")
	forkRec := httptest.NewRecorder()
	handler.ServeHTTP(forkRec, forkReq)
	if forkRec.Code != http.StatusNoContent {
		t.Fatalf("fork status=%d, want %d", forkRec.Code, http.StatusNoContent)
	}
}

func TestDynamicMiddlewareFailsClosedWhenResolverUnavailable(t *testing.T) {
	t.Parallel()

	handler := DynamicMiddleware(func(_ *http.Request) (*Authorizer, error) {
		return nil, errors.New("key store unavailable")
	}, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	protectedReq := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	protectedRec := httptest.NewRecorder()
	handler.ServeHTTP(protectedRec, protectedReq)
	if protectedRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("protected status=%d, want %d", protectedRec.Code, http.StatusServiceUnavailable)
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health status=%d, want %d", healthRec.Code, http.StatusOK)
	}
}

func TestMiddlewareReturns429WithLimitErrorCode(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-dev-1",
				Token: "dev-token",
				Team:  "team-a",
				Role:  "developer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
		ProxyLimiter: func(_ *http.Request, _ *Identity) (*ProxyLimitResult, error) {
			return &ProxyLimitResult{
				Code:              "KEY_RATE_LIMIT_EXCEEDED",
				Message:           "request rate limit exceeded for key",
				RetryAfterSeconds: 12,
			}, nil
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "dev-token")
	req.Header.Set("Authorization", "Bearer sk-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if got := rec.Header().Get("Retry-After"); got != "12" {
		t.Fatalf("Retry-After=%q, want 12", got)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if body["code"] != "KEY_RATE_LIMIT_EXCEEDED" {
		t.Fatalf("code=%v, want KEY_RATE_LIMIT_EXCEEDED", body["code"])
	}
	if body["retry_after_seconds"] != float64(12) {
		t.Fatalf("retry_after_seconds=%v, want 12", body["retry_after_seconds"])
	}
}

func TestMiddlewareInvokesProxyUsageRecorderOnAuthorizedProxyRequest(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-dev-1",
				Token: "dev-token",
				Team:  "team-a",
				Role:  "developer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	var called bool
	var seenKeyID string
	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
		ProxyUsageRecorder: func(_ *http.Request, identity *Identity) {
			called = true
			if identity != nil {
				seenKeyID = identity.KeyID
			}
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "dev-token")
	req.Header.Set("Authorization", "Bearer sk-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("expected ProxyUsageRecorder to be called")
	}
	if seenKeyID != "team-a-dev-1" {
		t.Fatalf("usage recorder key id=%q, want team-a-dev-1", seenKeyID)
	}
}

func TestMiddlewareEmitsAuditEventOnPermissionDenied(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-viewer-1",
				Token: "viewer-token",
				OrgID: "org-a",
				Team:  "workspace-a",
				Role:  "viewer",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	var seen AuditEvent
	var called bool
	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
		AuditRecorder: func(_ *http.Request, event AuditEvent) {
			called = true
			seen = event
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "viewer-token")
	req.Header.Set("Authorization", "Bearer sk-test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusForbidden)
	}
	if !called {
		t.Fatal("expected audit recorder to be called")
	}
	if seen.Action != "gateway_auth" || seen.Outcome != "deny" || seen.Reason != "permission_denied" {
		t.Fatalf("audit event action/outcome/reason=%q/%q/%q", seen.Action, seen.Outcome, seen.Reason)
	}
	if seen.StatusCode != http.StatusForbidden {
		t.Fatalf("audit status_code=%d, want %d", seen.StatusCode, http.StatusForbidden)
	}
	if seen.Provider != "openai" {
		t.Fatalf("audit provider=%q, want openai", seen.Provider)
	}
	if seen.KeyID != "team-a-viewer-1" || seen.OrgID != "org-a" || seen.WorkspaceID != "workspace-a" {
		t.Fatalf("audit tenant/actor=%+v", seen)
	}
}

func TestMiddlewareAuditEventIncludesResourceMetadata(t *testing.T) {
	t.Parallel()

	authorizer, err := NewAuthorizer(Options{
		Enabled: true,
		Keys: []KeyConfig{
			{
				ID:    "team-a-owner-1",
				Token: "owner-token",
				Role:  "owner",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	var seen AuditEvent
	handler := Middleware(authorizer, MiddlewareOptions{
		APIPrefix:       "/api",
		OpenAIPrefix:    "/openai",
		AnthropicPrefix: "/anthropic",
		AuditRecorder: func(_ *http.Request, event AuditEvent) {
			seen = event
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/internal/debug", nil)
	req.Header.Set("X-OngoingAI-Gateway-Key", "owner-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusForbidden)
	}
	if seen.Resource != "api" {
		t.Fatalf("audit resource=%q, want api", seen.Resource)
	}
	if seen.Scope != "workspace" {
		t.Fatalf("audit scope=%q, want workspace", seen.Scope)
	}
	if seen.Reason != "action_unmapped" {
		t.Fatalf("audit reason=%q, want action_unmapped", seen.Reason)
	}
}

func TestWithIdentityHandlesNilContext(t *testing.T) {
	t.Parallel()

	identity := &Identity{KeyID: "key-1"}
	ctx := WithIdentity(nil, identity)
	if ctx == nil {
		t.Fatal("WithIdentity(nil, identity) returned nil context")
	}

	got, ok := IdentityFromContext(ctx)
	if !ok || got == nil {
		t.Fatal("IdentityFromContext() missing identity")
	}
	if got.KeyID != identity.KeyID {
		t.Fatalf("identity key id=%q, want %q", got.KeyID, identity.KeyID)
	}
}

func TestWithIdentityReturnsNonNilContextWhenInputsNil(t *testing.T) {
	t.Parallel()

	ctx := WithIdentity(nil, nil)
	if ctx == nil {
		t.Fatal("WithIdentity(nil, nil) returned nil context")
	}
	if _, ok := IdentityFromContext(ctx); ok {
		t.Fatal("IdentityFromContext() should be empty")
	}
}
