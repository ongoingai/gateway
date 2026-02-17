package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/configstore"
)

func TestShouldCaptureTrace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{path: "/api/health", want: false},
		{path: "/api/traces", want: false},
		{path: "/api", want: false},
		{path: "/apiish", want: true},
		{path: "/openai/v1/chat/completions", want: true},
		{path: "/anthropic/v1/messages", want: true},
	}

	for _, tt := range tests {
		if got := shouldCaptureTrace(tt.path); got != tt.want {
			t.Fatalf("shouldCaptureTrace(%q)=%t, want %t", tt.path, got, tt.want)
		}
	}
}

func TestConfiguredProviderSummaries(t *testing.T) {
	t.Parallel()

	cfg := config.Default()

	got := configuredProviderSummaries(cfg)
	want := []string{
		"openai:/openai->https://api.openai.com",
		"anthropic:/anthropic->https://api.anthropic.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("configuredProviderSummaries()=%v, want %v", got, want)
	}
}

func TestConfiguredProviderSummariesSkipsIncompleteProviders(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Providers.OpenAI.Prefix = ""
	cfg.Providers.Anthropic.Upstream = ""

	got := configuredProviderSummaries(cfg)
	if len(got) != 0 {
		t.Fatalf("configuredProviderSummaries()=%v, want empty result", got)
	}
}

func TestRunServeRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "invalid.yaml")
	configBody := `server:
  host: 127.0.0.1
  port: 70000
storage:
  driver: sqlite
  path: ./data/ongoingai.db
providers:
  openai:
    upstream: https://api.openai.com
    prefix: /openai
  anthropic:
    upstream: https://api.anthropic.com
    prefix: /anthropic
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if code := runServe([]string{"--config", configPath}); code != 1 {
		t.Fatalf("runServe exit code=%d, want 1", code)
	}
}

func TestNewGatewayServerUsesSafeTimeouts(t *testing.T) {
	t.Parallel()

	server := newGatewayServer(config.Default(), nil, http.NotFoundHandler())
	if server.ReadHeaderTimeout != serverReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout=%s, want %s", server.ReadHeaderTimeout, serverReadHeaderTimeout)
	}
	if server.ReadTimeout != serverReadTimeout {
		t.Fatalf("ReadTimeout=%s, want %s", server.ReadTimeout, serverReadTimeout)
	}
	if server.IdleTimeout != serverIdleTimeout {
		t.Fatalf("IdleTimeout=%s, want %s", server.IdleTimeout, serverIdleTimeout)
	}
}

type stubGatewayKeyUsageTracker struct {
	called     bool
	lastID     string
	lastFilter configstore.GatewayKeyFilter
	err        error
}

func (s *stubGatewayKeyUsageTracker) TouchGatewayKeyLastUsed(_ context.Context, id string, filter configstore.GatewayKeyFilter) error {
	s.called = true
	s.lastID = id
	s.lastFilter = filter
	return s.err
}

func TestNewGatewayKeyProxyUsageRecorderTouchesLastUsed(t *testing.T) {
	t.Parallel()

	tracker := &stubGatewayKeyUsageTracker{}
	recorder := newGatewayKeyProxyUsageRecorder(nil, tracker)
	if recorder == nil {
		t.Fatal("expected proxy usage recorder")
	}

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	recorder(req, &auth.Identity{
		KeyID:       " key-1 ",
		OrgID:       " org-a ",
		WorkspaceID: " workspace-a ",
	})

	if !tracker.called {
		t.Fatal("expected usage tracker to be called")
	}
	if tracker.lastID != "key-1" {
		t.Fatalf("last id=%q, want key-1", tracker.lastID)
	}
	if tracker.lastFilter.OrgID != "org-a" || tracker.lastFilter.WorkspaceID != "workspace-a" {
		t.Fatalf("last filter=%+v, want org-a/workspace-a", tracker.lastFilter)
	}
}

func TestNewGatewayKeyProxyUsageRecorderLogsTouchFailures(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	tracker := &stubGatewayKeyUsageTracker{
		err: errors.New("write failed"),
	}
	recorder := newGatewayKeyProxyUsageRecorder(logger, tracker)
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	recorder(req, &auth.Identity{
		KeyID:       "key-2",
		OrgID:       "org-b",
		WorkspaceID: "workspace-b",
	})

	if !tracker.called {
		t.Fatal("expected usage tracker to be called")
	}
	logged := logs.String()
	if !strings.Contains(logged, `"msg":"failed to update gateway key last_used_at"`) {
		t.Fatalf("logs=%q, want failure message", logged)
	}
	if !strings.Contains(logged, `"key_id":"key-2"`) {
		t.Fatalf("logs=%q, want key_id", logged)
	}
}
