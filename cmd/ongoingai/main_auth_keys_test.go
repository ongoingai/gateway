package main

import (
	"context"
	"testing"

	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/configstore"
)

type stubGatewayKeyStore struct {
	keys    []configstore.GatewayKey
	listErr error
	closed  bool
}

func (s *stubGatewayKeyStore) ListGatewayKeys(_ context.Context, _ configstore.GatewayKeyFilter) ([]configstore.GatewayKey, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]configstore.GatewayKey, 0, len(s.keys))
	for _, key := range s.keys {
		copyKey := key
		copyKey.Permissions = append([]string(nil), key.Permissions...)
		out = append(out, copyKey)
	}
	return out, nil
}

func (s *stubGatewayKeyStore) Close() error {
	s.closed = true
	return nil
}

func (s *stubGatewayKeyStore) CreateGatewayKey(_ context.Context, _ configstore.GatewayKey) (*configstore.GatewayKey, error) {
	return nil, configstore.ErrNotImplemented
}

func (s *stubGatewayKeyStore) RevokeGatewayKey(_ context.Context, _ string, _ configstore.GatewayKeyFilter) error {
	return configstore.ErrNotImplemented
}

func (s *stubGatewayKeyStore) RotateGatewayKey(_ context.Context, _ string, _ string, _ configstore.GatewayKeyFilter) (*configstore.GatewayKey, error) {
	return nil, configstore.ErrNotImplemented
}

func TestLoadGatewayAuthKeysUsesConfigForNonPostgres(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.Enabled = true
	cfg.Storage.Driver = "sqlite"
	cfg.Auth.Keys = []config.GatewayKeyConfig{
		{
			ID:    "yaml-key",
			Token: "yaml-token",
			Role:  "developer",
		},
	}

	got, err := loadGatewayAuthKeys(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("loadGatewayAuthKeys() error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "yaml-key" || got[0].Token != "yaml-token" {
		t.Fatalf("loaded keys=%+v, want yaml key", got)
	}
}

func TestLoadGatewayAuthKeysUsesPostgresStoreWhenKeysExist(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.Enabled = true
	cfg.Storage.Driver = "postgres"
	cfg.Storage.DSN = "postgres://example"
	cfg.Auth.Keys = []config.GatewayKeyConfig{
		{ID: "yaml-key", Token: "yaml-token"},
	}

	stubStore := &stubGatewayKeyStore{
		keys: []configstore.GatewayKey{
			{
				ID:          "db-key",
				Token:       "db-token",
				OrgID:       "org-a",
				WorkspaceID: "workspace-a",
				Role:        "owner",
				Permissions: []string{"proxy:write"},
			},
		},
	}

	got, err := loadGatewayAuthKeys(context.Background(), cfg, nil, stubStore)
	if err != nil {
		t.Fatalf("loadGatewayAuthKeys() error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "db-key" || got[0].Token != "db-token" {
		t.Fatalf("loaded keys=%+v, want postgres key", got)
	}
}

func TestLoadGatewayAuthKeysFallsBackToYAMLWhenPostgresStoreIsEmpty(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.Enabled = true
	cfg.Storage.Driver = "postgres"
	cfg.Storage.DSN = "postgres://example"
	cfg.Auth.Keys = []config.GatewayKeyConfig{
		{ID: "yaml-key", Token: "yaml-token", Role: "developer"},
	}

	stubStore := &stubGatewayKeyStore{}
	got, err := loadGatewayAuthKeys(context.Background(), cfg, nil, stubStore)
	if err != nil {
		t.Fatalf("loadGatewayAuthKeys() error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "yaml-key" {
		t.Fatalf("loaded keys=%+v, want yaml fallback key", got)
	}
}

func TestLoadGatewayAuthKeysReturnsErrorWhenPostgresStoreFails(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.Enabled = true
	cfg.Storage.Driver = "postgres"
	cfg.Storage.DSN = "postgres://example"

	if _, err := loadGatewayAuthKeys(context.Background(), cfg, nil, nil); err == nil {
		t.Fatal("expected error when postgres config store is missing")
	}
}
