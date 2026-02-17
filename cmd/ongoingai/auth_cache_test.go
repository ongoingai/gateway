package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/configstore"
)

func TestGatewayAuthorizerCacheCurrentFresh(t *testing.T) {
	t.Parallel()

	authorizer, err := auth.NewAuthorizer(auth.Options{
		Enabled: true,
		Keys: []auth.KeyConfig{
			{ID: "key-1", Token: "token-1", Role: "owner"},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	cache := newGatewayAuthorizerCache(authorizer, time.Now().UTC())
	got, err := cache.Current(time.Minute)
	if err != nil {
		t.Fatalf("Current() error: %v", err)
	}
	if got == nil || !got.Enabled() {
		t.Fatalf("Current() authorizer=%v, want enabled authorizer", got)
	}
}

func TestGatewayAuthorizerCacheCurrentStaleAndSet(t *testing.T) {
	t.Parallel()

	authorizer, err := auth.NewAuthorizer(auth.Options{
		Enabled: true,
		Keys: []auth.KeyConfig{
			{ID: "key-1", Token: "token-1", Role: "owner"},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() error: %v", err)
	}

	cache := newGatewayAuthorizerCache(authorizer, time.Now().Add(-2*time.Minute).UTC())
	if _, err := cache.Current(time.Minute); err == nil {
		t.Fatal("expected stale cache error")
	}

	cache.Set(authorizer, time.Now().UTC())
	if _, err := cache.Current(time.Minute); err != nil {
		t.Fatalf("Current() after Set() error: %v", err)
	}
}

type mutableGatewayKeyStore struct {
	mu   sync.RWMutex
	keys []configstore.GatewayKey
}

func (s *mutableGatewayKeyStore) ListGatewayKeys(_ context.Context, _ configstore.GatewayKeyFilter) ([]configstore.GatewayKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]configstore.GatewayKey, 0, len(s.keys))
	for _, key := range s.keys {
		copyKey := key
		copyKey.Permissions = append([]string(nil), key.Permissions...)
		out = append(out, copyKey)
	}
	return out, nil
}

func (s *mutableGatewayKeyStore) SetKeys(keys []configstore.GatewayKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys = make([]configstore.GatewayKey, 0, len(keys))
	for _, key := range keys {
		copyKey := key
		copyKey.Permissions = append([]string(nil), key.Permissions...)
		s.keys = append(s.keys, copyKey)
	}
}

func (s *mutableGatewayKeyStore) CreateGatewayKey(_ context.Context, _ configstore.GatewayKey) (*configstore.GatewayKey, error) {
	return nil, configstore.ErrNotImplemented
}

func (s *mutableGatewayKeyStore) RevokeGatewayKey(_ context.Context, _ string, _ configstore.GatewayKeyFilter) error {
	return configstore.ErrNotImplemented
}

func (s *mutableGatewayKeyStore) RotateGatewayKey(_ context.Context, _ string, _ string, _ configstore.GatewayKeyFilter) (*configstore.GatewayKey, error) {
	return nil, configstore.ErrNotImplemented
}

func (s *mutableGatewayKeyStore) Close() error {
	return nil
}

func TestGatewayAuthRefresherPropagatesRevocationAcrossInstancesWithinSLA(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.Enabled = true
	cfg.Storage.Driver = "postgres"
	cfg.Storage.DSN = "postgres://revocation-sla-test"
	cfg.Auth.Keys = []config.GatewayKeyConfig{
		{
			ID:    "fallback-key",
			Token: "fallback-token",
			Role:  "developer",
		},
	}

	store := &mutableGatewayKeyStore{}
	store.SetKeys([]configstore.GatewayKey{
		{
			ID:          "revocable-key",
			Token:       "revocable-token",
			OrgID:       "org-a",
			WorkspaceID: "workspace-a",
			Role:        "developer",
			Permissions: []string{"proxy:write", "analytics:read"},
		},
	})

	initialKeys, err := loadGatewayAuthKeys(context.Background(), cfg, nil, store)
	if err != nil {
		t.Fatalf("loadGatewayAuthKeys() initial error: %v", err)
	}
	initialAuthorizer, err := auth.NewAuthorizer(auth.Options{
		Enabled: cfg.Auth.Enabled,
		Header:  cfg.Auth.Header,
		Keys:    initialKeys,
	})
	if err != nil {
		t.Fatalf("NewAuthorizer() initial error: %v", err)
	}

	cacheA := newGatewayAuthorizerCache(initialAuthorizer, time.Now().UTC())
	cacheB := newGatewayAuthorizerCache(initialAuthorizer, time.Now().UTC())

	if !cacheAllowsToken(t, cacheA, "revocable-token") {
		t.Fatal("instance A should allow revocable token before revocation")
	}
	if !cacheAllowsToken(t, cacheB, "revocable-token") {
		t.Fatal("instance B should allow revocable token before revocation")
	}

	refreshInterval := 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startGatewayAuthRefresherWithInterval(ctx, cacheA, cfg, store, nil, refreshInterval)
	go startGatewayAuthRefresherWithInterval(ctx, cacheB, cfg, store, nil, refreshInterval)

	revokedAt := time.Now()
	store.SetKeys(nil)

	deadline := time.Now().Add(gatewayKeyCacheMaxStaleness)
	revokedA := false
	revokedB := false
	for time.Now().Before(deadline) {
		if !revokedA {
			revokedA = cacheRejectsToken(t, cacheA, "revocable-token")
		}
		if !revokedB {
			revokedB = cacheRejectsToken(t, cacheB, "revocable-token")
		}
		if revokedA && revokedB {
			break
		}
		time.Sleep(refreshInterval / 2)
	}

	if !revokedA || !revokedB {
		t.Fatalf("revocation did not propagate to all instances within %s (instanceA=%t instanceB=%t)", gatewayKeyCacheMaxStaleness, revokedA, revokedB)
	}
	if elapsed := time.Since(revokedAt); elapsed > gatewayKeyCacheMaxStaleness {
		t.Fatalf("revocation propagation exceeded SLA: elapsed=%s, sla=%s", elapsed, gatewayKeyCacheMaxStaleness)
	}
}

func TestGatewayKeyRefreshCadenceWithinRevocationSLA(t *testing.T) {
	if gatewayKeyRefreshInterval <= 0 {
		t.Fatalf("gateway key refresh interval=%s, want > 0", gatewayKeyRefreshInterval)
	}
	if gatewayKeyCacheMaxStaleness <= 0 {
		t.Fatalf("gateway key cache max staleness=%s, want > 0", gatewayKeyCacheMaxStaleness)
	}
	if gatewayKeyRefreshInterval > gatewayKeyCacheMaxStaleness {
		t.Fatalf("gateway key refresh interval=%s exceeds cache staleness window=%s", gatewayKeyRefreshInterval, gatewayKeyCacheMaxStaleness)
	}
	if gatewayKeyCacheMaxStaleness > 60*time.Second {
		t.Fatalf("gateway key cache staleness window=%s exceeds revocation SLA 60s", gatewayKeyCacheMaxStaleness)
	}
}

func cacheAllowsToken(t *testing.T, cache *gatewayAuthorizerCache, token string) bool {
	t.Helper()

	authorizer, err := cache.Current(gatewayKeyCacheMaxStaleness)
	if err != nil {
		t.Fatalf("cache.Current() error: %v", err)
	}
	req := httptest.NewRequest("GET", "/openai/v1/chat/completions", nil)
	req.Header.Set(authorizer.HeaderName(), token)

	_, err = authorizer.Authenticate(req)
	return err == nil
}

func cacheRejectsToken(t *testing.T, cache *gatewayAuthorizerCache, token string) bool {
	t.Helper()

	authorizer, err := cache.Current(gatewayKeyCacheMaxStaleness)
	if err != nil {
		t.Fatalf("cache.Current() error: %v", err)
	}
	req := httptest.NewRequest("GET", "/openai/v1/chat/completions", nil)
	req.Header.Set(authorizer.HeaderName(), token)

	_, err = authorizer.Authenticate(req)
	if err == nil {
		return false
	}
	return errors.Is(err, auth.ErrInvalidGatewayKey)
}
