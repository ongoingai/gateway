package configstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStaticStoreCopiesAndReturnsKeys(t *testing.T) {
	t.Parallel()

	input := []GatewayKey{
		{
			ID:          "key-1",
			Token:       "token-1",
			OrgID:       "org-a",
			WorkspaceID: "workspace-a",
			Role:        "developer",
			Permissions: []string{"proxy:write", "analytics:read"},
		},
	}
	store := NewStaticStore(input)

	input[0].ID = "mutated"
	input[0].Permissions[0] = "mutated"

	got, err := store.ListGatewayKeys(context.Background(), GatewayKeyFilter{})
	if err != nil {
		t.Fatalf("ListGatewayKeys() error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(keys)=%d, want 1", len(got))
	}
	if got[0].ID != "key-1" {
		t.Fatalf("key id=%q, want key-1", got[0].ID)
	}
	if got[0].Permissions[0] != "proxy:write" {
		t.Fatalf("permissions[0]=%q, want proxy:write", got[0].Permissions[0])
	}

	got[0].Permissions[0] = "mutated-again"
	gotAgain, err := store.ListGatewayKeys(context.Background(), GatewayKeyFilter{})
	if err != nil {
		t.Fatalf("ListGatewayKeys() second call error: %v", err)
	}
	if gotAgain[0].Permissions[0] != "proxy:write" {
		t.Fatalf("permissions[0] on second call=%q, want proxy:write", gotAgain[0].Permissions[0])
	}

	filtered, err := store.ListGatewayKeys(context.Background(), GatewayKeyFilter{OrgID: "org-a", WorkspaceID: "workspace-a"})
	if err != nil {
		t.Fatalf("ListGatewayKeys() filtered call error: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("filtered len(keys)=%d, want 1", len(filtered))
	}

	empty, err := store.ListGatewayKeys(context.Background(), GatewayKeyFilter{OrgID: "org-b"})
	if err != nil {
		t.Fatalf("ListGatewayKeys() empty filtered call error: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty filtered len(keys)=%d, want 0", len(empty))
	}
}

func TestStaticStoreMutationsReturnNotImplemented(t *testing.T) {
	t.Parallel()

	store := NewStaticStore(nil)
	if _, err := store.CreateGatewayKey(context.Background(), GatewayKey{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("CreateGatewayKey() error=%v, want ErrNotImplemented", err)
	}
	if err := store.RevokeGatewayKey(context.Background(), "id", GatewayKeyFilter{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RevokeGatewayKey() error=%v, want ErrNotImplemented", err)
	}
	if _, err := store.RotateGatewayKey(context.Background(), "id", "token", GatewayKeyFilter{}); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("RotateGatewayKey() error=%v, want ErrNotImplemented", err)
	}
}

func TestStaticStoreHierarchyDerivedFromGatewayKeys(t *testing.T) {
	t.Parallel()

	store := NewStaticStore([]GatewayKey{
		{ID: "k1", OrgID: "org-a", WorkspaceID: "workspace-b"},
		{ID: "k2", OrgID: "org-a", WorkspaceID: "workspace-a"},
		{ID: "k3", OrgID: "org-b", WorkspaceID: "workspace-z"},
	})

	org, err := store.GetOrganization(context.Background(), "org-a")
	if err != nil {
		t.Fatalf("GetOrganization() error: %v", err)
	}
	if org.ID != "org-a" {
		t.Fatalf("org.id=%q, want org-a", org.ID)
	}

	workspace, err := store.GetWorkspace(context.Background(), "workspace-a")
	if err != nil {
		t.Fatalf("GetWorkspace() error: %v", err)
	}
	if workspace.OrgID != "org-a" {
		t.Fatalf("workspace.org_id=%q, want org-a", workspace.OrgID)
	}

	workspaces, err := store.ListWorkspaces(context.Background(), "org-a")
	if err != nil {
		t.Fatalf("ListWorkspaces() error: %v", err)
	}
	if len(workspaces) != 2 {
		t.Fatalf("len(workspaces)=%d, want 2", len(workspaces))
	}
	if workspaces[0].ID != "workspace-a" || workspaces[1].ID != "workspace-b" {
		t.Fatalf("workspace order=%v, want [workspace-a workspace-b]", []string{workspaces[0].ID, workspaces[1].ID})
	}

	if _, err := store.GetOrganization(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetOrganization(missing) error=%v, want ErrNotFound", err)
	}
	if _, err := store.GetWorkspace(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWorkspace(missing) error=%v, want ErrNotFound", err)
	}
}

func TestStaticStoreHierarchyDefaultsWithoutGatewayKeys(t *testing.T) {
	t.Parallel()

	store := NewStaticStore(nil)

	org, err := store.GetOrganization(context.Background(), "default")
	if err != nil {
		t.Fatalf("GetOrganization(default) error: %v", err)
	}
	if org.ID != "default" {
		t.Fatalf("org.id=%q, want default", org.ID)
	}

	workspace, err := store.GetWorkspace(context.Background(), "default")
	if err != nil {
		t.Fatalf("GetWorkspace(default) error: %v", err)
	}
	if workspace.ID != "default" || workspace.OrgID != "default" {
		t.Fatalf("workspace=%+v, want default/default", workspace)
	}

	workspaces, err := store.ListWorkspaces(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListWorkspaces(default) error: %v", err)
	}
	if len(workspaces) != 1 || workspaces[0].ID != "default" {
		t.Fatalf("workspaces=%+v, want one default workspace", workspaces)
	}
}

func TestStaticStoreGetGatewayKeyByTokenHash(t *testing.T) {
	t.Parallel()

	activeHash := hashToken("token-active")
	store := NewStaticStore([]GatewayKey{
		{
			ID:          "key-active",
			Token:       "token-active",
			OrgID:       "org-a",
			WorkspaceID: "workspace-a",
			Role:        "developer",
			Permissions: []string{"proxy:write"},
		},
		{
			ID:          "key-revoked",
			TokenHash:   hashToken("token-revoked"),
			OrgID:       "org-a",
			WorkspaceID: "workspace-a",
			RevokedAt:   time.Now().UTC(),
		},
	})

	key, err := store.GetGatewayKey(context.Background(), activeHash)
	if err != nil {
		t.Fatalf("GetGatewayKey() error: %v", err)
	}
	if key.ID != "key-active" {
		t.Fatalf("key.id=%q, want key-active", key.ID)
	}
	if key.Token != "" {
		t.Fatalf("key.token=%q, want empty", key.Token)
	}
	if key.TokenHash != activeHash {
		t.Fatalf("key.token_hash=%q, want %q", key.TokenHash, activeHash)
	}

	if _, err := store.GetGatewayKey(context.Background(), hashToken("token-revoked")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGatewayKey(revoked) error=%v, want ErrNotFound", err)
	}
	if _, err := store.GetGatewayKey(context.Background(), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGatewayKey(empty) error=%v, want ErrNotFound", err)
	}
	if _, err := store.GetGatewayKey(context.Background(), hashToken("missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGatewayKey(missing) error=%v, want ErrNotFound", err)
	}
}
