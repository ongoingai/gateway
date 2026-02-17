package configstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
)

func TestPostgresStoreListsOnlyActiveGatewayKeys(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	ensurePostgresTestTenant(t, store, "org-a", "workspace-a")
	if _, err := store.db.ExecContext(ctx, `DELETE FROM gateway_keys WHERE id IN ('configstore-test-active', 'configstore-test-revoked')`); err != nil {
		t.Fatalf("cleanup before insert: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO gateway_keys (id, token_hash, token, org_id, workspace_id, role, permissions)
VALUES ('configstore-test-active', $1, 'redacted:configstore-test-active', 'org-a', 'workspace-a', 'owner', '["proxy:write","analytics:read"]'::jsonb)
ON CONFLICT (id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash,
    token = EXCLUDED.token,
    org_id = EXCLUDED.org_id,
    workspace_id = EXCLUDED.workspace_id,
    role = EXCLUDED.role,
    permissions = EXCLUDED.permissions,
    revoked_at = NULL`, hashToken("token-active")); err != nil {
		t.Fatalf("insert active key: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO gateway_keys (id, token_hash, token, org_id, workspace_id, role, permissions, revoked_at)
VALUES ('configstore-test-revoked', $1, 'redacted:configstore-test-revoked', 'org-a', 'workspace-a', 'viewer', '["analytics:read"]'::jsonb, NOW())
ON CONFLICT (id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash,
    token = EXCLUDED.token,
    org_id = EXCLUDED.org_id,
    workspace_id = EXCLUDED.workspace_id,
    role = EXCLUDED.role,
    permissions = EXCLUDED.permissions,
    revoked_at = EXCLUDED.revoked_at`, hashToken("token-revoked")); err != nil {
		t.Fatalf("insert revoked key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM gateway_keys WHERE id IN ('configstore-test-active', 'configstore-test-revoked')`)
	})

	keys, err := store.ListGatewayKeys(ctx, GatewayKeyFilter{})
	if err != nil {
		t.Fatalf("ListGatewayKeys() error: %v", err)
	}

	foundActive := false
	for _, key := range keys {
		if key.ID != "configstore-test-active" {
			if key.ID == "configstore-test-revoked" {
				t.Fatal("revoked key should not be returned")
			}
			continue
		}
		foundActive = true
		if key.Token != "" {
			t.Fatalf("active key token=%q, want empty (plaintext not stored in list)", key.Token)
		}
		if key.TokenHash != hashToken("token-active") || key.OrgID != "org-a" || key.WorkspaceID != "workspace-a" {
			t.Fatalf("active key=%+v, want token_hash/org/workspace to match inserted values", key)
		}
		if len(key.Permissions) != 2 {
			t.Fatalf("active key permissions=%v, want 2 permissions", key.Permissions)
		}
	}
	if !foundActive {
		t.Fatal("expected to find active key")
	}
}

func TestPostgresStoreGatewayKeyCRUD(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	keyID := "configstore-test-crud"
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM gateway_keys WHERE id = $1`, keyID)
	})
	_, _ = store.db.ExecContext(ctx, `DELETE FROM gateway_keys WHERE id = $1`, keyID)

	created, err := store.CreateGatewayKey(ctx, GatewayKey{
		ID:          keyID,
		Token:       "token-initial",
		OrgID:       "org-crud",
		WorkspaceID: "workspace-crud",
		Name:        "CI key",
		Description: "used by CI pipeline",
		CreatedBy:   "owner-key",
		Role:        "developer",
		Permissions: []string{"proxy:write"},
	})
	if err != nil {
		t.Fatalf("CreateGatewayKey() error: %v", err)
	}
	if created.ID != keyID || created.Token != "token-initial" {
		t.Fatalf("created key=%+v", created)
	}
	if created.Name != "CI key" || created.Description != "used by CI pipeline" || created.CreatedBy != "owner-key" {
		t.Fatalf("created metadata=%+v", created)
	}

	filtered, err := store.ListGatewayKeys(ctx, GatewayKeyFilter{OrgID: "org-crud", WorkspaceID: "workspace-crud"})
	if err != nil {
		t.Fatalf("ListGatewayKeys() filtered error: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != keyID {
		t.Fatalf("filtered keys=%+v, want one created key", filtered)
	}
	if filtered[0].Token != "" {
		t.Fatalf("filtered key token=%q, want empty", filtered[0].Token)
	}
	if filtered[0].TokenHash != hashToken("token-initial") {
		t.Fatalf("filtered key token_hash=%q, want hash of token-initial", filtered[0].TokenHash)
	}
	if filtered[0].Name != "CI key" || filtered[0].Description != "used by CI pipeline" || filtered[0].CreatedBy != "owner-key" {
		t.Fatalf("filtered key metadata=%+v", filtered[0])
	}
	if !filtered[0].LastUsedAt.IsZero() {
		t.Fatalf("filtered key last_used_at=%s, want zero before touch", filtered[0].LastUsedAt)
	}

	if err := store.TouchGatewayKeyLastUsed(ctx, keyID, GatewayKeyFilter{OrgID: "org-crud", WorkspaceID: "workspace-crud"}); err != nil {
		t.Fatalf("TouchGatewayKeyLastUsed() error: %v", err)
	}
	filteredAfterTouch, err := store.ListGatewayKeys(ctx, GatewayKeyFilter{OrgID: "org-crud", WorkspaceID: "workspace-crud"})
	if err != nil {
		t.Fatalf("ListGatewayKeys() after touch error: %v", err)
	}
	if len(filteredAfterTouch) != 1 {
		t.Fatalf("filteredAfterTouch len=%d, want 1", len(filteredAfterTouch))
	}
	if filteredAfterTouch[0].LastUsedAt.IsZero() {
		t.Fatalf("filteredAfterTouch last_used_at=%s, want non-zero", filteredAfterTouch[0].LastUsedAt)
	}

	rotated, err := store.RotateGatewayKey(ctx, keyID, "token-rotated", GatewayKeyFilter{OrgID: "org-crud", WorkspaceID: "workspace-crud"})
	if err != nil {
		t.Fatalf("RotateGatewayKey() error: %v", err)
	}
	if rotated.Token != "token-rotated" {
		t.Fatalf("rotated token=%q, want token-rotated", rotated.Token)
	}
	if rotated.Name != "CI key" || rotated.Description != "used by CI pipeline" || rotated.CreatedBy != "owner-key" {
		t.Fatalf("rotated metadata=%+v", rotated)
	}

	if err := store.RevokeGatewayKey(ctx, keyID, GatewayKeyFilter{OrgID: "org-crud", WorkspaceID: "workspace-crud"}); err != nil {
		t.Fatalf("RevokeGatewayKey() error: %v", err)
	}

	if _, err := store.RotateGatewayKey(ctx, keyID, "token-after-revoke", GatewayKeyFilter{OrgID: "org-crud", WorkspaceID: "workspace-crud"}); err == nil {
		t.Fatal("expected RotateGatewayKey() error for revoked key")
	}
}

func TestPostgresStoreGatewayKeyTenantIsolation(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	keyID := "configstore-test-tenant-isolation"
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM gateway_keys WHERE id = $1`, keyID)
	})
	_, _ = store.db.ExecContext(ctx, `DELETE FROM gateway_keys WHERE id = $1`, keyID)

	created, err := store.CreateGatewayKey(ctx, GatewayKey{
		ID:          keyID,
		Token:       "token-tenant-initial",
		OrgID:       "org-tenant-a",
		WorkspaceID: "workspace-tenant-a",
		Role:        "developer",
		Permissions: []string{"proxy:write"},
	})
	if err != nil {
		t.Fatalf("CreateGatewayKey() error: %v", err)
	}
	if created.OrgID != "org-tenant-a" || created.WorkspaceID != "workspace-tenant-a" {
		t.Fatalf("created key tenant=%s/%s, want org-tenant-a/workspace-tenant-a", created.OrgID, created.WorkspaceID)
	}

	sameTenantKeys, err := store.ListGatewayKeys(ctx, GatewayKeyFilter{
		OrgID:       "org-tenant-a",
		WorkspaceID: "workspace-tenant-a",
	})
	if err != nil {
		t.Fatalf("ListGatewayKeys(same tenant) error: %v", err)
	}
	if len(sameTenantKeys) != 1 || sameTenantKeys[0].ID != keyID {
		t.Fatalf("same-tenant keys=%+v, want one key %q", sameTenantKeys, keyID)
	}

	if err := store.TouchGatewayKeyLastUsed(ctx, keyID, GatewayKeyFilter{
		OrgID:       "org-tenant-a",
		WorkspaceID: "workspace-tenant-a",
	}); err != nil {
		t.Fatalf("TouchGatewayKeyLastUsed(same tenant) error: %v", err)
	}

	if _, err := store.RotateGatewayKey(ctx, keyID, "token-tenant-rotated", GatewayKeyFilter{
		OrgID:       "org-tenant-a",
		WorkspaceID: "workspace-tenant-a",
	}); err != nil {
		t.Fatalf("RotateGatewayKey(same tenant) error: %v", err)
	}

	crossTenantKeys, err := store.ListGatewayKeys(ctx, GatewayKeyFilter{
		OrgID:       "org-tenant-b",
		WorkspaceID: "workspace-tenant-b",
	})
	if err != nil {
		t.Fatalf("ListGatewayKeys(cross tenant) error: %v", err)
	}
	if len(crossTenantKeys) != 0 {
		t.Fatalf("cross-tenant keys=%+v, want no keys", crossTenantKeys)
	}

	if err := store.TouchGatewayKeyLastUsed(ctx, keyID, GatewayKeyFilter{
		OrgID:       "org-tenant-b",
		WorkspaceID: "workspace-tenant-b",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TouchGatewayKeyLastUsed(cross tenant) error=%v, want ErrNotFound", err)
	}

	if _, err := store.RotateGatewayKey(ctx, keyID, "token-cross-tenant", GatewayKeyFilter{
		OrgID:       "org-tenant-b",
		WorkspaceID: "workspace-tenant-b",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RotateGatewayKey(cross tenant) error=%v, want ErrNotFound", err)
	}

	if err := store.RevokeGatewayKey(ctx, keyID, GatewayKeyFilter{
		OrgID:       "org-tenant-b",
		WorkspaceID: "workspace-tenant-b",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RevokeGatewayKey(cross tenant) error=%v, want ErrNotFound", err)
	}

	if err := store.RevokeGatewayKey(ctx, keyID, GatewayKeyFilter{
		OrgID:       "org-tenant-a",
		WorkspaceID: "workspace-tenant-a",
	}); err != nil {
		t.Fatalf("RevokeGatewayKey(same tenant) error: %v", err)
	}
}

func TestPostgresStoreEnsuresTenantTablesAndDefaultSeed(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	var tableCount int
	if err := store.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM information_schema.tables
WHERE table_schema = 'public' AND table_name IN ('organizations', 'workspaces')
`).Scan(&tableCount); err != nil {
		t.Fatalf("query tenant table existence: %v", err)
	}
	if tableCount != 2 {
		t.Fatalf("tenant table count=%d, want 2", tableCount)
	}

	var orgName string
	if err := store.db.QueryRowContext(ctx, `SELECT name FROM organizations WHERE id = 'default'`).Scan(&orgName); err != nil {
		t.Fatalf("query default organization: %v", err)
	}
	if orgName == "" {
		t.Fatal("default organization name is empty")
	}

	var workspaceOrgID, workspaceName string
	if err := store.db.QueryRowContext(ctx, `SELECT org_id, name FROM workspaces WHERE id = 'default'`).Scan(&workspaceOrgID, &workspaceName); err != nil {
		t.Fatalf("query default workspace: %v", err)
	}
	if workspaceOrgID != "default" {
		t.Fatalf("default workspace org_id=%q, want default", workspaceOrgID)
	}
	if workspaceName == "" {
		t.Fatal("default workspace name is empty")
	}
}

func TestPostgresStoreOrgHierarchyQueries(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO organizations (id, name)
VALUES ('org-hierarchy-test', 'Hierarchy Test Org')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO organizations (id, name)
VALUES ('org-hierarchy-other', 'Hierarchy Other Org')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`); err != nil {
		t.Fatalf("insert other org: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO workspaces (id, org_id, name) VALUES
  ('workspace-hierarchy-a', 'org-hierarchy-test', 'Workspace A'),
  ('workspace-hierarchy-b', 'org-hierarchy-test', 'Workspace B'),
  ('workspace-hierarchy-c', 'org-hierarchy-other', 'Workspace C')
ON CONFLICT (org_id, id) DO UPDATE SET
  name = EXCLUDED.name`); err != nil {
		t.Fatalf("insert workspaces: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM workspaces WHERE id IN ('workspace-hierarchy-a', 'workspace-hierarchy-b', 'workspace-hierarchy-c')`)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id IN ('org-hierarchy-test', 'org-hierarchy-other')`)
	})

	org, err := store.GetOrganization(ctx, "org-hierarchy-test")
	if err != nil {
		t.Fatalf("GetOrganization() error: %v", err)
	}
	if org.ID != "org-hierarchy-test" || org.Name != "Hierarchy Test Org" {
		t.Fatalf("organization=%+v", org)
	}

	workspace, err := store.GetWorkspace(ctx, "workspace-hierarchy-a")
	if err != nil {
		t.Fatalf("GetWorkspace() error: %v", err)
	}
	if workspace.OrgID != "org-hierarchy-test" {
		t.Fatalf("workspace org_id=%q, want org-hierarchy-test", workspace.OrgID)
	}

	workspaces, err := store.ListWorkspaces(ctx, "org-hierarchy-test")
	if err != nil {
		t.Fatalf("ListWorkspaces() error: %v", err)
	}
	if len(workspaces) != 2 {
		t.Fatalf("len(workspaces)=%d, want 2", len(workspaces))
	}
	for _, item := range workspaces {
		if item.OrgID != "org-hierarchy-test" {
			t.Fatalf("workspace=%+v, want org-hierarchy-test scoped list", item)
		}
	}

	if _, err := store.GetOrganization(ctx, "missing-org"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetOrganization(missing) error=%v, want ErrNotFound", err)
	}
	if _, err := store.GetWorkspace(ctx, "missing-workspace"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWorkspace(missing) error=%v, want ErrNotFound", err)
	}
}

func TestPostgresStoreEnsureTenantScopeAllowsWorkspaceIDReuseAcrossOrgs(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	const (
		workspaceID = "workspace-shared-tenant-scope"
		orgA        = "org-shared-tenant-scope-a"
		orgB        = "org-shared-tenant-scope-b"
	)
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM workspaces WHERE id = $1 AND org_id IN ($2, $3)`, workspaceID, orgA, orgB)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id IN ($1, $2)`, orgA, orgB)
	})

	if err := store.ensureTenantScope(ctx, orgA, workspaceID); err != nil {
		t.Fatalf("ensureTenantScope(%q/%q) error: %v", orgA, workspaceID, err)
	}
	if err := store.ensureTenantScope(ctx, orgB, workspaceID); err != nil {
		t.Fatalf("ensureTenantScope(%q/%q) error: %v", orgB, workspaceID, err)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM workspaces
WHERE id = $1 AND org_id IN ($2, $3)`, workspaceID, orgA, orgB).Scan(&count); err != nil {
		t.Fatalf("count shared workspace rows: %v", err)
	}
	if count != 2 {
		t.Fatalf("shared workspace row count=%d, want 2", count)
	}
}

func TestPostgresStoreGetGatewayKeyByTokenHash(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	ensurePostgresTestTenant(t, store, "org-getkey", "workspace-getkey")
	if _, err := store.db.ExecContext(ctx, `DELETE FROM gateway_keys WHERE id IN ('configstore-test-getkey-active', 'configstore-test-getkey-revoked')`); err != nil {
		t.Fatalf("cleanup before insert: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO gateway_keys (id, token_hash, token, org_id, workspace_id, role, permissions)
VALUES ('configstore-test-getkey-active', $1, 'redacted:configstore-test-getkey-active', 'org-getkey', 'workspace-getkey', 'developer', '["proxy:write"]'::jsonb)
ON CONFLICT (id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash,
    token = EXCLUDED.token,
    org_id = EXCLUDED.org_id,
    workspace_id = EXCLUDED.workspace_id,
    role = EXCLUDED.role,
    permissions = EXCLUDED.permissions,
    revoked_at = NULL`, hashToken("token-getkey-active")); err != nil {
		t.Fatalf("insert active key: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO gateway_keys (id, token_hash, token, org_id, workspace_id, role, permissions, revoked_at)
VALUES ('configstore-test-getkey-revoked', $1, 'redacted:configstore-test-getkey-revoked', 'org-getkey', 'workspace-getkey', 'developer', '["proxy:write"]'::jsonb, NOW())
ON CONFLICT (id) DO UPDATE SET
    token_hash = EXCLUDED.token_hash,
    token = EXCLUDED.token,
    org_id = EXCLUDED.org_id,
    workspace_id = EXCLUDED.workspace_id,
    role = EXCLUDED.role,
    permissions = EXCLUDED.permissions,
    revoked_at = EXCLUDED.revoked_at`, hashToken("token-getkey-revoked")); err != nil {
		t.Fatalf("insert revoked key: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM gateway_keys WHERE id IN ('configstore-test-getkey-active', 'configstore-test-getkey-revoked')`)
	})

	key, err := store.GetGatewayKey(ctx, hashToken("token-getkey-active"))
	if err != nil {
		t.Fatalf("GetGatewayKey(active) error: %v", err)
	}
	if key.ID != "configstore-test-getkey-active" {
		t.Fatalf("key.id=%q, want configstore-test-getkey-active", key.ID)
	}
	if key.Token != "" {
		t.Fatalf("key.token=%q, want empty", key.Token)
	}
	if key.OrgID != "org-getkey" || key.WorkspaceID != "workspace-getkey" {
		t.Fatalf("key tenant=%s/%s, want org-getkey/workspace-getkey", key.OrgID, key.WorkspaceID)
	}

	if _, err := store.GetGatewayKey(ctx, hashToken("token-getkey-revoked")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGatewayKey(revoked) error=%v, want ErrNotFound", err)
	}
	if _, err := store.GetGatewayKey(ctx, hashToken("token-getkey-missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGatewayKey(missing) error=%v, want ErrNotFound", err)
	}
}

func TestPostgresStoreRLSBlocksCrossTenantUnfilteredQueries(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	ensurePostgresTestTenant(t, store, "org-rls-a", "workspace-rls-a")
	ensurePostgresTestTenant(t, store, "org-rls-b", "workspace-rls-b")
	const (
		keyAID = "configstore-test-rls-tenant-a"
		keyBID = "configstore-test-rls-tenant-b"
	)
	if _, err := store.db.ExecContext(ctx, `DELETE FROM gateway_keys WHERE id IN ($1, $2)`, keyAID, keyBID); err != nil {
		t.Fatalf("cleanup before insert: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO gateway_keys (id, token_hash, token, org_id, workspace_id, role, permissions, revoked_at)
VALUES
  ($1, $2, $3, 'org-rls-a', 'workspace-rls-a', 'owner', '["proxy:write"]'::jsonb, NULL),
  ($4, $5, $6, 'org-rls-b', 'workspace-rls-b', 'owner', '["proxy:write"]'::jsonb, NULL)
ON CONFLICT (id) DO UPDATE SET
  token_hash = EXCLUDED.token_hash,
  token = EXCLUDED.token,
  org_id = EXCLUDED.org_id,
  workspace_id = EXCLUDED.workspace_id,
  role = EXCLUDED.role,
  permissions = EXCLUDED.permissions,
  revoked_at = NULL`,
		keyAID,
		hashToken("token-rls-a"),
		redactedTokenValue(keyAID),
		keyBID,
		hashToken("token-rls-b"),
		redactedTokenValue(keyBID),
	); err != nil {
		t.Fatalf("insert tenant rows: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM gateway_keys WHERE id IN ($1, $2)`, keyAID, keyBID)
	})

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tenant-scoped tx: %v", err)
	}
	defer tx.Rollback()

	ensureGatewayKeysRLSActive(t, tx)

	if _, err := tx.ExecContext(ctx, `
SELECT
  set_config('ongoingai.org_id', $1, true),
  set_config('ongoingai.workspace_id', $2, true)`,
		"org-rls-a",
		"workspace-rls-a",
	); err != nil {
		t.Fatalf("set tenant session context: %v", err)
	}

	rows, err := tx.QueryContext(ctx, `
SELECT id, org_id, workspace_id
FROM gateway_keys
WHERE revoked_at IS NULL
ORDER BY id`)
	if err != nil {
		t.Fatalf("unfiltered query with tenant context: %v", err)
	}
	defer rows.Close()

	type seenRow struct {
		id          string
		orgID       string
		workspaceID string
	}
	seen := make([]seenRow, 0, 2)
	for rows.Next() {
		var item seenRow
		if err := rows.Scan(&item.id, &item.orgID, &item.workspaceID); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		seen = append(seen, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate rows: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("visible row count=%d, want 1 (cross-tenant row must be filtered by RLS)", len(seen))
	}
	if seen[0].id != keyAID || seen[0].orgID != "org-rls-a" || seen[0].workspaceID != "workspace-rls-a" {
		t.Fatalf("visible row=%+v, want tenant-a row only", seen[0])
	}

	var leakedID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM gateway_keys WHERE id = $1`, keyBID).Scan(&leakedID)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-tenant row lookup error=%v, want sql.ErrNoRows", err)
	}
}

func TestPostgresStoreEnforcesTenantForeignKeys(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	const (
		orgID                     = "org-fk-enforced"
		workspaceID               = "workspace-fk-enforced"
		keyID                     = "key-fk-enforced"
		missingWorkspaceKeyID     = "key-fk-missing-workspace"
		missingWorkspaceOrgID     = "org-fk-missing-workspace"
		missingWorkspaceWorkspace = "workspace-fk-missing-workspace"
	)
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM gateway_keys WHERE id IN ($1, $2)`, keyID, missingWorkspaceKeyID)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM workspaces WHERE id IN ($1, $2)`, workspaceID, missingWorkspaceWorkspace)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id IN ($1, $2, $3)`, orgID, "org-fk-missing-org", missingWorkspaceOrgID)
	})

	var constraintCount int
	if err := store.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM pg_constraint
WHERE conname IN ('fk_workspaces_organization', 'fk_gateway_keys_workspace_tenant')`).Scan(&constraintCount); err != nil {
		t.Fatalf("query tenant foreign key constraints: %v", err)
	}
	if constraintCount != 2 {
		t.Fatalf("tenant foreign key constraint count=%d, want 2", constraintCount)
	}

	if _, err := store.db.ExecContext(ctx, `
INSERT INTO workspaces (id, org_id, name)
VALUES ($1, $2, 'missing-org-workspace')`,
		"workspace-fk-missing-org",
		"org-fk-missing-org",
	); !isPostgresForeignKeyViolation(err) {
		t.Fatalf("insert workspace without organization error=%v, want foreign-key violation", err)
	}

	ensurePostgresTestTenant(t, store, orgID, workspaceID)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO gateway_keys (id, token_hash, token, org_id, workspace_id, role, permissions)
VALUES ($1, $2, $3, $4, $5, 'owner', '["proxy:write"]'::jsonb)`,
		keyID,
		hashToken("token-fk-ok"),
		redactedTokenValue(keyID),
		orgID,
		workspaceID,
	); err != nil {
		t.Fatalf("insert gateway key with valid tenant scope: %v", err)
	}

	_, _ = store.db.ExecContext(ctx, `INSERT INTO organizations (id, name) VALUES ($1, $1) ON CONFLICT (id) DO NOTHING`, missingWorkspaceOrgID)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO gateway_keys (id, token_hash, token, org_id, workspace_id, role, permissions)
VALUES ($1, $2, $3, $4, $5, 'owner', '["proxy:write"]'::jsonb)`,
		missingWorkspaceKeyID,
		hashToken("token-fk-missing-workspace"),
		redactedTokenValue(missingWorkspaceKeyID),
		missingWorkspaceOrgID,
		missingWorkspaceWorkspace,
	); !isPostgresForeignKeyViolation(err) {
		t.Fatalf("insert gateway key without workspace scope error=%v, want foreign-key violation", err)
	}
}

func ensurePostgresTestTenant(t *testing.T, store *PostgresStore, orgID, workspaceID string) {
	t.Helper()

	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO organizations (id, name)
VALUES ($1, $1)
ON CONFLICT (id) DO NOTHING`, orgID); err != nil {
		t.Fatalf("insert test organization %q: %v", orgID, err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO workspaces (id, org_id, name)
VALUES ($1, $2, $1)
ON CONFLICT (org_id, id) DO NOTHING`, workspaceID, orgID); err != nil {
		t.Fatalf("insert test workspace %q/%q: %v", orgID, workspaceID, err)
	}
}

func ensureGatewayKeysRLSActive(t *testing.T, tx *sql.Tx) {
	t.Helper()

	ctx := context.Background()
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT row_security_active('gateway_keys'::regclass)`).Scan(&active); err != nil {
		t.Fatalf("check row security state for gateway_keys: %v", err)
	}
	if active {
		return
	}

	// CI often connects as the postgres superuser, which bypasses RLS even with
	// FORCE RLS enabled. Switch to a non-bypass role before asserting policy behavior.
	if _, err := tx.ExecContext(ctx, `
DO $$
BEGIN
	CREATE ROLE ongoingai_rls_test_role;
EXCEPTION
	WHEN duplicate_object THEN
		NULL;
END $$;`); err != nil {
		t.Fatalf("create non-bypass role for RLS assertions: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `GRANT USAGE ON SCHEMA public TO ongoingai_rls_test_role`); err != nil {
		t.Fatalf("grant schema usage to RLS test role: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `GRANT SELECT ON gateway_keys TO ongoingai_rls_test_role`); err != nil {
		t.Fatalf("grant gateway_keys select to RLS test role: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL ROLE ongoingai_rls_test_role`); err != nil {
		t.Fatalf("switch to RLS test role: %v", err)
	}

	if err := tx.QueryRowContext(ctx, `SELECT row_security_active('gateway_keys'::regclass)`).Scan(&active); err != nil {
		t.Fatalf("re-check row security state for gateway_keys: %v", err)
	}
	if !active {
		t.Fatal("row_security_active(gateway_keys)=false; cannot validate tenant RLS behavior")
	}
}
