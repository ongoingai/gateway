package configstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	DSN string
	db  *sql.DB
}

func NewPostgresStore(dsn string) (*PostgresStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("postgres dsn cannot be empty")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres config store: %w", err)
	}
	store := &PostgresStore{
		DSN: dsn,
		db:  db,
	}
	if err := store.configure(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.ensureOptionalColumns(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) ListGatewayKeys(ctx context.Context, filter GatewayKeyFilter) ([]GatewayKey, error) {
	whereSQL, args := postgresGatewayKeyTenantWhere(filter, 1)
	rows, err := s.db.QueryContext(ctx, `
SELECT
    id,
    token_hash,
    org_id,
    workspace_id,
    name,
    description,
    created_by,
    last_used_at,
    role,
    permissions,
    created_at,
    revoked_at
FROM gateway_keys
WHERE revoked_at IS NULL`+whereSQL+`
ORDER BY created_at ASC, id ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("list gateway keys: %w", err)
	}
	defer rows.Close()

	items := make([]GatewayKey, 0)
	for rows.Next() {
		var (
			item        GatewayKey
			lastUsedAt  sql.NullTime
			permissions sql.NullString
			revokedAt   sql.NullTime
		)
		if err := rows.Scan(
			&item.ID,
			&item.TokenHash,
			&item.OrgID,
			&item.WorkspaceID,
			&item.Name,
			&item.Description,
			&item.CreatedBy,
			&lastUsedAt,
			&item.Role,
			&permissions,
			&item.CreatedAt,
			&revokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan gateway key: %w", err)
		}
		if permissions.Valid && strings.TrimSpace(permissions.String) != "" {
			if err := json.Unmarshal([]byte(permissions.String), &item.Permissions); err != nil {
				return nil, fmt.Errorf("decode gateway key permissions for %q: %w", item.ID, err)
			}
		}
		if revokedAt.Valid {
			item.RevokedAt = revokedAt.Time.UTC()
		}
		if lastUsedAt.Valid {
			item.LastUsedAt = lastUsedAt.Time.UTC()
		}
		item.Team = item.WorkspaceID
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate gateway keys: %w", err)
	}

	return items, nil
}

func (s *PostgresStore) GetGatewayKey(ctx context.Context, keyHash string) (*GatewayKey, error) {
	keyHash = normalizeTokenHash(keyHash)
	if keyHash == "" {
		return nil, ErrNotFound
	}

	var (
		item        GatewayKey
		lastUsedAt  sql.NullTime
		permissions sql.NullString
		createdAt   time.Time
		revokedAt   sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
SELECT
    id,
    token_hash,
    org_id,
    workspace_id,
    name,
    description,
    created_by,
    last_used_at,
    role,
    permissions,
    created_at,
    revoked_at
FROM gateway_keys
WHERE token_hash = $1 AND revoked_at IS NULL
LIMIT 1`, keyHash).Scan(
		&item.ID,
		&item.TokenHash,
		&item.OrgID,
		&item.WorkspaceID,
		&item.Name,
		&item.Description,
		&item.CreatedBy,
		&lastUsedAt,
		&item.Role,
		&permissions,
		&createdAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get gateway key by token hash: %w", err)
	}
	if permissions.Valid && strings.TrimSpace(permissions.String) != "" {
		if err := json.Unmarshal([]byte(permissions.String), &item.Permissions); err != nil {
			return nil, fmt.Errorf("decode gateway key permissions for %q: %w", item.ID, err)
		}
	}
	item.Team = item.WorkspaceID
	item.TokenHash = normalizeTokenHash(item.TokenHash)
	item.CreatedAt = createdAt.UTC()
	if lastUsedAt.Valid {
		item.LastUsedAt = lastUsedAt.Time.UTC()
	}
	if revokedAt.Valid {
		item.RevokedAt = revokedAt.Time.UTC()
	}
	// Never return token material from config stores.
	item.Token = ""
	return &item, nil
}

func (s *PostgresStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}

	var item Organization
	err := s.db.QueryRowContext(ctx, `
SELECT id, name, created_at
FROM organizations
WHERE id = $1
LIMIT 1`, id).Scan(&item.ID, &item.Name, &item.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get organization %q: %w", id, err)
	}
	item.CreatedAt = item.CreatedAt.UTC()
	return &item, nil
}

func (s *PostgresStore) GetWorkspace(ctx context.Context, id string) (*Workspace, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}

	var item Workspace
	err := s.db.QueryRowContext(ctx, `
SELECT id, org_id, name, created_at
FROM workspaces
WHERE id = $1
LIMIT 1`, id).Scan(&item.ID, &item.OrgID, &item.Name, &item.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get workspace %q: %w", id, err)
	}
	item.CreatedAt = item.CreatedAt.UTC()
	return &item, nil
}

func (s *PostgresStore) ListWorkspaces(ctx context.Context, orgID string) ([]Workspace, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, ErrNotFound
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT id, org_id, name, created_at
FROM workspaces
WHERE org_id = $1
ORDER BY created_at ASC, id ASC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("list workspaces for org %q: %w", orgID, err)
	}
	defer rows.Close()

	items := make([]Workspace, 0)
	for rows.Next() {
		var item Workspace
		if err := rows.Scan(&item.ID, &item.OrgID, &item.Name, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan workspace: %w", err)
		}
		item.CreatedAt = item.CreatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate workspaces: %w", err)
	}

	return items, nil
}

func (s *PostgresStore) CreateGatewayKey(ctx context.Context, key GatewayKey) (*GatewayKey, error) {
	row := normalizeGatewayKey(key)
	if row.ID == "" {
		return nil, fmt.Errorf("gateway key id cannot be empty")
	}
	if row.Token == "" {
		return nil, fmt.Errorf("gateway key token cannot be empty")
	}
	permissionsJSON, err := json.Marshal(row.Permissions)
	if err != nil {
		return nil, fmt.Errorf("encode gateway key permissions: %w", err)
	}
	if err := s.ensureTenantScope(ctx, row.OrgID, row.WorkspaceID); err != nil {
		return nil, fmt.Errorf("ensure gateway key tenant scope %q/%q: %w", row.OrgID, row.WorkspaceID, err)
	}

	var createdAt time.Time
	err = s.db.QueryRowContext(ctx, `
INSERT INTO gateway_keys (
    id,
    token_hash,
    token,
    org_id,
    workspace_id,
    name,
    description,
    created_by,
    role,
    permissions
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
RETURNING created_at`,
		row.ID,
		row.TokenHash,
		redactedTokenValue(row.ID),
		row.OrgID,
		row.WorkspaceID,
		row.Name,
		row.Description,
		row.CreatedBy,
		row.Role,
		string(permissionsJSON),
	).Scan(&createdAt)
	if err != nil {
		if isPostgresUniqueViolation(err) {
			return nil, ErrConflict
		}
		if isPostgresForeignKeyViolation(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("create gateway key %q: %w", row.ID, err)
	}
	row.CreatedAt = createdAt.UTC()
	return &row, nil
}

func (s *PostgresStore) RevokeGatewayKey(ctx context.Context, id string, filter GatewayKeyFilter) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	whereSQL, args := postgresGatewayKeyTenantWhere(filter, 2)
	query := `UPDATE gateway_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL` + whereSQL
	result, err := s.db.ExecContext(ctx, query, append([]any{id}, args...)...)
	if err != nil {
		return fmt.Errorf("revoke gateway key %q: %w", id, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoke gateway key rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) RotateGatewayKey(ctx context.Context, id, token string, filter GatewayKeyFilter) (*GatewayKey, error) {
	id = strings.TrimSpace(id)
	token = strings.TrimSpace(token)
	if id == "" {
		return nil, ErrNotFound
	}
	if token == "" {
		return nil, fmt.Errorf("gateway key token cannot be empty")
	}

	tokenHash := hashToken(token)
	whereSQL, args := postgresGatewayKeyTenantWhere(filter, 4)
	query := `
UPDATE gateway_keys
SET token_hash = $1, token = $2
WHERE id = $3 AND revoked_at IS NULL` + whereSQL + `
RETURNING
    id,
    token_hash,
    org_id,
    workspace_id,
    name,
    description,
    created_by,
    last_used_at,
    role,
    permissions,
    created_at,
    revoked_at`
	var (
		item        GatewayKey
		lastUsedAt  sql.NullTime
		permissions sql.NullString
		createdAt   time.Time
		revokedAt   sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, query, append([]any{tokenHash, redactedTokenValue(id), id}, args...)...).Scan(
		&item.ID,
		&item.TokenHash,
		&item.OrgID,
		&item.WorkspaceID,
		&item.Name,
		&item.Description,
		&item.CreatedBy,
		&lastUsedAt,
		&item.Role,
		&permissions,
		&createdAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if isPostgresUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("rotate gateway key %q: %w", id, err)
	}
	if permissions.Valid && strings.TrimSpace(permissions.String) != "" {
		if err := json.Unmarshal([]byte(permissions.String), &item.Permissions); err != nil {
			return nil, fmt.Errorf("decode rotated gateway key permissions for %q: %w", item.ID, err)
		}
	}
	item.Team = item.WorkspaceID
	item.CreatedAt = createdAt.UTC()
	if lastUsedAt.Valid {
		item.LastUsedAt = lastUsedAt.Time.UTC()
	}
	if revokedAt.Valid {
		item.RevokedAt = revokedAt.Time.UTC()
	}
	item.Token = token
	return &item, nil
}

func (s *PostgresStore) TouchGatewayKeyLastUsed(ctx context.Context, id string, filter GatewayKeyFilter) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrNotFound
	}
	whereSQL, args := postgresGatewayKeyTenantWhere(filter, 2)
	query := `UPDATE gateway_keys SET last_used_at = NOW() WHERE id = $1 AND revoked_at IS NULL` + whereSQL
	result, err := s.db.ExecContext(ctx, query, append([]any{id}, args...)...)
	if err != nil {
		return fmt.Errorf("touch gateway key %q last_used_at: %w", id, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read touch gateway key %q rows affected: %w", id, err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func postgresGatewayKeyTenantWhere(filter GatewayKeyFilter, argStart int) (string, []any) {
	parts := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if orgID := strings.TrimSpace(filter.OrgID); orgID != "" {
		parts = append(parts, fmt.Sprintf("org_id = $%d", argStart+len(args)))
		args = append(args, orgID)
	}
	if workspaceID := strings.TrimSpace(filter.WorkspaceID); workspaceID != "" {
		parts = append(parts, fmt.Sprintf("workspace_id = $%d", argStart+len(args)))
		args = append(args, workspaceID)
	}
	if len(parts) == 0 {
		return "", nil
	}
	return " AND " + strings.Join(parts, " AND "), args
}

func normalizeGatewayKey(key GatewayKey) GatewayKey {
	row := key
	row.ID = strings.TrimSpace(row.ID)
	row.Token = strings.TrimSpace(row.Token)
	row.TokenHash = normalizeTokenHash(row.TokenHash)
	if row.TokenHash == "" && row.Token != "" {
		row.TokenHash = hashToken(row.Token)
	}
	row.OrgID = nonEmpty(strings.TrimSpace(row.OrgID), "default")
	row.WorkspaceID = nonEmpty(strings.TrimSpace(row.WorkspaceID), "default")
	row.Team = row.WorkspaceID
	row.Name = strings.TrimSpace(row.Name)
	row.Description = strings.TrimSpace(row.Description)
	row.CreatedBy = strings.TrimSpace(row.CreatedBy)
	row.Role = nonEmpty(strings.TrimSpace(strings.ToLower(row.Role)), "developer")
	row.Permissions = normalizePermissions(row.Permissions)
	return row
}

func normalizePermissions(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		permission := strings.TrimSpace(strings.ToLower(raw))
		if permission == "" {
			continue
		}
		if _, exists := seen[permission]; exists {
			continue
		}
		seen[permission] = struct{}{}
		out = append(out, permission)
	}
	return out
}

func isPostgresUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isPostgresForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func normalizeTokenHash(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func redactedTokenValue(id string) string {
	return "redacted:" + strings.TrimSpace(id)
}

func (s *PostgresStore) configure() error {
	if s.db == nil {
		return fmt.Errorf("postgres config store database is not initialized")
	}

	s.db.SetMaxOpenConns(10)
	s.db.SetMaxIdleConns(5)
	s.db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres config store: %w", err)
	}
	return nil
}

func (s *PostgresStore) ensureSchema() error {
	const schema = `
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_workspaces_organization
        FOREIGN KEY (org_id)
        REFERENCES organizations(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_workspaces_org_id ON workspaces(org_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_id ON workspaces(id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_org_id_id ON workspaces(org_id, id);

CREATE TABLE IF NOT EXISTS gateway_keys (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token TEXT,
    org_id TEXT NOT NULL DEFAULT 'default',
    workspace_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    last_used_at TIMESTAMPTZ,
    role TEXT NOT NULL DEFAULT 'developer',
    permissions JSONB,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_gateway_keys_workspace_tenant
        FOREIGN KEY (org_id, workspace_id)
        REFERENCES workspaces(org_id, id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_gateway_keys_active ON gateway_keys(revoked_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_gateway_keys_org_workspace_active ON gateway_keys(org_id, workspace_id) WHERE revoked_at IS NULL;
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("ensure postgres config store schema: %w", err)
	}
	if err := s.ensureDefaultTenant(); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) ensureDefaultTenant() error {
	// Seed a default tenant for self-hosted installs so tenant-scoped auth and
	// query filters always have a valid org/workspace boundary.
	statements := []string{
		`INSERT INTO organizations (id, name) VALUES ('default', 'Default Organization') ON CONFLICT (id) DO NOTHING;`,
		`INSERT INTO workspaces (id, org_id, name) VALUES ('default', 'default', 'Default Workspace') ON CONFLICT (org_id, id) DO UPDATE SET name = EXCLUDED.name;`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres default tenant seed data: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) ensureOptionalColumns() error {
	statements := []string{
		`ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'default';`,
		`CREATE INDEX IF NOT EXISTS idx_workspaces_org_id ON workspaces(org_id);`,
		`CREATE INDEX IF NOT EXISTS idx_workspaces_id ON workspaces(id);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_org_id_id ON workspaces(org_id, id);`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'default';`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'default';`,
		`CREATE INDEX IF NOT EXISTS idx_gateway_keys_org_workspace_active ON gateway_keys(org_id, workspace_id) WHERE revoked_at IS NULL;`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS token_hash TEXT;`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS token TEXT;`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';`,
		`ALTER TABLE gateway_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_keys_token_hash ON gateway_keys(token_hash);`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres config store optional schema component: %w", err)
		}
	}
	if err := s.ensureWorkspaceScopeUniqueness(); err != nil {
		return err
	}

	rows, err := s.db.Query(`SELECT id, token FROM gateway_keys WHERE (token_hash IS NULL OR token_hash = '') AND token IS NOT NULL AND token <> ''`)
	if err != nil {
		return fmt.Errorf("query legacy gateway keys missing token_hash: %w", err)
	}
	defer rows.Close()

	type legacyRow struct {
		id    string
		token string
	}
	legacy := make([]legacyRow, 0)
	for rows.Next() {
		var item legacyRow
		if err := rows.Scan(&item.id, &item.token); err != nil {
			return fmt.Errorf("scan legacy gateway key row: %w", err)
		}
		legacy = append(legacy, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy gateway key rows: %w", err)
	}

	for _, item := range legacy {
		if _, err := s.db.Exec(
			`UPDATE gateway_keys SET token_hash = $1, token = $2 WHERE id = $3`,
			hashToken(item.token),
			redactedTokenValue(item.id),
			item.id,
		); err != nil {
			return fmt.Errorf("migrate legacy gateway key %q token_hash: %w", item.id, err)
		}
	}

	if _, err := s.db.Exec(`UPDATE gateway_keys SET token = 'redacted:' || id WHERE token IS NULL OR token = '' OR token NOT LIKE 'redacted:%'`); err != nil {
		return fmt.Errorf("scrub legacy gateway key tokens: %w", err)
	}

	row := s.db.QueryRow(`SELECT id FROM gateway_keys WHERE token_hash IS NULL OR token_hash = '' LIMIT 1`)
	var missingID string
	err = row.Scan(&missingID)
	if err == nil {
		return fmt.Errorf("gateway key %q is missing token_hash after migration", missingID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("verify gateway key token_hash migration: %w", err)
	}

	if err := s.ensureTenantForeignKeys(); err != nil {
		return err
	}
	if err := s.ensureTenantRLS(); err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) ensureTenantScope(ctx context.Context, orgID, workspaceID string) error {
	orgID = nonEmpty(strings.TrimSpace(orgID), "default")
	workspaceID = nonEmpty(strings.TrimSpace(workspaceID), "default")

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO organizations (id, name)
VALUES ($1, $2)
ON CONFLICT (id) DO NOTHING`, orgID, orgID); err != nil {
		return fmt.Errorf("ensure organization %q exists: %w", orgID, err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO workspaces (id, org_id, name)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, id) DO NOTHING`, workspaceID, orgID, workspaceID); err != nil {
		return fmt.Errorf("ensure workspace %q/%q exists: %w", orgID, workspaceID, err)
	}
	return nil
}

func (s *PostgresStore) ensureTenantForeignKeys() error {
	statements := []string{
		`INSERT INTO organizations (id, name)
SELECT DISTINCT org_id, org_id
FROM workspaces
WHERE org_id <> ''
ON CONFLICT (id) DO NOTHING;`,
		`INSERT INTO organizations (id, name)
SELECT DISTINCT org_id, org_id
FROM gateway_keys
WHERE org_id <> ''
ON CONFLICT (id) DO NOTHING;`,
		`INSERT INTO workspaces (id, org_id, name)
SELECT DISTINCT workspace_id, org_id, workspace_id
FROM gateway_keys
WHERE workspace_id <> '' AND org_id <> ''
ON CONFLICT (org_id, id) DO NOTHING;`,
		`CREATE INDEX IF NOT EXISTS idx_workspaces_id ON workspaces(id);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_org_id_id ON workspaces(org_id, id);`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres tenant foreign key prerequisites: %w", err)
		}
	}

	var missingWorkspaceOrgCount int
	if err := s.db.QueryRow(`
SELECT COUNT(*)
FROM workspaces w
LEFT JOIN organizations o ON o.id = w.org_id
WHERE o.id IS NULL`).Scan(&missingWorkspaceOrgCount); err != nil {
		return fmt.Errorf("count workspaces without organizations: %w", err)
	}
	if missingWorkspaceOrgCount > 0 {
		return fmt.Errorf("found %d workspaces without matching organization rows", missingWorkspaceOrgCount)
	}

	var missingKeyWorkspaceCount int
	if err := s.db.QueryRow(`
SELECT COUNT(*)
FROM gateway_keys g
LEFT JOIN workspaces w ON w.id = g.workspace_id AND w.org_id = g.org_id
WHERE w.id IS NULL`).Scan(&missingKeyWorkspaceCount); err != nil {
		return fmt.Errorf("count gateway keys without workspace scope rows: %w", err)
	}
	if missingKeyWorkspaceCount > 0 {
		return fmt.Errorf("found %d gateway keys without matching workspace scope rows", missingKeyWorkspaceCount)
	}

	constraintStatements := []string{
		`DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM pg_constraint
		WHERE conname = 'fk_workspaces_organization'
	) THEN
		ALTER TABLE workspaces
			ADD CONSTRAINT fk_workspaces_organization
			FOREIGN KEY (org_id)
			REFERENCES organizations(id)
			ON UPDATE CASCADE
			ON DELETE RESTRICT;
	END IF;
END $$;`,
		`DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1
		FROM pg_constraint
		WHERE conname = 'fk_gateway_keys_workspace_tenant'
	) THEN
		ALTER TABLE gateway_keys
			ADD CONSTRAINT fk_gateway_keys_workspace_tenant
			FOREIGN KEY (org_id, workspace_id)
			REFERENCES workspaces(org_id, id)
			ON UPDATE CASCADE
			ON DELETE RESTRICT;
	END IF;
END $$;`,
	}
	for _, stmt := range constraintStatements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres tenant foreign key constraints: %w", err)
		}
	}

	return nil
}

func (s *PostgresStore) ensureWorkspaceScopeUniqueness() error {
	statements := []string{
		`CREATE INDEX IF NOT EXISTS idx_workspaces_id ON workspaces(id);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_org_id_id ON workspaces(org_id, id);`,
		`DO $$
DECLARE
	pk_cols TEXT[];
BEGIN
	SELECT array_agg(att.attname ORDER BY ord.n)
	INTO pk_cols
	FROM pg_constraint con
	JOIN pg_class rel ON rel.oid = con.conrelid
	JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
	JOIN unnest(con.conkey) WITH ORDINALITY AS ord(attnum, n) ON TRUE
	JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = ord.attnum
	WHERE con.contype = 'p'
	  AND nsp.nspname = 'public'
	  AND rel.relname = 'workspaces';

	IF pk_cols = ARRAY['id'] THEN
		ALTER TABLE workspaces DROP CONSTRAINT workspaces_pkey;
	END IF;
END $$;`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres workspace tenant keying: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) ensureTenantRLS() error {
	// RLS is an additional safety net in multi-instance mode. Policies scope visibility to
	// session tenant settings when present and remain permissive otherwise to
	// preserve self-hosted/default behavior.
	statements := []string{
		`ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE organizations FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS organizations_org_scope ON organizations;`,
		`CREATE POLICY organizations_org_scope ON organizations
USING (
    NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
    OR id = NULLIF(current_setting('ongoingai.org_id', true), '')
)
WITH CHECK (
    NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
    OR id = NULLIF(current_setting('ongoingai.org_id', true), '')
);`,
		`ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE workspaces FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS workspaces_org_scope ON workspaces;`,
		`CREATE POLICY workspaces_org_scope ON workspaces
USING (
    NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
    OR org_id = NULLIF(current_setting('ongoingai.org_id', true), '')
)
WITH CHECK (
    NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
    OR org_id = NULLIF(current_setting('ongoingai.org_id', true), '')
);`,
		`ALTER TABLE gateway_keys ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE gateway_keys FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS gateway_keys_tenant_scope ON gateway_keys;`,
		`CREATE POLICY gateway_keys_tenant_scope ON gateway_keys
USING (
    (NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
        OR org_id = NULLIF(current_setting('ongoingai.org_id', true), ''))
    AND
    (NULLIF(current_setting('ongoingai.workspace_id', true), '') IS NULL
        OR workspace_id = NULLIF(current_setting('ongoingai.workspace_id', true), ''))
)
WITH CHECK (
    (NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
        OR org_id = NULLIF(current_setting('ongoingai.org_id', true), ''))
    AND
    (NULLIF(current_setting('ongoingai.workspace_id', true), '') IS NULL
        OR workspace_id = NULLIF(current_setting('ongoingai.workspace_id', true), ''))
);`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres config store rls policy: %w", err)
		}
	}
	return nil
}
