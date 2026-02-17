CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_workspaces_org_id ON workspaces(org_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_id ON workspaces(id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_org_id_id ON workspaces(org_id, id);

INSERT INTO organizations (id, name)
VALUES ('default', 'Default Organization')
ON CONFLICT (id) DO NOTHING;

INSERT INTO workspaces (id, org_id, name)
VALUES ('default', 'default', 'Default Workspace')
ON CONFLICT (org_id, id) DO UPDATE SET name = EXCLUDED.name;

INSERT INTO organizations (id, name)
SELECT DISTINCT org_id, org_id
FROM traces
WHERE org_id <> ''
ON CONFLICT (id) DO NOTHING;

INSERT INTO workspaces (id, org_id, name)
SELECT DISTINCT workspace_id, org_id, workspace_id
FROM traces
WHERE workspace_id <> '' AND org_id <> ''
ON CONFLICT (org_id, id) DO NOTHING;

DO $$
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
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_traces_workspace_tenant'
    ) THEN
        ALTER TABLE traces
            ADD CONSTRAINT fk_traces_workspace_tenant
            FOREIGN KEY (org_id, workspace_id)
            REFERENCES workspaces(org_id, id)
            ON UPDATE CASCADE
            ON DELETE RESTRICT;
    END IF;
END $$;
