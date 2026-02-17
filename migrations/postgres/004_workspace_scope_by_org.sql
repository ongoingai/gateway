CREATE INDEX IF NOT EXISTS idx_workspaces_org_id ON workspaces(org_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_id ON workspaces(id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_org_id_id ON workspaces(org_id, id);

DO $$
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

    -- Legacy schemas used a global primary key on id, which prevented the same
    -- workspace id from being reused under different organizations.
    IF pk_cols = ARRAY['id'] THEN
        ALTER TABLE workspaces DROP CONSTRAINT workspaces_pkey;
    END IF;
END $$;
