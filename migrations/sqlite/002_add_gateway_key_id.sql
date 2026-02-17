ALTER TABLE traces ADD COLUMN gateway_key_id TEXT;

UPDATE traces
SET gateway_key_id = NULLIF(json_extract(metadata, '$.gateway_key_id'), '')
WHERE gateway_key_id IS NULL
  AND json_valid(metadata);

CREATE INDEX IF NOT EXISTS idx_traces_gateway_key_id ON traces(gateway_key_id);
CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_gateway_key_timestamp ON traces(org_id, workspace_id, gateway_key_id, timestamp);
