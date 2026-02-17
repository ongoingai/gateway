CREATE TABLE IF NOT EXISTS traces (
    id TEXT PRIMARY KEY,
    trace_group_id TEXT,
    org_id TEXT NOT NULL DEFAULT 'default',
    workspace_id TEXT NOT NULL DEFAULT 'default',
    timestamp TIMESTAMPTZ NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    request_headers JSONB,
    request_body TEXT,
    response_status INTEGER,
    response_headers JSONB,
    response_body TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    total_tokens INTEGER,
    latency_ms BIGINT,
    time_to_first_token_ms BIGINT,
    time_to_first_token_us BIGINT,
    api_key_hash TEXT,
    estimated_cost_usd DOUBLE PRECISION,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_traces_timestamp ON traces(timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_provider ON traces(provider);
CREATE INDEX IF NOT EXISTS idx_traces_model ON traces(model);
CREATE INDEX IF NOT EXISTS idx_traces_api_key_hash ON traces(api_key_hash);
CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_created_at_id ON traces(org_id, workspace_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_timestamp ON traces(org_id, workspace_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_created_at_id ON traces(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_traces_provider_created_at_id ON traces(provider, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_traces_model_created_at_id ON traces(model, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_traces_api_key_hash_created_at_id ON traces(api_key_hash, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_traces_response_status_created_at_id ON traces(response_status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_traces_provider_timestamp ON traces(provider, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_model_timestamp ON traces(model, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_api_key_hash_timestamp ON traces(api_key_hash, timestamp);
CREATE INDEX IF NOT EXISTS idx_traces_response_status_timestamp ON traces(response_status, timestamp);
