package main

import "time"

const (
	defaultDebugFormat = "text"
	defaultDebugLimit  = 200
	maxDebugLimit      = 500
	debugSchemaVersion = "debug-chain.v1"
)

type debugDocument struct {
	SchemaVersion   string                `json:"schema_version"`
	GeneratedAt     time.Time             `json:"generated_at"`
	Selection       debugSelectionInfo    `json:"selection"`
	Options         debugOptionInfo       `json:"options"`
	SourceTraceID   string                `json:"source_trace_id"`
	SourceTimestamp time.Time             `json:"source_timestamp"`
	Source          debugTraceCheckpoint  `json:"source"`
	Chain           debugChain            `json:"chain"`
	Diffs           []debugCheckpointDiff `json:"diffs,omitempty"`
}

type debugSelectionInfo struct {
	TraceID      string `json:"trace_id,omitempty"`
	TraceGroupID string `json:"trace_group_id,omitempty"`
	ThreadID     string `json:"thread_id,omitempty"`
	RunID        string `json:"run_id,omitempty"`
}

type debugOptionInfo struct {
	Limit          int  `json:"limit"`
	IncludeDiff    bool `json:"include_diff"`
	IncludeHeaders bool `json:"include_headers"`
	IncludeBodies  bool `json:"include_bodies"`
}

type debugChain struct {
	GroupID           string                 `json:"group_id,omitempty"`
	ThreadID          string                 `json:"thread_id,omitempty"`
	RunID             string                 `json:"run_id,omitempty"`
	TargetCheckpoint  string                 `json:"target_checkpoint_id"`
	CheckpointCount   int                    `json:"checkpoint_count"`
	Truncated         bool                   `json:"truncated"`
	Checkpoints       []debugTraceCheckpoint `json:"checkpoints"`
	LineageIdentifier string                 `json:"lineage_identifier,omitempty"`
}

type debugTraceCheckpoint struct {
	Step               int            `json:"step"`
	ID                 string         `json:"id"`
	Timestamp          time.Time      `json:"timestamp"`
	CreatedAt          time.Time      `json:"created_at"`
	Provider           string         `json:"provider"`
	Model              string         `json:"model"`
	RequestMethod      string         `json:"request_method"`
	RequestPath        string         `json:"request_path"`
	ResponseStatus     int            `json:"response_status"`
	InputTokens        int            `json:"input_tokens"`
	OutputTokens       int            `json:"output_tokens"`
	TotalTokens        int            `json:"total_tokens"`
	EstimatedCostUSD   float64        `json:"estimated_cost_usd"`
	LatencyMS          int64          `json:"latency_ms"`
	TimeToFirstTokenMS int64          `json:"time_to_first_token_ms"`
	TimeToFirstTokenUS int64          `json:"time_to_first_token_us"`
	Lineage            debugLineage   `json:"lineage"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	RequestHeaders     string         `json:"request_headers,omitempty"`
	ResponseHeaders    string         `json:"response_headers,omitempty"`
	RequestBody        string         `json:"request_body,omitempty"`
	ResponseBody       string         `json:"response_body,omitempty"`
}

type debugLineage struct {
	GroupID            string `json:"group_id,omitempty"`
	ThreadID           string `json:"thread_id,omitempty"`
	RunID              string `json:"run_id,omitempty"`
	CheckpointID       string `json:"checkpoint_id,omitempty"`
	ParentCheckpointID string `json:"parent_checkpoint_id,omitempty"`
	CheckpointSeq      int64  `json:"checkpoint_seq,omitempty"`
	Immutable          bool   `json:"immutable"`
}

type debugCheckpointDiff struct {
	FromCheckpointID         string   `json:"from_checkpoint_id"`
	ToCheckpointID           string   `json:"to_checkpoint_id"`
	ProviderChanged          bool     `json:"provider_changed"`
	ModelChanged             bool     `json:"model_changed"`
	RequestMethodChanged     bool     `json:"request_method_changed"`
	RequestPathChanged       bool     `json:"request_path_changed"`
	ResponseStatusChanged    bool     `json:"response_status_changed"`
	InputTokensDelta         int      `json:"input_tokens_delta"`
	OutputTokensDelta        int      `json:"output_tokens_delta"`
	TotalTokensDelta         int      `json:"total_tokens_delta"`
	LatencyDeltaMS           int64    `json:"latency_delta_ms"`
	EstimatedCostDeltaUSD    float64  `json:"estimated_cost_delta_usd"`
	RequestHeadersChanged    bool     `json:"request_headers_changed"`
	ResponseHeadersChanged   bool     `json:"response_headers_changed"`
	RequestBodyChanged       bool     `json:"request_body_changed"`
	ResponseBodyChanged      bool     `json:"response_body_changed"`
	RequestHeadersBytesFrom  int      `json:"request_headers_bytes_from"`
	RequestHeadersBytesTo    int      `json:"request_headers_bytes_to"`
	ResponseHeadersBytesFrom int      `json:"response_headers_bytes_from"`
	ResponseHeadersBytesTo   int      `json:"response_headers_bytes_to"`
	RequestBodyBytesFrom     int      `json:"request_body_bytes_from"`
	RequestBodyBytesTo       int      `json:"request_body_bytes_to"`
	ResponseBodyBytesFrom    int      `json:"response_body_bytes_from"`
	ResponseBodyBytesTo      int      `json:"response_body_bytes_to"`
	MetadataKeysAdded        []string `json:"metadata_keys_added,omitempty"`
	MetadataKeysRemoved      []string `json:"metadata_keys_removed,omitempty"`
	MetadataKeysChanged      []string `json:"metadata_keys_changed,omitempty"`
}

type debugSelection struct {
	TraceID      string
	TraceGroupID string
	ThreadID     string
	RunID        string
}

type debugBundleManifest struct {
	SchemaVersion  string             `json:"schema_version"`
	GeneratedAt    time.Time          `json:"generated_at"`
	SelectionMode  string             `json:"selection_mode"`
	Selection      debugSelectionInfo `json:"selection"`
	Limit          int                `json:"limit"`
	IncludeDiff    bool               `json:"include_diff"`
	IncludeBodies  bool               `json:"include_bodies"`
	IncludeHeaders bool               `json:"include_headers"`
	Chain          debugBundleChain   `json:"chain"`
	Files          []debugBundleFile  `json:"files"`
}

type debugBundleChain struct {
	SourceTraceID    string `json:"source_trace_id"`
	CheckpointCount  int    `json:"checkpoint_count"`
	Truncated        bool   `json:"truncated"`
	DiffCount        int    `json:"diff_count"`
	TargetCheckpoint string `json:"target_checkpoint_id"`
}

type debugBundleFile struct {
	Name   string `json:"name"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
