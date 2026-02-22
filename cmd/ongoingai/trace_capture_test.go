package main

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/providers"
	"github.com/ongoingai/gateway/internal/proxy"
)

func TestBuildTraceRecordParsesButDoesNotStoreBodiesWhenDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/anthropic/v1/messages",
		StatusCode:     http.StatusOK,
		RequestHeaders: http.Header{"X-Api-Key": {"sk-ant-123456"}},
		RequestBody:    []byte(`{"model":"claude-haiku-4-5-20251001"}`),
		ResponseBody:   []byte(`{"usage":{"input_tokens":1000,"output_tokens":500,"total_tokens":1500}}`),
		DurationMS:     123,
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.Provider != "anthropic" {
		t.Fatalf("provider=%q, want anthropic", record.Provider)
	}
	if record.Model != "claude-haiku-4-5-20251001" {
		t.Fatalf("model=%q", record.Model)
	}
	if record.InputTokens != 1000 || record.OutputTokens != 500 || record.TotalTokens != 1500 {
		t.Fatalf("usage=%d/%d/%d", record.InputTokens, record.OutputTokens, record.TotalTokens)
	}
	if math.Abs(record.EstimatedCostUSD-0.0035) > 1e-9 {
		t.Fatalf("estimated_cost_usd=%f", record.EstimatedCostUSD)
	}
	if record.RequestBody != "" || record.ResponseBody != "" {
		t.Fatalf("expected bodies not stored when capture disabled")
	}
	if record.TimeToFirstTokenMS != 0 {
		t.Fatalf("ttft_ms=%d, want 0 for non-stream trace", record.TimeToFirstTokenMS)
	}
	if record.TimeToFirstTokenUS != 0 {
		t.Fatalf("ttft_us=%d, want 0 for non-stream trace", record.TimeToFirstTokenUS)
	}
	if record.APIKeyHash == "" {
		t.Fatal("expected API key hash to be set")
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["api_key_last4"] != "3456" {
		t.Fatalf("api_key_last4=%v, want 3456", metadata["api_key_last4"])
	}
}

func TestBuildTraceRecordParsesStreamingUsageWithCaptureDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	exchange := &proxy.CapturedExchange{
		Method:             http.MethodPost,
		Path:               "/anthropic/v1/messages",
		StatusCode:         http.StatusOK,
		Streaming:          true,
		StreamChunks:       2,
		TimeToFirstTokenUS: 42123,
		ResponseBody: []byte("data: {\"model\":\"claude-opus-4-6-20260220\"}\n\n" +
			"data: {\"usage\":{\"input_tokens\":2000,\"output_tokens\":1000,\"total_tokens\":3000}}\n\n" +
			"data: [DONE]\n\n"),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.Model != "claude-opus-4-6-20260220" {
		t.Fatalf("model=%q", record.Model)
	}
	if record.InputTokens != 2000 || record.OutputTokens != 1000 || record.TotalTokens != 3000 {
		t.Fatalf("usage=%d/%d/%d", record.InputTokens, record.OutputTokens, record.TotalTokens)
	}
	if math.Abs(record.EstimatedCostUSD-0.035) > 1e-9 {
		t.Fatalf("estimated_cost_usd=%f", record.EstimatedCostUSD)
	}
	if record.TimeToFirstTokenUS != 42123 {
		t.Fatalf("ttft_us=%d, want 42123", record.TimeToFirstTokenUS)
	}
	if record.TimeToFirstTokenMS != 43 {
		t.Fatalf("ttft_ms=%d, want 43", record.TimeToFirstTokenMS)
	}
	if record.ResponseBody != "" {
		t.Fatalf("expected response body not stored when capture disabled")
	}
}

func TestBuildTraceRecordParsesStreamingAnthropicEnvelopeUsageAndModel(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	exchange := &proxy.CapturedExchange{
		Method:       http.MethodPost,
		Path:         "/anthropic/v1/messages",
		StatusCode:   http.StatusOK,
		Streaming:    true,
		StreamChunks: 3,
		ResponseBody: []byte(
			"data: {oops}\n\n" +
				"data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-latest\",\"usage\":{\"input_tokens\":9}}}\n\n" +
				"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":6}}\n\n" +
				"data: [DONE]\n\n",
		),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.Model != "claude-sonnet-4-latest" {
		t.Fatalf("model=%q, want claude-sonnet-4-latest", record.Model)
	}
	if record.InputTokens != 9 || record.OutputTokens != 6 || record.TotalTokens != 15 {
		t.Fatalf("usage=%d/%d/%d, want 9/6/15", record.InputTokens, record.OutputTokens, record.TotalTokens)
	}
	if record.ResponseBody != "" {
		t.Fatalf("expected response body not stored when capture disabled")
	}
}

func TestBuildTraceRecordBackfillsTTFTUSFromMS(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	exchange := &proxy.CapturedExchange{
		Method:             http.MethodPost,
		Path:               "/openai/v1/chat/completions",
		StatusCode:         http.StatusOK,
		Streaming:          true,
		TimeToFirstTokenMS: 42,
		ResponseBody: []byte("data: {\"model\":\"gpt-4o-mini\"}\n\n" +
			"data: {\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n" +
			"data: [DONE]\n\n"),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.TimeToFirstTokenMS != 42 {
		t.Fatalf("ttft_ms=%d, want 42", record.TimeToFirstTokenMS)
	}
	if record.TimeToFirstTokenUS != 42000 {
		t.Fatalf("ttft_us=%d, want 42000", record.TimeToFirstTokenUS)
	}
}

func TestExtractUsageFromSSEMergesPartialUsageAcrossMixedPayloadShapes(t *testing.T) {
	t.Parallel()

	body := []byte(
		"event: message\ndata: {\"usage\":{\"prompt_tokens\":11}}\n\n" +
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":13}}}\n\n" +
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n" +
			"data: [DONE]\n\n",
	)

	input, output, total := extractUsageFromSSE(body)
	if input != 13 || output != 5 || total != 18 {
		t.Fatalf("usage=%d/%d/%d, want 13/5/18", input, output, total)
	}
}

func TestExtractUsageFromSSEIgnoresMalformedPayloads(t *testing.T) {
	t.Parallel()

	body := []byte(
		"data: {\"usage\":\n\n" +
			"data: totally-not-json\n\n" +
			"data: {\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}\n\n",
	)

	input, output, total := extractUsageFromSSE(body)
	if input != 2 || output != 1 || total != 3 {
		t.Fatalf("usage=%d/%d/%d, want 2/1/3", input, output, total)
	}
}

func TestExtractModelFromSSESupportsAnthropicMessageEnvelope(t *testing.T) {
	t.Parallel()

	body := []byte(
		"data: {bad}\n\n" +
			"data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4-6-20260220\"}}\n\n",
	)

	model := extractModelFromSSE(body)
	if model != "claude-opus-4-6-20260220" {
		t.Fatalf("model=%q, want claude-opus-4-6-20260220", model)
	}
}

func TestBuildTraceRecordIncludesGatewayIdentityMetadata(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	exchange := &proxy.CapturedExchange{
		Method:             http.MethodPost,
		Path:               "/openai/v1/chat/completions",
		StatusCode:         http.StatusOK,
		GatewayOrgID:       "org-a",
		GatewayWorkspaceID: "workspace-a",
		GatewayKeyID:       "team-a-dev-1",
		GatewayTeam:        "team-a",
		GatewayRole:        "developer",
		ResponseBody:       []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.OrgID != "org-a" {
		t.Fatalf("org_id=%q, want org-a", record.OrgID)
	}
	if record.WorkspaceID != "workspace-a" {
		t.Fatalf("workspace_id=%q, want workspace-a", record.WorkspaceID)
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["gateway_key_id"] != "team-a-dev-1" {
		t.Fatalf("gateway_key_id=%v, want team-a-dev-1", metadata["gateway_key_id"])
	}
	if metadata["team"] != "team-a" {
		t.Fatalf("team=%v, want team-a", metadata["team"])
	}
	if metadata["role"] != "developer" {
		t.Fatalf("role=%v, want developer", metadata["role"])
	}
	if metadata["org_id"] != "org-a" {
		t.Fatalf("org_id=%v, want org-a", metadata["org_id"])
	}
	if metadata["workspace_id"] != "workspace-a" {
		t.Fatalf("workspace_id=%v, want workspace-a", metadata["workspace_id"])
	}
}

func TestBuildTraceRecordIncludesLineageMetadataAndCheckpoint(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	headers := make(http.Header)
	headers.Set("X-OngoingAI-Trace-Group-ID", "group-1")
	headers.Set("X-OngoingAI-Thread-ID", "thread-1")
	headers.Set("X-OngoingAI-Run-ID", "run-1")
	headers.Set("X-OngoingAI-Parent-Checkpoint-ID", "checkpoint-0")
	headers.Set("X-OngoingAI-Checkpoint-Seq", "2")

	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/openai/v1/chat/completions",
		StatusCode:     http.StatusOK,
		RequestHeaders: headers,
		ResponseBody:   []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.TraceGroupID != "group-1" {
		t.Fatalf("trace_group_id=%q, want group-1", record.TraceGroupID)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["lineage_group_id"] != "group-1" {
		t.Fatalf("lineage_group_id=%v, want group-1", metadata["lineage_group_id"])
	}
	if metadata["lineage_thread_id"] != "thread-1" {
		t.Fatalf("lineage_thread_id=%v, want thread-1", metadata["lineage_thread_id"])
	}
	if metadata["lineage_run_id"] != "run-1" {
		t.Fatalf("lineage_run_id=%v, want run-1", metadata["lineage_run_id"])
	}
	if metadata["lineage_parent_checkpoint_id"] != "checkpoint-0" {
		t.Fatalf("lineage_parent_checkpoint_id=%v, want checkpoint-0", metadata["lineage_parent_checkpoint_id"])
	}
	if metadata["lineage_checkpoint_id"] != record.ID {
		t.Fatalf("lineage_checkpoint_id=%v, want %q", metadata["lineage_checkpoint_id"], record.ID)
	}
	if metadata["lineage_immutable"] != true {
		t.Fatalf("lineage_immutable=%v, want true", metadata["lineage_immutable"])
	}
	if metadata["lineage_checkpoint_seq"] != float64(2) {
		t.Fatalf("lineage_checkpoint_seq=%v, want 2", metadata["lineage_checkpoint_seq"])
	}
}

func TestBuildTraceRecordRedactsSensitiveRequestHeaders(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer sk-openai-secret")
	headers.Set("X-API-Key", "sk-anthropic-secret")
	headers.Set("X-OngoingAI-Gateway-Key", "gwk-secret")
	headers.Set("Content-Type", "application/json")

	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/openai/v1/chat/completions",
		StatusCode:     http.StatusOK,
		RequestHeaders: headers,
		ResponseBody:   []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)

	var got map[string][]string
	if err := json.Unmarshal([]byte(record.RequestHeaders), &got); err != nil {
		t.Fatalf("unmarshal request headers: %v", err)
	}

	if value := headerValueIgnoreCase(got, "Authorization"); value != "[REDACTED]" {
		t.Fatalf("authorization header=%q, want [REDACTED]", value)
	}
	if value := headerValueIgnoreCase(got, "X-API-Key"); value != "[REDACTED]" {
		t.Fatalf("x-api-key header=%q, want [REDACTED]", value)
	}
	if value := headerValueIgnoreCase(got, "X-OngoingAI-Gateway-Key"); value != "[REDACTED]" {
		t.Fatalf("gateway key header=%q, want [REDACTED]", value)
	}
	if value := headerValueIgnoreCase(got, "Content-Type"); value != "application/json" {
		t.Fatalf("content-type header=%q, want application/json", value)
	}
}

func TestBuildTraceRecordRedactsSensitiveResponseHeaders(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = false

	responseHeaders := make(http.Header)
	responseHeaders.Set("Set-Cookie", "session=abc123")
	responseHeaders.Set("X-API-Key", "resp-secret")
	responseHeaders.Set("Content-Type", "application/json")

	exchange := &proxy.CapturedExchange{
		Method:          http.MethodPost,
		Path:            "/openai/v1/chat/completions",
		StatusCode:      http.StatusOK,
		RequestHeaders:  http.Header{"Content-Type": {"application/json"}},
		ResponseHeaders: responseHeaders,
		ResponseBody:    []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)

	var got map[string][]string
	if err := json.Unmarshal([]byte(record.ResponseHeaders), &got); err != nil {
		t.Fatalf("unmarshal response headers: %v", err)
	}

	if value := headerValueIgnoreCase(got, "Set-Cookie"); value != "[REDACTED]" {
		t.Fatalf("set-cookie header=%q, want [REDACTED]", value)
	}
	if value := headerValueIgnoreCase(got, "X-API-Key"); value != "[REDACTED]" {
		t.Fatalf("x-api-key header=%q, want [REDACTED]", value)
	}
	if value := headerValueIgnoreCase(got, "Content-Type"); value != "application/json" {
		t.Fatalf("content-type header=%q, want application/json", value)
	}
}

func TestBuildTraceRecordPIIRedactsBodiesByDefaultWhenCaptureEnabled(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = ""

	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/openai/v1/chat/completions",
		StatusCode:     http.StatusOK,
		RequestHeaders: http.Header{"Content-Type": {"application/json"}},
		RequestBody:    []byte(`{"email":"alice@example.com","profile":{"phone":"415-555-1212"},"api_key":"sk_test_1234567890"}`),
		ResponseBody:   []byte(`{"ssn":"123-45-6789","token":"ghp_abcd1234efgh5678"}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)

	if strings.Contains(record.RequestBody, "alice@example.com") || strings.Contains(record.RequestBody, "415-555-1212") {
		t.Fatalf("request body still contains raw pii: %q", record.RequestBody)
	}
	if strings.Contains(record.ResponseBody, "123-45-6789") || strings.Contains(record.ResponseBody, "ghp_abcd1234efgh5678") {
		t.Fatalf("response body still contains raw pii: %q", record.ResponseBody)
	}
	if !strings.Contains(record.RequestBody, "_REDACTED:") {
		t.Fatalf("request body=%q, want redaction placeholders", record.RequestBody)
	}
	if !strings.Contains(record.ResponseBody, "_REDACTED:") {
		t.Fatalf("response body=%q, want redaction placeholders", record.ResponseBody)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["redaction_mode"] != "redact_storage" {
		t.Fatalf("redaction_mode=%v, want redact_storage", metadata["redaction_mode"])
	}
	if metadata["redaction_applied"] != true {
		t.Fatalf("redaction_applied=%v, want true", metadata["redaction_applied"])
	}

	counts, ok := metadata["redaction_counts"].(map[string]any)
	if !ok {
		t.Fatalf("redaction_counts missing or invalid: %T", metadata["redaction_counts"])
	}
	if counts["email"] == nil && counts["field_name"] == nil {
		t.Fatalf("expected redaction counts for body detectors, got %v", counts)
	}
}

func TestBuildTraceRecordPIIModeOffKeepsBodiesUnchanged(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = config.PIIModeOff

	reqBody := `{"email":"alice@example.com"}`
	respBody := `{"phone":"415-555-1212"}`
	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/openai/v1/chat/completions",
		StatusCode:     http.StatusOK,
		RequestHeaders: http.Header{"Content-Type": {"application/json"}},
		RequestBody:    []byte(reqBody),
		ResponseBody:   []byte(respBody),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.RequestBody != reqBody {
		t.Fatalf("request body=%q, want unchanged %q", record.RequestBody, reqBody)
	}
	if record.ResponseBody != respBody {
		t.Fatalf("response body=%q, want unchanged %q", record.ResponseBody, respBody)
	}
}

func TestBuildTraceRecordPIIScopeOverridesModeAndPolicy(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = config.PIIModeOff
	cfg.PII.PolicyID = "global/v1"
	cfg.PII.Scopes = []config.PIIScopeConfig{
		{
			Match: config.PIIScopeMatchConfig{
				WorkspaceID: "workspace-strict",
				Provider:    "openai",
				RoutePrefix: "/openai/v1/chat",
			},
			Mode:     config.PIIModeRedactStorage,
			PolicyID: "workspace-strict/v1",
		},
	}

	exchange := &proxy.CapturedExchange{
		Method:             http.MethodPost,
		Path:               "/openai/v1/chat/completions",
		StatusCode:         http.StatusOK,
		GatewayWorkspaceID: "workspace-strict",
		RequestHeaders:     http.Header{"Content-Type": {"application/json"}},
		RequestBody:        []byte(`{"email":"alice@example.com"}`),
		ResponseBody:       []byte(`{"ok":true}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if strings.Contains(record.RequestBody, "alice@example.com") {
		t.Fatalf("request body still contains raw pii under scoped redaction: %q", record.RequestBody)
	}
	if !strings.Contains(record.RequestBody, "_REDACTED:") {
		t.Fatalf("request body=%q, want redaction placeholder", record.RequestBody)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["redaction_mode"] != config.PIIModeRedactStorage {
		t.Fatalf("redaction_mode=%v, want %q", metadata["redaction_mode"], config.PIIModeRedactStorage)
	}
	if metadata["redaction_policy_id"] != "workspace-strict/v1" {
		t.Fatalf("redaction_policy_id=%v, want workspace-strict/v1", metadata["redaction_policy_id"])
	}
}

func TestBuildTraceRecordPIIScopeCanDisableRedactionForSpecificKey(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = config.PIIModeRedactStorage
	cfg.PII.PolicyID = "global/v1"
	cfg.PII.Scopes = []config.PIIScopeConfig{
		{
			Match: config.PIIScopeMatchConfig{
				KeyID:       "key-dev",
				Provider:    "openai",
				RoutePrefix: "/openai/v1/chat",
			},
			Mode:     config.PIIModeOff,
			PolicyID: "key-dev/off",
		},
	}

	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/openai/v1/chat/completions",
		StatusCode:     http.StatusOK,
		GatewayKeyID:   "key-dev",
		RequestHeaders: http.Header{"Content-Type": {"application/json"}},
		RequestBody:    []byte(`{"email":"alice@example.com"}`),
		ResponseBody:   []byte(`{"ok":true}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.RequestBody != `{"email":"alice@example.com"}` {
		t.Fatalf("request body=%q, want unchanged under scoped off mode", record.RequestBody)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["redaction_mode"] != config.PIIModeOff {
		t.Fatalf("redaction_mode=%v, want %q", metadata["redaction_mode"], config.PIIModeOff)
	}
	if metadata["redaction_policy_id"] != "key-dev/off" {
		t.Fatalf("redaction_policy_id=%v, want key-dev/off", metadata["redaction_policy_id"])
	}
}

func TestBuildTraceRecordPIIStageControlsBodyRedaction(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = config.PIIModeRedactStorage
	cfg.PII.Stages.RequestBody = false
	cfg.PII.Stages.ResponseBody = true

	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/openai/v1/chat/completions",
		StatusCode:     http.StatusOK,
		RequestHeaders: http.Header{"Content-Type": {"application/json"}},
		RequestBody:    []byte(`{"email":"alice@example.com"}`),
		ResponseBody:   []byte(`{"email":"bob@example.com"}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.RequestBody != `{"email":"alice@example.com"}` {
		t.Fatalf("request body=%q, want unchanged", record.RequestBody)
	}
	if strings.Contains(record.ResponseBody, "bob@example.com") {
		t.Fatalf("response body=%q, want redacted response body", record.ResponseBody)
	}
}

func TestBuildTraceRecordSetsRedactionTruncatedMetadata(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = config.PIIModeRedactStorage

	exchange := &proxy.CapturedExchange{
		Method:               http.MethodPost,
		Path:                 "/openai/v1/chat/completions",
		StatusCode:           http.StatusOK,
		RequestHeaders:       http.Header{"Content-Type": {"application/json"}},
		RequestBody:          []byte(`{"email":"alice@example.com"}`),
		RequestBodyTruncated: true,
		ResponseBody:         []byte(`{"ok":true}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)

	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["redaction_truncated"] != true {
		t.Fatalf("redaction_truncated=%v, want true", metadata["redaction_truncated"])
	}
}

func TestBuildTraceRecordRedactStorageDropsBodiesOnRedactionError(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = config.PIIModeRedactStorage

	exchange := &proxy.CapturedExchange{
		Method:         http.MethodPost,
		Path:           "/openai/v1/chat/completions",
		StatusCode:     http.StatusOK,
		RequestHeaders: http.Header{"Content-Type": {"text/plain"}},
		RequestBody:    []byte{0xff, 0xfe, 0xfd},
		ResponseBody:   []byte(`{"ok":true}`),
	}

	record := buildTraceRecord(cfg, providers.DefaultRegistry(), exchange)
	if record.RequestBody != "" || record.ResponseBody != "" {
		t.Fatalf("expected storage bodies dropped on redaction error, got request=%q response=%q", record.RequestBody, record.ResponseBody)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(record.Metadata), &metadata); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if metadata["redaction_storage_drop"] != true {
		t.Fatalf("redaction_storage_drop=%v, want true", metadata["redaction_storage_drop"])
	}
	if metadata["redaction_failure_semantics"] != "storage_drop_continue_proxy" {
		t.Fatalf(
			"redaction_failure_semantics=%v, want storage_drop_continue_proxy",
			metadata["redaction_failure_semantics"],
		)
	}
}

func headerValueIgnoreCase(headers map[string][]string, name string) string {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}
	return ""
}
