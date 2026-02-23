package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/observability"
	"github.com/ongoingai/gateway/internal/pathutil"
	"github.com/ongoingai/gateway/internal/providers"
	"github.com/ongoingai/gateway/internal/proxy"
	"github.com/ongoingai/gateway/internal/trace"
)

var (
	emailPIIPattern = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	phonePIIPattern = regexp.MustCompile(`\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b`)
	ssnPIIPattern   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// Token-like PII pattern composed from shared credential regexes in
	// internal/observability/sanitize.go to prevent pattern drift.
	tokenPIIPattern = regexp.MustCompile(observability.TokenPrefixPattern.String() + `|` + observability.JWTPattern.String())
)

const (
	lineageTraceGroupHeader       = "X-OngoingAI-Trace-Group-ID"
	lineageThreadHeader           = "X-OngoingAI-Thread-ID"
	lineageRunHeader              = "X-OngoingAI-Run-ID"
	lineageParentCheckpointHeader = "X-OngoingAI-Parent-Checkpoint-ID"
	lineageCheckpointSeqHeader    = "X-OngoingAI-Checkpoint-Seq"
)

type redactionSummary struct {
	applied bool
	counts  map[string]int
}

type lineageContext struct {
	groupID            string
	threadID           string
	runID              string
	parentCheckpointID string
	checkpointSeq      int
	checkpointSeqSet   bool
}

func newRedactionSummary() redactionSummary {
	return redactionSummary{
		counts: make(map[string]int),
	}
}

func (summary *redactionSummary) add(kind string, count int) {
	if summary == nil || count <= 0 {
		return
	}
	summary.applied = true
	summary.counts[kind] += count
}

func (summary *redactionSummary) merge(other redactionSummary) {
	if summary == nil {
		return
	}
	if other.applied {
		summary.applied = true
	}
	for kind, count := range other.counts {
		summary.counts[kind] += count
	}
}

func buildTraceRecord(cfg config.Config, registry *providers.Registry, exchange *proxy.CapturedExchange) *trace.Trace {
	now := time.Now().UTC()
	traceID := newTraceID()

	provider := detectProvider(cfg, exchange.Path)
	model := extractModel(exchange.RequestBody, exchange.ResponseBody, exchange.Streaming)
	inputTokens, outputTokens, totalTokens := extractUsage(exchange.ResponseBody, exchange.Streaming)
	workspaceID := nonEmpty(exchange.GatewayWorkspaceID, "default")
	orgID := nonEmpty(exchange.GatewayOrgID, "default")
	lineage := extractLineageContext(exchange.RequestHeaders)
	piiPolicy := cfg.ResolvePIIPolicy(config.PIIScopeInput{
		OrgID:       orgID,
		WorkspaceID: workspaceID,
		KeyID:       exchange.GatewayKeyID,
		Provider:    provider,
		Route:       exchange.Path,
	})
	piiMode := piiPolicy.Mode

	requestHeaders, requestHeaderRedactions := redactHeaders(exchange.RequestHeaders, piiPolicy, piiPolicy.Stages.RequestHeaders)
	responseHeaders, responseHeaderRedactions := redactHeaders(exchange.ResponseHeaders, piiPolicy, piiPolicy.Stages.ResponseHeaders)
	apiKey := extractAPIKey(exchange.RequestHeaders)
	apiKeyHash := ""
	last4 := ""
	if apiKey != "" {
		apiKeyHash = hashSHA256(apiKey)
		last4 = tail(apiKey, 4)
	}

	policyID := strings.TrimSpace(piiPolicy.PolicyID)
	if policyID == "" {
		policyID = "default/v1"
	}
	summary := newRedactionSummary()
	summary.merge(requestHeaderRedactions)
	summary.merge(responseHeaderRedactions)

	requestBody := ""
	responseBody := ""
	redactionDroppedBodies := false
	redactionTruncated := false
	if cfg.Tracing.CaptureBodies {
		requestBody = string(exchange.RequestBody)
		responseBody = string(exchange.ResponseBody)

		if piiMode != config.PIIModeOff {
			var err error

			if piiPolicy.Stages.RequestBody {
				requestBody, err = redactBodyForStorage(exchange.RequestBody, piiPolicy, workspaceID, &summary)
				if err != nil {
					redactionDroppedBodies = true
				}
				if exchange.RequestBodyTruncated {
					redactionTruncated = true
				}
			}

			if !redactionDroppedBodies && piiPolicy.Stages.ResponseBody {
				responseBody, err = redactBodyForStorage(exchange.ResponseBody, piiPolicy, workspaceID, &summary)
				if err != nil {
					redactionDroppedBodies = true
				}
				if exchange.ResponseBodyTruncated {
					redactionTruncated = true
				}
			}

			if redactionDroppedBodies {
				// In storage redaction mode, never persist raw captured bodies if
				// redaction fails for either side.
				requestBody = ""
				responseBody = ""
			}
		}
	}

	estimatedCostUSD := 0.0
	if registry != nil {
		if providerAdapter, ok := registry.Get(provider); ok {
			estimatedCostUSD = providerAdapter.EstimateCost(model, inputTokens, outputTokens)
		}
	}

	metadata := map[string]any{
		"streaming":             exchange.Streaming,
		"stream_chunks":         exchange.StreamChunks,
		"redaction_mode":        piiMode,
		"redaction_policy_id":   policyID,
		"redaction_applied":     summary.applied,
		"lineage_checkpoint_id": traceID,
		"lineage_immutable":     true,
	}
	if lineage.groupID != "" {
		metadata["lineage_group_id"] = lineage.groupID
	}
	if lineage.threadID != "" {
		metadata["lineage_thread_id"] = lineage.threadID
	}
	if lineage.runID != "" {
		metadata["lineage_run_id"] = lineage.runID
	}
	if lineage.parentCheckpointID != "" {
		metadata["lineage_parent_checkpoint_id"] = lineage.parentCheckpointID
	}
	if lineage.checkpointSeqSet {
		metadata["lineage_checkpoint_seq"] = lineage.checkpointSeq
	}
	if len(summary.counts) > 0 {
		metadata["redaction_counts"] = summary.counts
	}
	if redactionTruncated {
		metadata["redaction_truncated"] = true
	}
	if redactionDroppedBodies {
		metadata["redaction_storage_drop"] = true
		metadata["redaction_failure_semantics"] = "storage_drop_continue_proxy"
	}
	if last4 != "" {
		metadata["api_key_last4"] = last4
	}
	if exchange.GatewayKeyID != "" {
		metadata["gateway_key_id"] = exchange.GatewayKeyID
	}
	if exchange.GatewayTeam != "" {
		metadata["team"] = exchange.GatewayTeam
	}
	if exchange.GatewayRole != "" {
		metadata["role"] = exchange.GatewayRole
	}
	if exchange.GatewayOrgID != "" {
		metadata["org_id"] = exchange.GatewayOrgID
	}
	if exchange.GatewayWorkspaceID != "" {
		metadata["workspace_id"] = exchange.GatewayWorkspaceID
	}
	if correlationID := strings.TrimSpace(exchange.CorrelationID); correlationID != "" {
		metadata["correlation_id"] = correlationID
	}

	metadataJSON, _ := json.Marshal(metadata)
	timeToFirstTokenUS, timeToFirstTokenMS := normalizeTTFT(exchange.TimeToFirstTokenUS, exchange.TimeToFirstTokenMS)

	return &trace.Trace{
		ID:                 traceID,
		TraceGroupID:       lineage.groupID,
		Timestamp:          now,
		OrgID:              nonEmpty(exchange.GatewayOrgID, "default"),
		WorkspaceID:        nonEmpty(exchange.GatewayWorkspaceID, "default"),
		GatewayKeyID:       exchange.GatewayKeyID,
		Provider:           provider,
		Model:              nonEmpty(model, "unknown"),
		RequestMethod:      nonEmpty(exchange.Method, "UNKNOWN"),
		RequestPath:        nonEmpty(exchange.Path, "/"),
		RequestHeaders:     headersToJSON(requestHeaders),
		RequestBody:        requestBody,
		ResponseStatus:     exchange.StatusCode,
		ResponseHeaders:    headersToJSON(responseHeaders),
		ResponseBody:       responseBody,
		InputTokens:        inputTokens,
		OutputTokens:       outputTokens,
		TotalTokens:        totalTokens,
		LatencyMS:          exchange.DurationMS,
		TimeToFirstTokenMS: timeToFirstTokenMS,
		TimeToFirstTokenUS: timeToFirstTokenUS,
		APIKeyHash:         apiKeyHash,
		EstimatedCostUSD:   estimatedCostUSD,
		Metadata:           string(metadataJSON),
		CreatedAt:          now,
	}
}

func extractLineageContext(headers http.Header) lineageContext {
	seq, seqSet := parseLineageCheckpointSeq(headers.Get(lineageCheckpointSeqHeader))
	return lineageContext{
		groupID:            strings.TrimSpace(headers.Get(lineageTraceGroupHeader)),
		threadID:           strings.TrimSpace(headers.Get(lineageThreadHeader)),
		runID:              strings.TrimSpace(headers.Get(lineageRunHeader)),
		parentCheckpointID: strings.TrimSpace(headers.Get(lineageParentCheckpointHeader)),
		checkpointSeq:      seq,
		checkpointSeqSet:   seqSet,
	}
}

func parseLineageCheckpointSeq(raw string) (int, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, false
	}
	return parsed, true
}

func normalizeTTFT(us, ms int64) (int64, int64) {
	if us > 0 {
		if ms <= 0 {
			ms = (us + 999) / 1000
		}
		return us, ms
	}

	if ms > 0 {
		return ms * 1000, ms
	}

	return 0, 0
}

func detectProvider(cfg config.Config, path string) string {
	if pathutil.HasPathPrefix(path, cfg.Providers.OpenAI.Prefix) {
		return "openai"
	}
	if pathutil.HasPathPrefix(path, cfg.Providers.Anthropic.Prefix) {
		return "anthropic"
	}
	return "unknown"
}

func extractModel(requestBody, responseBody []byte, streaming bool) string {
	if model := extractModelFromJSON(requestBody); model != "" {
		return model
	}
	if streaming {
		return extractModelFromSSE(responseBody)
	}
	return extractModelFromJSON(responseBody)
}

func extractModelFromJSON(body []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return extractModelFromPayload(payload)
}

func extractModelFromSSE(body []byte) string {
	for _, payload := range ssePayloads(body) {
		if model := extractModelFromJSON(payload); model != "" {
			return model
		}
	}
	return ""
}

func extractUsage(body []byte, streaming bool) (int, int, int) {
	if streaming {
		return extractUsageFromSSE(body)
	}
	return extractUsageFromJSON(body)
}

func extractUsageFromSSE(body []byte) (int, int, int) {
	input, output := 0, 0
	total := 0
	hasExplicitTotal := false
	for _, payload := range ssePayloads(body) {
		nextInput, nextOutput, nextTotal := extractUsageFromJSON(payload)
		if nextInput > 0 {
			input = nextInput
		}
		if nextOutput > 0 {
			output = nextOutput
		}
		if nextTotal > 0 {
			total = nextTotal
			hasExplicitTotal = true
		}
	}
	if !hasExplicitTotal {
		total = input + output
	} else if total < input+output {
		// Streaming providers can emit partial usage updates where total is
		// stale relative to later input/output updates.
		total = input + output
	}
	return input, output, total
}

func extractUsageFromJSON(body []byte) (int, int, int) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, 0, 0
	}

	usageObj := extractUsageObject(payload)
	if usageObj == nil {
		return 0, 0, 0
	}

	input := firstInt(usageObj, "prompt_tokens", "input_tokens")
	output := firstInt(usageObj, "completion_tokens", "output_tokens")
	total := firstInt(usageObj, "total_tokens")
	if total == 0 {
		total = input + output
	}

	return input, output, total
}

func extractModelFromPayload(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	if model, ok := payload["model"].(string); ok {
		model = strings.TrimSpace(model)
		if model != "" {
			return model
		}
	}

	// Anthropic message_start events put model under message.model.
	if message, ok := payload["message"].(map[string]any); ok {
		if model, ok := message["model"].(string); ok {
			model = strings.TrimSpace(model)
			if model != "" {
				return model
			}
		}
	}
	return ""
}

func extractUsageObject(payload map[string]any) map[string]any {
	if payload == nil {
		return nil
	}
	if usageObj, ok := payload["usage"].(map[string]any); ok {
		return usageObj
	}
	// Anthropic message_start events can place usage under message.usage.
	if message, ok := payload["message"].(map[string]any); ok {
		if usageObj, ok := message["usage"].(map[string]any); ok {
			return usageObj
		}
	}
	return nil
}

func ssePayloads(body []byte) [][]byte {
	lines := strings.Split(string(body), "\n")
	payloads := make([][]byte, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		payloads = append(payloads, []byte(payload))
	}
	return payloads
}

func firstInt(values map[string]any, keys ...string) int {
	for _, key := range keys {
		v, ok := values[key]
		if !ok {
			continue
		}
		switch typed := v.(type) {
		case float64:
			return int(typed)
		case int:
			return typed
		}
	}
	return 0
}

func redactHeaders(headers http.Header, piiCfg config.PIIConfig, includeCustomDenylist bool) (http.Header, redactionSummary) {
	summary := newRedactionSummary()
	cloned := make(http.Header, len(headers))
	denylist := headerDenylist(piiCfg, includeCustomDenylist)

	for key, values := range headers {
		copied := make([]string, len(values))
		copy(copied, values)

		if _, ok := denylist[strings.ToLower(strings.TrimSpace(key))]; ok {
			copied = []string{"[REDACTED]"}
			if len(values) == 0 {
				summary.add("header", 1)
			} else {
				summary.add("header", len(values))
			}
		}

		cloned[key] = copied
	}
	return cloned, summary
}

func redactBodyForStorage(body []byte, piiCfg config.PIIConfig, workspaceID string, summary *redactionSummary) (string, error) {
	if len(body) == 0 {
		return "", nil
	}

	var payload any
	if err := json.Unmarshal(body, &payload); err == nil {
		denylist := normalizedDenylist(piiCfg.Body.KeyDenylist)
		redacted := redactJSONValue(payload, piiCfg, workspaceID, summary, denylist)
		marshaled, marshalErr := json.Marshal(redacted)
		if marshalErr != nil {
			return "", fmt.Errorf("marshal redacted body: %w", marshalErr)
		}
		return string(marshaled), nil
	}
	if !utf8.Valid(body) {
		return "", fmt.Errorf("non-json body is not valid utf-8")
	}

	return redactStringPII(string(body), piiCfg, workspaceID, summary), nil
}

func redactJSONValue(
	value any,
	piiCfg config.PIIConfig,
	workspaceID string,
	summary *redactionSummary,
	fieldDenylist []string,
) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, raw := range typed {
			if shouldRedactFieldName(key, fieldDenylist) {
				out[key] = redactionPlaceholder(
					"FIELD",
					stringifyForHash(raw),
					workspaceID,
					piiCfg.Replacement,
				)
				if summary != nil {
					summary.add("field_name", 1)
				}
				continue
			}
			out[key] = redactJSONValue(raw, piiCfg, workspaceID, summary, fieldDenylist)
		}
		return out
	case []any:
		for i := range typed {
			typed[i] = redactJSONValue(typed[i], piiCfg, workspaceID, summary, fieldDenylist)
		}
		return typed
	case string:
		return redactStringPII(typed, piiCfg, workspaceID, summary)
	default:
		return value
	}
}

func redactStringPII(value string, piiCfg config.PIIConfig, workspaceID string, summary *redactionSummary) string {
	redacted := value
	if piiCfg.Detectors.Email {
		redacted = replacePatternMatches(redacted, emailPIIPattern, "EMAIL", "email", piiCfg, workspaceID, summary)
	}
	if piiCfg.Detectors.Phone {
		redacted = replacePatternMatches(redacted, phonePIIPattern, "PHONE", "phone", piiCfg, workspaceID, summary)
	}
	if piiCfg.Detectors.SSN {
		redacted = replacePatternMatches(redacted, ssnPIIPattern, "SSN", "ssn", piiCfg, workspaceID, summary)
	}
	if piiCfg.Detectors.TokenLike {
		redacted = replacePatternMatches(redacted, tokenPIIPattern, "TOKEN", "token_like", piiCfg, workspaceID, summary)
	}
	return redacted
}

func replacePatternMatches(
	input string,
	pattern *regexp.Regexp,
	placeholderType string,
	detectorKey string,
	piiCfg config.PIIConfig,
	workspaceID string,
	summary *redactionSummary,
) string {
	if pattern == nil || input == "" {
		return input
	}

	matchCount := 0
	redacted := pattern.ReplaceAllStringFunc(input, func(match string) string {
		matchCount++
		return redactionPlaceholder(placeholderType, match, workspaceID, piiCfg.Replacement)
	})
	if summary != nil && matchCount > 0 {
		summary.add(detectorKey, matchCount)
	}
	return redacted
}

func headerDenylist(piiCfg config.PIIConfig, includeCustom bool) map[string]struct{} {
	denylist := map[string]struct{}{
		"authorization":           {},
		"cookie":                  {},
		"set-cookie":              {},
		"x-api-key":               {},
		"x-ongoingai-gateway-key": {},
	}
	if includeCustom {
		for _, key := range piiCfg.Headers.Denylist {
			normalized := strings.ToLower(strings.TrimSpace(key))
			if normalized == "" {
				continue
			}
			denylist[normalized] = struct{}{}
		}
	}
	return denylist
}

func normalizedDenylist(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		item := normalizePIIFieldName(value)
		if item == "" {
			continue
		}
		normalized = append(normalized, item)
	}
	return normalized
}

func shouldRedactFieldName(key string, denylist []string) bool {
	if len(denylist) == 0 {
		return false
	}
	normalized := normalizePIIFieldName(key)
	for _, item := range denylist {
		if normalized == item || strings.Contains(normalized, item) {
			return true
		}
	}
	return false
}

func normalizePIIFieldName(value string) string {
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	return strings.ToLower(strings.TrimSpace(replacer.Replace(value)))
}

func redactionPlaceholder(
	placeholderType string,
	rawValue string,
	workspaceID string,
	replacement config.PIIReplacementConfig,
) string {
	format := strings.TrimSpace(replacement.Format)
	if format == "" {
		format = "[{type}_REDACTED:{hash}]"
	}

	hash := hashPIIValue(rawValue, workspaceID, replacement.HashSalt)
	value := strings.ReplaceAll(format, "{type}", strings.ToUpper(strings.TrimSpace(placeholderType)))
	value = strings.ReplaceAll(value, "{hash}", hash)
	return value
}

func hashPIIValue(value, workspaceID, hashSalt string) string {
	sum := sha256.Sum256([]byte(workspaceID + ":" + hashSalt + ":" + value))
	return hex.EncodeToString(sum[:8])
}

func stringifyForHash(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(data)
	}
}

func headersToJSON(headers http.Header) string {
	if headers == nil {
		return "{}"
	}
	data, err := json.Marshal(headers)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func extractAPIKey(headers http.Header) string {
	auth := strings.TrimSpace(headers.Get("Authorization"))
	if auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return strings.TrimSpace(auth[7:])
		}
		return auth
	}
	return strings.TrimSpace(headers.Get("X-API-Key"))
}

func hashSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func tail(value string, size int) string {
	if size <= 0 || len(value) <= size {
		return value
	}
	return value[len(value)-size:]
}

func newTraceID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return fmt.Sprintf("trace-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes[:])
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
