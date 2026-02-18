package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/trace"
)

const (
	defaultDebugFormat = "text"
	defaultDebugLimit  = 200
	maxDebugLimit      = 500
)

type debugDocument struct {
	GeneratedAt     time.Time            `json:"generated_at"`
	SourceTraceID   string               `json:"source_trace_id"`
	SourceTimestamp time.Time            `json:"source_timestamp"`
	Source          debugTraceCheckpoint `json:"source"`
	Chain           debugChain           `json:"chain"`
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

func runDebug(args []string, out io.Writer, errOut io.Writer) int {
	explicitLast := false
	if len(args) > 0 && strings.TrimSpace(args[0]) == "last" {
		explicitLast = true
		args = args[1:]
	}

	flagSet := flag.NewFlagSet("debug", flag.ContinueOnError)
	flagSet.SetOutput(errOut)

	configPath := flagSet.String("config", defaultConfigPath, "Path to config file")
	traceID := flagSet.String("trace-id", "", "Trace ID to debug (defaults to latest trace)")
	format := flagSet.String("format", defaultDebugFormat, "Output format: text or json")
	limit := flagSet.Int("limit", defaultDebugLimit, "Maximum checkpoints to include (1-500)")
	includeHeaders := flagSet.Bool("include-headers", false, "Include request/response headers")
	includeBodies := flagSet.Bool("include-bodies", false, "Include request/response bodies")

	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if flagSet.NArg() > 1 {
		fmt.Fprintln(errOut, "debug accepts at most one positional argument: last")
		return 2
	}
	if flagSet.NArg() == 1 && strings.TrimSpace(flagSet.Arg(0)) != "last" {
		fmt.Fprintln(errOut, `debug positional argument must be "last"`)
		return 2
	}
	if flagSet.NArg() == 1 && strings.TrimSpace(flagSet.Arg(0)) == "last" {
		explicitLast = true
	}

	normalizedFormat := strings.ToLower(strings.TrimSpace(*format))
	if normalizedFormat == "" {
		normalizedFormat = defaultDebugFormat
	}
	if normalizedFormat != "text" && normalizedFormat != "json" {
		fmt.Fprintf(errOut, "invalid debug format %q: expected text or json\n", *format)
		return 2
	}
	if *limit <= 0 || *limit > maxDebugLimit {
		fmt.Fprintf(errOut, "limit must be between 1 and %d\n", maxDebugLimit)
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(errOut, "failed to load config: %v\n", err)
		return 1
	}
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(errOut, "config is invalid: %v\n", err)
		return 1
	}

	store, err := openReportTraceStore(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "failed to initialize trace store: %v\n", err)
		return 1
	}
	if closer, ok := store.(interface{ Close() error }); ok {
		defer func() {
			if err := closer.Close(); err != nil {
				fmt.Fprintf(errOut, "warning: failed to close trace store: %v\n", err)
			}
		}()
	}

	resolvedTraceID := strings.TrimSpace(*traceID)
	if explicitLast {
		resolvedTraceID = ""
	}
	source, err := resolveDebugSourceTrace(context.Background(), store, resolvedTraceID)
	if err != nil {
		if errors.Is(err, trace.ErrNotFound) {
			fmt.Fprintln(errOut, "trace not found")
			return 1
		}
		fmt.Fprintf(errOut, "failed to resolve source trace: %v\n", err)
		return 1
	}
	if source == nil {
		fmt.Fprintln(errOut, "no traces found in storage")
		return 1
	}

	document, err := buildDebugDocument(context.Background(), store, source, *limit, *includeHeaders, *includeBodies)
	if err != nil {
		fmt.Fprintf(errOut, "failed to build debug chain: %v\n", err)
		return 1
	}

	if err := writeDebug(out, normalizedFormat, document, *includeHeaders, *includeBodies); err != nil {
		fmt.Fprintf(errOut, "failed to write debug output: %v\n", err)
		return 1
	}

	return 0
}

func resolveDebugSourceTrace(ctx context.Context, store trace.TraceStore, traceID string) (*trace.Trace, error) {
	if traceID != "" {
		return store.GetTrace(ctx, traceID)
	}

	result, err := store.QueryTraces(ctx, trace.TraceFilter{Limit: 1})
	if err != nil {
		return nil, err
	}
	if result == nil || len(result.Items) == 0 {
		return nil, nil
	}
	return result.Items[0], nil
}

func buildDebugDocument(
	ctx context.Context,
	store trace.TraceStore,
	source *trace.Trace,
	limit int,
	includeHeaders bool,
	includeBodies bool,
) (debugDocument, error) {
	sourceLineage := extractDebugLineage(source, true)
	filter := trace.TraceFilter{
		TraceGroupID: sourceLineage.GroupID,
		ThreadID:     sourceLineage.ThreadID,
		RunID:        sourceLineage.RunID,
	}

	items := make([]*trace.Trace, 0, limit)
	truncated := false
	if sourceLineage.GroupID != "" || sourceLineage.ThreadID != "" || sourceLineage.RunID != "" {
		var err error
		items, truncated, err = queryDebugChainItems(ctx, store, filter, limit)
		if err != nil {
			return debugDocument{}, err
		}
	}
	if len(items) == 0 {
		items = append(items, source)
	}
	if !containsDebugTraceID(items, source.ID) {
		items = append(items, source)
	}
	sortDebugItems(items)

	checkpoints := make([]debugTraceCheckpoint, 0, len(items))
	for i, item := range items {
		checkpoints = append(checkpoints, toDebugTraceCheckpoint(item, i+1, includeHeaders, includeBodies))
	}

	lineageIdentifier := "(single trace)"
	switch {
	case sourceLineage.GroupID != "":
		lineageIdentifier = "trace_group_id"
	case sourceLineage.ThreadID != "":
		lineageIdentifier = "lineage_thread_id"
	case sourceLineage.RunID != "":
		lineageIdentifier = "lineage_run_id"
	}

	return debugDocument{
		GeneratedAt:     time.Now().UTC(),
		SourceTraceID:   strings.TrimSpace(source.ID),
		SourceTimestamp: debugOrderTime(source),
		Source:          toDebugTraceCheckpoint(source, 0, includeHeaders, includeBodies),
		Chain: debugChain{
			GroupID:           sourceLineage.GroupID,
			ThreadID:          sourceLineage.ThreadID,
			RunID:             sourceLineage.RunID,
			TargetCheckpoint:  strings.TrimSpace(source.ID),
			CheckpointCount:   len(checkpoints),
			Truncated:         truncated,
			Checkpoints:       checkpoints,
			LineageIdentifier: lineageIdentifier,
		},
	}, nil
}

func queryDebugChainItems(ctx context.Context, store trace.TraceStore, filter trace.TraceFilter, totalLimit int) ([]*trace.Trace, bool, error) {
	if totalLimit <= 0 {
		return nil, false, nil
	}
	pageSize := 200
	if pageSize > totalLimit {
		pageSize = totalLimit
	}

	items := make([]*trace.Trace, 0, totalLimit)
	cursor := ""
	truncated := false

	for len(items) < totalLimit {
		filter.Limit = pageSize
		filter.Cursor = cursor
		result, err := store.QueryTraces(ctx, filter)
		if err != nil {
			return nil, false, err
		}
		if result == nil {
			break
		}

		items = append(items, result.Items...)
		if result.NextCursor == "" || len(result.Items) == 0 {
			break
		}
		if len(items) >= totalLimit {
			truncated = true
			break
		}
		cursor = result.NextCursor
	}

	if len(items) > totalLimit {
		items = items[:totalLimit]
		truncated = true
	}

	return items, truncated, nil
}

func sortDebugItems(items []*trace.Trace) {
	sort.SliceStable(items, func(i, j int) bool {
		left := debugOrderTime(items[i])
		right := debugOrderTime(items[j])
		if left.Equal(right) {
			return strings.TrimSpace(items[i].ID) < strings.TrimSpace(items[j].ID)
		}
		return left.Before(right)
	})
}

func debugOrderTime(item *trace.Trace) time.Time {
	if item == nil {
		return time.Time{}
	}
	if !item.CreatedAt.IsZero() {
		return item.CreatedAt.UTC()
	}
	return item.Timestamp.UTC()
}

func containsDebugTraceID(items []*trace.Trace, traceID string) bool {
	needle := strings.TrimSpace(traceID)
	for _, item := range items {
		if strings.TrimSpace(item.ID) == needle {
			return true
		}
	}
	return false
}

func toDebugTraceCheckpoint(item *trace.Trace, step int, includeHeaders bool, includeBodies bool) debugTraceCheckpoint {
	if item == nil {
		return debugTraceCheckpoint{Step: step}
	}
	metadata := decodeDebugMetadataMap(item.Metadata)
	checkpoint := debugTraceCheckpoint{
		Step:               step,
		ID:                 strings.TrimSpace(item.ID),
		Timestamp:          item.Timestamp.UTC(),
		CreatedAt:          item.CreatedAt.UTC(),
		Provider:           strings.TrimSpace(item.Provider),
		Model:              strings.TrimSpace(item.Model),
		RequestMethod:      strings.TrimSpace(item.RequestMethod),
		RequestPath:        strings.TrimSpace(item.RequestPath),
		ResponseStatus:     item.ResponseStatus,
		InputTokens:        item.InputTokens,
		OutputTokens:       item.OutputTokens,
		TotalTokens:        item.TotalTokens,
		EstimatedCostUSD:   item.EstimatedCostUSD,
		LatencyMS:          item.LatencyMS,
		TimeToFirstTokenMS: item.TimeToFirstTokenMS,
		TimeToFirstTokenUS: item.TimeToFirstTokenUS,
		Lineage:            extractDebugLineage(item, true),
		Metadata:           metadata,
	}
	if includeHeaders {
		checkpoint.RequestHeaders = item.RequestHeaders
		checkpoint.ResponseHeaders = item.ResponseHeaders
	}
	if includeBodies {
		checkpoint.RequestBody = item.RequestBody
		checkpoint.ResponseBody = item.ResponseBody
	}
	return checkpoint
}

func extractDebugLineage(item *trace.Trace, includeDefaults bool) debugLineage {
	if item == nil {
		return debugLineage{}
	}
	metadata := decodeDebugMetadataMap(item.Metadata)
	lineage := debugLineage{
		GroupID: strings.TrimSpace(item.TraceGroupID),
	}

	immutableSet := false
	if value := debugMetadataString(metadata, "lineage_group_id"); value != "" {
		lineage.GroupID = value
	}
	lineage.ThreadID = debugMetadataString(metadata, "lineage_thread_id")
	lineage.RunID = debugMetadataString(metadata, "lineage_run_id")
	lineage.CheckpointID = debugMetadataString(metadata, "lineage_checkpoint_id")
	lineage.ParentCheckpointID = debugMetadataString(metadata, "lineage_parent_checkpoint_id")
	if seq, ok := debugMetadataInt64(metadata, "lineage_checkpoint_seq"); ok {
		lineage.CheckpointSeq = seq
	}
	if immutable, ok := debugMetadataBool(metadata, "lineage_immutable"); ok {
		lineage.Immutable = immutable
		immutableSet = true
	}

	if includeDefaults {
		if lineage.CheckpointID == "" {
			lineage.CheckpointID = strings.TrimSpace(item.ID)
		}
		if !immutableSet {
			lineage.Immutable = true
		}
	}

	return lineage
}

func decodeDebugMetadataMap(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	decoded := make(map[string]any)
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return map[string]any{"raw": raw}
	}
	return decoded
}

func debugMetadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	raw, ok := metadata[key]
	if !ok {
		return ""
	}
	value, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func debugMetadataInt64(metadata map[string]any, key string) (int64, bool) {
	if len(metadata) == 0 {
		return 0, false
	}
	raw, ok := metadata[key]
	if !ok {
		return 0, false
	}

	switch typed := raw.(type) {
	case float64:
		return int64(typed), true
	case float32:
		return int64(typed), true
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func debugMetadataBool(metadata map[string]any, key string) (bool, bool) {
	if len(metadata) == 0 {
		return false, false
	}
	raw, ok := metadata[key]
	if !ok {
		return false, false
	}
	switch typed := raw.(type) {
	case bool:
		return typed, true
	case string:
		value := strings.ToLower(strings.TrimSpace(typed))
		if value == "true" {
			return true, true
		}
		if value == "false" {
			return false, true
		}
	}
	return false, false
}

func writeDebug(out io.Writer, format string, document debugDocument, includeHeaders bool, includeBodies bool) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(document)
	default:
		return writeDebugText(out, document, includeHeaders, includeBodies)
	}
}

func writeDebugText(out io.Writer, document debugDocument, includeHeaders bool, includeBodies bool) error {
	fmt.Fprintln(out, "OngoingAI Debug Chain")

	meta := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(meta, "Generated at\t%s\n", document.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(meta, "Source trace\t%s\n", document.SourceTraceID)
	fmt.Fprintf(meta, "Source time\t%s\n", document.SourceTimestamp.Format(time.RFC3339))
	fmt.Fprintf(meta, "Source provider\t%s\n", reportValueOr(document.Source.Provider, "(unknown)"))
	fmt.Fprintf(meta, "Source model\t%s\n", reportValueOr(document.Source.Model, "(unknown)"))
	fmt.Fprintf(meta, "Source path\t%s\n", reportValueOr(document.Source.RequestPath, "(unknown)"))
	fmt.Fprintf(meta, "Source status\t%d\n", document.Source.ResponseStatus)
	fmt.Fprintf(meta, "Chain identifier\t%s\n", reportValueOr(document.Chain.LineageIdentifier, "(single trace)"))
	fmt.Fprintf(meta, "Chain group_id\t%s\n", reportValueOr(document.Chain.GroupID, "(none)"))
	fmt.Fprintf(meta, "Chain thread_id\t%s\n", reportValueOr(document.Chain.ThreadID, "(none)"))
	fmt.Fprintf(meta, "Chain run_id\t%s\n", reportValueOr(document.Chain.RunID, "(none)"))
	fmt.Fprintf(meta, "Chain checkpoints\t%d\n", document.Chain.CheckpointCount)
	fmt.Fprintf(meta, "Truncated\t%t\n", document.Chain.Truncated)
	if err := meta.Flush(); err != nil {
		return err
	}

	for _, checkpoint := range document.Chain.Checkpoints {
		fmt.Fprintf(out, "\nStep %d: %s\n", checkpoint.Step, checkpoint.ID)
		step := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(step, "time\t%s\n", debugCheckpointTime(checkpoint).Format(time.RFC3339))
		fmt.Fprintf(step, "provider\t%s\n", reportValueOr(checkpoint.Provider, "(unknown)"))
		fmt.Fprintf(step, "model\t%s\n", reportValueOr(checkpoint.Model, "(unknown)"))
		fmt.Fprintf(step, "request\t%s %s\n", reportValueOr(checkpoint.RequestMethod, "UNKNOWN"), reportValueOr(checkpoint.RequestPath, "(unknown)"))
		fmt.Fprintf(step, "response_status\t%d\n", checkpoint.ResponseStatus)
		fmt.Fprintf(step, "tokens\tinput=%d output=%d total=%d\n", checkpoint.InputTokens, checkpoint.OutputTokens, checkpoint.TotalTokens)
		fmt.Fprintf(step, "estimated_cost_usd\t%.6f\n", checkpoint.EstimatedCostUSD)
		fmt.Fprintf(step, "latency_ms\t%d\n", checkpoint.LatencyMS)
		fmt.Fprintf(step, "ttft_ms\t%d\n", checkpoint.TimeToFirstTokenMS)
		fmt.Fprintf(step, "lineage\tcheckpoint=%s parent=%s seq=%d immutable=%t\n", reportValueOr(checkpoint.Lineage.CheckpointID, "(none)"), reportValueOr(checkpoint.Lineage.ParentCheckpointID, "(none)"), checkpoint.Lineage.CheckpointSeq, checkpoint.Lineage.Immutable)
		if checkpoint.Metadata != nil {
			if encoded, err := json.Marshal(checkpoint.Metadata); err == nil {
				fmt.Fprintf(step, "metadata\t%s\n", string(encoded))
			}
		}
		if err := step.Flush(); err != nil {
			return err
		}

		if includeHeaders {
			if strings.TrimSpace(checkpoint.RequestHeaders) != "" {
				fmt.Fprintf(out, "request_headers: %s\n", checkpoint.RequestHeaders)
			}
			if strings.TrimSpace(checkpoint.ResponseHeaders) != "" {
				fmt.Fprintf(out, "response_headers: %s\n", checkpoint.ResponseHeaders)
			}
		}
		if includeBodies {
			if strings.TrimSpace(checkpoint.RequestBody) != "" {
				fmt.Fprintf(out, "request_body: %s\n", checkpoint.RequestBody)
			}
			if strings.TrimSpace(checkpoint.ResponseBody) != "" {
				fmt.Fprintf(out, "response_body: %s\n", checkpoint.ResponseBody)
			}
		}
	}

	return nil
}

func debugCheckpointTime(item debugTraceCheckpoint) time.Time {
	if !item.CreatedAt.IsZero() {
		return item.CreatedAt.UTC()
	}
	return item.Timestamp.UTC()
}
