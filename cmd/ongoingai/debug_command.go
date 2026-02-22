package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

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
	SchemaVersion  string               `json:"schema_version"`
	GeneratedAt    time.Time            `json:"generated_at"`
	SelectionMode  string               `json:"selection_mode"`
	Selection      debugBundleSelection `json:"selection"`
	Limit          int                  `json:"limit"`
	IncludeDiff    bool                 `json:"include_diff"`
	IncludeBodies  bool                 `json:"include_bodies"`
	IncludeHeaders bool                 `json:"include_headers"`
	Chain          debugBundleChain     `json:"chain"`
	Files          []debugBundleFile    `json:"files"`
}

type debugBundleSelection struct {
	TraceID      string `json:"trace_id,omitempty"`
	TraceGroupID string `json:"trace_group_id,omitempty"`
	ThreadID     string `json:"thread_id,omitempty"`
	RunID        string `json:"run_id,omitempty"`
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
	traceGroupID := flagSet.String("trace-group-id", "", "Trace group ID filter")
	threadID := flagSet.String("thread-id", "", "Thread ID filter")
	runID := flagSet.String("run-id", "", "Run ID filter")
	format := flagSet.String("format", defaultDebugFormat, "Output format: text or json")
	limit := flagSet.Int("limit", defaultDebugLimit, "Maximum checkpoints to include (1-500)")
	includeDiff := flagSet.Bool("diff", false, "Include redaction-safe checkpoint diffs")
	bundleOut := flagSet.String("bundle-out", "", "Directory to write debug bundle (debug-chain.json + manifest.json)")
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

	selection := debugSelection{
		TraceID:      strings.TrimSpace(*traceID),
		TraceGroupID: strings.TrimSpace(*traceGroupID),
		ThreadID:     strings.TrimSpace(*threadID),
		RunID:        strings.TrimSpace(*runID),
	}
	if explicitLast && (selection.TraceID != "" || selection.hasChainFilter()) {
		fmt.Fprintln(errOut, `debug "last" cannot be combined with --trace-id, --trace-group-id, --thread-id, or --run-id`)
		return 2
	}
	if selection.TraceID != "" && selection.hasChainFilter() {
		fmt.Fprintln(errOut, "trace-id cannot be combined with trace-group-id/thread-id/run-id filters")
		return 2
	}

	normalizedFormat, err := normalizeTextJSONFormat("debug", *format, defaultDebugFormat)
	if err != nil {
		fmt.Fprintln(errOut, err.Error())
		return 2
	}
	if *limit <= 0 || *limit > maxDebugLimit {
		fmt.Fprintf(errOut, "limit must be between 1 and %d\n", maxDebugLimit)
		return 2
	}

	cfg, stage, err := loadAndValidateConfig(*configPath)
	if err != nil {
		if stage == configStageLoad {
			fmt.Fprintf(errOut, "failed to load config: %v\n", err)
		} else {
			fmt.Fprintf(errOut, "config is invalid: %v\n", err)
		}
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

	if explicitLast {
		selection = debugSelection{}
	}
	source, err := resolveDebugSourceTrace(context.Background(), store, selection)
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

	document, err := buildDebugDocument(context.Background(), store, source, selection, *limit, *includeHeaders, *includeBodies, *includeDiff)
	if err != nil {
		fmt.Fprintf(errOut, "failed to build debug chain: %v\n", err)
		return 1
	}

	if err := writeDebug(out, normalizedFormat, document, *includeHeaders, *includeBodies, *includeDiff); err != nil {
		fmt.Fprintf(errOut, "failed to write debug output: %v\n", err)
		return 1
	}
	if strings.TrimSpace(*bundleOut) != "" {
		manifestPath, err := writeDebugBundle(strings.TrimSpace(*bundleOut), document, selection, *limit, *includeDiff, *includeHeaders, *includeBodies)
		if err != nil {
			fmt.Fprintf(errOut, "failed to write debug bundle: %v\n", err)
			return 1
		}
		fmt.Fprintf(errOut, "wrote debug bundle: %s\n", manifestPath)
	}

	return 0
}

func (s debugSelection) hasChainFilter() bool {
	return s.TraceGroupID != "" || s.ThreadID != "" || s.RunID != ""
}

func resolveDebugSourceTrace(ctx context.Context, store trace.TraceStore, selection debugSelection) (*trace.Trace, error) {
	if selection.TraceID != "" {
		return store.GetTrace(ctx, selection.TraceID)
	}

	filter := trace.TraceFilter{Limit: 1}
	if selection.hasChainFilter() {
		filter.TraceGroupID = selection.TraceGroupID
		filter.ThreadID = selection.ThreadID
		filter.RunID = selection.RunID
	}

	result, err := store.QueryTraces(ctx, filter)
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
	selection debugSelection,
	limit int,
	includeHeaders bool,
	includeBodies bool,
	includeDiff bool,
) (debugDocument, error) {
	sourceLineage := extractDebugLineage(source, true)
	filter := trace.TraceFilter{}
	chainGroupID := sourceLineage.GroupID
	chainThreadID := sourceLineage.ThreadID
	chainRunID := sourceLineage.RunID
	lineageIdentifier := "(single trace)"

	if selection.hasChainFilter() {
		filter.TraceGroupID = selection.TraceGroupID
		filter.ThreadID = selection.ThreadID
		filter.RunID = selection.RunID
		chainGroupID = selection.TraceGroupID
		chainThreadID = selection.ThreadID
		chainRunID = selection.RunID
		lineageIdentifier = debugSelectionIdentifier(selection)
	} else {
		filter.TraceGroupID = sourceLineage.GroupID
		filter.ThreadID = sourceLineage.ThreadID
		filter.RunID = sourceLineage.RunID
		switch {
		case sourceLineage.GroupID != "":
			lineageIdentifier = "trace_group_id"
		case sourceLineage.ThreadID != "":
			lineageIdentifier = "lineage_thread_id"
		case sourceLineage.RunID != "":
			lineageIdentifier = "lineage_run_id"
		}
	}

	items := make([]*trace.Trace, 0, limit)
	truncated := false
	if filter.TraceGroupID != "" || filter.ThreadID != "" || filter.RunID != "" {
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
	var diffs []debugCheckpointDiff
	if includeDiff {
		diffs = buildDebugDiffs(items)
	}

	return debugDocument{
		SchemaVersion: debugSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Selection: debugSelectionInfo{
			TraceID:      selection.TraceID,
			TraceGroupID: selection.TraceGroupID,
			ThreadID:     selection.ThreadID,
			RunID:        selection.RunID,
		},
		Options: debugOptionInfo{
			Limit:          limit,
			IncludeDiff:    includeDiff,
			IncludeHeaders: includeHeaders,
			IncludeBodies:  includeBodies,
		},
		SourceTraceID:   strings.TrimSpace(source.ID),
		SourceTimestamp: debugOrderTime(source),
		Source:          toDebugTraceCheckpoint(source, 0, includeHeaders, includeBodies),
		Chain: debugChain{
			GroupID:           chainGroupID,
			ThreadID:          chainThreadID,
			RunID:             chainRunID,
			TargetCheckpoint:  strings.TrimSpace(source.ID),
			CheckpointCount:   len(checkpoints),
			Truncated:         truncated,
			Checkpoints:       checkpoints,
			LineageIdentifier: lineageIdentifier,
		},
		Diffs: diffs,
	}, nil
}

func debugSelectionIdentifier(selection debugSelection) string {
	count := 0
	identifier := "(single trace)"
	if selection.TraceGroupID != "" {
		count++
		identifier = "trace_group_id"
	}
	if selection.ThreadID != "" {
		count++
		identifier = "lineage_thread_id"
	}
	if selection.RunID != "" {
		count++
		identifier = "lineage_run_id"
	}
	if count > 1 {
		return "composite_filter"
	}
	return identifier
}

func (s debugSelection) mode() string {
	if s.TraceID != "" {
		return "trace_id"
	}
	if s.hasChainFilter() {
		return "filter"
	}
	return "latest"
}

func writeDebugBundle(
	outputDir string,
	document debugDocument,
	selection debugSelection,
	limit int,
	includeDiff bool,
	includeHeaders bool,
	includeBodies bool,
) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("create bundle directory %q: %w", outputDir, err)
	}

	chainBytes, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode debug chain: %w", err)
	}
	chainBytes = append(chainBytes, '\n')

	chainFilename := "debug-chain.json"
	chainPath := filepath.Join(outputDir, chainFilename)
	if err := os.WriteFile(chainPath, chainBytes, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", chainFilename, err)
	}

	manifest := debugBundleManifest{
		SchemaVersion: "debug-bundle.v1",
		GeneratedAt:   time.Now().UTC(),
		SelectionMode: selection.mode(),
		Selection: debugBundleSelection{
			TraceID:      selection.TraceID,
			TraceGroupID: selection.TraceGroupID,
			ThreadID:     selection.ThreadID,
			RunID:        selection.RunID,
		},
		Limit:          limit,
		IncludeDiff:    includeDiff,
		IncludeBodies:  includeBodies,
		IncludeHeaders: includeHeaders,
		Chain: debugBundleChain{
			SourceTraceID:    document.SourceTraceID,
			CheckpointCount:  document.Chain.CheckpointCount,
			Truncated:        document.Chain.Truncated,
			DiffCount:        len(document.Diffs),
			TargetCheckpoint: document.Chain.TargetCheckpoint,
		},
		Files: []debugBundleFile{
			{
				Name:   chainFilename,
				Bytes:  len(chainBytes),
				SHA256: debugHashedBytes(chainBytes),
			},
		},
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	manifestFilename := "manifest.json"
	manifestPath := filepath.Join(outputDir, manifestFilename)
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", manifestFilename, err)
	}
	return manifestPath, nil
}

func buildDebugDiffs(items []*trace.Trace) []debugCheckpointDiff {
	if len(items) < 2 {
		return nil
	}
	diffs := make([]debugCheckpointDiff, 0, len(items)-1)
	for i := 1; i < len(items); i++ {
		prev := items[i-1]
		curr := items[i]
		if prev == nil || curr == nil {
			continue
		}

		prevMetadata := decodeDebugMetadataMap(prev.Metadata)
		currMetadata := decodeDebugMetadataMap(curr.Metadata)
		added, removed, changed := debugMetadataKeyDiff(prevMetadata, currMetadata)

		diff := debugCheckpointDiff{
			FromCheckpointID:         strings.TrimSpace(prev.ID),
			ToCheckpointID:           strings.TrimSpace(curr.ID),
			ProviderChanged:          strings.TrimSpace(prev.Provider) != strings.TrimSpace(curr.Provider),
			ModelChanged:             strings.TrimSpace(prev.Model) != strings.TrimSpace(curr.Model),
			RequestMethodChanged:     strings.TrimSpace(prev.RequestMethod) != strings.TrimSpace(curr.RequestMethod),
			RequestPathChanged:       strings.TrimSpace(prev.RequestPath) != strings.TrimSpace(curr.RequestPath),
			ResponseStatusChanged:    prev.ResponseStatus != curr.ResponseStatus,
			InputTokensDelta:         curr.InputTokens - prev.InputTokens,
			OutputTokensDelta:        curr.OutputTokens - prev.OutputTokens,
			TotalTokensDelta:         curr.TotalTokens - prev.TotalTokens,
			LatencyDeltaMS:           curr.LatencyMS - prev.LatencyMS,
			EstimatedCostDeltaUSD:    curr.EstimatedCostUSD - prev.EstimatedCostUSD,
			RequestHeadersChanged:    debugHashedString(prev.RequestHeaders) != debugHashedString(curr.RequestHeaders),
			ResponseHeadersChanged:   debugHashedString(prev.ResponseHeaders) != debugHashedString(curr.ResponseHeaders),
			RequestBodyChanged:       debugHashedString(prev.RequestBody) != debugHashedString(curr.RequestBody),
			ResponseBodyChanged:      debugHashedString(prev.ResponseBody) != debugHashedString(curr.ResponseBody),
			RequestHeadersBytesFrom:  len(prev.RequestHeaders),
			RequestHeadersBytesTo:    len(curr.RequestHeaders),
			ResponseHeadersBytesFrom: len(prev.ResponseHeaders),
			ResponseHeadersBytesTo:   len(curr.ResponseHeaders),
			RequestBodyBytesFrom:     len(prev.RequestBody),
			RequestBodyBytesTo:       len(curr.RequestBody),
			ResponseBodyBytesFrom:    len(prev.ResponseBody),
			ResponseBodyBytesTo:      len(curr.ResponseBody),
			MetadataKeysAdded:        added,
			MetadataKeysRemoved:      removed,
			MetadataKeysChanged:      changed,
		}
		diffs = append(diffs, diff)
	}
	return diffs
}

func debugMetadataKeyDiff(before map[string]any, after map[string]any) ([]string, []string, []string) {
	if before == nil {
		before = map[string]any{}
	}
	if after == nil {
		after = map[string]any{}
	}

	added := make([]string, 0)
	removed := make([]string, 0)
	changed := make([]string, 0)
	keys := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		keys[key] = struct{}{}
	}
	for key := range after {
		keys[key] = struct{}{}
	}

	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		beforeValue, beforeOK := before[key]
		afterValue, afterOK := after[key]

		switch {
		case !beforeOK && afterOK:
			added = append(added, key)
		case beforeOK && !afterOK:
			removed = append(removed, key)
		default:
			if debugValueHash(beforeValue) != debugValueHash(afterValue) {
				changed = append(changed, key)
			}
		}
	}

	return added, removed, changed
}

func debugHashedString(value string) string {
	return debugHashedBytes([]byte(value))
}

func debugHashedBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("%x", sum[:])
}

func debugValueHash(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%T:%v", value, value)
	}
	sum := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", sum[:])
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
	trace.SortLineageTraces(items)
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

func writeDebug(out io.Writer, format string, document debugDocument, includeHeaders bool, includeBodies bool, includeDiff bool) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(document)
	default:
		return writeDebugText(out, document, includeHeaders, includeBodies, includeDiff)
	}
}

func writeDebugText(out io.Writer, document debugDocument, includeHeaders bool, includeBodies bool, includeDiff bool) error {
	fmt.Fprintln(out, "OngoingAI Debug Chain")

	meta := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(meta, "Schema version\t%s\n", document.SchemaVersion)
	fmt.Fprintf(meta, "Generated at\t%s\n", document.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(meta, "Filter trace_id\t%s\n", reportValueOr(document.Selection.TraceID, "(latest)"))
	fmt.Fprintf(meta, "Filter trace_group_id\t%s\n", reportValueOr(document.Selection.TraceGroupID, "(none)"))
	fmt.Fprintf(meta, "Filter thread_id\t%s\n", reportValueOr(document.Selection.ThreadID, "(none)"))
	fmt.Fprintf(meta, "Filter run_id\t%s\n", reportValueOr(document.Selection.RunID, "(none)"))
	fmt.Fprintf(meta, "Option limit\t%d\n", document.Options.Limit)
	fmt.Fprintf(meta, "Option include_diff\t%t\n", document.Options.IncludeDiff)
	fmt.Fprintf(meta, "Option include_headers\t%t\n", document.Options.IncludeHeaders)
	fmt.Fprintf(meta, "Option include_bodies\t%t\n", document.Options.IncludeBodies)
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

	if includeDiff {
		fmt.Fprintln(out, "\nDiffs")
		if len(document.Diffs) == 0 {
			fmt.Fprintln(out, "(no checkpoint diffs)")
			return nil
		}

		diffWriter := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(diffWriter, "FROM\tTO\tTOTAL_TOKENS_DELTA\tLATENCY_DELTA_MS\tPATH_CHANGED\tMODEL_CHANGED\tSTATUS_CHANGED\tREQUEST_BODY_CHANGED\tRESPONSE_BODY_CHANGED\tMETADATA_KEYS_CHANGED")
		for _, diff := range document.Diffs {
			fmt.Fprintf(
				diffWriter,
				"%s\t%s\t%d\t%d\t%t\t%t\t%t\t%t\t%t\t%d\n",
				diff.FromCheckpointID,
				diff.ToCheckpointID,
				diff.TotalTokensDelta,
				diff.LatencyDeltaMS,
				diff.RequestPathChanged,
				diff.ModelChanged,
				diff.ResponseStatusChanged,
				diff.RequestBodyChanged,
				diff.ResponseBodyChanged,
				len(diff.MetadataKeysChanged),
			)
		}
		if err := diffWriter.Flush(); err != nil {
			return err
		}

		for _, diff := range document.Diffs {
			if len(diff.MetadataKeysAdded) == 0 && len(diff.MetadataKeysRemoved) == 0 && len(diff.MetadataKeysChanged) == 0 {
				continue
			}
			fmt.Fprintf(out, "\nDiff %s -> %s metadata keys\n", diff.FromCheckpointID, diff.ToCheckpointID)
			metaDiff := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintf(metaDiff, "added\t%s\n", strings.Join(diff.MetadataKeysAdded, ","))
			fmt.Fprintf(metaDiff, "removed\t%s\n", strings.Join(diff.MetadataKeysRemoved, ","))
			fmt.Fprintf(metaDiff, "changed\t%s\n", strings.Join(diff.MetadataKeysChanged, ","))
			if err := metaDiff.Flush(); err != nil {
				return err
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
