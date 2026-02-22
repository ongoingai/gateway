package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

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

	store, err := openTraceStore(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "failed to initialize trace store: %v\n", err)
		return 1
	}
	defer closeTraceStoreWithWarning(store, errOut)

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

func (s debugSelection) mode() string {
	if s.TraceID != "" {
		return "trace_id"
	}
	if s.hasChainFilter() {
		return "filter"
	}
	return "latest"
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
	trace.SortLineageTraces(items)

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
		SourceTimestamp:  trace.OrderTime(source),
		Source:           toDebugTraceCheckpoint(source, 0, includeHeaders, includeBodies),
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
	if value := trace.MetadataString(metadata, "lineage_group_id"); value != "" {
		lineage.GroupID = value
	}
	lineage.ThreadID = trace.MetadataString(metadata, "lineage_thread_id")
	lineage.RunID = trace.MetadataString(metadata, "lineage_run_id")
	lineage.CheckpointID = trace.MetadataString(metadata, "lineage_checkpoint_id")
	lineage.ParentCheckpointID = trace.MetadataString(metadata, "lineage_parent_checkpoint_id")
	if seq, ok := trace.MetadataInt64(metadata, "lineage_checkpoint_seq"); ok {
		lineage.CheckpointSeq = seq
	}
	if immutable, ok := trace.MetadataBool(metadata, "lineage_immutable"); ok {
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

// decodeDebugMetadataMap wraps trace.DecodeMetadataMap with a debug-specific
// fallback that preserves the raw string when JSON parsing fails.
func decodeDebugMetadataMap(raw string) map[string]any {
	if m := trace.DecodeMetadataMap(raw); m != nil {
		return m
	}
	if strings.TrimSpace(raw) != "" {
		return map[string]any{"raw": raw}
	}
	return nil
}
