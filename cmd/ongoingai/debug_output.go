package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

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
	fmt.Fprintf(meta, "Filter trace_id\t%s\n", valueOr(document.Selection.TraceID, "(latest)"))
	fmt.Fprintf(meta, "Filter trace_group_id\t%s\n", valueOr(document.Selection.TraceGroupID, "(none)"))
	fmt.Fprintf(meta, "Filter thread_id\t%s\n", valueOr(document.Selection.ThreadID, "(none)"))
	fmt.Fprintf(meta, "Filter run_id\t%s\n", valueOr(document.Selection.RunID, "(none)"))
	fmt.Fprintf(meta, "Option limit\t%d\n", document.Options.Limit)
	fmt.Fprintf(meta, "Option include_diff\t%t\n", document.Options.IncludeDiff)
	fmt.Fprintf(meta, "Option include_headers\t%t\n", document.Options.IncludeHeaders)
	fmt.Fprintf(meta, "Option include_bodies\t%t\n", document.Options.IncludeBodies)
	fmt.Fprintf(meta, "Source trace\t%s\n", document.SourceTraceID)
	fmt.Fprintf(meta, "Source time\t%s\n", document.SourceTimestamp.Format(time.RFC3339))
	fmt.Fprintf(meta, "Source provider\t%s\n", valueOr(document.Source.Provider, "(unknown)"))
	fmt.Fprintf(meta, "Source model\t%s\n", valueOr(document.Source.Model, "(unknown)"))
	fmt.Fprintf(meta, "Source path\t%s\n", valueOr(document.Source.RequestPath, "(unknown)"))
	fmt.Fprintf(meta, "Source status\t%d\n", document.Source.ResponseStatus)
	fmt.Fprintf(meta, "Chain identifier\t%s\n", valueOr(document.Chain.LineageIdentifier, "(single trace)"))
	fmt.Fprintf(meta, "Chain group_id\t%s\n", valueOr(document.Chain.GroupID, "(none)"))
	fmt.Fprintf(meta, "Chain thread_id\t%s\n", valueOr(document.Chain.ThreadID, "(none)"))
	fmt.Fprintf(meta, "Chain run_id\t%s\n", valueOr(document.Chain.RunID, "(none)"))
	fmt.Fprintf(meta, "Chain checkpoints\t%d\n", document.Chain.CheckpointCount)
	fmt.Fprintf(meta, "Truncated\t%t\n", document.Chain.Truncated)
	if err := meta.Flush(); err != nil {
		return err
	}

	for _, checkpoint := range document.Chain.Checkpoints {
		fmt.Fprintf(out, "\nStep %d: %s\n", checkpoint.Step, checkpoint.ID)
		step := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintf(step, "time\t%s\n", debugCheckpointTime(checkpoint).Format(time.RFC3339))
		fmt.Fprintf(step, "provider\t%s\n", valueOr(checkpoint.Provider, "(unknown)"))
		fmt.Fprintf(step, "model\t%s\n", valueOr(checkpoint.Model, "(unknown)"))
		fmt.Fprintf(step, "request\t%s %s\n", valueOr(checkpoint.RequestMethod, "UNKNOWN"), valueOr(checkpoint.RequestPath, "(unknown)"))
		fmt.Fprintf(step, "response_status\t%d\n", checkpoint.ResponseStatus)
		fmt.Fprintf(step, "tokens\tinput=%d output=%d total=%d\n", checkpoint.InputTokens, checkpoint.OutputTokens, checkpoint.TotalTokens)
		fmt.Fprintf(step, "estimated_cost_usd\t%.6f\n", checkpoint.EstimatedCostUSD)
		fmt.Fprintf(step, "latency_ms\t%d\n", checkpoint.LatencyMS)
		fmt.Fprintf(step, "ttft_ms\t%d\n", checkpoint.TimeToFirstTokenMS)
		fmt.Fprintf(step, "lineage\tcheckpoint=%s parent=%s seq=%d immutable=%t\n", valueOr(checkpoint.Lineage.CheckpointID, "(none)"), valueOr(checkpoint.Lineage.ParentCheckpointID, "(none)"), checkpoint.Lineage.CheckpointSeq, checkpoint.Lineage.Immutable)
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
		Selection: debugSelectionInfo{
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
