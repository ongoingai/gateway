package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

func TestRunDebugLastShowsFullChain(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"last", "--config", configPath, "--limit", "10"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDebug() code=%d, stderr=%q", code, stderr.String())
	}

	body := stdout.String()
	if !strings.Contains(body, "OngoingAI Debug Chain") {
		t.Fatalf("stdout=%q, want debug header", body)
	}
	if !strings.Contains(body, "Chain checkpoints") {
		t.Fatalf("stdout=%q, want chain checkpoint summary", body)
	}
	if !strings.Contains(body, "trace-step-1") || !strings.Contains(body, "trace-step-2") {
		t.Fatalf("stdout=%q, want lineage checkpoints", body)
	}
	if !strings.Contains(body, "checkpoint=trace-step-2 parent=trace-step-1 seq=2") {
		t.Fatalf("stdout=%q, want lineage parent sequence details", body)
	}
}

func TestRunDebugByTraceIDJSON(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath, "--trace-id", "trace-step-1", "--format", "json", "--limit", "10"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDebug() code=%d, stderr=%q", code, stderr.String())
	}

	var payload debugDocument
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode debug json: %v\nbody=%s", err, stdout.String())
	}
	if payload.SchemaVersion != debugSchemaVersion {
		t.Fatalf("schema_version=%q, want %q", payload.SchemaVersion, debugSchemaVersion)
	}
	if payload.SourceTraceID != "trace-step-1" {
		t.Fatalf("source_trace_id=%q, want trace-step-1", payload.SourceTraceID)
	}
	if payload.Selection.TraceID != "trace-step-1" {
		t.Fatalf("selection.trace_id=%q, want trace-step-1", payload.Selection.TraceID)
	}
	if payload.Options.Limit != 10 {
		t.Fatalf("options.limit=%d, want 10", payload.Options.Limit)
	}
	if payload.Options.IncludeDiff || payload.Options.IncludeHeaders || payload.Options.IncludeBodies {
		t.Fatalf("options=%+v, want diff/headers/bodies false", payload.Options)
	}
	if payload.Chain.CheckpointCount != 2 {
		t.Fatalf("checkpoint_count=%d, want 2", payload.Chain.CheckpointCount)
	}
	if len(payload.Chain.Checkpoints) != 2 {
		t.Fatalf("checkpoints=%d, want 2", len(payload.Chain.Checkpoints))
	}
	if payload.Chain.Checkpoints[0].ID != "trace-step-1" {
		t.Fatalf("first checkpoint=%q, want trace-step-1", payload.Chain.Checkpoints[0].ID)
	}
	if payload.Chain.Checkpoints[1].ID != "trace-step-2" {
		t.Fatalf("second checkpoint=%q, want trace-step-2", payload.Chain.Checkpoints[1].ID)
	}
}

func TestRunDebugByTraceGroupIDJSON(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath, "--trace-group-id", "group-demo", "--format", "json", "--limit", "10"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDebug() code=%d, stderr=%q", code, stderr.String())
	}

	var payload debugDocument
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode debug json: %v\nbody=%s", err, stdout.String())
	}
	if payload.SourceTraceID != "trace-step-2" {
		t.Fatalf("source_trace_id=%q, want trace-step-2", payload.SourceTraceID)
	}
	if payload.Chain.LineageIdentifier != "trace_group_id" {
		t.Fatalf("lineage_identifier=%q, want trace_group_id", payload.Chain.LineageIdentifier)
	}
	if payload.Selection.TraceGroupID != "group-demo" {
		t.Fatalf("selection.trace_group_id=%q, want group-demo", payload.Selection.TraceGroupID)
	}
	if payload.Chain.GroupID != "group-demo" {
		t.Fatalf("group_id=%q, want group-demo", payload.Chain.GroupID)
	}
	if payload.Chain.CheckpointCount != 2 {
		t.Fatalf("checkpoint_count=%d, want 2", payload.Chain.CheckpointCount)
	}
}

func TestRunDebugByThreadIDJSON(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath, "--thread-id", "thread-demo", "--format", "json", "--limit", "10"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDebug() code=%d, stderr=%q", code, stderr.String())
	}

	var payload debugDocument
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode debug json: %v\nbody=%s", err, stdout.String())
	}
	if payload.Chain.LineageIdentifier != "lineage_thread_id" {
		t.Fatalf("lineage_identifier=%q, want lineage_thread_id", payload.Chain.LineageIdentifier)
	}
	if payload.Chain.ThreadID != "thread-demo" {
		t.Fatalf("thread_id=%q, want thread-demo", payload.Chain.ThreadID)
	}
	if payload.Chain.CheckpointCount != 2 {
		t.Fatalf("checkpoint_count=%d, want 2", payload.Chain.CheckpointCount)
	}
}

func TestRunDebugByRunIDJSON(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath, "--run-id", "run-demo", "--format", "json", "--limit", "10"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDebug() code=%d, stderr=%q", code, stderr.String())
	}

	var payload debugDocument
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode debug json: %v\nbody=%s", err, stdout.String())
	}
	if payload.Chain.LineageIdentifier != "lineage_run_id" {
		t.Fatalf("lineage_identifier=%q, want lineage_run_id", payload.Chain.LineageIdentifier)
	}
	if payload.Chain.RunID != "run-demo" {
		t.Fatalf("run_id=%q, want run-demo", payload.Chain.RunID)
	}
	if payload.Chain.CheckpointCount != 2 {
		t.Fatalf("checkpoint_count=%d, want 2", payload.Chain.CheckpointCount)
	}
}

func TestRunDebugDiffJSON(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath, "--trace-group-id", "group-demo", "--format", "json", "--diff"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDebug() code=%d, stderr=%q", code, stderr.String())
	}

	var payload debugDocument
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode debug json: %v\nbody=%s", err, stdout.String())
	}
	if len(payload.Diffs) != 1 {
		t.Fatalf("diff_count=%d, want 1", len(payload.Diffs))
	}
	diff := payload.Diffs[0]
	if diff.FromCheckpointID != "trace-step-1" || diff.ToCheckpointID != "trace-step-2" {
		t.Fatalf("diff edge=%s->%s, want trace-step-1->trace-step-2", diff.FromCheckpointID, diff.ToCheckpointID)
	}
	if !diff.RequestPathChanged || !diff.ModelChanged {
		t.Fatalf("diff=%+v, want request path/model changed", diff)
	}
	if diff.TotalTokensDelta != 5 {
		t.Fatalf("total_tokens_delta=%d, want 5", diff.TotalTokensDelta)
	}
}

func TestRunDebugBundleExport(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)
	bundleDir := filepath.Join(t.TempDir(), "bundle")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath, "--trace-group-id", "group-demo", "--format", "json", "--diff", "--bundle-out", bundleDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDebug() code=%d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "wrote debug bundle") {
		t.Fatalf("stderr=%q, want bundle write confirmation", stderr.String())
	}

	chainPath := filepath.Join(bundleDir, "debug-chain.json")
	manifestPath := filepath.Join(bundleDir, "manifest.json")

	chainRaw, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read debug-chain.json: %v", err)
	}
	var chain debugDocument
	if err := json.Unmarshal(chainRaw, &chain); err != nil {
		t.Fatalf("decode debug-chain.json: %v", err)
	}
	if chain.SourceTraceID == "" || chain.Chain.CheckpointCount != 2 {
		t.Fatalf("chain summary=%+v, want source id and two checkpoints", chain.Chain)
	}

	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var manifest debugBundleManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("decode manifest.json: %v", err)
	}
	if manifest.SchemaVersion != "debug-bundle.v1" {
		t.Fatalf("schema_version=%q, want debug-bundle.v1", manifest.SchemaVersion)
	}
	if manifest.SelectionMode != "filter" {
		t.Fatalf("selection_mode=%q, want filter", manifest.SelectionMode)
	}
	if manifest.Selection.TraceGroupID != "group-demo" {
		t.Fatalf("selection trace_group_id=%q, want group-demo", manifest.Selection.TraceGroupID)
	}
	if len(manifest.Files) != 1 || manifest.Files[0].Name != "debug-chain.json" || manifest.Files[0].SHA256 == "" {
		t.Fatalf("manifest files=%+v, want debug-chain.json with checksum", manifest.Files)
	}
}

func TestRunDebugNoTraces(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, false)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDebug() code=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "no traces found in storage") {
		t.Fatalf("stderr=%q, want no traces message", stderr.String())
	}
}

func TestRunDebugRejectsUnsupportedPositional(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"banana"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runDebug() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `must be "last"`) {
		t.Fatalf("stderr=%q, want positional argument validation", stderr.String())
	}
}

func TestRunDebugRejectsTraceIDWithLineageFilter(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--trace-id", "trace-1", "--trace-group-id", "group-1"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runDebug() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "cannot be combined") {
		t.Fatalf("stderr=%q, want combination validation", stderr.String())
	}
}

func TestRunDebugRejectsLastWithExplicitFilter(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"last", "--trace-group-id", "group-1"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runDebug() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "cannot be combined") {
		t.Fatalf("stderr=%q, want combination validation", stderr.String())
	}
}

func TestRunDebugBundleExportInvalidPath(t *testing.T) {
	t.Parallel()

	configPath := writeDebugTestFixture(t, true)
	bundlePath := filepath.Join(t.TempDir(), "bundle-file")
	if err := os.WriteFile(bundlePath, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write bundle path fixture: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDebug([]string{"--config", configPath, "--bundle-out", bundlePath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDebug() code=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to write debug bundle") {
		t.Fatalf("stderr=%q, want bundle write failure", stderr.String())
	}
}

func writeDebugTestFixture(t *testing.T, seedTraces bool) string {
	t.Helper()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "debug.db")
	store, err := trace.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close sqlite store: %v", err)
		}
	}()

	if seedTraces {
		base := time.Date(2026, 2, 18, 14, 0, 0, 0, time.UTC)
		traces := []*trace.Trace{
			{
				ID:               "trace-unrelated",
				Timestamp:        base.Add(-5 * time.Minute),
				CreatedAt:        base.Add(-5 * time.Minute),
				TraceGroupID:     "group-other",
				Provider:         "openai",
				Model:            "gpt-4o-mini",
				RequestMethod:    "POST",
				RequestPath:      "/openai/v1/chat/completions",
				ResponseStatus:   200,
				TotalTokens:      9,
				LatencyMS:        99,
				EstimatedCostUSD: 0.00009,
				Metadata:         `{"lineage_group_id":"group-other","lineage_thread_id":"thread-other","lineage_run_id":"run-other","lineage_checkpoint_id":"trace-unrelated","lineage_checkpoint_seq":1,"lineage_immutable":true}`,
			},
			{
				ID:               "trace-step-1",
				Timestamp:        base,
				CreatedAt:        base,
				TraceGroupID:     "group-demo",
				Provider:         "openai",
				Model:            "gpt-4o-mini",
				RequestMethod:    "POST",
				RequestPath:      "/openai/v1/chat/completions",
				ResponseStatus:   200,
				InputTokens:      11,
				OutputTokens:     7,
				TotalTokens:      18,
				LatencyMS:        120,
				EstimatedCostUSD: 0.00018,
				Metadata:         `{"lineage_group_id":"group-demo","lineage_thread_id":"thread-demo","lineage_run_id":"run-demo","lineage_checkpoint_id":"trace-step-1","lineage_checkpoint_seq":1,"lineage_immutable":true}`,
			},
			{
				ID:               "trace-step-2",
				Timestamp:        base.Add(2 * time.Minute),
				CreatedAt:        base.Add(2 * time.Minute),
				TraceGroupID:     "group-demo",
				Provider:         "anthropic",
				Model:            "claude-sonnet-4-latest",
				RequestMethod:    "POST",
				RequestPath:      "/anthropic/v1/messages",
				ResponseStatus:   200,
				InputTokens:      13,
				OutputTokens:     10,
				TotalTokens:      23,
				LatencyMS:        180,
				EstimatedCostUSD: 0.00031,
				Metadata:         `{"lineage_group_id":"group-demo","lineage_thread_id":"thread-demo","lineage_run_id":"run-demo","lineage_checkpoint_id":"trace-step-2","lineage_parent_checkpoint_id":"trace-step-1","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
			},
		}
		if err := store.WriteBatch(context.Background(), traces); err != nil {
			t.Fatalf("seed traces: %v", err)
		}
	}

	configPath := filepath.Join(tempDir, "ongoingai.yaml")
	configBody := "storage:\n  driver: sqlite\n  path: " + dbPath + "\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}
