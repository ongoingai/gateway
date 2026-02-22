package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

func TestRunReportTextOutputIncludesSummaries(t *testing.T) {
	t.Parallel()

	configPath := writeReportTestFixture(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runReport([]string{"--config", configPath, "--limit", "5"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runReport() code=%d, stderr=%q", code, stderr.String())
	}

	body := stdout.String()
	if !strings.Contains(body, "OngoingAI Report") {
		t.Fatalf("stdout=%q, want report header", body)
	}
	if !strings.Contains(body, "Total requests") || !strings.Contains(body, "4") {
		t.Fatalf("stdout=%q, want total request summary", body)
	}
	if !strings.Contains(body, "Providers") || !strings.Contains(body, "openai") || !strings.Contains(body, "anthropic") {
		t.Fatalf("stdout=%q, want provider section for openai and anthropic", body)
	}
	if !strings.Contains(body, "Recent Traces") || !strings.Contains(body, "trace-openai") || !strings.Contains(body, "trace-anthropic-1") || !strings.Contains(body, "trace-anthropic-2") {
		t.Fatalf("stdout=%q, want recent traces section", body)
	}
}

func TestRunReportJSONOutput(t *testing.T) {
	t.Parallel()

	configPath := writeReportTestFixture(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runReport([]string{"--config", configPath, "--format", "json", "--limit", "5"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runReport() code=%d, stderr=%q", code, stderr.String())
	}

	var report reportDocument
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode json report: %v\nbody=%s", err, stdout.String())
	}
	if report.SchemaVersion != reportSchemaVersion {
		t.Fatalf("schema_version=%q, want %q", report.SchemaVersion, reportSchemaVersion)
	}
	if report.Filters.Limit != 5 {
		t.Fatalf("filters.limit=%d, want 5", report.Filters.Limit)
	}
	if report.Filters.From != nil || report.Filters.To != nil {
		t.Fatalf("filters from/to should be omitted when unset, got from=%v to=%v", report.Filters.From, report.Filters.To)
	}

	if report.Summary.TotalRequests != 4 {
		t.Fatalf("total_requests=%d, want 4", report.Summary.TotalRequests)
	}
	if report.Summary.TotalTokens != 90 {
		t.Fatalf("total_tokens=%d, want 90", report.Summary.TotalTokens)
	}
	if len(report.Providers) != 2 {
		t.Fatalf("provider_count=%d, want 2", len(report.Providers))
	}
	if len(report.Models) != 3 {
		t.Fatalf("model_count=%d, want 3", len(report.Models))
	}
	if len(report.APIKeys) != 3 {
		t.Fatalf("api_key_count=%d, want 3", len(report.APIKeys))
	}
	if len(report.Recent) != 4 {
		t.Fatalf("recent_count=%d, want 4", len(report.Recent))
	}
	if report.Models[0].Model != "claude-sonnet-4-latest" || report.Models[0].RequestCount != 2 {
		t.Fatalf("models[0]=%+v, want claude-sonnet-4-latest with request_count=2", report.Models[0])
	}
	if report.Models[1].Model != "gpt-4o" || report.Models[2].Model != "gpt-4o-mini" {
		t.Fatalf("model order=%+v, want deterministic tie ordering gpt-4o then gpt-4o-mini", report.Models)
	}
	if report.APIKeys[0].APIKeyHash != "key-a" || report.APIKeys[1].APIKeyHash != "key-anthropic" || report.APIKeys[2].APIKeyHash != "key-b" {
		t.Fatalf("api key ordering=%+v, want deterministic hash ordering for tied request counts", report.APIKeys)
	}
	if report.Recent[0].ID != "trace-anthropic-2" || report.Recent[1].ID != "trace-anthropic-1" {
		t.Fatalf("recent ordering=%+v, want deterministic id tie-break order for equal timestamps", report.Recent)
	}
}

func TestRunReportJSONOutputPostgres(t *testing.T) {
	t.Parallel()

	configPath, ids, from, to := writeReportPostgresTestFixture(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runReport([]string{
		"--config", configPath,
		"--format", "json",
		"--from", from.Format(time.RFC3339Nano),
		"--to", to.Format(time.RFC3339Nano),
		"--limit", "5",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runReport() code=%d, stderr=%q", code, stderr.String())
	}

	var report reportDocument
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode json report: %v\nbody=%s", err, stdout.String())
	}
	if report.SchemaVersion != reportSchemaVersion {
		t.Fatalf("schema_version=%q, want %q", report.SchemaVersion, reportSchemaVersion)
	}
	if report.Storage.Driver != "postgres" {
		t.Fatalf("storage.driver=%q, want postgres", report.Storage.Driver)
	}
	if report.Storage.Path != "" {
		t.Fatalf("storage.path=%q, want empty for postgres", report.Storage.Path)
	}
	if report.Summary.TotalRequests != 4 {
		t.Fatalf("total_requests=%d, want 4", report.Summary.TotalRequests)
	}
	if report.Summary.TotalTokens != 90 {
		t.Fatalf("total_tokens=%d, want 90", report.Summary.TotalTokens)
	}
	if len(report.Models) != 3 {
		t.Fatalf("model_count=%d, want 3", len(report.Models))
	}
	if len(report.APIKeys) != 3 {
		t.Fatalf("api_key_count=%d, want 3", len(report.APIKeys))
	}
	if len(report.Recent) != 4 {
		t.Fatalf("recent_count=%d, want 4", len(report.Recent))
	}
	if report.Models[0].Model != "claude-sonnet-4-latest" || report.Models[0].RequestCount != 2 {
		t.Fatalf("models[0]=%+v, want claude-sonnet-4-latest with request_count=2", report.Models[0])
	}
	if report.Models[1].Model != "gpt-4o" || report.Models[2].Model != "gpt-4o-mini" {
		t.Fatalf("model order=%+v, want deterministic tie ordering gpt-4o then gpt-4o-mini", report.Models)
	}
	if report.APIKeys[0].APIKeyHash != "key-a" || report.APIKeys[1].APIKeyHash != "key-anthropic" || report.APIKeys[2].APIKeyHash != "key-b" {
		t.Fatalf("api key ordering=%+v, want deterministic hash ordering for tied request counts", report.APIKeys)
	}
	if report.Recent[0].ID != ids.TraceAnthropic2 || report.Recent[1].ID != ids.TraceAnthropic1 {
		t.Fatalf("recent ordering=%+v, want deterministic id tie-break order for equal timestamps", report.Recent)
	}
}

func TestRunReportJSONOutputIncludesExplicitTimeFilters(t *testing.T) {
	t.Parallel()

	configPath := writeReportTestFixture(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runReport([]string{"--config", configPath, "--format", "json", "--from", "2026-02-18", "--to", "2026-02-18", "--limit", "5"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runReport() code=%d, stderr=%q", code, stderr.String())
	}

	var report reportDocument
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode json report: %v\nbody=%s", err, stdout.String())
	}
	if report.Filters.From == nil || report.Filters.To == nil {
		t.Fatalf("filters from/to should be set when explicit range is passed, got from=%v to=%v", report.Filters.From, report.Filters.To)
	}
	if got, want := report.Filters.From.UTC().Format(time.RFC3339Nano), "2026-02-18T00:00:00Z"; got != want {
		t.Fatalf("filters.from=%q, want %q", got, want)
	}
	if got, want := report.Filters.To.UTC().Format(time.RFC3339Nano), "2026-02-18T23:59:59.999999999Z"; got != want {
		t.Fatalf("filters.to=%q, want %q", got, want)
	}
}

func TestRunReportRejectsInvalidFormat(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runReport([]string{"--format", "yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runReport() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "expected text or json") {
		t.Fatalf("stderr=%q, want invalid format message", stderr.String())
	}
}

func TestRunReportRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runReport([]string{"extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runReport() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%q, want positional argument message", stderr.String())
	}
}

func writeReportTestFixture(t *testing.T) string {
	t.Helper()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "report.db")
	store, err := trace.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close sqlite store: %v", err)
		}
	}()

	base := time.Date(2026, 2, 18, 12, 0, 0, 0, time.UTC)
	traces := []*trace.Trace{
		{
			ID:               "trace-openai",
			Timestamp:        base,
			CreatedAt:        base,
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			RequestMethod:    "POST",
			RequestPath:      "/openai/v1/chat/completions",
			ResponseStatus:   200,
			InputTokens:      12,
			OutputTokens:     8,
			TotalTokens:      20,
			LatencyMS:        145,
			APIKeyHash:       "key-a",
			EstimatedCostUSD: 0.00015,
		},
		{
			ID:               "trace-anthropic-1",
			Timestamp:        base.Add(2 * time.Minute),
			CreatedAt:        base.Add(2 * time.Minute),
			Provider:         "anthropic",
			Model:            "claude-sonnet-4-latest",
			RequestMethod:    "POST",
			RequestPath:      "/anthropic/v1/messages",
			ResponseStatus:   200,
			InputTokens:      15,
			OutputTokens:     10,
			TotalTokens:      25,
			LatencyMS:        210,
			APIKeyHash:       "key-anthropic",
			EstimatedCostUSD: 0.00035,
		},
		{
			ID:               "trace-anthropic-2",
			Timestamp:        base.Add(2 * time.Minute),
			CreatedAt:        base.Add(2 * time.Minute),
			Provider:         "anthropic",
			Model:            "claude-sonnet-4-latest",
			RequestMethod:    "POST",
			RequestPath:      "/anthropic/v1/messages",
			ResponseStatus:   200,
			InputTokens:      20,
			OutputTokens:     15,
			TotalTokens:      35,
			LatencyMS:        190,
			APIKeyHash:       "key-b",
			EstimatedCostUSD: 0.00045,
		},
		{
			ID:               "trace-openai-alt",
			Timestamp:        base.Add(1 * time.Minute),
			CreatedAt:        base.Add(1 * time.Minute),
			Provider:         "openai",
			Model:            "gpt-4o",
			RequestMethod:    "POST",
			RequestPath:      "/openai/v1/chat/completions",
			ResponseStatus:   200,
			InputTokens:      5,
			OutputTokens:     5,
			TotalTokens:      10,
			LatencyMS:        150,
			APIKeyHash:       "key-a",
			EstimatedCostUSD: 0.00010,
		},
	}
	if err := store.WriteBatch(context.Background(), traces); err != nil {
		t.Fatalf("seed traces: %v", err)
	}

	configPath := filepath.Join(tempDir, "ongoingai.yaml")
	configBody := "storage:\n  driver: sqlite\n  path: " + dbPath + "\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

type reportFixtureIDs struct {
	TraceOpenAI     string
	TraceAnthropic1 string
	TraceAnthropic2 string
	TraceOpenAIAlt  string
}

func writeReportPostgresTestFixture(t *testing.T) (string, reportFixtureIDs, time.Time, time.Time) {
	t.Helper()

	dsn := requirePostgresTestDSN(t)
	idPrefix := postgresTraceTestPrefix("report")
	deletePostgresTracesByPrefix(t, dsn, idPrefix)
	t.Cleanup(func() {
		deletePostgresTracesByPrefix(t, dsn, idPrefix)
	})

	store, err := trace.NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("create postgres store: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close postgres store: %v", err)
		}
	}()

	base := time.Unix(0, time.Now().UTC().UnixNano()).UTC().AddDate(75, 6, 0)
	ids := reportFixtureIDs{
		TraceOpenAI:     idPrefix + "trace-openai",
		TraceAnthropic1: idPrefix + "trace-anthropic-1",
		TraceAnthropic2: idPrefix + "trace-anthropic-2",
		TraceOpenAIAlt:  idPrefix + "trace-openai-alt",
	}
	traces := []*trace.Trace{
		{
			ID:               ids.TraceOpenAI,
			Timestamp:        base,
			CreatedAt:        base,
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			RequestMethod:    "POST",
			RequestPath:      "/openai/v1/chat/completions",
			ResponseStatus:   200,
			InputTokens:      12,
			OutputTokens:     8,
			TotalTokens:      20,
			LatencyMS:        145,
			APIKeyHash:       "key-a",
			EstimatedCostUSD: 0.00015,
		},
		{
			ID:               ids.TraceAnthropic1,
			Timestamp:        base.Add(2 * time.Minute),
			CreatedAt:        base.Add(2 * time.Minute),
			Provider:         "anthropic",
			Model:            "claude-sonnet-4-latest",
			RequestMethod:    "POST",
			RequestPath:      "/anthropic/v1/messages",
			ResponseStatus:   200,
			InputTokens:      15,
			OutputTokens:     10,
			TotalTokens:      25,
			LatencyMS:        210,
			APIKeyHash:       "key-anthropic",
			EstimatedCostUSD: 0.00035,
		},
		{
			ID:               ids.TraceAnthropic2,
			Timestamp:        base.Add(2 * time.Minute),
			CreatedAt:        base.Add(2 * time.Minute),
			Provider:         "anthropic",
			Model:            "claude-sonnet-4-latest",
			RequestMethod:    "POST",
			RequestPath:      "/anthropic/v1/messages",
			ResponseStatus:   200,
			InputTokens:      20,
			OutputTokens:     15,
			TotalTokens:      35,
			LatencyMS:        190,
			APIKeyHash:       "key-b",
			EstimatedCostUSD: 0.00045,
		},
		{
			ID:               ids.TraceOpenAIAlt,
			Timestamp:        base.Add(1 * time.Minute),
			CreatedAt:        base.Add(1 * time.Minute),
			Provider:         "openai",
			Model:            "gpt-4o",
			RequestMethod:    "POST",
			RequestPath:      "/openai/v1/chat/completions",
			ResponseStatus:   200,
			InputTokens:      5,
			OutputTokens:     5,
			TotalTokens:      10,
			LatencyMS:        150,
			APIKeyHash:       "key-a",
			EstimatedCostUSD: 0.00010,
		},
	}
	if err := store.WriteBatch(context.Background(), traces); err != nil {
		t.Fatalf("seed traces: %v", err)
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "ongoingai.yaml")
	configBody := fmt.Sprintf("storage:\n  driver: postgres\n  dsn: %q\n", dsn)
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return configPath, ids, base.Add(-time.Second), base.Add(3 * time.Minute)
}
