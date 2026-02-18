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
	if !strings.Contains(body, "Total requests") || !strings.Contains(body, "2") {
		t.Fatalf("stdout=%q, want total request summary", body)
	}
	if !strings.Contains(body, "Providers") || !strings.Contains(body, "openai") || !strings.Contains(body, "anthropic") {
		t.Fatalf("stdout=%q, want provider section for openai and anthropic", body)
	}
	if !strings.Contains(body, "Recent Traces") || !strings.Contains(body, "trace-openai") || !strings.Contains(body, "trace-anthropic") {
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

	if report.Summary.TotalRequests != 2 {
		t.Fatalf("total_requests=%d, want 2", report.Summary.TotalRequests)
	}
	if report.Summary.TotalTokens != 45 {
		t.Fatalf("total_tokens=%d, want 45", report.Summary.TotalTokens)
	}
	if len(report.Providers) != 2 {
		t.Fatalf("provider_count=%d, want 2", len(report.Providers))
	}
	if len(report.Recent) != 2 {
		t.Fatalf("recent_count=%d, want 2", len(report.Recent))
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
			APIKeyHash:       "key-openai",
			EstimatedCostUSD: 0.00015,
		},
		{
			ID:               "trace-anthropic",
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
