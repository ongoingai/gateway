package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

func TestRunDiagnosticsJSONOutput(t *testing.T) {
	t.Parallel()

	lastQueueDrop := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	lastWriteDrop := time.Date(2026, 2, 22, 10, 1, 0, 0, time.UTC)
	response := tracePipelineDiagnosticsDocument{
		SchemaVersion: "trace-pipeline-diagnostics.v1",
		GeneratedAt:   time.Date(2026, 2, 22, 10, 2, 0, 0, time.UTC),
		Diagnostics: trace.TracePipelineDiagnostics{
			QueueCapacity:                    1024,
			QueueDepth:                       9,
			QueueDepthHighWatermark:          512,
			QueueUtilizationPct:              0,
			QueueHighWatermarkUtilizationPct: 50,
			QueuePressureState:               trace.TraceQueuePressureOK,
			QueueHighWatermarkPressureState:  trace.TraceQueuePressureElevated,
			EnqueueAcceptedTotal:             99,
			EnqueueDroppedTotal:              2,
			WriteDroppedTotal:                1,
			TotalDroppedTotal:                3,
			LastEnqueueDropAt:                &lastQueueDrop,
			LastWriteDropAt:                  &lastWriteDrop,
			LastWriteDropOperation:           "write_batch_fallback",
			WriteFailuresByClass: map[string]int64{
				"contention": 1,
			},
			StoreDriver: "sqlite",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/trace-pipeline" {
			t.Fatalf("path=%q, want /api/diagnostics/trace-pipeline", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDiagnostics([]string{
		"--base-url", server.URL,
		"--auth-header", "X-OngoingAI-Gateway-Key",
		"--format", "json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDiagnostics() code=%d, want 0 (stderr=%q)", code, stderr.String())
	}

	var payload tracePipelineDiagnosticsDocument
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode diagnostics json: %v\nbody=%s", err, stdout.String())
	}
	if payload.SchemaVersion != response.SchemaVersion {
		t.Fatalf("schema_version=%q, want %q", payload.SchemaVersion, response.SchemaVersion)
	}
	if payload.Diagnostics.TotalDroppedTotal != 3 {
		t.Fatalf("total_dropped_total=%d, want 3", payload.Diagnostics.TotalDroppedTotal)
	}
	if payload.Diagnostics.LastWriteDropOperation != "write_batch_fallback" {
		t.Fatalf("last_write_drop_operation=%q, want write_batch_fallback", payload.Diagnostics.LastWriteDropOperation)
	}
	if payload.Diagnostics.WriteFailuresByClass == nil {
		t.Fatal("write_failures_by_class should be populated")
	}
	if payload.Diagnostics.WriteFailuresByClass["contention"] != 1 {
		t.Fatalf("contention=%d, want 1", payload.Diagnostics.WriteFailuresByClass["contention"])
	}
	if payload.Diagnostics.StoreDriver != "sqlite" {
		t.Fatalf("store_driver=%q, want sqlite", payload.Diagnostics.StoreDriver)
	}
}

func TestRunDiagnosticsTextOutput(t *testing.T) {
	t.Parallel()

	response := tracePipelineDiagnosticsDocument{
		SchemaVersion: "trace-pipeline-diagnostics.v1",
		GeneratedAt:   time.Date(2026, 2, 22, 11, 0, 0, 0, time.UTC),
		Diagnostics: trace.TracePipelineDiagnostics{
			QueueCapacity:                    1024,
			QueueDepth:                       1024,
			QueueDepthHighWatermark:          1024,
			QueueUtilizationPct:              100,
			QueueHighWatermarkUtilizationPct: 100,
			QueuePressureState:               trace.TraceQueuePressureSaturated,
			QueueHighWatermarkPressureState:  trace.TraceQueuePressureSaturated,
			EnqueueAcceptedTotal:             10,
			EnqueueDroppedTotal:              7,
			WriteDroppedTotal:                5,
			TotalDroppedTotal:                12,
			WriteFailuresByClass: map[string]int64{
				"connection": 3,
				"timeout":    2,
			},
			StoreDriver: "sqlite",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDiagnostics([]string{
		"--base-url", server.URL,
		"--auth-header", "X-OngoingAI-Gateway-Key",
		"--format", "text",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDiagnostics() code=%d, want 0 (stderr=%q)", code, stderr.String())
	}

	body := stdout.String()
	if !strings.Contains(body, "OngoingAI Diagnostics") {
		t.Fatalf("stdout=%q, want diagnostics header", body)
	}
	if !strings.Contains(body, "Queue pressure") || !strings.Contains(body, "SATURATED") {
		t.Fatalf("stdout=%q, want saturated queue pressure", body)
	}
	if !strings.Contains(body, "Total dropped") || !strings.Contains(body, "12") {
		t.Fatalf("stdout=%q, want dropped trace totals", body)
	}
	if !strings.Contains(body, "Write Failures by Class") {
		t.Fatalf("stdout=%q, want Write Failures by Class section", body)
	}
	if !strings.Contains(body, "connection") || !strings.Contains(body, "3") {
		t.Fatalf("stdout=%q, want connection failure count", body)
	}
	if !strings.Contains(body, "timeout") || !strings.Contains(body, "2") {
		t.Fatalf("stdout=%q, want timeout failure count", body)
	}
	if !strings.Contains(body, "Store") || !strings.Contains(body, "sqlite") {
		t.Fatalf("stdout=%q, want Store driver section", body)
	}
}

func TestRunDiagnosticsSendsGatewayKeyWithConfiguredHeader(t *testing.T) {
	t.Parallel()

	var seenHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get("X-Test-Gateway-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tracePipelineDiagnosticsDocument{
			SchemaVersion: "trace-pipeline-diagnostics.v1",
			GeneratedAt:   time.Date(2026, 2, 22, 11, 30, 0, 0, time.UTC),
		})
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDiagnostics([]string{
		"--base-url", server.URL,
		"--auth-header", "X-Test-Gateway-Key",
		"--gateway-key", "token-123",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDiagnostics() code=%d, want 0 (stderr=%q)", code, stderr.String())
	}
	if seenHeader != "token-123" {
		t.Fatalf("gateway key header=%q, want token-123", seenHeader)
	}
}

func TestRunDiagnosticsRejectsUnknownTarget(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDiagnostics([]string{"queue"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runDiagnostics() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unsupported diagnostics target "queue"`) {
		t.Fatalf("stderr=%q, want unsupported target message", stderr.String())
	}
}

func TestRunDiagnosticsRejectsInvalidFormat(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDiagnostics([]string{"--format", "yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runDiagnostics() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "expected text or json") {
		t.Fatalf("stderr=%q, want invalid format message", stderr.String())
	}
}

func TestRunDiagnosticsReturnsErrorOnNon200(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"trace pipeline diagnostics unavailable"}`))
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDiagnostics([]string{
		"--base-url", server.URL,
		"--auth-header", "X-OngoingAI-Gateway-Key",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDiagnostics() code=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "status 503") || !strings.Contains(stderr.String(), "trace pipeline diagnostics unavailable") {
		t.Fatalf("stderr=%q, want status and error message", stderr.String())
	}
}
