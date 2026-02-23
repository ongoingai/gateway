package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTraceLogHandlerAddsTraceIDAndSpanID(t *testing.T) {
	t.Parallel()

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	var buf bytes.Buffer
	handler := NewTraceLogHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger := slog.New(handler)

	ctx, span := tp.Tracer("test").Start(context.Background(), "test.span")
	defer span.End()

	logger.InfoContext(ctx, "with trace context", "extra", "value")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	traceID, ok := entry["trace_id"].(string)
	if !ok || len(traceID) != 32 {
		t.Fatalf("trace_id=%q, want 32 hex chars", traceID)
	}
	spanID, ok := entry["span_id"].(string)
	if !ok || len(spanID) != 16 {
		t.Fatalf("span_id=%q, want 16 hex chars", spanID)
	}
	if extra, ok := entry["extra"].(string); !ok || extra != "value" {
		t.Fatalf("extra=%q, want %q", entry["extra"], "value")
	}
}

func TestTraceLogHandlerNoSpanOmitsTraceAttrs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := NewTraceLogHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger := slog.New(handler)

	logger.InfoContext(context.Background(), "no span")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	if _, ok := entry["trace_id"]; ok {
		t.Fatal("trace_id should not be present without active span")
	}
	if _, ok := entry["span_id"]; ok {
		t.Fatal("span_id should not be present without active span")
	}
}

func TestTraceLogHandlerNoContextOmitsTraceAttrs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := NewTraceLogHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger := slog.New(handler)

	// logger.Info() passes context.Background() internally.
	logger.Info("no context")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	if _, ok := entry["trace_id"]; ok {
		t.Fatal("trace_id should not be present without context span")
	}
	if _, ok := entry["span_id"]; ok {
		t.Fatal("span_id should not be present without context span")
	}
}

func TestTraceLogHandlerEnabledDelegatesToInner(t *testing.T) {
	t.Parallel()

	handler := NewTraceLogHandler(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("expected Info to be disabled when inner level is Warn")
	}
	if !handler.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("expected Warn to be enabled when inner level is Warn")
	}
	if !handler.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("expected Error to be enabled when inner level is Warn")
	}
}

func TestTraceLogHandlerWithAttrsPreservesBaseAndTraceAttrs(t *testing.T) {
	t.Parallel()

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	var buf bytes.Buffer
	handler := NewTraceLogHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	derived := handler.WithAttrs([]slog.Attr{slog.String("service", "gateway")})
	logger := slog.New(derived)

	ctx, span := tp.Tracer("test").Start(context.Background(), "test.span")
	defer span.End()

	logger.InfoContext(ctx, "with base attrs")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}

	if svc, ok := entry["service"].(string); !ok || svc != "gateway" {
		t.Fatalf("service=%q, want %q", entry["service"], "gateway")
	}
	if _, ok := entry["trace_id"].(string); !ok {
		t.Fatal("trace_id missing after WithAttrs")
	}
	if _, ok := entry["span_id"].(string); !ok {
		t.Fatal("span_id missing after WithAttrs")
	}
}

func TestTraceLogHandlerWithGroupPreservesTraceAttrs(t *testing.T) {
	t.Parallel()

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	var buf bytes.Buffer
	handler := NewTraceLogHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	grouped := handler.WithGroup("subsystem")
	logger := slog.New(grouped)

	ctx, span := tp.Tracer("test").Start(context.Background(), "test.span")
	defer span.End()

	logger.InfoContext(ctx, "grouped log", "key", "val")

	output := buf.String()
	// trace_id and span_id should appear in the output (they'll be inside the group).
	if !strings.Contains(output, "trace_id") {
		t.Fatal("trace_id missing in grouped output")
	}
	if !strings.Contains(output, "span_id") {
		t.Fatal("span_id missing in grouped output")
	}
}

func TestNewTraceLogHandlerNilFallback(t *testing.T) {
	t.Parallel()

	handler := NewTraceLogHandler(nil)
	if handler == nil {
		t.Fatal("NewTraceLogHandler(nil) returned nil")
	}
	// Should not panic.
	logger := slog.New(handler)
	logger.Info("nil fallback test")
}
