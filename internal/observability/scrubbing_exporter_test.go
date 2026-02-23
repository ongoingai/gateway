package observability

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// recordingExporter captures exported spans for test assertions.
type recordingExporter struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

func (e *recordingExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = append(e.spans, spans...)
	return nil
}

func (e *recordingExporter) Shutdown(_ context.Context) error { return nil }

func (e *recordingExporter) Spans() []sdktrace.ReadOnlySpan {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]sdktrace.ReadOnlySpan(nil), e.spans...)
}

func TestScrubbingExporterRemovesCredentialFromAttribute(t *testing.T) {
	t.Parallel()

	inner := &recordingExporter{}
	exporter := newScrubbingExporter(inner)

	stub := tracetest.SpanStub{
		Name: "test.span",
		Attributes: []attribute.KeyValue{
			attribute.String("error.message", "auth failed with key sk_live_abc123def456"),
			attribute.String("safe.attr", "openai"),
			attribute.Int("batch_size", 5),
		},
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{1},
			SpanID:  trace.SpanID{1},
		}),
	}

	err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{stub.Snapshot()})
	if err != nil {
		t.Fatalf("ExportSpans() error: %v", err)
	}

	spans := inner.Spans()
	if len(spans) != 1 {
		t.Fatalf("exported spans=%d, want 1", len(spans))
	}

	attrs := spanAttrMap(spans[0])
	if got := attrs["error.message"]; got != "auth failed with key [CREDENTIAL_REDACTED]" {
		t.Fatalf("error.message=%q, want credential scrubbed", got)
	}
	if got := attrs["safe.attr"]; got != "openai" {
		t.Fatalf("safe.attr=%q, want %q", got, "openai")
	}
	if got := attrs["batch_size"]; got != "5" {
		t.Fatalf("batch_size=%q, want %q", got, "5")
	}
}

func TestScrubbingExporterCleanSpanPassesThrough(t *testing.T) {
	t.Parallel()

	inner := &recordingExporter{}
	exporter := newScrubbingExporter(inner)

	stub := tracetest.SpanStub{
		Name: "gateway.route",
		Attributes: []attribute.KeyValue{
			attribute.String("gateway.route.provider", "openai"),
			attribute.String("gateway.org_id", "org-test"),
			attribute.Int("http.status_code", 200),
		},
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{2},
			SpanID:  trace.SpanID{2},
		}),
	}

	err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{stub.Snapshot()})
	if err != nil {
		t.Fatalf("ExportSpans() error: %v", err)
	}

	spans := inner.Spans()
	if len(spans) != 1 {
		t.Fatalf("exported spans=%d, want 1", len(spans))
	}

	attrs := spanAttrMap(spans[0])
	if got := attrs["gateway.route.provider"]; got != "openai" {
		t.Fatalf("gateway.route.provider=%q, want %q", got, "openai")
	}
	if got := attrs["gateway.org_id"]; got != "org-test" {
		t.Fatalf("gateway.org_id=%q, want %q", got, "org-test")
	}
}

func TestScrubbingExporterScrubsEventAttributes(t *testing.T) {
	t.Parallel()

	inner := &recordingExporter{}
	exporter := newScrubbingExporter(inner)

	stub := tracetest.SpanStub{
		Name: "test.span",
		Attributes: []attribute.KeyValue{
			attribute.String("safe.attr", "clean"),
		},
		Events: []sdktrace.Event{
			{
				Name: "error",
				Time: time.Now(),
				Attributes: []attribute.KeyValue{
					attribute.String("error.detail", "failed with token=my_secret_token_value"),
				},
			},
		},
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{3},
			SpanID:  trace.SpanID{3},
		}),
	}

	err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{stub.Snapshot()})
	if err != nil {
		t.Fatalf("ExportSpans() error: %v", err)
	}

	spans := inner.Spans()
	if len(spans) != 1 {
		t.Fatalf("exported spans=%d, want 1", len(spans))
	}

	events := spans[0].Events()
	if len(events) != 1 {
		t.Fatalf("events=%d, want 1", len(events))
	}
	for _, a := range events[0].Attributes {
		if string(a.Key) == "error.detail" {
			if ContainsCredential(a.Value.AsString()) {
				t.Fatalf("event attribute %q still contains credential: %q", a.Key, a.Value.AsString())
			}
			return
		}
	}
	t.Fatal("missing error.detail event attribute")
}

func TestScrubbingExporterScrubsStatusDescription(t *testing.T) {
	t.Parallel()

	inner := &recordingExporter{}
	exporter := newScrubbingExporter(inner)

	stub := tracetest.SpanStub{
		Name: "test.span",
		Attributes: []attribute.KeyValue{
			attribute.String("safe", "value"),
		},
		Status: sdktrace.Status{
			Code:        codes.Error,
			Description: "connection to password=supersecret123 failed",
		},
		SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{4},
			SpanID:  trace.SpanID{4},
		}),
	}

	err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{stub.Snapshot()})
	if err != nil {
		t.Fatalf("ExportSpans() error: %v", err)
	}

	spans := inner.Spans()
	if len(spans) != 1 {
		t.Fatalf("exported spans=%d, want 1", len(spans))
	}

	status := spans[0].Status()
	if ContainsCredential(status.Description) {
		t.Fatalf("status description still contains credential: %q", status.Description)
	}
	if status.Code != codes.Error {
		t.Fatalf("status code=%v, want %v", status.Code, codes.Error)
	}
}

func TestScrubbingExporterShutdownDelegates(t *testing.T) {
	t.Parallel()

	inner := &recordingExporter{}
	exporter := newScrubbingExporter(inner)

	if err := exporter.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
}
