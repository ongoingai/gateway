package observability

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// scrubbingExporter wraps a SpanExporter and sanitizes all string attribute
// values before they leave the process. This provides defense-in-depth
// against credential material leaking into telemetry exports.
//
// The scrubbing runs in the async batch export goroutine, not on the
// request hot path, so performance impact is negligible.
type scrubbingExporter struct {
	wrapped sdktrace.SpanExporter
}

// newScrubbingExporter returns a SpanExporter that sanitizes spans before
// delegating to the wrapped exporter.
func newScrubbingExporter(wrapped sdktrace.SpanExporter) sdktrace.SpanExporter {
	return &scrubbingExporter{wrapped: wrapped}
}

// ExportSpans scrubs credential patterns from span attributes, event
// attributes, and status descriptions, then delegates to the wrapped exporter.
// Clean spans pass through with zero allocation.
func (e *scrubbingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	scrubbed := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		scrubbed[i] = scrubSpan(s)
	}
	return e.wrapped.ExportSpans(ctx, scrubbed)
}

// Shutdown delegates to the wrapped exporter.
func (e *scrubbingExporter) Shutdown(ctx context.Context) error {
	return e.wrapped.Shutdown(ctx)
}

// scrubSpan returns the original span if no credential patterns are found,
// or a sanitized copy otherwise.
func scrubSpan(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	if !spanNeedsScrubbing(s) {
		return s
	}

	stub := tracetest.SpanStubFromReadOnlySpan(s)
	stub.Attributes = scrubAttributes(stub.Attributes)

	for i, event := range stub.Events {
		stub.Events[i].Attributes = scrubAttributes(event.Attributes)
	}

	if ContainsCredential(stub.Status.Description) {
		stub.Status.Description = ScrubCredentials(stub.Status.Description)
	}

	return stub.Snapshot()
}

// spanNeedsScrubbing returns true if any string attribute value, event
// attribute, or the status description contains a credential pattern.
func spanNeedsScrubbing(s sdktrace.ReadOnlySpan) bool {
	for _, a := range s.Attributes() {
		if a.Value.Type() == attribute.STRING && ContainsCredential(a.Value.AsString()) {
			return true
		}
	}
	for _, event := range s.Events() {
		for _, a := range event.Attributes {
			if a.Value.Type() == attribute.STRING && ContainsCredential(a.Value.AsString()) {
				return true
			}
		}
	}
	if ContainsCredential(s.Status().Description) {
		return true
	}
	return false
}

// scrubAttributes returns a new slice with credential patterns replaced in
// string attribute values. Non-string attributes are passed through unchanged.
func scrubAttributes(attrs []attribute.KeyValue) []attribute.KeyValue {
	result := make([]attribute.KeyValue, len(attrs))
	for i, a := range attrs {
		if a.Value.Type() == attribute.STRING {
			val := a.Value.AsString()
			if ContainsCredential(val) {
				result[i] = attribute.String(string(a.Key), ScrubCredentials(val))
				continue
			}
		}
		result[i] = a
	}
	return result
}
