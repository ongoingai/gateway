package observability

import (
	"context"
	"log/slog"

	oteltrace "go.opentelemetry.io/otel/trace"
)

// traceLogHandler wraps an slog.Handler and enriches log records with
// trace_id and span_id when an active OpenTelemetry span is present in
// the context. This enables operators to correlate structured log lines
// with distributed traces.
type traceLogHandler struct {
	inner slog.Handler
}

// NewTraceLogHandler returns an slog.Handler that injects trace_id and
// span_id attributes from the context's active span into each log record.
// If inner is nil, slog.Default().Handler() is used.
func NewTraceLogHandler(inner slog.Handler) slog.Handler {
	if inner == nil {
		inner = slog.Default().Handler()
	}
	return &traceLogHandler{inner: inner}
}

func (h *traceLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *traceLogHandler) Handle(ctx context.Context, record slog.Record) error {
	span := oteltrace.SpanFromContext(ctx)
	if span != nil && span.SpanContext().IsValid() && span.IsRecording() {
		sc := span.SpanContext()
		record.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.inner.Handle(ctx, record)
}

func (h *traceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceLogHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *traceLogHandler) WithGroup(name string) slog.Handler {
	return &traceLogHandler{inner: h.inner.WithGroup(name)}
}
