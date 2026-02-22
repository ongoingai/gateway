package observability

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/correlation"
	"github.com/ongoingai/gateway/internal/pathutil"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	instrumentationName = "ongoingai.gateway"
)

// Runtime exposes OpenTelemetry HTTP wrappers and gateway metric hooks.
type Runtime struct {
	enabled bool

	traceQueueDroppedCounter metric.Int64Counter
	traceWriteFailedCounter  metric.Int64Counter

	shutdownFns []func(context.Context) error
}

// Setup initializes OpenTelemetry providers and runtime hooks.
func Setup(ctx context.Context, cfg config.OTelConfig, serviceVersion string, logger *slog.Logger) (*Runtime, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	runtime := &Runtime{}
	if !cfg.Enabled {
		return runtime, nil
	}

	exportTimeout := time.Duration(cfg.ExportTimeoutMS) * time.Millisecond
	metricInterval := time.Duration(cfg.MetricExportIntervalMS) * time.Millisecond
	otlpEndpoint, inferredInsecure, err := normalizeOTLPEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	insecure := cfg.Insecure
	if strings.Contains(strings.TrimSpace(cfg.Endpoint), "://") {
		// Endpoint URLs carry explicit transport intent and win over the
		// insecure toggle to avoid mismatches like https endpoints + insecure=true.
		insecure = inferredInsecure
	}

	res := resource.NewSchemaless(
		attribute.String("service.name", strings.TrimSpace(cfg.ServiceName)),
		attribute.String("service.version", strings.TrimSpace(serviceVersion)),
	)

	if cfg.TracesEnabled {
		traceExporterOptions := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(otlpEndpoint),
			otlptracehttp.WithTimeout(exportTimeout),
		}
		if insecure {
			traceExporterOptions = append(traceExporterOptions, otlptracehttp.WithInsecure())
		}
		traceExporter, err := otlptracehttp.New(ctx, traceExporterOptions...)
		if err != nil {
			return nil, fmt.Errorf("initialize otel trace exporter: %w", err)
		}

		tracerProvider := sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SamplingRatio))),
			sdktrace.WithBatcher(traceExporter),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tracerProvider)
		runtime.shutdownFns = append(runtime.shutdownFns, tracerProvider.Shutdown)
	}

	if cfg.MetricsEnabled {
		metricExporterOptions := []otlpmetrichttp.Option{
			otlpmetrichttp.WithEndpoint(otlpEndpoint),
			otlpmetrichttp.WithTimeout(exportTimeout),
		}
		if insecure {
			metricExporterOptions = append(metricExporterOptions, otlpmetrichttp.WithInsecure())
		}
		metricExporter, err := otlpmetrichttp.New(ctx, metricExporterOptions...)
		if err != nil {
			_ = runtime.Shutdown(context.Background())
			return nil, fmt.Errorf("initialize otel metric exporter: %w", err)
		}

		reader := sdkmetric.NewPeriodicReader(
			metricExporter,
			sdkmetric.WithInterval(metricInterval),
			sdkmetric.WithTimeout(exportTimeout),
		)
		meterProvider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(reader),
		)
		otel.SetMeterProvider(meterProvider)
		runtime.shutdownFns = append(runtime.shutdownFns, meterProvider.Shutdown)
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})

	meter := otel.Meter(instrumentationName)
	traceQueueDroppedCounter, metricErr := meter.Int64Counter(
		"ongoingai.trace.queue_dropped_total",
		metric.WithDescription("Count of traces dropped because the async trace queue was full."),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry counter", "metric", "ongoingai.trace.queue_dropped_total", "error", metricErr)
	}
	runtime.traceQueueDroppedCounter = traceQueueDroppedCounter

	traceWriteFailedCounter, metricErr := meter.Int64Counter(
		"ongoingai.trace.write_failed_total",
		metric.WithDescription("Count of trace records dropped after storage write failures."),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry counter", "metric", "ongoingai.trace.write_failed_total", "error", metricErr)
	}
	runtime.traceWriteFailedCounter = traceWriteFailedCounter

	runtime.enabled = true
	if logger != nil {
		logger.Info(
			"opentelemetry enabled",
			"otel_endpoint", otlpEndpoint,
			"otel_traces_enabled", cfg.TracesEnabled,
			"otel_metrics_enabled", cfg.MetricsEnabled,
			"otel_sampling_ratio", cfg.SamplingRatio,
		)
	}

	return runtime, nil
}

// Enabled reports whether OpenTelemetry instrumentation is active.
func (r *Runtime) Enabled() bool {
	return r != nil && r.enabled
}

// WrapHTTPHandler wraps an inbound HTTP handler with OpenTelemetry spans.
func (r *Runtime) WrapHTTPHandler(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if !r.Enabled() {
		return next
	}
	return otelhttp.NewHandler(
		next,
		"gateway.request",
		otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
			return serverSpanName(req.Method, req.URL.Path)
		}),
	)
}

// SpanEnrichmentMiddleware adds gateway attributes and stable error status on 5xx responses.
func (r *Runtime) SpanEnrichmentMiddleware(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if !r.Enabled() {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		recorder := &statusCapturingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, req)

		span := oteltrace.SpanFromContext(req.Context())
		if span == nil || !span.IsRecording() {
			return
		}

		statusCode := recorder.StatusCode()
		if statusCode >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, fmt.Sprintf("http %d", statusCode))
		}

		attrs := make([]attribute.KeyValue, 0, 5)
		if correlationID, ok := correlation.FromContext(req.Context()); ok {
			attrs = append(attrs, attribute.String("gateway.correlation_id", correlationID))
		}

		identity, ok := auth.IdentityFromContext(req.Context())
		if ok && identity != nil {
			if orgID := strings.TrimSpace(identity.OrgID); orgID != "" {
				attrs = append(attrs, attribute.String("gateway.org_id", orgID))
			}
			if workspaceID := strings.TrimSpace(identity.WorkspaceID); workspaceID != "" {
				attrs = append(attrs, attribute.String("gateway.workspace_id", workspaceID))
			}
			if gatewayKeyID := strings.TrimSpace(identity.KeyID); gatewayKeyID != "" {
				attrs = append(attrs, attribute.String("gateway.key_id", gatewayKeyID))
			}
			if role := strings.TrimSpace(identity.Role); role != "" {
				attrs = append(attrs, attribute.String("gateway.role", role))
			}
		}
		if len(attrs) > 0 {
			span.SetAttributes(attrs...)
		}
	})
}

// WrapHTTPTransport wraps an outbound HTTP transport with OpenTelemetry spans.
func (r *Runtime) WrapHTTPTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if !r.Enabled() {
		return base
	}
	return otelhttp.NewTransport(
		base,
		otelhttp.WithSpanNameFormatter(func(_ string, req *http.Request) string {
			return clientSpanName(req.Method, req.URL.Path)
		}),
	)
}

// RecordTraceQueueDrop increments a counter when the async trace queue is full.
func (r *Runtime) RecordTraceQueueDrop(path string, status int) {
	if !r.Enabled() || r.traceQueueDroppedCounter == nil {
		return
	}
	r.traceQueueDroppedCounter.Add(
		context.Background(),
		1,
		metric.WithAttributes(
			attribute.String("route", routePatternForPath(path)),
			attribute.Int("status_code", status),
		),
	)
}

// RecordTraceWriteFailure increments a counter for dropped trace records.
func (r *Runtime) RecordTraceWriteFailure(operation string, failedCount int) {
	if !r.Enabled() || failedCount <= 0 || r.traceWriteFailedCounter == nil {
		return
	}
	r.traceWriteFailedCounter.Add(
		context.Background(),
		int64(failedCount),
		metric.WithAttributes(attribute.String("operation", strings.TrimSpace(operation))),
	)
}

// Shutdown flushes and stops OpenTelemetry providers.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil || len(r.shutdownFns) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var errs []error
	for i := len(r.shutdownFns) - 1; i >= 0; i-- {
		if err := r.shutdownFns[i](ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func normalizeOTLPEndpoint(raw string) (string, bool, error) {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return "", false, errors.New("observability.otel.endpoint must not be empty")
	}

	if !strings.Contains(endpoint, "://") {
		return endpoint, false, nil
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", false, fmt.Errorf("parse observability.otel.endpoint: %w", err)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", false, fmt.Errorf("observability.otel.endpoint must include host (got %q)", raw)
	}

	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "http":
		return parsed.Host, true, nil
	case "https":
		return parsed.Host, false, nil
	default:
		return "", false, fmt.Errorf("observability.otel.endpoint scheme must be http or https when provided (got %q)", parsed.Scheme)
	}
}

func routePatternForPath(path string) string {
	switch {
	case pathutil.HasPathPrefix(path, "/openai"):
		return "/openai/*"
	case pathutil.HasPathPrefix(path, "/anthropic"):
		return "/anthropic/*"
	case pathutil.HasPathPrefix(path, "/api"):
		return "/api/*"
	default:
		return "/other"
	}
}

func serverSpanName(method, path string) string {
	return normalizedMethod(method) + " " + routePatternForPath(path)
}

func clientSpanName(method, path string) string {
	return "proxy " + normalizedMethod(method) + " " + routePatternForPath(path)
}

func normalizedMethod(method string) string {
	method = strings.TrimSpace(method)
	if method == "" {
		return "UNKNOWN"
	}
	return method
}

type statusCapturingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// Unwrap lets http.ResponseController discover optional interfaces provided by
// the underlying writer (for example SetWriteDeadline).
func (w *statusCapturingResponseWriter) Unwrap() http.ResponseWriter {
	if w == nil {
		return nil
	}
	return w.ResponseWriter
}

func (w *statusCapturingResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *statusCapturingResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusCapturingResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusCapturingResponseWriter) StatusCode() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

func (w *statusCapturingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusCapturingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *statusCapturingResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (w *statusCapturingResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	readerFrom, ok := w.ResponseWriter.(io.ReaderFrom)
	if !ok {
		return io.Copy(w.ResponseWriter, r)
	}
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return readerFrom.ReadFrom(r)
}
