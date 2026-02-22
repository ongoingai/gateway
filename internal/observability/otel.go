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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
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
	tracer  oteltrace.Tracer

	traceQueueDroppedCounter     metric.Int64Counter
	traceWriteFailedCounter      metric.Int64Counter
	traceEnqueuedCounter         metric.Int64Counter
	traceWrittenCounter          metric.Int64Counter
	traceFlushLatencyHistogram   metric.Float64Histogram
	traceBatchSizeHistogram      metric.Int64Histogram

	providerRequestCounter           metric.Int64Counter
	providerRequestDurationHistogram metric.Float64Histogram

	proxyRequestCounter           metric.Int64Counter
	proxyRequestDurationHistogram metric.Float64Histogram

	prometheusHandler http.Handler

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

	// OTLP endpoint is only needed when traces or OTLP metrics push is enabled.
	var otlpEndpoint string
	insecure := cfg.Insecure
	if cfg.TracesEnabled || cfg.MetricsEnabled {
		var inferredInsecure bool
		var err error
		otlpEndpoint, inferredInsecure, err = normalizeOTLPEndpoint(cfg.Endpoint)
		if err != nil {
			return nil, err
		}
		if strings.Contains(strings.TrimSpace(cfg.Endpoint), "://") {
			// Endpoint URLs carry explicit transport intent and win over the
			// insecure toggle to avoid mismatches like https endpoints + insecure=true.
			insecure = inferredInsecure
		}
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

	var meterOpts []sdkmetric.Option
	meterOpts = append(meterOpts, sdkmetric.WithResource(res))

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
		meterOpts = append(meterOpts, sdkmetric.WithReader(reader))
	}

	if cfg.PrometheusEnabled {
		reg := prometheus.NewRegistry()
		promReader, err := promexporter.New(promexporter.WithRegisterer(reg))
		if err != nil {
			_ = runtime.Shutdown(context.Background())
			return nil, fmt.Errorf("initialize prometheus metric exporter: %w", err)
		}
		meterOpts = append(meterOpts, sdkmetric.WithReader(promReader))
		runtime.prometheusHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	}

	if cfg.MetricsEnabled || cfg.PrometheusEnabled {
		meterProvider := sdkmetric.NewMeterProvider(meterOpts...)
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

	traceEnqueuedCounter, metricErr := meter.Int64Counter(
		"ongoingai.trace.enqueued_total",
		metric.WithDescription("Count of traces successfully enqueued to the async write queue."),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry counter", "metric", "ongoingai.trace.enqueued_total", "error", metricErr)
	}
	runtime.traceEnqueuedCounter = traceEnqueuedCounter

	traceFlushLatencyHistogram, metricErr := meter.Float64Histogram(
		"ongoingai.trace.flush_duration_seconds",
		metric.WithDescription("Time to flush a batch of traces to storage."),
		metric.WithUnit("s"),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry histogram", "metric", "ongoingai.trace.flush_duration_seconds", "error", metricErr)
	}
	runtime.traceFlushLatencyHistogram = traceFlushLatencyHistogram

	traceBatchSizeHistogram, metricErr := meter.Int64Histogram(
		"ongoingai.trace.flush_batch_size",
		metric.WithDescription("Number of traces per flush batch."),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry histogram", "metric", "ongoingai.trace.flush_batch_size", "error", metricErr)
	}
	runtime.traceBatchSizeHistogram = traceBatchSizeHistogram

	traceWrittenCounter, metricErr := meter.Int64Counter(
		"ongoingai.trace.written_total",
		metric.WithDescription("Count of traces successfully persisted to storage."),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry counter", "metric", "ongoingai.trace.written_total", "error", metricErr)
	}
	runtime.traceWrittenCounter = traceWrittenCounter

	providerRequestCounter, metricErr := meter.Int64Counter(
		"ongoingai.provider.request_total",
		metric.WithDescription("Count of upstream provider requests."),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry counter", "metric", "ongoingai.provider.request_total", "error", metricErr)
	}
	runtime.providerRequestCounter = providerRequestCounter

	providerRequestDurationHistogram, metricErr := meter.Float64Histogram(
		"ongoingai.provider.request_duration_seconds",
		metric.WithDescription("Upstream provider request duration."),
		metric.WithUnit("s"),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry histogram", "metric", "ongoingai.provider.request_duration_seconds", "error", metricErr)
	}
	runtime.providerRequestDurationHistogram = providerRequestDurationHistogram

	proxyRequestCounter, metricErr := meter.Int64Counter(
		"ongoingai.proxy.request_total",
		metric.WithDescription("Count of proxy requests with tenant scoping."),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry counter", "metric", "ongoingai.proxy.request_total", "error", metricErr)
	}
	runtime.proxyRequestCounter = proxyRequestCounter

	proxyRequestDurationHistogram, metricErr := meter.Float64Histogram(
		"ongoingai.proxy.request_duration_seconds",
		metric.WithDescription("Proxy request duration with tenant scoping."),
		metric.WithUnit("s"),
	)
	if metricErr != nil && logger != nil {
		logger.Warn("failed to create opentelemetry histogram", "metric", "ongoingai.proxy.request_duration_seconds", "error", metricErr)
	}
	runtime.proxyRequestDurationHistogram = proxyRequestDurationHistogram

	runtime.tracer = otel.Tracer(instrumentationName)
	runtime.enabled = true
	if logger != nil {
		logger.Info(
			"opentelemetry enabled",
			"otel_endpoint", otlpEndpoint,
			"otel_traces_enabled", cfg.TracesEnabled,
			"otel_metrics_enabled", cfg.MetricsEnabled,
			"otel_prometheus_enabled", cfg.PrometheusEnabled,
			"otel_sampling_ratio", cfg.SamplingRatio,
		)
	}

	return runtime, nil
}

// Enabled reports whether OpenTelemetry instrumentation is active.
func (r *Runtime) Enabled() bool {
	return r != nil && r.enabled
}

// PrometheusHandler returns the HTTP handler for Prometheus metric scraping,
// or nil when Prometheus export is not enabled.
func (r *Runtime) PrometheusHandler() http.Handler {
	if r == nil {
		return nil
	}
	return r.prometheusHandler
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

// WrapAuthMiddleware wraps an auth handler with a gateway.auth child span.
// The span records whether the auth check allowed or denied the request.
func (r *Runtime) WrapAuthMiddleware(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if !r.Enabled() {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx, span := r.tracer.Start(req.Context(), "gateway.auth")
		defer span.End()

		recorder := &statusCapturingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, req.WithContext(ctx))

		statusCode := recorder.StatusCode()
		switch {
		case statusCode == http.StatusUnauthorized:
			span.SetAttributes(
				attribute.String("gateway.auth.result", "deny"),
				attribute.String("gateway.auth.deny_reason", "unauthorized"),
			)
			span.SetStatus(codes.Error, "unauthorized")
		case statusCode == http.StatusForbidden:
			span.SetAttributes(
				attribute.String("gateway.auth.result", "deny"),
				attribute.String("gateway.auth.deny_reason", "forbidden"),
			)
			span.SetStatus(codes.Error, "forbidden")
		default:
			span.SetAttributes(attribute.String("gateway.auth.result", "allow"))
		}
	})
}

// WrapRouteSpan wraps a proxy handler with a gateway.route child span.
// The provider and prefix are inferred from the request path.
func (r *Runtime) WrapRouteSpan(next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if !r.Enabled() {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		provider, prefix := providerForPath(req.URL.Path)
		ctx, span := r.tracer.Start(req.Context(), "gateway.route")
		defer span.End()

		span.SetAttributes(
			attribute.String("gateway.route.provider", provider),
			attribute.String("gateway.route.prefix", prefix),
		)

		recorder := &statusCapturingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, req.WithContext(ctx))

		if recorder.StatusCode() >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, fmt.Sprintf("http %d", recorder.StatusCode()))
		}

		if identity, ok := auth.IdentityFromContext(req.Context()); ok && identity != nil {
			if orgID := strings.TrimSpace(identity.OrgID); orgID != "" {
				span.SetAttributes(attribute.String("gateway.org_id", orgID))
			}
			if workspaceID := strings.TrimSpace(identity.WorkspaceID); workspaceID != "" {
				span.SetAttributes(attribute.String("gateway.workspace_id", workspaceID))
			}
		}
	})
}

// StartTraceEnqueueSpan starts a gateway.trace.enqueue span as a child of
// the provided context. The returned function must be called to end the span,
// passing whether the enqueue was accepted.
func (r *Runtime) StartTraceEnqueueSpan(ctx context.Context) (context.Context, func(accepted bool)) {
	if !r.Enabled() {
		return ctx, func(bool) {}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, span := r.tracer.Start(ctx, "gateway.trace.enqueue")
	if identity, ok := auth.IdentityFromContext(ctx); ok && identity != nil {
		if orgID := strings.TrimSpace(identity.OrgID); orgID != "" {
			span.SetAttributes(attribute.String("gateway.org_id", orgID))
		}
		if workspaceID := strings.TrimSpace(identity.WorkspaceID); workspaceID != "" {
			span.SetAttributes(attribute.String("gateway.workspace_id", workspaceID))
		}
	}
	return ctx, func(accepted bool) {
		if accepted {
			span.SetAttributes(attribute.String("gateway.trace.enqueue.result", "accepted"))
		} else {
			span.SetAttributes(attribute.String("gateway.trace.enqueue.result", "dropped"))
			span.SetStatus(codes.Error, "trace dropped")
		}
		span.End()
	}
}

// MakeWriteSpanHook returns a function suitable for WriterMetrics.OnWriteStart.
// Each invocation starts a top-level gateway.trace.write span and returns an
// end function the writer calls after the storage write completes.
func (r *Runtime) MakeWriteSpanHook() func(batchSize int) func(error) {
	if !r.Enabled() {
		return nil
	}
	return func(batchSize int) func(error) {
		_, span := r.tracer.Start(context.Background(), "gateway.trace.write")
		span.SetAttributes(attribute.Int("gateway.trace.write.batch_size", batchSize))
		return func(err error) {
			if err != nil {
				span.SetAttributes(attribute.String("gateway.trace.write.error_class", err.Error()))
				span.SetStatus(codes.Error, "write failed")
			}
			span.End()
		}
	}
}

func providerForPath(path string) (provider, prefix string) {
	switch {
	case pathutil.HasPathPrefix(path, "/openai"):
		return "openai", "/openai"
	case pathutil.HasPathPrefix(path, "/anthropic"):
		return "anthropic", "/anthropic"
	default:
		return "unknown", "/"
	}
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
func (r *Runtime) RecordTraceQueueDrop(provider, orgID, workspaceID, path string, status int) {
	if !r.Enabled() || r.traceQueueDroppedCounter == nil {
		return
	}
	r.traceQueueDroppedCounter.Add(
		context.Background(),
		1,
		metric.WithAttributes(
			attribute.String("provider", strings.TrimSpace(provider)),
			attribute.String("org_id", strings.TrimSpace(orgID)),
			attribute.String("workspace_id", strings.TrimSpace(workspaceID)),
			attribute.String("route", routePatternForPath(path)),
			attribute.Int("status_code", status),
		),
	)
}

// RecordTraceWriteFailure increments a counter for dropped trace records.
func (r *Runtime) RecordTraceWriteFailure(operation string, failedCount int, errorClass string, store string) {
	if !r.Enabled() || failedCount <= 0 || r.traceWriteFailedCounter == nil {
		return
	}
	r.traceWriteFailedCounter.Add(
		context.Background(),
		int64(failedCount),
		metric.WithAttributes(
			attribute.String("operation", strings.TrimSpace(operation)),
			attribute.String("error_class", strings.TrimSpace(errorClass)),
			attribute.String("store", strings.TrimSpace(store)),
		),
	)
}

// RecordTraceEnqueued increments a counter when a trace is successfully enqueued.
func (r *Runtime) RecordTraceEnqueued() {
	if !r.Enabled() || r.traceEnqueuedCounter == nil {
		return
	}
	r.traceEnqueuedCounter.Add(context.Background(), 1)
}

// RecordTraceFlush records a batch flush event with its size and duration.
func (r *Runtime) RecordTraceFlush(batchSize int, duration time.Duration) {
	if !r.Enabled() || batchSize <= 0 {
		return
	}
	ctx := context.Background()
	if r.traceBatchSizeHistogram != nil {
		r.traceBatchSizeHistogram.Record(ctx, int64(batchSize))
	}
	if r.traceFlushLatencyHistogram != nil {
		r.traceFlushLatencyHistogram.Record(ctx, duration.Seconds())
	}
}

// RecordProviderRequest records a single upstream provider request with its
// status code and latency.
func (r *Runtime) RecordProviderRequest(provider, model string, statusCode int, durationMS int64) {
	if !r.Enabled() {
		return
	}
	ctx := context.Background()
	provider = strings.TrimSpace(provider)
	model = strings.TrimSpace(model)
	if r.providerRequestCounter != nil {
		r.providerRequestCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("provider", provider),
			attribute.String("model", model),
			attribute.Int("status_code", statusCode),
		))
	}
	if r.providerRequestDurationHistogram != nil {
		r.providerRequestDurationHistogram.Record(ctx, float64(durationMS)/1000.0, metric.WithAttributes(
			attribute.String("provider", provider),
			attribute.String("model", model),
		))
	}
}

// RegisterTraceQueueDepthGauge registers an async gauge that reports the
// current trace write queue depth each collection cycle.
func (r *Runtime) RegisterTraceQueueDepthGauge(queueLenFn func() int) {
	if !r.Enabled() || queueLenFn == nil {
		return
	}
	meter := otel.Meter(instrumentationName)
	gauge, err := meter.Int64ObservableGauge(
		"ongoingai.trace.queue_depth",
		metric.WithDescription("Current number of traces waiting in the async write queue."),
	)
	if err != nil {
		return
	}
	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(gauge, int64(queueLenFn()))
		return nil
	}, gauge)
	if err != nil {
		return
	}
}

// RecordTraceWritten increments a counter for traces successfully persisted.
func (r *Runtime) RecordTraceWritten(count int) {
	if !r.Enabled() || count <= 0 || r.traceWrittenCounter == nil {
		return
	}
	r.traceWrittenCounter.Add(context.Background(), int64(count))
}

// RegisterTraceQueueCapacityGauge registers an async gauge that reports the
// trace write queue capacity each collection cycle.
func (r *Runtime) RegisterTraceQueueCapacityGauge(capacityFn func() int) {
	if !r.Enabled() || capacityFn == nil {
		return
	}
	meter := otel.Meter(instrumentationName)
	gauge, err := meter.Int64ObservableGauge(
		"ongoingai.trace.queue_capacity",
		metric.WithDescription("Capacity of the async trace write queue."),
	)
	if err != nil {
		return
	}
	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(gauge, int64(capacityFn()))
		return nil
	}, gauge)
	if err != nil {
		return
	}
}

// RecordProxyRequest records a proxy request with tenant-scoped attributes.
func (r *Runtime) RecordProxyRequest(provider, orgID, workspaceID, path string, statusCode int, durationMS int64) {
	if !r.Enabled() {
		return
	}
	ctx := context.Background()
	route := routePatternForPath(path)
	if r.proxyRequestCounter != nil {
		r.proxyRequestCounter.Add(ctx, 1, metric.WithAttributes(
			attribute.String("provider", strings.TrimSpace(provider)),
			attribute.String("org_id", strings.TrimSpace(orgID)),
			attribute.String("workspace_id", strings.TrimSpace(workspaceID)),
			attribute.String("route", route),
			attribute.Int("status_code", statusCode),
		))
	}
	if r.proxyRequestDurationHistogram != nil {
		r.proxyRequestDurationHistogram.Record(ctx, float64(durationMS)/1000.0, metric.WithAttributes(
			attribute.String("provider", strings.TrimSpace(provider)),
			attribute.String("org_id", strings.TrimSpace(orgID)),
			attribute.String("workspace_id", strings.TrimSpace(workspaceID)),
			attribute.String("route", route),
		))
	}
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
