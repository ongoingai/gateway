package observability

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/correlation"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNormalizeOTLPEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		wantEndpoint  string
		wantInsecure  bool
		wantErrSubstr string
	}{
		{
			name:         "host and port",
			input:        "collector:4318",
			wantEndpoint: "collector:4318",
		},
		{
			name:         "http url",
			input:        "http://collector:4318",
			wantEndpoint: "collector:4318",
			wantInsecure: true,
		},
		{
			name:         "https url",
			input:        "https://collector:4318",
			wantEndpoint: "collector:4318",
		},
		{
			name:          "invalid scheme",
			input:         "ftp://collector:4318",
			wantErrSubstr: "scheme must be http or https",
		},
		{
			name:          "empty endpoint",
			input:         "   ",
			wantErrSubstr: "must not be empty",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotEndpoint, gotInsecure, err := normalizeOTLPEndpoint(tt.input)
			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("normalizeOTLPEndpoint(%q) error=nil, want %q", tt.input, tt.wantErrSubstr)
				}
				if got := err.Error(); !strings.Contains(got, tt.wantErrSubstr) {
					t.Fatalf("error=%q, want substring %q", got, tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeOTLPEndpoint(%q) error=%v", tt.input, err)
			}
			if gotEndpoint != tt.wantEndpoint {
				t.Fatalf("endpoint=%q, want %q", gotEndpoint, tt.wantEndpoint)
			}
			if gotInsecure != tt.wantInsecure {
				t.Fatalf("insecure=%v, want %v", gotInsecure, tt.wantInsecure)
			}
		})
	}
}

func TestRoutePatternForPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want string
	}{
		{path: "/openai/v1/chat/completions", want: "/openai/*"},
		{path: "/anthropic/v1/messages", want: "/anthropic/*"},
		{path: "/api/traces", want: "/api/*"},
		{path: "/custom", want: "/other"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			if got := routePatternForPath(tt.path); got != tt.want {
				t.Fatalf("routePatternForPath(%q)=%q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSpanNames(t *testing.T) {
	t.Parallel()

	if got := serverSpanName("POST", "/openai/v1/chat/completions"); got != "POST /openai/*" {
		t.Fatalf("serverSpanName=%q, want %q", got, "POST /openai/*")
	}
	if got := clientSpanName("POST", "/v1/chat/completions"); got != "proxy POST /other" {
		t.Fatalf("clientSpanName=%q, want %q", got, "proxy POST /other")
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestSpanEnrichmentMiddleware(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		identity      *auth.Identity
		correlationID string
		wantError     bool
		wantAttrs     map[string]string
	}{
		{
			name:          "5xx with full identity sets error status and all attributes",
			statusCode:    http.StatusBadGateway,
			correlationID: "corr-otel-1",
			identity: &auth.Identity{
				KeyID:       "gwk_test_1",
				OrgID:       "org-test",
				WorkspaceID: "workspace-test",
				Role:        "developer",
			},
			wantError: true,
			wantAttrs: map[string]string{
				"gateway.correlation_id": "corr-otel-1",
				"gateway.org_id":         "org-test",
				"gateway.workspace_id":   "workspace-test",
				"gateway.key_id":         "gwk_test_1",
				"gateway.role":           "developer",
			},
		},
		{
			name:       "2xx with full identity sets attributes without error status",
			statusCode: http.StatusOK,
			identity: &auth.Identity{
				KeyID:       "gwk_test_2",
				OrgID:       "org-ok",
				WorkspaceID: "workspace-ok",
				Role:        "admin",
			},
			wantError: false,
			wantAttrs: map[string]string{
				"gateway.org_id":       "org-ok",
				"gateway.workspace_id": "workspace-ok",
				"gateway.key_id":       "gwk_test_2",
				"gateway.role":         "admin",
			},
		},
		{
			name:       "4xx does not set error status",
			statusCode: http.StatusNotFound,
			identity: &auth.Identity{
				KeyID: "gwk_test_3",
				OrgID: "org-notfound",
			},
			wantError: false,
			wantAttrs: map[string]string{
				"gateway.org_id": "org-notfound",
				"gateway.key_id": "gwk_test_3",
			},
		},
		{
			name:          "5xx without identity sets error status only",
			statusCode:    http.StatusServiceUnavailable,
			identity:      nil,
			correlationID: "corr-otel-2",
			wantError:     true,
			wantAttrs:     map[string]string{"gateway.correlation_id": "corr-otel-2"},
		},
		{
			name:       "partial identity emits only populated fields",
			statusCode: http.StatusOK,
			identity:   &auth.Identity{OrgID: "org-only"},
			wantError:  false,
			wantAttrs:  map[string]string{"gateway.org_id": "org-only"},
		},
		{
			name:       "whitespace-only identity fields are omitted",
			statusCode: http.StatusOK,
			identity: &auth.Identity{
				OrgID:       "   ",
				WorkspaceID: "  ",
				KeyID:       " ",
				Role:        "  ",
			},
			wantError: false,
			wantAttrs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldTP := otel.GetTracerProvider()
			defer otel.SetTracerProvider(oldTP)

			recorder := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
			otel.SetTracerProvider(tp)
			defer func() { _ = tp.Shutdown(context.Background()) }()

			runtime := &Runtime{enabled: true}
			handler := runtime.WrapHTTPHandler(runtime.SpanEnrichmentMiddleware(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.statusCode)
				}),
			))

			req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
			if tt.identity != nil {
				req = req.WithContext(auth.WithIdentity(req.Context(), tt.identity))
			}
			if tt.correlationID != "" {
				req = req.WithContext(correlation.WithContext(req.Context(), tt.correlationID))
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)

			spans := recorder.Ended()
			if len(spans) != 1 {
				t.Fatalf("ended spans=%d, want 1", len(spans))
			}

			span := spans[0]
			if tt.wantError && span.Status().Code != codes.Error {
				t.Fatalf("span status=%v, want %v", span.Status().Code, codes.Error)
			}
			if !tt.wantError && span.Status().Code == codes.Error {
				t.Fatalf("span status=%v, want non-error", span.Status().Code)
			}

			attrs := make(map[string]string)
			for _, a := range span.Attributes() {
				key := string(a.Key)
				if strings.HasPrefix(key, "gateway.") {
					attrs[key] = a.Value.AsString()
				}
			}
			for wantKey, wantVal := range tt.wantAttrs {
				if got := attrs[wantKey]; got != wantVal {
					t.Errorf("attr %q=%q, want %q", wantKey, got, wantVal)
				}
			}
			for gotKey := range attrs {
				if _, expected := tt.wantAttrs[gotKey]; !expected {
					t.Errorf("unexpected attr %q=%q", gotKey, attrs[gotKey])
				}
			}
		})
	}
}

func TestRecordTraceWriteFailureIncludesMetricAttributes(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Fatalf("meterProvider.Shutdown() error: %v", err)
		}
	})

	counter, err := meterProvider.Meter("test").Int64Counter("test.trace.write_failed_total")
	if err != nil {
		t.Fatalf("Int64Counter() error: %v", err)
	}

	runtime := &Runtime{
		enabled:                 true,
		traceWriteFailedCounter: counter,
	}

	runtime.RecordTraceWriteFailure("write_batch_fallback", 3, "timeout", "postgres")

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	found := false
	var dataPoint metricdata.DataPoint[int64]
	for _, scope := range metrics.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "test.trace.write_failed_total" {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric data type=%T, want metricdata.Sum[int64]", metric.Data)
			}
			if len(sum.DataPoints) != 1 {
				t.Fatalf("datapoints=%d, want 1", len(sum.DataPoints))
			}
			dataPoint = sum.DataPoints[0]
			found = true
		}
	}
	if !found {
		t.Fatal("missing test.trace.write_failed_total metric")
	}
	if dataPoint.Value != 3 {
		t.Fatalf("value=%d, want 3", dataPoint.Value)
	}

	gotAttrs := make(map[string]string)
	for _, kv := range dataPoint.Attributes.ToSlice() {
		gotAttrs[string(kv.Key)] = kv.Value.AsString()
	}
	wantAttrs := map[string]string{
		"operation":   "write_batch_fallback",
		"error_class": "timeout",
		"store":       "postgres",
	}
	for key, want := range wantAttrs {
		if got := gotAttrs[key]; got != want {
			t.Fatalf("attribute %q=%q, want %q", key, got, want)
		}
	}
	for key, value := range gotAttrs {
		if _, ok := wantAttrs[key]; !ok {
			t.Fatalf("unexpected attribute %q=%q", key, value)
		}
	}
}

func TestRecordTraceQueueDropIncludesTenantAttributes(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Fatalf("meterProvider.Shutdown() error: %v", err)
		}
	})

	counter, err := meterProvider.Meter("test").Int64Counter("test.trace.queue_dropped_total")
	if err != nil {
		t.Fatalf("Int64Counter() error: %v", err)
	}

	runtime := &Runtime{
		enabled:                  true,
		traceQueueDroppedCounter: counter,
	}

	runtime.RecordTraceQueueDrop("openai", "org-drop", "ws-drop", "/openai/v1/chat/completions", 502)

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	found := false
	var dataPoint metricdata.DataPoint[int64]
	for _, scope := range metrics.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "test.trace.queue_dropped_total" {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric data type=%T, want metricdata.Sum[int64]", metric.Data)
			}
			if len(sum.DataPoints) != 1 {
				t.Fatalf("datapoints=%d, want 1", len(sum.DataPoints))
			}
			dataPoint = sum.DataPoints[0]
			found = true
		}
	}
	if !found {
		t.Fatal("missing test.trace.queue_dropped_total metric")
	}
	if dataPoint.Value != 1 {
		t.Fatalf("value=%d, want 1", dataPoint.Value)
	}

	gotAttrs := make(map[string]string)
	for _, kv := range dataPoint.Attributes.ToSlice() {
		gotAttrs[string(kv.Key)] = kv.Value.Emit()
	}
	wantAttrs := map[string]string{
		"provider":     "openai",
		"org_id":       "org-drop",
		"workspace_id": "ws-drop",
		"route":        "/openai/*",
		"status_code":  "502",
	}
	for key, want := range wantAttrs {
		if got := gotAttrs[key]; got != want {
			t.Fatalf("attribute %q=%q, want %q", key, got, want)
		}
	}
	for key, value := range gotAttrs {
		if _, ok := wantAttrs[key]; !ok {
			t.Fatalf("unexpected attribute %q=%q", key, value)
		}
	}
}

func TestRecordProviderRequestIncludesMetricAttributes(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Fatalf("meterProvider.Shutdown() error: %v", err)
		}
	})

	meter := meterProvider.Meter("test")
	counter, err := meter.Int64Counter("test.provider.request_total")
	if err != nil {
		t.Fatalf("Int64Counter() error: %v", err)
	}
	histogram, err := meter.Float64Histogram("test.provider.request_duration_seconds")
	if err != nil {
		t.Fatalf("Float64Histogram() error: %v", err)
	}

	runtime := &Runtime{
		enabled:                          true,
		providerRequestCounter:           counter,
		providerRequestDurationHistogram: histogram,
	}

	runtime.RecordProviderRequest("openai", "gpt-4o", 200, 1250)

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	var counterFound, histogramFound bool
	for _, scope := range metrics.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch m.Name {
			case "test.provider.request_total":
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("counter data type=%T, want metricdata.Sum[int64]", m.Data)
				}
				if len(sum.DataPoints) != 1 {
					t.Fatalf("counter datapoints=%d, want 1", len(sum.DataPoints))
				}
				dp := sum.DataPoints[0]
				if dp.Value != 1 {
					t.Fatalf("counter value=%d, want 1", dp.Value)
				}
				gotAttrs := make(map[string]string)
				for _, kv := range dp.Attributes.ToSlice() {
					gotAttrs[string(kv.Key)] = kv.Value.Emit()
				}
				wantAttrs := map[string]string{
					"provider":    "openai",
					"model":       "gpt-4o",
					"status_code": "200",
				}
				for key, want := range wantAttrs {
					if got := gotAttrs[key]; got != want {
						t.Fatalf("counter attribute %q=%q, want %q", key, got, want)
					}
				}
				for key, value := range gotAttrs {
					if _, ok := wantAttrs[key]; !ok {
						t.Fatalf("unexpected counter attribute %q=%q", key, value)
					}
				}
				counterFound = true

			case "test.provider.request_duration_seconds":
				hist, ok := m.Data.(metricdata.Histogram[float64])
				if !ok {
					t.Fatalf("histogram data type=%T, want metricdata.Histogram[float64]", m.Data)
				}
				if len(hist.DataPoints) != 1 {
					t.Fatalf("histogram datapoints=%d, want 1", len(hist.DataPoints))
				}
				dp := hist.DataPoints[0]
				if dp.Count != 1 {
					t.Fatalf("histogram count=%d, want 1", dp.Count)
				}
				// 1250ms = 1.25s
				wantSum := 1.25
				if dp.Sum < wantSum-0.001 || dp.Sum > wantSum+0.001 {
					t.Fatalf("histogram sum=%f, want ~%f", dp.Sum, wantSum)
				}
				gotAttrs := make(map[string]string)
				for _, kv := range dp.Attributes.ToSlice() {
					gotAttrs[string(kv.Key)] = kv.Value.Emit()
				}
				wantAttrs := map[string]string{
					"provider": "openai",
					"model":    "gpt-4o",
				}
				for key, want := range wantAttrs {
					if got := gotAttrs[key]; got != want {
						t.Fatalf("histogram attribute %q=%q, want %q", key, got, want)
					}
				}
				for key, value := range gotAttrs {
					if _, ok := wantAttrs[key]; !ok {
						t.Fatalf("unexpected histogram attribute %q=%q", key, value)
					}
				}
				histogramFound = true
			}
		}
	}
	if !counterFound {
		t.Fatal("missing test.provider.request_total metric")
	}
	if !histogramFound {
		t.Fatal("missing test.provider.request_duration_seconds metric")
	}
}

// Cannot be parallel: mutates global OTel providers.
//
// The config uses Insecure: false with an http:// endpoint URL, which
// implicitly validates that the scheme-based insecure override in Setup
// works correctly (the connection must be insecure for the export to
// reach the plain HTTP test server).
func TestSetupExportsTracesAndMetrics(t *testing.T) {
	oldTracerProvider := otel.GetTracerProvider()
	oldMeterProvider := otel.GetMeterProvider()
	oldPropagator := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(oldTracerProvider)
		otel.SetMeterProvider(oldMeterProvider)
		otel.SetTextMapPropagator(oldPropagator)
	}()

	var traceRequests atomic.Int64
	var metricRequests atomic.Int64
	var unexpectedPath atomic.Bool
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()

		switch r.URL.Path {
		case "/v1/traces":
			traceRequests.Add(1)
		case "/v1/metrics":
			metricRequests.Add(1)
		default:
			unexpectedPath.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	runtime, err := Setup(context.Background(), config.OTelConfig{
		Enabled:                true,
		Endpoint:               collector.URL,
		Insecure:               false,
		ServiceName:            "ongoingai-gateway-test",
		TracesEnabled:          true,
		MetricsEnabled:         true,
		SamplingRatio:          1.0,
		ExportTimeoutMS:        1000,
		MetricExportIntervalMS: 25,
	}, "test", nil)
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}

	_, span := otel.Tracer("test").Start(context.Background(), "gateway.test")
	span.End()
	runtime.RecordTraceQueueDrop("openai", "org-test", "ws-test", "/openai/v1/chat/completions", http.StatusBadGateway)
	runtime.RecordTraceWriteFailure("write_trace", 2, "unknown", "sqlite")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("runtime.Shutdown() error: %v", err)
	}

	waitFor(t, 2*time.Second, func() bool {
		return traceRequests.Load() > 0 && metricRequests.Load() > 0
	})
	if unexpectedPath.Load() {
		t.Fatal("collector observed unexpected OTLP request path")
	}
}

func waitFor(t *testing.T, timeout time.Duration, predicate func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestStatusCapturingResponseWriterUnwrapSupportsResponseController(t *testing.T) {
	t.Parallel()

	base := &deadlineAwareResponseWriter{
		header: make(http.Header),
	}
	wrapped := &statusCapturingResponseWriter{
		ResponseWriter: base,
	}

	controller := http.NewResponseController(wrapped)
	deadline := time.Now().Add(250 * time.Millisecond)
	if err := controller.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline() error: %v", err)
	}
	if base.writeDeadlineCalls != 1 {
		t.Fatalf("write deadline calls=%d, want 1", base.writeDeadlineCalls)
	}
	if !base.lastWriteDeadline.Equal(deadline) {
		t.Fatalf("write deadline=%v, want %v", base.lastWriteDeadline, deadline)
	}
}

type deadlineAwareResponseWriter struct {
	header             http.Header
	statusCode         int
	writeDeadlineCalls int
	lastWriteDeadline  time.Time
}

func (w *deadlineAwareResponseWriter) Header() http.Header {
	return w.header
}

func (w *deadlineAwareResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return len(p), nil
}

func (w *deadlineAwareResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
}

func (w *deadlineAwareResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if w == nil {
		return errors.New("nil writer")
	}
	w.writeDeadlineCalls++
	w.lastWriteDeadline = deadline
	return nil
}

func TestRuntimeGuardsDoNotPanic(t *testing.T) {
	t.Parallel()

	runtimes := []struct {
		name    string
		runtime *Runtime
	}{
		{name: "nil runtime", runtime: nil},
		{name: "disabled runtime", runtime: &Runtime{enabled: false}},
	}

	for _, tt := range runtimes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.runtime.Enabled() {
				t.Fatal("expected Enabled()=false")
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			wrapped := tt.runtime.WrapHTTPHandler(handler)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, httptest.NewRequest("GET", "/test", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("WrapHTTPHandler pass-through status=%d, want 200", rec.Code)
			}

			enriched := tt.runtime.SpanEnrichmentMiddleware(handler)
			rec = httptest.NewRecorder()
			enriched.ServeHTTP(rec, httptest.NewRequest("GET", "/test", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("SpanEnrichmentMiddleware pass-through status=%d, want 200", rec.Code)
			}

			transport := tt.runtime.WrapHTTPTransport(http.DefaultTransport)
			if transport != http.DefaultTransport {
				t.Fatal("WrapHTTPTransport should return base transport unchanged")
			}

			tt.runtime.RecordTraceQueueDrop("openai", "org-1", "ws-1", "/openai/v1/chat", 502)
			tt.runtime.RecordTraceWriteFailure("write_trace", 5, "unknown", "sqlite")
			tt.runtime.RecordTraceEnqueued()
			tt.runtime.RecordTraceWritten(3)
			tt.runtime.RecordTraceFlush(10, 50*time.Millisecond)
			tt.runtime.RecordProviderRequest("openai", "gpt-4o", 200, 1000)
			tt.runtime.RecordProxyRequest("openai", "org-1", "ws-1", "/openai/v1/chat", 200, 1000)
			tt.runtime.RegisterTraceQueueDepthGauge(func() int { return 0 })
			tt.runtime.RegisterTraceQueueCapacityGauge(func() int { return 256 })

			if tt.runtime.PrometheusHandler() != nil {
				t.Fatal("PrometheusHandler() should be nil when disabled")
			}

			if err := tt.runtime.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown() error: %v", err)
			}
		})
	}
}

// Cannot be parallel: mutates global OTel providers.
func TestSetupConfigPermutations(t *testing.T) {
	t.Run("disabled returns noop runtime", func(t *testing.T) {
		runtime, err := Setup(context.Background(), config.OTelConfig{Enabled: false}, "test", nil)
		if err != nil {
			t.Fatalf("Setup() error: %v", err)
		}
		if runtime.Enabled() {
			t.Fatal("expected Enabled()=false for disabled config")
		}
	})

	t.Run("traces only skips metric export", func(t *testing.T) {
		oldTP := otel.GetTracerProvider()
		oldMP := otel.GetMeterProvider()
		oldProp := otel.GetTextMapPropagator()
		defer func() {
			otel.SetTracerProvider(oldTP)
			otel.SetMeterProvider(oldMP)
			otel.SetTextMapPropagator(oldProp)
		}()

		var traceRequests atomic.Int64
		var metricRequests atomic.Int64
		collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			switch r.URL.Path {
			case "/v1/traces":
				traceRequests.Add(1)
			case "/v1/metrics":
				metricRequests.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer collector.Close()

		runtime, err := Setup(context.Background(), config.OTelConfig{
			Enabled:                true,
			Endpoint:               collector.URL,
			ServiceName:            "test-traces-only",
			TracesEnabled:          true,
			MetricsEnabled:         false,
			SamplingRatio:          1.0,
			ExportTimeoutMS:        1000,
			MetricExportIntervalMS: 25,
		}, "test", nil)
		if err != nil {
			t.Fatalf("Setup() error: %v", err)
		}

		_, span := otel.Tracer("test").Start(context.Background(), "test.span")
		span.End()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := runtime.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown() error: %v", err)
		}

		waitFor(t, 2*time.Second, func() bool {
			return traceRequests.Load() > 0
		})
		if metricRequests.Load() > 0 {
			t.Fatal("unexpected metric export requests when MetricsEnabled=false")
		}
	})

	t.Run("metrics only skips trace export", func(t *testing.T) {
		oldTP := otel.GetTracerProvider()
		oldMP := otel.GetMeterProvider()
		oldProp := otel.GetTextMapPropagator()
		defer func() {
			otel.SetTracerProvider(oldTP)
			otel.SetMeterProvider(oldMP)
			otel.SetTextMapPropagator(oldProp)
		}()

		var traceRequests atomic.Int64
		var metricRequests atomic.Int64
		collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			switch r.URL.Path {
			case "/v1/traces":
				traceRequests.Add(1)
			case "/v1/metrics":
				metricRequests.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer collector.Close()

		runtime, err := Setup(context.Background(), config.OTelConfig{
			Enabled:                true,
			Endpoint:               collector.URL,
			ServiceName:            "test-metrics-only",
			TracesEnabled:          false,
			MetricsEnabled:         true,
			SamplingRatio:          1.0,
			ExportTimeoutMS:        1000,
			MetricExportIntervalMS: 25,
		}, "test", nil)
		if err != nil {
			t.Fatalf("Setup() error: %v", err)
		}

		runtime.RecordTraceQueueDrop("openai", "org-1", "ws-1", "/openai/v1/chat", 502)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := runtime.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown() error: %v", err)
		}

		waitFor(t, 2*time.Second, func() bool {
			return metricRequests.Load() > 0
		})
		if traceRequests.Load() > 0 {
			t.Fatal("unexpected trace export requests when TracesEnabled=false")
		}
	})
}

// Cannot be parallel: mutates global OTel providers.
func TestRecordTraceEnqueuedAndFlushMetrics(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	oldMP := otel.GetMeterProvider()
	oldProp := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(oldTP)
		otel.SetMeterProvider(oldMP)
		otel.SetTextMapPropagator(oldProp)
	}()

	var metricRequests atomic.Int64
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		if r.URL.Path == "/v1/metrics" {
			metricRequests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	runtime, err := Setup(context.Background(), config.OTelConfig{
		Enabled:                true,
		Endpoint:               collector.URL,
		ServiceName:            "test-trace-pipeline-metrics",
		TracesEnabled:          false,
		MetricsEnabled:         true,
		SamplingRatio:          1.0,
		ExportTimeoutMS:        1000,
		MetricExportIntervalMS: 25,
	}, "test", nil)
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}

	// Exercise all new recording methods.
	runtime.RecordTraceEnqueued()
	runtime.RecordTraceEnqueued()
	runtime.RecordTraceFlush(5, 10*time.Millisecond)
	runtime.RegisterTraceQueueDepthGauge(func() int { return 3 })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	waitFor(t, 2*time.Second, func() bool {
		return metricRequests.Load() > 0
	})
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestWrapAuthMiddlewareAllowSetsSpanAttributes(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := runtime.WrapAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "gateway.auth" {
		t.Fatalf("span name=%q, want %q", span.Name(), "gateway.auth")
	}
	if span.Status().Code == codes.Error {
		t.Fatal("span status should not be error for allow")
	}
	attrs := spanAttrMap(span)
	if got := attrs["gateway.auth.result"]; got != "allow" {
		t.Fatalf("gateway.auth.result=%q, want %q", got, "allow")
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestWrapAuthMiddlewareDenySetsSpanAttributes(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	handler := runtime.WrapAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	if span.Status().Code != codes.Error {
		t.Fatalf("span status=%v, want %v", span.Status().Code, codes.Error)
	}
	attrs := spanAttrMap(span)
	if got := attrs["gateway.auth.result"]; got != "deny" {
		t.Fatalf("gateway.auth.result=%q, want %q", got, "deny")
	}
	if got := attrs["gateway.auth.deny_reason"]; got != "forbidden" {
		t.Fatalf("gateway.auth.deny_reason=%q, want %q", got, "forbidden")
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestWrapRouteSpanSetsProviderAttributes(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := runtime.WrapRouteSpan(inner)

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-route",
		WorkspaceID: "ws-route",
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "gateway.route" {
		t.Fatalf("span name=%q, want %q", span.Name(), "gateway.route")
	}
	attrs := spanAttrMap(span)
	if got := attrs["gateway.route.provider"]; got != "openai" {
		t.Fatalf("gateway.route.provider=%q, want %q", got, "openai")
	}
	if got := attrs["gateway.route.prefix"]; got != "/openai" {
		t.Fatalf("gateway.route.prefix=%q, want %q", got, "/openai")
	}
	if got := attrs["gateway.org_id"]; got != "org-route" {
		t.Fatalf("gateway.org_id=%q, want %q", got, "org-route")
	}
	if got := attrs["gateway.workspace_id"]; got != "ws-route" {
		t.Fatalf("gateway.workspace_id=%q, want %q", got, "ws-route")
	}
	if span.Status().Code == codes.Error {
		t.Fatal("span status should not be error for 200")
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestWrapRouteSpanSetsErrorOn5xx(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	handler := runtime.WrapRouteSpan(inner)

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-5xx",
		WorkspaceID: "ws-5xx",
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	attrs := spanAttrMap(span)
	if got := attrs["gateway.route.provider"]; got != "anthropic" {
		t.Fatalf("gateway.route.provider=%q, want %q", got, "anthropic")
	}
	if got := attrs["gateway.org_id"]; got != "org-5xx" {
		t.Fatalf("gateway.org_id=%q, want %q", got, "org-5xx")
	}
	if got := attrs["gateway.workspace_id"]; got != "ws-5xx" {
		t.Fatalf("gateway.workspace_id=%q, want %q", got, "ws-5xx")
	}
	if span.Status().Code != codes.Error {
		t.Fatalf("span status=%v, want %v", span.Status().Code, codes.Error)
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestStartTraceEnqueueSpanAccepted(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		OrgID:       "org-enqueue",
		WorkspaceID: "ws-enqueue",
	})
	_, endSpan := runtime.StartTraceEnqueueSpan(ctx)
	endSpan(true)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "gateway.trace.enqueue" {
		t.Fatalf("span name=%q, want %q", span.Name(), "gateway.trace.enqueue")
	}
	attrs := spanAttrMap(span)
	if got := attrs["gateway.trace.enqueue.result"]; got != "accepted" {
		t.Fatalf("gateway.trace.enqueue.result=%q, want %q", got, "accepted")
	}
	if got := attrs["gateway.org_id"]; got != "org-enqueue" {
		t.Fatalf("gateway.org_id=%q, want %q", got, "org-enqueue")
	}
	if got := attrs["gateway.workspace_id"]; got != "ws-enqueue" {
		t.Fatalf("gateway.workspace_id=%q, want %q", got, "ws-enqueue")
	}
	if span.Status().Code == codes.Error {
		t.Fatal("span status should not be error for accepted enqueue")
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestStartTraceEnqueueSpanDropped(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		OrgID:       "org-dropped",
		WorkspaceID: "ws-dropped",
	})
	_, endSpan := runtime.StartTraceEnqueueSpan(ctx)
	endSpan(false)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	attrs := spanAttrMap(span)
	if got := attrs["gateway.trace.enqueue.result"]; got != "dropped" {
		t.Fatalf("gateway.trace.enqueue.result=%q, want %q", got, "dropped")
	}
	if got := attrs["gateway.org_id"]; got != "org-dropped" {
		t.Fatalf("gateway.org_id=%q, want %q", got, "org-dropped")
	}
	if got := attrs["gateway.workspace_id"]; got != "ws-dropped" {
		t.Fatalf("gateway.workspace_id=%q, want %q", got, "ws-dropped")
	}
	if span.Status().Code != codes.Error {
		t.Fatalf("span status=%v, want %v", span.Status().Code, codes.Error)
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestMakeWriteSpanHookRecordsSpan(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	hook := runtime.MakeWriteSpanHook()
	if hook == nil {
		t.Fatal("MakeWriteSpanHook() returned nil")
	}
	endFn := hook(5)
	endFn(nil)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "gateway.trace.write" {
		t.Fatalf("span name=%q, want %q", span.Name(), "gateway.trace.write")
	}
	attrs := spanAttrMap(span)
	if got := attrs["gateway.trace.write.batch_size"]; got != "5" {
		t.Fatalf("gateway.trace.write.batch_size=%q, want %q", got, "5")
	}
	if span.Status().Code == codes.Error {
		t.Fatal("span status should not be error for successful write")
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestMakeWriteSpanHookRecordsErrorSpan(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	hook := runtime.MakeWriteSpanHook()
	endFn := hook(3)
	endFn(errors.New("connection refused"))

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	span := spans[0]
	attrs := spanAttrMap(span)
	if got := attrs["gateway.trace.write.batch_size"]; got != "3" {
		t.Fatalf("gateway.trace.write.batch_size=%q, want %q", got, "3")
	}
	if got := attrs["gateway.trace.write.error_class"]; got != "connection refused" {
		t.Fatalf("gateway.trace.write.error_class=%q, want %q", got, "connection refused")
	}
	if span.Status().Code != codes.Error {
		t.Fatalf("span status=%v, want %v", span.Status().Code, codes.Error)
	}
}

func TestRecordTraceWrittenIncrementsCounter(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Fatalf("meterProvider.Shutdown() error: %v", err)
		}
	})

	counter, err := meterProvider.Meter("test").Int64Counter("test.trace.written_total")
	if err != nil {
		t.Fatalf("Int64Counter() error: %v", err)
	}

	runtime := &Runtime{
		enabled:             true,
		traceWrittenCounter: counter,
	}

	runtime.RecordTraceWritten(3)
	runtime.RecordTraceWritten(2)

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	found := false
	for _, scope := range metrics.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "test.trace.written_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("metric data type=%T, want metricdata.Sum[int64]", m.Data)
			}
			if len(sum.DataPoints) != 1 {
				t.Fatalf("datapoints=%d, want 1", len(sum.DataPoints))
			}
			if sum.DataPoints[0].Value != 5 {
				t.Fatalf("value=%d, want 5", sum.DataPoints[0].Value)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing test.trace.written_total metric")
	}
}

func TestRecordProxyRequestIncludesMetricAttributes(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Fatalf("meterProvider.Shutdown() error: %v", err)
		}
	})

	meter := meterProvider.Meter("test")
	counter, err := meter.Int64Counter("test.proxy.request_total")
	if err != nil {
		t.Fatalf("Int64Counter() error: %v", err)
	}
	histogram, err := meter.Float64Histogram("test.proxy.request_duration_seconds")
	if err != nil {
		t.Fatalf("Float64Histogram() error: %v", err)
	}

	runtime := &Runtime{
		enabled:                       true,
		proxyRequestCounter:           counter,
		proxyRequestDurationHistogram: histogram,
	}

	runtime.RecordProxyRequest("openai", "org-test", "ws-test", "/openai/v1/chat/completions", 200, 850)

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	var counterFound, histogramFound bool
	for _, scope := range metrics.ScopeMetrics {
		for _, m := range scope.Metrics {
			switch m.Name {
			case "test.proxy.request_total":
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("counter data type=%T, want metricdata.Sum[int64]", m.Data)
				}
				if len(sum.DataPoints) != 1 {
					t.Fatalf("counter datapoints=%d, want 1", len(sum.DataPoints))
				}
				dp := sum.DataPoints[0]
				if dp.Value != 1 {
					t.Fatalf("counter value=%d, want 1", dp.Value)
				}
				gotAttrs := make(map[string]string)
				for _, kv := range dp.Attributes.ToSlice() {
					gotAttrs[string(kv.Key)] = kv.Value.Emit()
				}
				wantAttrs := map[string]string{
					"provider":     "openai",
					"org_id":       "org-test",
					"workspace_id": "ws-test",
					"route":        "/openai/*",
					"status_code":  "200",
				}
				for key, want := range wantAttrs {
					if got := gotAttrs[key]; got != want {
						t.Fatalf("counter attribute %q=%q, want %q", key, got, want)
					}
				}
				for key, value := range gotAttrs {
					if _, ok := wantAttrs[key]; !ok {
						t.Fatalf("unexpected counter attribute %q=%q", key, value)
					}
				}
				counterFound = true

			case "test.proxy.request_duration_seconds":
				hist, ok := m.Data.(metricdata.Histogram[float64])
				if !ok {
					t.Fatalf("histogram data type=%T, want metricdata.Histogram[float64]", m.Data)
				}
				if len(hist.DataPoints) != 1 {
					t.Fatalf("histogram datapoints=%d, want 1", len(hist.DataPoints))
				}
				dp := hist.DataPoints[0]
				if dp.Count != 1 {
					t.Fatalf("histogram count=%d, want 1", dp.Count)
				}
				// 850ms = 0.85s
				wantSum := 0.85
				if dp.Sum < wantSum-0.001 || dp.Sum > wantSum+0.001 {
					t.Fatalf("histogram sum=%f, want ~%f", dp.Sum, wantSum)
				}
				gotAttrs := make(map[string]string)
				for _, kv := range dp.Attributes.ToSlice() {
					gotAttrs[string(kv.Key)] = kv.Value.Emit()
				}
				wantAttrs := map[string]string{
					"provider":     "openai",
					"org_id":       "org-test",
					"workspace_id": "ws-test",
					"route":        "/openai/*",
				}
				for key, want := range wantAttrs {
					if got := gotAttrs[key]; got != want {
						t.Fatalf("histogram attribute %q=%q, want %q", key, got, want)
					}
				}
				for key, value := range gotAttrs {
					if _, ok := wantAttrs[key]; !ok {
						t.Fatalf("unexpected histogram attribute %q=%q", key, value)
					}
				}
				histogramFound = true
			}
		}
	}
	if !counterFound {
		t.Fatal("missing test.proxy.request_total metric")
	}
	if !histogramFound {
		t.Fatal("missing test.proxy.request_duration_seconds metric")
	}
}

// Cannot be parallel: mutates global OTel providers.
func TestRegisterTraceQueueCapacityGaugeReportsValue(t *testing.T) {
	oldMP := otel.GetMeterProvider()
	defer otel.SetMeterProvider(oldMP)

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(meterProvider)
	t.Cleanup(func() {
		if err := meterProvider.Shutdown(context.Background()); err != nil {
			t.Fatalf("meterProvider.Shutdown() error: %v", err)
		}
	})

	runtime := &Runtime{enabled: true}
	runtime.RegisterTraceQueueCapacityGauge(func() int { return 1024 })

	var metrics metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &metrics); err != nil {
		t.Fatalf("Collect() error: %v", err)
	}

	found := false
	for _, scope := range metrics.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "ongoingai.trace.queue_capacity" {
				continue
			}
			gauge, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("metric data type=%T, want metricdata.Gauge[int64]", m.Data)
			}
			if len(gauge.DataPoints) != 1 {
				t.Fatalf("datapoints=%d, want 1", len(gauge.DataPoints))
			}
			if gauge.DataPoints[0].Value != 1024 {
				t.Fatalf("value=%d, want 1024", gauge.DataPoints[0].Value)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing ongoingai.trace.queue_capacity metric")
	}
}

func TestSpanWrappersNoopWhenDisabled(t *testing.T) {
	t.Parallel()

	runtimes := []struct {
		name    string
		runtime *Runtime
	}{
		{name: "nil runtime", runtime: nil},
		{name: "disabled runtime", runtime: &Runtime{enabled: false}},
	}

	for _, tt := range runtimes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// WrapAuthMiddleware passes through.
			authWrapped := tt.runtime.WrapAuthMiddleware(handler)
			rec := httptest.NewRecorder()
			authWrapped.ServeHTTP(rec, httptest.NewRequest("POST", "/openai/v1/chat", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("WrapAuthMiddleware pass-through status=%d, want 200", rec.Code)
			}

			// WrapRouteSpan passes through.
			routeWrapped := tt.runtime.WrapRouteSpan(handler)
			rec = httptest.NewRecorder()
			routeWrapped.ServeHTTP(rec, httptest.NewRequest("POST", "/openai/v1/chat", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("WrapRouteSpan pass-through status=%d, want 200", rec.Code)
			}

			// StartTraceEnqueueSpan returns noop end function.
			ctx, endSpan := tt.runtime.StartTraceEnqueueSpan(context.Background())
			endSpan(true)
			endSpan(false)
			if ctx == nil {
				t.Fatal("StartTraceEnqueueSpan returned nil context")
			}

			// MakeWriteSpanHook returns nil.
			hook := tt.runtime.MakeWriteSpanHook()
			if hook != nil {
				t.Fatal("MakeWriteSpanHook() should return nil when disabled")
			}

			// New methods no-op without panic.
			tt.runtime.RecordTraceWritten(5)
			tt.runtime.RecordProxyRequest("openai", "org-1", "ws-1", "/openai/v1/chat", 200, 500)
			tt.runtime.RegisterTraceQueueCapacityGauge(func() int { return 128 })

			if tt.runtime.PrometheusHandler() != nil {
				t.Fatal("PrometheusHandler() should be nil when disabled")
			}
		})
	}
}

// Cannot be parallel: mutates global OTel providers.
func TestSetupPrometheusCreatesHandler(t *testing.T) {
	oldMP := otel.GetMeterProvider()
	defer otel.SetMeterProvider(oldMP)

	runtime, err := Setup(context.Background(), config.OTelConfig{
		Enabled:                true,
		Endpoint:               "localhost:4318",
		ServiceName:            "test-prometheus",
		TracesEnabled:          false,
		MetricsEnabled:         false,
		PrometheusEnabled:      true,
		PrometheusPath:         "/metrics",
		SamplingRatio:          1.0,
		ExportTimeoutMS:        1000,
		MetricExportIntervalMS: 10000,
	}, "test", nil)
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	defer func() { _ = runtime.Shutdown(context.Background()) }()

	handler := runtime.PrometheusHandler()
	if handler == nil {
		t.Fatal("PrometheusHandler() returned nil, want non-nil handler")
	}

	// Scrape the handler and verify it returns metric content.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("prometheus scrape status=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if body == "" {
		t.Fatal("prometheus scrape returned empty body")
	}
}

// Cannot be parallel: mutates global OTel providers.
func TestSetupPrometheusAndOTLPCoexist(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	oldMP := otel.GetMeterProvider()
	oldProp := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(oldTP)
		otel.SetMeterProvider(oldMP)
		otel.SetTextMapPropagator(oldProp)
	}()

	var metricRequests atomic.Int64
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		if r.URL.Path == "/v1/metrics" {
			metricRequests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	runtime, err := Setup(context.Background(), config.OTelConfig{
		Enabled:                true,
		Endpoint:               collector.URL,
		ServiceName:            "test-dual",
		TracesEnabled:          false,
		MetricsEnabled:         true,
		PrometheusEnabled:      true,
		PrometheusPath:         "/metrics",
		SamplingRatio:          1.0,
		ExportTimeoutMS:        1000,
		MetricExportIntervalMS: 25,
	}, "test", nil)
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}

	// Record a metric so the OTLP reader has something to export.
	runtime.RecordTraceEnqueued()

	// Verify Prometheus handler is available and works.
	handler := runtime.PrometheusHandler()
	if handler == nil {
		t.Fatal("PrometheusHandler() returned nil, want non-nil when both enabled")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("prometheus scrape status=%d, want 200", rec.Code)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// Verify OTLP push also received metrics.
	waitFor(t, 2*time.Second, func() bool {
		return metricRequests.Load() > 0
	})
}

func TestSetupDisabledReturnsNilPrometheusHandler(t *testing.T) {
	t.Parallel()

	runtime, err := Setup(context.Background(), config.OTelConfig{Enabled: false}, "test", nil)
	if err != nil {
		t.Fatalf("Setup() error: %v", err)
	}
	if runtime.PrometheusHandler() != nil {
		t.Fatal("PrometheusHandler() should be nil when disabled")
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestMakeWriteSpanHookScrubsCredentialInError(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	hook := runtime.MakeWriteSpanHook()
	if hook == nil {
		t.Fatal("MakeWriteSpanHook() returned nil")
	}

	// Simulate an error that leaks a credential (e.g. connection string with password).
	endFn := hook(2)
	endFn(errors.New("connect to host=db.example.com password=supersecret123 failed"))

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans=%d, want 1", len(spans))
	}
	attrs := spanAttrMap(spans[0])
	errorClass := attrs["gateway.trace.write.error_class"]
	if ContainsCredential(errorClass) {
		t.Fatalf("credential leaked into span attribute: %q", errorClass)
	}
	if !strings.Contains(errorClass, "[CREDENTIAL_REDACTED]") {
		t.Fatalf("error_class=%q, want redaction marker", errorClass)
	}
}

// Cannot be parallel: mutates global OTel tracer provider.
func TestOtelHTTPDoesNotCaptureAuthHeaders(t *testing.T) {
	oldTP := otel.GetTracerProvider()
	defer otel.SetTracerProvider(oldTP)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(tp)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	runtime := &Runtime{enabled: true, tracer: tp.Tracer(instrumentationName)}
	handler := runtime.WrapHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk_live_secret_key_value")
	req.Header.Set("X-API-Key", "sk_test_another_secret_key")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}

	for _, span := range spans {
		for _, a := range span.Attributes() {
			val := a.Value.Emit()
			if ContainsCredential(val) {
				t.Fatalf("credential found in span attribute %q=%q", a.Key, val)
			}
		}
		for _, event := range span.Events() {
			for _, a := range event.Attributes {
				val := a.Value.Emit()
				if ContainsCredential(val) {
					t.Fatalf("credential found in event attribute %q=%q", a.Key, val)
				}
			}
		}
	}
}

func spanAttrMap(span sdktrace.ReadOnlySpan) map[string]string {
	attrs := make(map[string]string)
	for _, a := range span.Attributes() {
		attrs[string(a.Key)] = a.Value.Emit()
	}
	return attrs
}
