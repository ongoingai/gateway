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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
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
		name       string
		statusCode int
		identity   *auth.Identity
		wantError  bool
		wantAttrs  map[string]string
	}{
		{
			name:       "5xx with full identity sets error status and all attributes",
			statusCode: http.StatusBadGateway,
			identity: &auth.Identity{
				KeyID:       "gwk_test_1",
				OrgID:       "org-test",
				WorkspaceID: "workspace-test",
				Role:        "developer",
			},
			wantError: true,
			wantAttrs: map[string]string{
				"gateway.org_id":       "org-test",
				"gateway.workspace_id": "workspace-test",
				"gateway.key_id":       "gwk_test_1",
				"gateway.role":         "developer",
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
			name:       "5xx without identity sets error status only",
			statusCode: http.StatusServiceUnavailable,
			identity:   nil,
			wantError:  true,
			wantAttrs:  nil,
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
	runtime.RecordTraceQueueDrop("/openai/v1/chat/completions", http.StatusBadGateway)
	runtime.RecordTraceWriteFailure("write_trace", 2)

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

			tt.runtime.RecordTraceQueueDrop("/openai/v1/chat", 502)
			tt.runtime.RecordTraceWriteFailure("write_trace", 5)
			tt.runtime.RecordTraceEnqueued()
			tt.runtime.RecordTraceFlush(10, 50*time.Millisecond)
			tt.runtime.RegisterTraceQueueDepthGauge(func() int { return 0 })

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

		runtime.RecordTraceQueueDrop("/openai/v1/chat", 502)

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
