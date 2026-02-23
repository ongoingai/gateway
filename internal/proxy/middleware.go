package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/correlation"
)

func LoggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if next == nil {
		next = http.NotFoundHandler()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var correlationID string
		r, correlationID = correlation.EnsureRequest(r)
		if correlationID != "" {
			w.Header().Set(correlation.HeaderName, correlationID)
		}

		start := time.Now()
		recorder := newStatusResponseWriter(w)
		next.ServeHTTP(recorder, r)
		logger.InfoContext(r.Context(),
			"request complete",
			"correlation_id", correlationID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.StatusCode(),
			"latency_ms", time.Since(start).Milliseconds(),
		)
	})
}

type BodyCaptureOptions struct {
	Enabled     bool
	ParseBodies bool
	MaxBodySize int
}

type CapturedExchange struct {
	// Context carries the request context so downstream consumers (e.g. trace
	// enqueue) can create child spans of the HTTP request span.
	Context               context.Context
	Method                string
	Path                  string
	StatusCode            int
	RequestHeaders        http.Header
	RequestBody           []byte
	RequestBodyTruncated  bool
	ResponseHeaders       http.Header
	ResponseBody          []byte
	ResponseBodyTruncated bool
	Streaming             bool
	StreamChunks          int
	TimeToFirstTokenMS    int64
	TimeToFirstTokenUS    int64
	DurationMS            int64
	GatewayOrgID          string
	GatewayWorkspaceID    string
	GatewayKeyID          string
	GatewayTeam           string
	GatewayRole           string
	CorrelationID         string
}

type BodyCaptureSink func(*CapturedExchange)

func BodyCaptureMiddleware(options BodyCaptureOptions, sink BodyCaptureSink, next http.Handler) http.Handler {
	if next == nil {
		next = http.NotFoundHandler()
	}
	if sink == nil {
		return next
	}
	if options.MaxBodySize <= 0 {
		options.MaxBodySize = 1 << 20
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var correlationID string
		r, correlationID = correlation.EnsureRequest(r)

		start := time.Now()

		captureBodies := options.Enabled || options.ParseBodies
		requestBody := []byte(nil)
		requestBodyTruncated := false
		if captureBodies {
			capturedBody, restoredBody, truncated, err := captureRequestBody(r.Body, options.MaxBodySize)
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}
			requestBody = capturedBody
			requestBodyTruncated = truncated
			r.Body = restoredBody
		}

		recorder := newCaptureResponseWriter(w, options.MaxBodySize, captureBodies, start)
		next.ServeHTTP(recorder, r)

		statusCode := recorder.StatusCode()
		if statusCode == 0 {
			statusCode = http.StatusOK
		}

		streaming := recorder.IsStreaming()
		responseBody := recorder.Body()
		responseBodyTruncated := recorder.BodyTruncated()
		timeToFirstTokenMS := int64(0)
		timeToFirstTokenUS := int64(0)
		if streaming {
			// TTFT is measured from handler entry to the first upstream write so it
			// reflects perceived latency for streaming clients.
			timeToFirstTokenUS = recorder.TimeToFirstWriteUS()
			timeToFirstTokenMS = microsecondsToRoundedMilliseconds(timeToFirstTokenUS)
		}
		identity, _ := auth.IdentityFromContext(r.Context())

		gatewayOrgID := ""
		gatewayWorkspaceID := ""
		gatewayKeyID := ""
		gatewayTeam := ""
		gatewayRole := ""
		if identity != nil {
			gatewayOrgID = identity.OrgID
			gatewayWorkspaceID = identity.WorkspaceID
			gatewayKeyID = identity.KeyID
			gatewayTeam = identity.Team
			gatewayRole = identity.Role
		}

		sink(&CapturedExchange{
			Context:               r.Context(),
			Method:                r.Method,
			Path:                  r.URL.Path,
			StatusCode:            statusCode,
			RequestHeaders:        r.Header.Clone(),
			RequestBody:           requestBody,
			RequestBodyTruncated:  requestBodyTruncated,
			ResponseHeaders:       recorder.Header().Clone(),
			ResponseBody:          responseBody,
			ResponseBodyTruncated: responseBodyTruncated,
			Streaming:             streaming,
			StreamChunks:          recorder.StreamChunkCount(),
			TimeToFirstTokenMS:    timeToFirstTokenMS,
			TimeToFirstTokenUS:    timeToFirstTokenUS,
			DurationMS:            time.Since(start).Milliseconds(),
			GatewayOrgID:          gatewayOrgID,
			GatewayWorkspaceID:    gatewayWorkspaceID,
			GatewayKeyID:          gatewayKeyID,
			GatewayTeam:           gatewayTeam,
			GatewayRole:           gatewayRole,
			CorrelationID:         correlationID,
		})
	})
}

type readerWithCloser struct {
	io.Reader
	closer io.Closer
}

func (r *readerWithCloser) Close() error {
	if r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

func captureRequestBody(body io.ReadCloser, maxBodySize int) ([]byte, io.ReadCloser, bool, error) {
	if body == nil {
		return nil, http.NoBody, false, nil
	}
	if maxBodySize < 0 {
		maxBodySize = 0
	}

	limited := &io.LimitedReader{R: body, N: int64(maxBodySize) + 1}
	prefix, err := io.ReadAll(limited)
	if err != nil {
		_ = body.Close()
		return nil, nil, false, err
	}

	captured := limitBytes(prefix, maxBodySize)
	truncated := len(prefix) > maxBodySize
	// Replay bytes consumed for capture, then continue streaming from the original body.
	restored := &readerWithCloser{
		Reader: io.MultiReader(bytes.NewReader(prefix), body),
		closer: body,
	}
	return captured, restored, truncated, nil
}

func limitBytes(data []byte, max int) []byte {
	if len(data) <= max {
		copied := make([]byte, len(data))
		copy(copied, data)
		return copied
	}
	copied := make([]byte, max)
	copy(copied, data[:max])
	return copied
}

type captureResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	maxBodySize  int
	captureBody  bool
	body         bytes.Buffer
	streaming    bool
	stream       StreamBuffer
	truncated    bool
	startedAt    time.Time
	firstWriteUS int64
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newStatusResponseWriter(w http.ResponseWriter) *statusResponseWriter {
	return &statusResponseWriter{ResponseWriter: w}
}

func (w *statusResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *statusResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *statusResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (w *statusResponseWriter) StatusCode() int {
	if w.statusCode == 0 {
		return http.StatusOK
	}
	return w.statusCode
}

func newCaptureResponseWriter(w http.ResponseWriter, maxBodySize int, captureBody bool, startedAt time.Time) *captureResponseWriter {
	return &captureResponseWriter{
		ResponseWriter: w,
		maxBodySize:    maxBodySize,
		captureBody:    captureBody,
		stream:         newStreamBuffer(maxBodySize),
		startedAt:      startedAt,
		firstWriteUS:   -1,
	}
}

func (w *captureResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *captureResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
	w.streaming = IsSSE(w.Header())
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *captureResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	if !w.streaming {
		w.streaming = IsSSE(w.Header())
	}

	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		if w.firstWriteUS < 0 {
			w.firstWriteUS = time.Since(w.startedAt).Microseconds()
		}
		w.capture(p[:n])
	}
	return n, err
}

func (w *captureResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *captureResponseWriter) StatusCode() int {
	return w.statusCode
}

func (w *captureResponseWriter) Body() []byte {
	if !w.captureBody {
		return nil
	}
	if w.streaming {
		return w.stream.Bytes()
	}
	return limitBytes(w.body.Bytes(), w.maxBodySize)
}

func (w *captureResponseWriter) capture(p []byte) {
	if !w.captureBody {
		return
	}
	if w.streaming {
		w.stream.Add(p)
		if w.stream.Truncated() {
			w.truncated = true
		}
		return
	}

	remaining := w.maxBodySize - w.body.Len()
	if remaining <= 0 {
		if len(p) > 0 {
			w.truncated = true
		}
		return
	}
	if len(p) > remaining {
		w.truncated = true
		p = p[:remaining]
	}
	_, _ = w.body.Write(p)
}

func (w *captureResponseWriter) IsStreaming() bool {
	return w.streaming || IsSSE(w.Header())
}

func (w *captureResponseWriter) StreamChunkCount() int {
	return w.stream.Count()
}

func (w *captureResponseWriter) TimeToFirstWriteUS() int64 {
	if w.firstWriteUS < 0 {
		return 0
	}
	return w.firstWriteUS
}

func (w *captureResponseWriter) BodyTruncated() bool {
	return w.truncated
}

func microsecondsToRoundedMilliseconds(us int64) int64 {
	if us <= 0 {
		return 0
	}
	return (us + 999) / 1000
}
