package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/correlation"
)

type scriptedWriteResponseWriter struct {
	header     http.Header
	statusCode int
	body       []byte
	writes     int
	failOn     int
	failBytes  int
	writeErr   error
}

func (w *scriptedWriteResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *scriptedWriteResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
}

func (w *scriptedWriteResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	w.writes++

	if w.failOn > 0 && w.writes == w.failOn {
		n := len(p)
		if w.failBytes >= 0 && w.failBytes < n {
			n = w.failBytes
		}
		w.body = append(w.body, p[:n]...)
		if w.writeErr == nil {
			w.writeErr = io.ErrShortWrite
		}
		return n, w.writeErr
	}

	w.body = append(w.body, p...)
	return len(p), nil
}

type trackingReadCloser struct {
	data       []byte
	offset     int
	bytesRead  int
	closeCalls int
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	r.bytesRead += n
	return n, nil
}

func (r *trackingReadCloser) Close() error {
	r.closeCalls++
	return nil
}

func TestBodyCaptureMiddlewareCapturesNonStreamingBodies(t *testing.T) {
	t.Parallel()

	var seenByHandler string
	var captured *CapturedExchange

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		seenByHandler = string(body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	handler := BodyCaptureMiddleware(BodyCaptureOptions{
		Enabled:     true,
		MaxBodySize: 1024,
	}, func(exchange *CapturedExchange) {
		captured = exchange
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusCreated)
	}
	if seenByHandler != `{"model":"gpt-4o-mini"}` {
		t.Fatalf("handler body=%q, want %q", seenByHandler, `{"model":"gpt-4o-mini"}`)
	}
	if captured == nil {
		t.Fatal("capture sink was not called")
	}
	if captured.Streaming {
		t.Fatal("expected non-streaming capture")
	}
	if captured.StatusCode != http.StatusCreated {
		t.Fatalf("captured status=%d, want %d", captured.StatusCode, http.StatusCreated)
	}
	if string(captured.RequestBody) != `{"model":"gpt-4o-mini"}` {
		t.Fatalf("captured request body=%q, want %q", string(captured.RequestBody), `{"model":"gpt-4o-mini"}`)
	}
	if string(captured.ResponseBody) != `{"ok":true}` {
		t.Fatalf("captured response body=%q, want %q", string(captured.ResponseBody), `{"ok":true}`)
	}
	if captured.TimeToFirstTokenMS != 0 {
		t.Fatalf("non-stream ttft=%d, want 0", captured.TimeToFirstTokenMS)
	}
	if captured.TimeToFirstTokenUS != 0 {
		t.Fatalf("non-stream ttft_us=%d, want 0", captured.TimeToFirstTokenUS)
	}
}

func TestBodyCaptureMiddlewareIncludesCorrelationID(t *testing.T) {
	t.Parallel()

	var captured *CapturedExchange
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := BodyCaptureMiddleware(BodyCaptureOptions{
		Enabled:     true,
		MaxBodySize: 128,
	}, func(exchange *CapturedExchange) {
		captured = exchange
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/openai/v1/models", nil)
	req.Header.Set(correlation.HeaderName, "corr-bodycapture-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("capture sink was not called")
	}
	if captured.CorrelationID != "corr-bodycapture-1" {
		t.Fatalf("captured correlation_id=%q, want corr-bodycapture-1", captured.CorrelationID)
	}
}

func TestLoggingMiddlewareAssignsCorrelationIDAndLogsIt(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	var seenCorrelationID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := correlation.FromContext(r.Context())
		if !ok {
			t.Fatal("expected correlation id in request context")
		}
		seenCorrelationID = id
		if headerValue := r.Header.Get(correlation.HeaderName); headerValue != id {
			t.Fatalf("request header correlation_id=%q, want %q", headerValue, id)
		}
		w.WriteHeader(http.StatusAccepted)
	})

	handler := LoggingMiddleware(logger, next)

	req := httptest.NewRequest(http.MethodGet, "/openai/v1/models", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusAccepted)
	}

	responseCorrelationID := rec.Header().Get(correlation.HeaderName)
	if responseCorrelationID == "" {
		t.Fatalf("response %s header is empty", correlation.HeaderName)
	}
	if seenCorrelationID != responseCorrelationID {
		t.Fatalf("context correlation_id=%q, response correlation_id=%q", seenCorrelationID, responseCorrelationID)
	}

	line := strings.TrimSpace(logs.String())
	if line == "" {
		t.Fatal("expected request log line")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("decode log line: %v", err)
	}
	if payload["correlation_id"] != responseCorrelationID {
		t.Fatalf("logged correlation_id=%v, want %q", payload["correlation_id"], responseCorrelationID)
	}
}

func TestBodyCaptureMiddlewareTruncatesBodies(t *testing.T) {
	t.Parallel()

	var captured *CapturedExchange

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	})

	handler := BodyCaptureMiddleware(BodyCaptureOptions{
		Enabled:     true,
		MaxBodySize: 4,
	}, func(exchange *CapturedExchange) {
		captured = exchange
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", strings.NewReader("123456"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("capture sink was not called")
	}
	if string(captured.RequestBody) != "1234" {
		t.Fatalf("captured request body=%q, want %q", string(captured.RequestBody), "1234")
	}
	if !captured.RequestBodyTruncated {
		t.Fatalf("request body truncated=%v, want true", captured.RequestBodyTruncated)
	}
	if string(captured.ResponseBody) != "abcd" {
		t.Fatalf("captured response body=%q, want %q", string(captured.ResponseBody), "abcd")
	}
	if !captured.ResponseBodyTruncated {
		t.Fatalf("response body truncated=%v, want true", captured.ResponseBodyTruncated)
	}
}

func TestCaptureRequestBodyReadsOnlyCaptureLimitUpfront(t *testing.T) {
	t.Parallel()

	body := &trackingReadCloser{data: []byte("0123456789")}
	captured, restored, truncated, err := captureRequestBody(body, 4)
	if err != nil {
		t.Fatalf("capture request body: %v", err)
	}
	if got := string(captured); got != "0123" {
		t.Fatalf("captured body=%q, want %q", got, "0123")
	}
	if !truncated {
		t.Fatalf("truncated=%v, want true", truncated)
	}
	if body.bytesRead != 5 {
		t.Fatalf("upfront bytes read=%d, want %d", body.bytesRead, 5)
	}

	full, err := io.ReadAll(restored)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if got := string(full); got != "0123456789" {
		t.Fatalf("restored body=%q, want %q", got, "0123456789")
	}
	if body.bytesRead != 10 {
		t.Fatalf("total bytes read=%d, want %d", body.bytesRead, 10)
	}
	if err := restored.Close(); err != nil {
		t.Fatalf("close restored body: %v", err)
	}
	if body.closeCalls != 1 {
		t.Fatalf("close calls=%d, want %d", body.closeCalls, 1)
	}
}

func TestBodyCaptureMiddlewareSkipsSSEBodyCapture(t *testing.T) {
	t.Parallel()

	var captured *CapturedExchange

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		time.Sleep(15 * time.Millisecond)
		_, _ = w.Write([]byte("data: hello\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte("data: world\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})

	handler := BodyCaptureMiddleware(BodyCaptureOptions{
		Enabled:     true,
		MaxBodySize: 1024,
	}, func(exchange *CapturedExchange) {
		captured = exchange
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/openai/v1/responses", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("capture sink was not called")
	}
	if !captured.Streaming {
		t.Fatal("expected streaming capture for SSE response")
	}
	if captured.StreamChunks != 2 {
		t.Fatalf("captured stream chunk count=%d, want %d", captured.StreamChunks, 2)
	}
	if captured.TimeToFirstTokenMS <= 0 {
		t.Fatalf("stream ttft=%d, want > 0", captured.TimeToFirstTokenMS)
	}
	if captured.TimeToFirstTokenUS <= 0 {
		t.Fatalf("stream ttft_us=%d, want > 0", captured.TimeToFirstTokenUS)
	}
	if captured.TimeToFirstTokenMS != microsecondsToRoundedMilliseconds(captured.TimeToFirstTokenUS) {
		t.Fatalf("stream ttft mismatch: ms=%d us=%d", captured.TimeToFirstTokenMS, captured.TimeToFirstTokenUS)
	}
	if captured.TimeToFirstTokenMS > captured.DurationMS+1 {
		t.Fatalf("stream ttft=%d cannot exceed duration=%d by more than 1ms rounding slack", captured.TimeToFirstTokenMS, captured.DurationMS)
	}
	if string(captured.ResponseBody) != "data: hello\n\ndata: world\n\n" {
		t.Fatalf("captured response body=%q, want %q", string(captured.ResponseBody), "data: hello\n\ndata: world\n\n")
	}
	if rec.Body.String() != "data: hello\n\ndata: world\n\n" {
		t.Fatalf("client response body=%q, want %q", rec.Body.String(), "data: hello\n\ndata: world\n\n")
	}
}

func TestBodyCaptureMiddlewareTruncatesStreamingCapture(t *testing.T) {
	t.Parallel()

	var captured *CapturedExchange

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: hello\n\n"))
		_, _ = w.Write([]byte("data: world\n\n"))
	})

	handler := BodyCaptureMiddleware(BodyCaptureOptions{
		Enabled:     true,
		MaxBodySize: 16,
	}, func(exchange *CapturedExchange) {
		captured = exchange
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/openai/v1/responses", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("capture sink was not called")
	}
	if !captured.Streaming {
		t.Fatal("expected streaming capture for SSE response")
	}
	if captured.StreamChunks != 2 {
		t.Fatalf("captured stream chunk count=%d, want %d", captured.StreamChunks, 2)
	}
	if got := string(captured.ResponseBody); got != "data: hello\n\ndat" {
		t.Fatalf("captured response body=%q, want %q", got, "data: hello\n\ndat")
	}
	if !captured.ResponseBodyTruncated {
		t.Fatalf("response body truncated=%v, want true", captured.ResponseBodyTruncated)
	}
	if rec.Body.String() != "data: hello\n\ndata: world\n\n" {
		t.Fatalf("client response body=%q, want %q", rec.Body.String(), "data: hello\n\ndata: world\n\n")
	}
}

func TestBodyCaptureMiddlewareStillEmitsMetadataWhenBodyCaptureDisabled(t *testing.T) {
	t.Parallel()

	var captured *CapturedExchange

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	handler := BodyCaptureMiddleware(BodyCaptureOptions{
		Enabled:     false,
		ParseBodies: false,
		MaxBodySize: 1024,
	}, func(exchange *CapturedExchange) {
		captured = exchange
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("capture sink was not called")
	}
	if captured.StatusCode != http.StatusAccepted {
		t.Fatalf("captured status=%d, want %d", captured.StatusCode, http.StatusAccepted)
	}
	if len(captured.RequestBody) != 0 {
		t.Fatalf("expected request body to be disabled, got %d bytes", len(captured.RequestBody))
	}
	if len(captured.ResponseBody) != 0 {
		t.Fatalf("expected response body to be disabled, got %d bytes", len(captured.ResponseBody))
	}
	if captured.TimeToFirstTokenMS != 0 {
		t.Fatalf("non-stream ttft=%d, want 0", captured.TimeToFirstTokenMS)
	}
	if captured.TimeToFirstTokenUS != 0 {
		t.Fatalf("non-stream ttft_us=%d, want 0", captured.TimeToFirstTokenUS)
	}
}

func TestBodyCaptureMiddlewareParseOnlyModeCapturesForTransientParsing(t *testing.T) {
	t.Parallel()

	var captured *CapturedExchange

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"usage":{"input_tokens":10,"output_tokens":5}}`))
	})

	handler := BodyCaptureMiddleware(BodyCaptureOptions{
		Enabled:     false,
		ParseBodies: true,
		MaxBodySize: 1024,
	}, func(exchange *CapturedExchange) {
		captured = exchange
	}, next)

	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", strings.NewReader(`{"model":"claude-haiku-4-5-20251001"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil {
		t.Fatal("capture sink was not called")
	}
	if got := string(captured.RequestBody); got != `{"model":"claude-haiku-4-5-20251001"}` {
		t.Fatalf("parse-only request body=%q", got)
	}
	if got := string(captured.ResponseBody); got != `{"usage":{"input_tokens":10,"output_tokens":5}}` {
		t.Fatalf("parse-only response body=%q", got)
	}
}

func TestMicrosecondsToRoundedMilliseconds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		us   int64
		want int64
	}{
		{us: -1, want: 0},
		{us: 0, want: 0},
		{us: 1, want: 1},
		{us: 999, want: 1},
		{us: 1000, want: 1},
		{us: 1001, want: 2},
		{us: 1999, want: 2},
	}

	for _, tc := range cases {
		if got := microsecondsToRoundedMilliseconds(tc.us); got != tc.want {
			t.Fatalf("microsecondsToRoundedMilliseconds(%d)=%d, want %d", tc.us, got, tc.want)
		}
	}
}

func TestCaptureResponseWriterCapturesPartialNonStreamingWrite(t *testing.T) {
	t.Parallel()

	base := &scriptedWriteResponseWriter{
		failOn:    1,
		failBytes: 3,
		writeErr:  io.ErrShortWrite,
	}
	recorder := newCaptureResponseWriter(base, 1024, true, time.Now().Add(-5*time.Millisecond))

	n, err := recorder.Write([]byte("abcdef"))
	if n != 3 {
		t.Fatalf("write n=%d, want 3", n)
	}
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write error=%v, want io.ErrShortWrite", err)
	}
	if recorder.StatusCode() != http.StatusOK {
		t.Fatalf("status=%d, want %d", recorder.StatusCode(), http.StatusOK)
	}
	if recorder.IsStreaming() {
		t.Fatal("expected non-streaming capture")
	}
	if got := string(recorder.Body()); got != "abc" {
		t.Fatalf("captured body=%q, want %q", got, "abc")
	}
}

func TestCaptureResponseWriterCapturesPartialStreamingWrite(t *testing.T) {
	t.Parallel()

	base := &scriptedWriteResponseWriter{
		failOn:    2,
		failBytes: 5,
		writeErr:  io.ErrUnexpectedEOF,
	}
	recorder := newCaptureResponseWriter(base, 1024, true, time.Now().Add(-5*time.Millisecond))
	recorder.Header().Set("Content-Type", "text/event-stream")
	recorder.WriteHeader(http.StatusOK)

	if _, err := recorder.Write([]byte("data: hello\n\n")); err != nil {
		t.Fatalf("first write error=%v, want nil", err)
	}

	n, err := recorder.Write([]byte("data: world\n\n"))
	if n != 5 {
		t.Fatalf("second write n=%d, want 5", n)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("second write error=%v, want io.ErrUnexpectedEOF", err)
	}
	if !recorder.IsStreaming() {
		t.Fatal("expected streaming capture")
	}
	if recorder.StreamChunkCount() != 2 {
		t.Fatalf("stream chunk count=%d, want 2", recorder.StreamChunkCount())
	}
	if recorder.TimeToFirstWriteUS() <= 0 {
		t.Fatalf("time_to_first_write_us=%d, want >0", recorder.TimeToFirstWriteUS())
	}
	if got := string(recorder.Body()); got != "data: hello\n\ndata:" {
		t.Fatalf("captured body=%q, want %q", got, "data: hello\n\ndata:")
	}
}

func TestCaptureResponseWriterTruncatesStreamingCaptureBuffer(t *testing.T) {
	t.Parallel()

	base := &scriptedWriteResponseWriter{}
	recorder := newCaptureResponseWriter(base, 7, true, time.Now().Add(-5*time.Millisecond))
	recorder.Header().Set("Content-Type", "text/event-stream")
	recorder.WriteHeader(http.StatusOK)

	if _, err := recorder.Write([]byte("abcdef")); err != nil {
		t.Fatalf("first write error=%v, want nil", err)
	}
	if _, err := recorder.Write([]byte("ghijkl")); err != nil {
		t.Fatalf("second write error=%v, want nil", err)
	}

	if got := string(recorder.Body()); got != "abcdefg" {
		t.Fatalf("captured body=%q, want %q", got, "abcdefg")
	}
	if recorder.StreamChunkCount() != 2 {
		t.Fatalf("stream chunk count=%d, want 2", recorder.StreamChunkCount())
	}
	if got := string(base.body); got != "abcdefghijkl" {
		t.Fatalf("upstream body=%q, want %q", got, "abcdefghijkl")
	}
}
