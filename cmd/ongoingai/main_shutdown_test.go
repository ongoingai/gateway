package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

type flushOnStopWriter struct {
	mu           sync.Mutex
	store        trace.TraceStore
	queue        []*trace.Trace
	stopCalled   bool
	enqueueCalls int
}

func (w *flushOnStopWriter) Start(_ context.Context) {}

func (w *flushOnStopWriter) Enqueue(t *trace.Trace) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.stopCalled {
		return false
	}
	w.queue = append(w.queue, t)
	w.enqueueCalls++
	return true
}

func (w *flushOnStopWriter) Stop() {
	w.mu.Lock()
	if w.stopCalled {
		w.mu.Unlock()
		return
	}
	w.stopCalled = true
	queued := append([]*trace.Trace(nil), w.queue...)
	w.mu.Unlock()

	for _, item := range queued {
		_ = w.store.WriteTrace(context.Background(), item)
	}
}

func (w *flushOnStopWriter) Shutdown(_ context.Context) error {
	w.Stop()
	return nil
}

func (w *flushOnStopWriter) StopCalled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopCalled
}

func (w *flushOnStopWriter) EnqueueCalls() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enqueueCalls
}

func TestRunServeFlushesQueuedTracesOnShutdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected upstream path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","model":"gpt-4o-mini","usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	}))
	defer upstream.Close()

	port := freeTCPPort(t)
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "traces.db")
	configPath := filepath.Join(tmpDir, "ongoingai.yaml")
	configBody := fmt.Sprintf(`server:
  host: 127.0.0.1
  port: %d
storage:
  driver: sqlite
  path: %q
providers:
  openai:
    upstream: %q
    prefix: /openai
  anthropic:
    upstream: %q
    prefix: /anthropic
tracing:
  capture_bodies: false
  body_max_size: 1048576
auth:
  enabled: false
  header: X-OngoingAI-Gateway-Key
`, port, dbPath, upstream.URL, upstream.URL)
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	originalSignalNotifyContext := signalNotifyContext
	originalNewTraceWriter := newTraceWriter
	t.Cleanup(func() {
		signalNotifyContext = originalSignalNotifyContext
		newTraceWriter = originalNewTraceWriter
	})

	shutdownCtx, shutdown := context.WithCancel(context.Background())
	t.Cleanup(shutdown)
	signalNotifyContext = func(_ context.Context, _ ...os.Signal) (context.Context, context.CancelFunc) {
		return shutdownCtx, func() {}
	}

	var (
		writerMu sync.Mutex
		writer   *flushOnStopWriter
	)
	newTraceWriter = func(store trace.TraceStore, _ int) asyncTraceWriter {
		w := &flushOnStopWriter{store: store}
		writerMu.Lock()
		writer = w
		writerMu.Unlock()
		return w
	}

	exitCodeCh := make(chan int, 1)
	go func() {
		exitCodeCh <- runServe([]string{"--config", configPath})
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHTTPReady(t, baseURL+"/api/health")

	req, err := http.NewRequest(http.MethodPost, baseURL+"/openai/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status=%d, want %d", resp.StatusCode, http.StatusOK)
	}

	shutdown()

	select {
	case code := <-exitCodeCh:
		if code != 0 {
			t.Fatalf("runServe exit code=%d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runServe shutdown")
	}

	writerMu.Lock()
	capturedWriter := writer
	writerMu.Unlock()
	if capturedWriter == nil {
		t.Fatal("trace writer was not constructed")
	}
	if !capturedWriter.StopCalled() {
		t.Fatal("expected trace writer Stop() to be called on shutdown")
	}
	if capturedWriter.EnqueueCalls() == 0 {
		t.Fatal("expected at least one trace to be enqueued")
	}

	store, err := trace.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open sqlite store: %v", err)
	}
	defer store.Close()

	result, err := store.QueryTraces(context.Background(), trace.TraceFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query traces: %v", err)
	}
	if len(result.Items) != capturedWriter.EnqueueCalls() {
		t.Fatalf("persisted trace count=%d, want %d", len(result.Items), capturedWriter.EnqueueCalls())
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer listener.Close()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type %T", listener.Addr())
	}
	return addr.Port
}

func waitForHTTPReady(t *testing.T, url string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for HTTP server at %s", url)
}
