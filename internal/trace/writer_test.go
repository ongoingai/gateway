package trace

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testStore struct {
	mu    sync.Mutex
	count int
}

func (s *testStore) WriteTrace(_ context.Context, _ *Trace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return nil
}

func (s *testStore) WriteBatch(_ context.Context, traces []*Trace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count += len(traces)
	return nil
}

type countingBatchStore struct {
	testStore
	batchWrites int
}

func (s *countingBatchStore) WriteBatch(_ context.Context, traces []*Trace) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batchWrites++
	s.count += len(traces)
	return nil
}

func (s *testStore) GetTrace(_ context.Context, _ string) (*Trace, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) QueryTraces(_ context.Context, _ TraceFilter) (*TraceResult, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) GetUsageSummary(_ context.Context, _ AnalyticsFilter) (*UsageSummary, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) GetUsageSeries(_ context.Context, _ AnalyticsFilter, _, _ string) ([]UsagePoint, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) GetCostSummary(_ context.Context, _ AnalyticsFilter) (*CostSummary, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) GetCostSeries(_ context.Context, _ AnalyticsFilter, _, _ string) ([]CostPoint, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) GetModelStats(_ context.Context, _ AnalyticsFilter) ([]ModelStats, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) GetKeyStats(_ context.Context, _ AnalyticsFilter) ([]KeyStats, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

type blockingStore struct {
	testStore
	started chan struct{}
	release chan struct{}
}

func (s *blockingStore) WriteTrace(_ context.Context, _ *Trace) error {
	s.mu.Lock()
	s.count++
	current := s.count
	s.mu.Unlock()

	if current == 1 {
		select {
		case <-s.started:
		default:
			close(s.started)
		}
		<-s.release
	}
	return nil
}

func (s *blockingStore) WriteBatch(_ context.Context, traces []*Trace) error {
	s.mu.Lock()
	s.count += len(traces)
	current := s.count
	s.mu.Unlock()

	if current <= len(traces) {
		select {
		case <-s.started:
		default:
			close(s.started)
		}
		<-s.release
	}
	return nil
}

type contextAwareBlockingStore struct {
	testStore
	started chan struct{}
}

func (s *contextAwareBlockingStore) WriteTrace(ctx context.Context, _ *Trace) error {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()

	select {
	case <-s.started:
	default:
		close(s.started)
	}

	<-ctx.Done()
	return ctx.Err()
}

func (s *contextAwareBlockingStore) WriteBatch(ctx context.Context, traces []*Trace) error {
	s.mu.Lock()
	s.count += len(traces)
	s.mu.Unlock()

	select {
	case <-s.started:
	default:
		close(s.started)
	}

	<-ctx.Done()
	return ctx.Err()
}

var errFlakyWrite = errors.New("flaky write")

type flakyStore struct {
	testStore
	failFirst int
	failures  int
}

func (s *flakyStore) WriteTrace(_ context.Context, _ *Trace) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.count++
	if s.count <= s.failFirst {
		s.failures++
		return errFlakyWrite
	}
	return nil
}

func (s *flakyStore) WriteBatch(_ context.Context, _ []*Trace) error {
	return errFlakyWrite
}

func (s *flakyStore) Failures() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures
}

func TestWriterDrainsQueueWhenStopped(t *testing.T) {
	t.Parallel()

	store := &testStore{}
	writer := NewWriter(store, 8)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	writer.Start(ctx)
	for i := 0; i < 4; i++ {
		if !writer.Enqueue(&Trace{ID: time.Now().UTC().String()}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	if got := store.Count(); got != 4 {
		t.Fatalf("write count=%d, want 4", got)
	}
}

func TestWriterUsesBatchWriteForMultipleQueuedTraces(t *testing.T) {
	t.Parallel()

	store := &countingBatchStore{}
	writer := NewWriter(store, 8)
	writer.Start(context.Background())

	for i := 0; i < 4; i++ {
		if !writer.Enqueue(&Trace{ID: time.Now().UTC().String()}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.batchWrites == 0 {
		t.Fatal("expected at least one WriteBatch call")
	}
	if store.count != 4 {
		t.Fatalf("write count=%d, want 4", store.count)
	}
}

func TestWriterEnqueueReturnsFalseWhenQueueIsFull(t *testing.T) {
	t.Parallel()

	store := &blockingStore{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writer := NewWriter(store, 1)
	writer.Start(context.Background())

	if !writer.Enqueue(&Trace{ID: "trace-1"}) {
		t.Fatal("first enqueue unexpectedly failed")
	}

	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first write to block")
	}

	if !writer.Enqueue(&Trace{ID: "trace-2"}) {
		t.Fatal("second enqueue unexpectedly failed")
	}
	if writer.Enqueue(&Trace{ID: "trace-3"}) {
		t.Fatal("third enqueue should fail when queue is full")
	}

	close(store.release)
	writer.Stop()

	if got := store.Count(); got != 2 {
		t.Fatalf("write count=%d, want 2", got)
	}
}

func TestWriterContinuesAfterWriteFailures(t *testing.T) {
	t.Parallel()

	store := &flakyStore{failFirst: 2}
	writer := NewWriter(store, 8)
	writeFailures := make(chan WriteFailure, 4)
	writer.SetWriteFailureHandler(func(failure WriteFailure) {
		writeFailures <- failure
	})
	writer.Start(context.Background())

	for i := 0; i < 4; i++ {
		if !writer.Enqueue(&Trace{}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	if got := store.Count(); got != 4 {
		t.Fatalf("attempted write count=%d, want 4", got)
	}
	if got := store.Failures(); got != 2 {
		t.Fatalf("failed write count=%d, want 2", got)
	}

	totalFailed := 0
	signaled := 0
	for {
		select {
		case failure := <-writeFailures:
			signaled++
			if failure.Operation == "" {
				t.Fatal("write failure operation should be set")
			}
			if failure.Err == nil {
				t.Fatal("write failure should include an error")
			}
			totalFailed += failure.FailedCount
		default:
			if signaled == 0 {
				t.Fatal("expected at least one write failure signal")
			}
			if totalFailed != 2 {
				t.Fatalf("write failure signal count=%d, want 2 dropped writes", totalFailed)
			}
			return
		}
	}
}

func TestWriterShutdownHonorsContextDeadline(t *testing.T) {
	t.Parallel()

	store := &blockingStore{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writer := NewWriter(store, 1)
	writer.Start(context.Background())

	if !writer.Enqueue(&Trace{ID: "trace-1"}) {
		t.Fatal("enqueue unexpectedly failed")
	}

	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first write to block")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	err := writer.Shutdown(shutdownCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown err=%v, want %v", err, context.DeadlineExceeded)
	}

	close(store.release)
	if err := writer.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown after release err=%v, want nil", err)
	}
}

func TestWriterShutdownCancelsInflightWriteOnTimeout(t *testing.T) {
	t.Parallel()

	store := &contextAwareBlockingStore{
		started: make(chan struct{}),
	}
	writer := NewWriter(store, 1)
	writer.Start(context.Background())

	if !writer.Enqueue(&Trace{ID: "trace-timeout"}) {
		t.Fatal("enqueue unexpectedly failed")
	}

	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for write to start")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := writer.Shutdown(shutdownCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown err=%v, want %v", err, context.DeadlineExceeded)
	}

	finalCtx, finalCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer finalCancel()
	if err := writer.Shutdown(finalCtx); err != nil {
		t.Fatalf("shutdown after cancellation err=%v, want nil", err)
	}
}

func TestWriterStopIsIdempotentWithoutStart(t *testing.T) {
	t.Parallel()

	writer := NewWriter(&testStore{}, 1)

	writer.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		writer.Stop()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second stop call blocked")
	}

	if writer.Enqueue(&Trace{ID: "after-stop"}) {
		t.Fatal("enqueue should fail after stop")
	}
}
