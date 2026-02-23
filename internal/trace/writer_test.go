package trace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

func (s *testStore) GetLatencyPercentiles(_ context.Context, _ AnalyticsFilter, _ string) ([]LatencyStats, error) {
	return nil, ErrNotImplemented
}

func (s *testStore) GetErrorRateBreakdown(_ context.Context, _ AnalyticsFilter, _ string) ([]ErrorRateStats, error) {
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

type alwaysFailStore struct {
	testStore
}

func (s *alwaysFailStore) WriteTrace(_ context.Context, _ *Trace) error {
	return errors.New("always fail")
}

func (s *alwaysFailStore) WriteBatch(_ context.Context, _ []*Trace) error {
	return errors.New("always fail")
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

func TestWriterTracePipelineDiagnosticsTracksQueuePressureAndDrops(t *testing.T) {
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

	snapshot := writer.TracePipelineDiagnostics()
	if snapshot.QueueCapacity != 1 {
		t.Fatalf("queue_capacity=%d, want 1", snapshot.QueueCapacity)
	}
	if snapshot.QueueDepth != 1 {
		t.Fatalf("queue_depth=%d, want 1", snapshot.QueueDepth)
	}
	if snapshot.QueueDepthHighWatermark != 1 {
		t.Fatalf("queue_depth_high_watermark=%d, want 1", snapshot.QueueDepthHighWatermark)
	}
	if snapshot.QueuePressureState != TraceQueuePressureSaturated {
		t.Fatalf("queue_pressure_state=%q, want %q", snapshot.QueuePressureState, TraceQueuePressureSaturated)
	}
	if snapshot.EnqueueAcceptedTotal != 2 {
		t.Fatalf("enqueue_accepted_total=%d, want 2", snapshot.EnqueueAcceptedTotal)
	}
	if snapshot.EnqueueDroppedTotal != 1 {
		t.Fatalf("enqueue_dropped_total=%d, want 1", snapshot.EnqueueDroppedTotal)
	}
	if snapshot.TotalDroppedTotal != 1 {
		t.Fatalf("total_dropped_total=%d, want 1", snapshot.TotalDroppedTotal)
	}
	if snapshot.LastEnqueueDropAt == nil {
		t.Fatal("last_enqueue_drop_at should be set")
	}

	close(store.release)
	writer.Stop()
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

func TestWriterTracePipelineDiagnosticsTracksWriteDrops(t *testing.T) {
	t.Parallel()

	store := &flakyStore{failFirst: 2}
	writer := NewWriter(store, 8)
	writer.Start(context.Background())

	for i := 0; i < 4; i++ {
		if !writer.Enqueue(&Trace{ID: time.Now().UTC().String()}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	snapshot := writer.TracePipelineDiagnostics()
	if snapshot.EnqueueAcceptedTotal != 4 {
		t.Fatalf("enqueue_accepted_total=%d, want 4", snapshot.EnqueueAcceptedTotal)
	}
	if snapshot.WriteDroppedTotal != 2 {
		t.Fatalf("write_dropped_total=%d, want 2", snapshot.WriteDroppedTotal)
	}
	if snapshot.TotalDroppedTotal != 2 {
		t.Fatalf("total_dropped_total=%d, want 2", snapshot.TotalDroppedTotal)
	}
	if snapshot.LastWriteDropAt == nil {
		t.Fatal("last_write_drop_at should be set")
	}
	if snapshot.LastWriteDropOperation != "write_batch_fallback" {
		t.Fatalf("last_write_drop_operation=%q, want write_batch_fallback", snapshot.LastWriteDropOperation)
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

func TestWriterMetricsOnEnqueueCalledOnSuccess(t *testing.T) {
	t.Parallel()

	store := &testStore{}
	writer := NewWriter(store, 8)
	writer.Start(context.Background())

	var enqueueCount int64
	writer.SetMetrics(&WriterMetrics{
		OnEnqueue: func() { atomic.AddInt64(&enqueueCount, 1) },
	})

	for i := 0; i < 5; i++ {
		if !writer.Enqueue(&Trace{ID: "trace"}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	if got := atomic.LoadInt64(&enqueueCount); got != 5 {
		t.Fatalf("OnEnqueue count=%d, want 5", got)
	}
}

func TestWriterMetricsOnDropCalledWhenQueueFull(t *testing.T) {
	t.Parallel()

	store := &blockingStore{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writer := NewWriter(store, 1)
	writer.Start(context.Background())

	var dropCount int64
	writer.SetMetrics(&WriterMetrics{
		OnDrop: func() { atomic.AddInt64(&dropCount, 1) },
	})

	// First enqueue: consumed by the worker goroutine.
	if !writer.Enqueue(&Trace{ID: "trace-1"}) {
		t.Fatal("first enqueue unexpectedly failed")
	}

	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first write to block")
	}

	// Second enqueue: fills the buffer (size 1).
	if !writer.Enqueue(&Trace{ID: "trace-2"}) {
		t.Fatal("second enqueue unexpectedly failed")
	}

	// Third enqueue: should drop.
	if writer.Enqueue(&Trace{ID: "trace-3"}) {
		t.Fatal("third enqueue should fail when queue is full")
	}

	close(store.release)
	writer.Stop()

	if got := atomic.LoadInt64(&dropCount); got != 1 {
		t.Fatalf("OnDrop count=%d, want 1", got)
	}
}

func TestWriterMetricsOnFlushCalledWithBatchSizeAndDuration(t *testing.T) {
	t.Parallel()

	store := &testStore{}
	writer := NewWriter(store, 8)

	type flushRecord struct {
		batchSize int
		duration  time.Duration
	}
	var mu sync.Mutex
	var flushes []flushRecord
	writer.SetMetrics(&WriterMetrics{
		OnFlush: func(batchSize int, duration time.Duration) {
			mu.Lock()
			flushes = append(flushes, flushRecord{batchSize: batchSize, duration: duration})
			mu.Unlock()
		},
	})

	writer.Start(context.Background())
	for i := 0; i < 4; i++ {
		if !writer.Enqueue(&Trace{ID: "trace"}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(flushes) == 0 {
		t.Fatal("expected at least one OnFlush call")
	}
	totalFlushed := 0
	for _, f := range flushes {
		if f.batchSize <= 0 {
			t.Fatalf("flush batchSize=%d, want >0", f.batchSize)
		}
		if f.duration < 0 {
			t.Fatalf("flush duration=%v, want >=0", f.duration)
		}
		totalFlushed += f.batchSize
	}
	if totalFlushed != 4 {
		t.Fatalf("total flushed=%d, want 4", totalFlushed)
	}
}

func TestWriterMetricsNilSafe(t *testing.T) {
	t.Parallel()

	store := &testStore{}
	writer := NewWriter(store, 8)
	// Do not call SetMetrics — ensure no panics with nil metrics.
	writer.Start(context.Background())

	for i := 0; i < 3; i++ {
		writer.Enqueue(&Trace{ID: "trace"})
	}
	writer.Stop()

	if got := store.Count(); got != 3 {
		t.Fatalf("write count=%d, want 3", got)
	}
}

func TestWriterQueueLen(t *testing.T) {
	t.Parallel()

	store := &blockingStore{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	writer := NewWriter(store, 4)
	writer.Start(context.Background())

	// Enqueue one to trigger the worker and block it.
	if !writer.Enqueue(&Trace{ID: "trace-1"}) {
		t.Fatal("first enqueue failed")
	}

	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first write to block")
	}

	// The worker consumed the first trace; these 2 remain in the channel buffer.
	if !writer.Enqueue(&Trace{ID: "trace-2"}) {
		t.Fatal("second enqueue failed")
	}
	if !writer.Enqueue(&Trace{ID: "trace-3"}) {
		t.Fatal("third enqueue failed")
	}

	if got := writer.QueueLen(); got != 2 {
		t.Fatalf("QueueLen()=%d, want 2", got)
	}

	close(store.release)
	writer.Stop()
}

func TestWriterTracePipelineDiagnosticsTracksWriteFailuresByClass(t *testing.T) {
	t.Parallel()

	writer := NewWriter(&testStore{}, 8)

	// Simulate classified failures directly to test per-class counter logic
	// independent of batch grouping behavior.
	writer.reportWriteFailure(WriteFailure{
		Operation:   "write_trace",
		BatchSize:   1,
		FailedCount: 1,
		Err:         errors.New("database is locked"),
	})
	writer.reportWriteFailure(WriteFailure{
		Operation:   "write_trace",
		BatchSize:   1,
		FailedCount: 1,
		Err:         errors.New("duplicate key value"),
	})
	writer.reportWriteFailure(WriteFailure{
		Operation:   "write_trace",
		BatchSize:   1,
		FailedCount: 2,
		Err:         errors.New("dial tcp 127.0.0.1: connection refused"),
	})

	snapshot := writer.TracePipelineDiagnostics()
	if snapshot.WriteDroppedTotal != 4 {
		t.Fatalf("write_dropped_total=%d, want 4", snapshot.WriteDroppedTotal)
	}
	if snapshot.WriteFailuresByClass == nil {
		t.Fatal("write_failures_by_class should be populated")
	}
	if snapshot.WriteFailuresByClass[WriteErrorClassContention] != 1 {
		t.Fatalf("contention=%d, want 1", snapshot.WriteFailuresByClass[WriteErrorClassContention])
	}
	if snapshot.WriteFailuresByClass[WriteErrorClassConstraint] != 1 {
		t.Fatalf("constraint=%d, want 1", snapshot.WriteFailuresByClass[WriteErrorClassConstraint])
	}
	if snapshot.WriteFailuresByClass[WriteErrorClassConnection] != 2 {
		t.Fatalf("connection=%d, want 2", snapshot.WriteFailuresByClass[WriteErrorClassConnection])
	}
	if _, ok := snapshot.WriteFailuresByClass[WriteErrorClassUnknown]; ok {
		t.Fatalf("unknown should not be present, got %d", snapshot.WriteFailuresByClass[WriteErrorClassUnknown])
	}
}

func TestWriterWriteFailureIncludesErrorClass(t *testing.T) {
	t.Parallel()

	store := &flakyStore{failFirst: 1}
	writer := NewWriter(store, 8)
	writeFailures := make(chan WriteFailure, 4)
	writer.SetWriteFailureHandler(func(failure WriteFailure) {
		writeFailures <- failure
	})
	writer.Start(context.Background())

	if !writer.Enqueue(&Trace{ID: "trace"}) {
		t.Fatal("enqueue failed")
	}
	writer.Stop()

	select {
	case failure := <-writeFailures:
		if failure.ErrorClass == "" {
			t.Fatal("ErrorClass should be populated")
		}
		if failure.ErrorClass != WriteErrorClassUnknown {
			t.Fatalf("ErrorClass=%q, want %q", failure.ErrorClass, WriteErrorClassUnknown)
		}
	default:
		t.Fatal("expected at least one write failure signal")
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

func TestWriterQueueCap(t *testing.T) {
	t.Parallel()

	writer := NewWriter(&testStore{}, 16)
	if got := writer.QueueCap(); got != 16 {
		t.Fatalf("QueueCap()=%d, want 16", got)
	}
}

func TestWriterMetricsOnWriteSuccessCalledOnSuccess(t *testing.T) {
	t.Parallel()

	store := &testStore{}
	writer := NewWriter(store, 8)

	var successCount int64
	writer.SetMetrics(&WriterMetrics{
		OnWriteSuccess: func(count int) { atomic.AddInt64(&successCount, int64(count)) },
	})

	writer.Start(context.Background())
	for i := 0; i < 5; i++ {
		if !writer.Enqueue(&Trace{ID: "trace"}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	if got := atomic.LoadInt64(&successCount); got != 5 {
		t.Fatalf("OnWriteSuccess total=%d, want 5", got)
	}
}

func TestWriterMetricsOnWriteSuccessNotCalledOnFailure(t *testing.T) {
	t.Parallel()

	store := &alwaysFailStore{}
	writer := NewWriter(store, 8)

	var successCount int64
	writer.SetMetrics(&WriterMetrics{
		OnWriteSuccess: func(count int) { atomic.AddInt64(&successCount, int64(count)) },
	})

	writer.Start(context.Background())
	for i := 0; i < 3; i++ {
		writer.Enqueue(&Trace{ID: "trace"})
	}
	writer.Stop()

	if got := atomic.LoadInt64(&successCount); got != 0 {
		t.Fatalf("OnWriteSuccess total=%d, want 0", got)
	}
}

func TestWriterMetricsOnWriteSuccessPartialBatchFallback(t *testing.T) {
	t.Parallel()

	// flakyStore: WriteBatch always fails, WriteTrace fails for the first failFirst items.
	store := &flakyStore{failFirst: 1}
	writer := NewWriter(store, 8)

	var successCount int64
	writer.SetMetrics(&WriterMetrics{
		OnWriteSuccess: func(count int) { atomic.AddInt64(&successCount, int64(count)) },
	})

	writer.Start(context.Background())
	for i := 0; i < 4; i++ {
		if !writer.Enqueue(&Trace{ID: "trace"}) {
			t.Fatalf("enqueue failed at index %d", i)
		}
	}
	writer.Stop()

	// The first item fails individual write, remaining 3 succeed.
	// Exact count depends on batching; at minimum some succeed and the failed ones don't count.
	got := atomic.LoadInt64(&successCount)
	if got <= 0 {
		t.Fatalf("OnWriteSuccess total=%d, want >0", got)
	}
	if got > 4 {
		t.Fatalf("OnWriteSuccess total=%d, want <=4", got)
	}
}
