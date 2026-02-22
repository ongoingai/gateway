package trace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const writerBatchSize = 64

const (
	TraceQueuePressureOK        = "ok"
	TraceQueuePressureElevated  = "elevated"
	TraceQueuePressureHigh      = "high"
	TraceQueuePressureSaturated = "saturated"
)

// TracePipelineDiagnosticsReader exposes runtime queue/drop diagnostics.
type TracePipelineDiagnosticsReader interface {
	TracePipelineDiagnostics() TracePipelineDiagnostics
}

// TracePipelineDiagnostics captures trace pipeline queue pressure and drop signals.
type TracePipelineDiagnostics struct {
	QueueCapacity                    int        `json:"queue_capacity"`
	QueueDepth                       int        `json:"queue_depth"`
	QueueDepthHighWatermark          int        `json:"queue_depth_high_watermark"`
	QueueUtilizationPct              int        `json:"queue_utilization_pct"`
	QueueHighWatermarkUtilizationPct int        `json:"queue_high_watermark_utilization_pct"`
	QueuePressureState               string     `json:"queue_pressure_state"`
	QueueHighWatermarkPressureState  string     `json:"queue_high_watermark_pressure_state"`
	EnqueueAcceptedTotal             int64      `json:"enqueue_accepted_total"`
	EnqueueDroppedTotal              int64      `json:"enqueue_dropped_total"`
	WriteDroppedTotal                int64      `json:"write_dropped_total"`
	TotalDroppedTotal                int64      `json:"total_dropped_total"`
	LastEnqueueDropAt                *time.Time `json:"last_enqueue_drop_at,omitempty"`
	LastWriteDropAt                  *time.Time `json:"last_write_drop_at,omitempty"`
	LastWriteDropOperation           string     `json:"last_write_drop_operation,omitempty"`
}

// WriteFailure describes trace records that could not be persisted.
type WriteFailure struct {
	Operation   string
	BatchSize   int
	FailedCount int
	Err         error
}

// WriteFailureHandler receives asynchronous trace write failure signals.
type WriteFailureHandler func(WriteFailure)

var noopWriteFailureHandler = WriteFailureHandler(func(WriteFailure) {})

type Writer struct {
	store TraceStore
	queue chan *Trace
	wg    sync.WaitGroup

	started            atomic.Bool
	stopped            atomic.Bool
	stopOnce           sync.Once
	doneOnce           sync.Once
	done               chan struct{}
	queueMu            sync.RWMutex
	lifecycleMu        sync.RWMutex
	workerCancel       context.CancelFunc
	writeFailureHandle atomic.Value // WriteFailureHandler

	queueDepthHighWatermark atomic.Int64
	enqueueAcceptedTotal    atomic.Int64
	enqueueDroppedTotal     atomic.Int64
	writeDroppedTotal       atomic.Int64
	lastEnqueueDropUnixNano atomic.Int64
	lastWriteDropUnixNano   atomic.Int64
	lastWriteDropOperation  atomic.Value // string
}

func NewWriter(store TraceStore, bufferSize int) *Writer {
	if bufferSize <= 0 {
		bufferSize = 256
	}

	writer := &Writer{
		store: store,
		queue: make(chan *Trace, bufferSize),
		done:  make(chan struct{}),
	}
	writer.writeFailureHandle.Store(noopWriteFailureHandler)
	writer.lastWriteDropOperation.Store("")
	return writer
}

// SetWriteFailureHandler replaces the callback used for dropped trace write signals.
func (w *Writer) SetWriteFailureHandler(handler WriteFailureHandler) {
	if w == nil {
		return
	}
	if handler == nil {
		handler = noopWriteFailureHandler
	}
	w.writeFailureHandle.Store(handler)
}

func (w *Writer) Start(ctx context.Context) {
	if !w.started.CompareAndSwap(false, true) {
		return
	}
	if ctx == nil || ctx.Err() != nil {
		// Keep the writer usable when Start is called without a live context.
		ctx = context.Background()
	}
	workerCtx, cancel := context.WithCancel(ctx)
	w.lifecycleMu.Lock()
	w.workerCancel = cancel
	w.lifecycleMu.Unlock()

	w.wg.Add(1)
	go func(workerCtx context.Context) {
		defer w.wg.Done()
		defer w.markDone()

		for {
			select {
			case <-workerCtx.Done():
				return
			case t, ok := <-w.queue:
				if !ok {
					return
				}

				batch := make([]*Trace, 0, writerBatchSize)
				if t != nil {
					batch = append(batch, t)
				}
			drain:
				for len(batch) < writerBatchSize {
					select {
					case <-workerCtx.Done():
						w.flushBatch(workerCtx, batch)
						return
					case next, ok := <-w.queue:
						if !ok {
							w.flushBatch(workerCtx, batch)
							return
						}
						if next != nil {
							batch = append(batch, next)
						}
					default:
						break drain
					}
				}
				w.flushBatch(workerCtx, batch)
			}
		}
	}(workerCtx)
}

func (w *Writer) Enqueue(t *Trace) bool {
	if w.stopped.Load() {
		return false
	}
	w.queueMu.RLock()
	defer w.queueMu.RUnlock()
	if w.stopped.Load() {
		return false
	}

	select {
	case w.queue <- t:
		w.enqueueAcceptedTotal.Add(1)
		w.observeQueueDepth(len(w.queue))
		return true
	default:
		w.enqueueDroppedTotal.Add(1)
		w.observeQueueDepth(cap(w.queue))
		w.lastEnqueueDropUnixNano.Store(time.Now().UTC().UnixNano())
		return false
	}
}

func (w *Writer) Stop() {
	_ = w.Shutdown(context.Background())
}

func (w *Writer) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	w.stopOnce.Do(func() {
		w.stopped.Store(true)
		w.queueMu.Lock()
		close(w.queue)
		w.queueMu.Unlock()
		if !w.started.Load() {
			w.markDone()
		}
	})

	select {
	case <-w.done:
		w.wg.Wait()
		w.cancelWorker()
		return nil
	case <-ctx.Done():
		w.cancelWorker()
		return ctx.Err()
	}
}

func (w *Writer) cancelWorker() {
	if w == nil {
		return
	}
	w.lifecycleMu.RLock()
	cancel := w.workerCancel
	w.lifecycleMu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

func (w *Writer) markDone() {
	w.doneOnce.Do(func() {
		close(w.done)
	})
}

func (w *Writer) reportWriteFailure(failure WriteFailure) {
	if w == nil || failure.FailedCount <= 0 {
		return
	}
	w.writeDroppedTotal.Add(int64(failure.FailedCount))
	w.lastWriteDropUnixNano.Store(time.Now().UTC().UnixNano())
	if failure.Operation != "" {
		w.lastWriteDropOperation.Store(failure.Operation)
	}
	handler, ok := w.writeFailureHandle.Load().(WriteFailureHandler)
	if !ok || handler == nil {
		return
	}
	handler(failure)
}

// TracePipelineDiagnostics returns a point-in-time snapshot of queue pressure
// and dropped-trace counters for operator diagnostics.
func (w *Writer) TracePipelineDiagnostics() TracePipelineDiagnostics {
	if w == nil {
		return TracePipelineDiagnostics{}
	}

	queueCapacity := cap(w.queue)
	queueDepth := len(w.queue)
	queueDepthHighWatermark := int(w.queueDepthHighWatermark.Load())
	if queueDepth > queueDepthHighWatermark {
		queueDepthHighWatermark = queueDepth
	}

	queueUtilPct := queueUtilizationPct(queueDepth, queueCapacity)
	queueHighWatermarkUtilPct := queueUtilizationPct(queueDepthHighWatermark, queueCapacity)

	enqueueDropped := w.enqueueDroppedTotal.Load()
	writeDropped := w.writeDroppedTotal.Load()

	snapshot := TracePipelineDiagnostics{
		QueueCapacity:                    queueCapacity,
		QueueDepth:                       queueDepth,
		QueueDepthHighWatermark:          queueDepthHighWatermark,
		QueueUtilizationPct:              queueUtilPct,
		QueueHighWatermarkUtilizationPct: queueHighWatermarkUtilPct,
		QueuePressureState:               queuePressureState(queueUtilPct),
		QueueHighWatermarkPressureState:  queuePressureState(queueHighWatermarkUtilPct),
		EnqueueAcceptedTotal:             w.enqueueAcceptedTotal.Load(),
		EnqueueDroppedTotal:              enqueueDropped,
		WriteDroppedTotal:                writeDropped,
		TotalDroppedTotal:                enqueueDropped + writeDropped,
	}

	if ts := w.lastEnqueueDropUnixNano.Load(); ts > 0 {
		last := time.Unix(0, ts).UTC()
		snapshot.LastEnqueueDropAt = &last
	}
	if ts := w.lastWriteDropUnixNano.Load(); ts > 0 {
		last := time.Unix(0, ts).UTC()
		snapshot.LastWriteDropAt = &last
	}
	if operation, ok := w.lastWriteDropOperation.Load().(string); ok {
		snapshot.LastWriteDropOperation = operation
	}
	return snapshot
}

func (w *Writer) observeQueueDepth(depth int) {
	if w == nil || depth < 0 {
		return
	}
	depthValue := int64(depth)
	for {
		current := w.queueDepthHighWatermark.Load()
		if depthValue <= current {
			return
		}
		if w.queueDepthHighWatermark.CompareAndSwap(current, depthValue) {
			return
		}
	}
}

func queueUtilizationPct(depth, capacity int) int {
	if capacity <= 0 || depth <= 0 {
		return 0
	}
	if depth >= capacity {
		return 100
	}
	return int((int64(depth) * 100) / int64(capacity))
}

func queuePressureState(utilizationPct int) string {
	switch {
	case utilizationPct >= 100:
		return TraceQueuePressureSaturated
	case utilizationPct >= 80:
		return TraceQueuePressureHigh
	case utilizationPct >= 50:
		return TraceQueuePressureElevated
	default:
		return TraceQueuePressureOK
	}
}

func (w *Writer) flushBatch(ctx context.Context, batch []*Trace) {
	if len(batch) == 0 {
		return
	}
	if len(batch) == 1 {
		if err := w.store.WriteTrace(ctx, batch[0]); err != nil {
			w.reportWriteFailure(WriteFailure{
				Operation:   "write_trace",
				BatchSize:   1,
				FailedCount: 1,
				Err:         err,
			})
		}
		return
	}
	if err := w.store.WriteBatch(ctx, batch); err != nil {
		// Fallback to per-item writes so a batch-level failure does not drop all traces.
		failedWrites := 0
		var fallbackErr error
		for _, trace := range batch {
			if traceErr := w.store.WriteTrace(ctx, trace); traceErr != nil {
				failedWrites++
				if fallbackErr == nil {
					fallbackErr = traceErr
				}
			}
		}
		if failedWrites > 0 {
			w.reportWriteFailure(WriteFailure{
				Operation:   "write_batch_fallback",
				BatchSize:   len(batch),
				FailedCount: failedWrites,
				Err:         errors.Join(err, fallbackErr),
			})
		}
	}
}
