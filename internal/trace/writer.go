package trace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const writerBatchSize = 64

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

// WriterMetrics holds optional callbacks the Writer invokes at key pipeline points.
type WriterMetrics struct {
	// OnEnqueue is called each time a trace is successfully placed on the queue.
	OnEnqueue func()
	// OnDrop is called each time a trace is dropped because the queue is full.
	OnDrop func()
	// OnFlush is called after each batch is flushed to storage.
	OnFlush func(batchSize int, duration time.Duration)
}

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
	metrics            atomic.Value // *WriterMetrics
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

// SetMetrics replaces the metric callbacks used by the writer pipeline.
func (w *Writer) SetMetrics(m *WriterMetrics) {
	if w == nil {
		return
	}
	if m == nil {
		m = &WriterMetrics{}
	}
	w.metrics.Store(m)
}

func (w *Writer) loadMetrics() *WriterMetrics {
	m, _ := w.metrics.Load().(*WriterMetrics)
	return m
}

// QueueLen returns the current number of items waiting in the write queue.
func (w *Writer) QueueLen() int {
	if w == nil {
		return 0
	}
	return len(w.queue)
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
		if m := w.loadMetrics(); m != nil && m.OnEnqueue != nil {
			m.OnEnqueue()
		}
		return true
	default:
		if m := w.loadMetrics(); m != nil && m.OnDrop != nil {
			m.OnDrop()
		}
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
	handler, ok := w.writeFailureHandle.Load().(WriteFailureHandler)
	if !ok || handler == nil {
		return
	}
	handler(failure)
}

func (w *Writer) flushBatch(ctx context.Context, batch []*Trace) {
	if len(batch) == 0 {
		return
	}
	start := time.Now()
	defer func() {
		if m := w.loadMetrics(); m != nil && m.OnFlush != nil {
			m.OnFlush(len(batch), time.Since(start))
		}
	}()
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
