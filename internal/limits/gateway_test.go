package limits

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/trace"
)

type stubTraceStore struct {
	usageSummary    *trace.UsageSummary
	usageSummaryErr error
	costSummary     *trace.CostSummary
	costSummaryErr  error
	lastUsageFilter trace.AnalyticsFilter
	lastCostFilter  trace.AnalyticsFilter
}

func (s *stubTraceStore) WriteTrace(context.Context, *trace.Trace) error   { return nil }
func (s *stubTraceStore) WriteBatch(context.Context, []*trace.Trace) error { return nil }
func (s *stubTraceStore) GetTrace(context.Context, string) (*trace.Trace, error) {
	return nil, trace.ErrNotImplemented
}
func (s *stubTraceStore) QueryTraces(context.Context, trace.TraceFilter) (*trace.TraceResult, error) {
	return nil, trace.ErrNotImplemented
}
func (s *stubTraceStore) GetUsageSummary(_ context.Context, filter trace.AnalyticsFilter) (*trace.UsageSummary, error) {
	s.lastUsageFilter = filter
	if s.usageSummaryErr != nil {
		return nil, s.usageSummaryErr
	}
	if s.usageSummary != nil {
		return s.usageSummary, nil
	}
	return &trace.UsageSummary{}, nil
}
func (s *stubTraceStore) GetUsageSeries(context.Context, trace.AnalyticsFilter, string, string) ([]trace.UsagePoint, error) {
	return nil, trace.ErrNotImplemented
}
func (s *stubTraceStore) GetCostSummary(_ context.Context, filter trace.AnalyticsFilter) (*trace.CostSummary, error) {
	s.lastCostFilter = filter
	if s.costSummaryErr != nil {
		return nil, s.costSummaryErr
	}
	if s.costSummary != nil {
		return s.costSummary, nil
	}
	return &trace.CostSummary{}, nil
}
func (s *stubTraceStore) GetCostSeries(context.Context, trace.AnalyticsFilter, string, string) ([]trace.CostPoint, error) {
	return nil, trace.ErrNotImplemented
}
func (s *stubTraceStore) GetModelStats(context.Context, trace.AnalyticsFilter) ([]trace.ModelStats, error) {
	return nil, trace.ErrNotImplemented
}
func (s *stubTraceStore) GetKeyStats(context.Context, trace.AnalyticsFilter) ([]trace.KeyStats, error) {
	return nil, trace.ErrNotImplemented
}

func TestGatewayLimiterPerKeyRateLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	limiter := NewGatewayLimiter(nil, Config{
		PerKey: Policy{
			RequestsPerMinute: 2,
		},
	})
	limiter.nowFn = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	identity := &auth.Identity{OrgID: "org-a", WorkspaceID: "workspace-a", KeyID: "key-a"}

	if result, err := limiter.CheckRequest(req, identity); err != nil || result != nil {
		t.Fatalf("first request result=%+v err=%v, want allow", result, err)
	}
	if result, err := limiter.CheckRequest(req, identity); err != nil || result != nil {
		t.Fatalf("second request result=%+v err=%v, want allow", result, err)
	}
	result, err := limiter.CheckRequest(req, identity)
	if err != nil {
		t.Fatalf("third request error=%v", err)
	}
	if result == nil || result.Code != "KEY_RATE_LIMIT_EXCEEDED" {
		t.Fatalf("third request result=%+v, want KEY_RATE_LIMIT_EXCEEDED", result)
	}
	if result.RetryAfterSeconds <= 0 {
		t.Fatalf("retry_after_seconds=%d, want >0", result.RetryAfterSeconds)
	}
}

func TestGatewayLimiterPerKeyDailyTokenLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	store := &stubTraceStore{
		usageSummary: &trace.UsageSummary{TotalTokens: 100},
	}
	limiter := NewGatewayLimiter(store, Config{
		PerKey: Policy{
			MaxTokensPerDay: 100,
		},
	})
	limiter.nowFn = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	identity := &auth.Identity{OrgID: "org-a", WorkspaceID: "workspace-a", KeyID: "key-a"}
	result, err := limiter.CheckRequest(req, identity)
	if err != nil {
		t.Fatalf("CheckRequest() error=%v", err)
	}
	if result == nil || result.Code != "KEY_DAILY_TOKENS_EXCEEDED" {
		t.Fatalf("result=%+v, want KEY_DAILY_TOKENS_EXCEEDED", result)
	}
	if store.lastUsageFilter.GatewayKeyID != "key-a" {
		t.Fatalf("usage filter gateway_key_id=%q, want key-a", store.lastUsageFilter.GatewayKeyID)
	}
}

func TestGatewayLimiterPerWorkspaceDailyCostLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	store := &stubTraceStore{
		costSummary: &trace.CostSummary{TotalCostUSD: 2.5},
	}
	limiter := NewGatewayLimiter(store, Config{
		PerWorkspace: Policy{
			MaxCostUSDPerDay: 2.5,
		},
	})
	limiter.nowFn = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	identity := &auth.Identity{OrgID: "org-a", WorkspaceID: "workspace-a", KeyID: "key-a"}
	result, err := limiter.CheckRequest(req, identity)
	if err != nil {
		t.Fatalf("CheckRequest() error=%v", err)
	}
	if result == nil || result.Code != "WORKSPACE_DAILY_COST_EXCEEDED" {
		t.Fatalf("result=%+v, want WORKSPACE_DAILY_COST_EXCEEDED", result)
	}
	if store.lastCostFilter.GatewayKeyID != "" {
		t.Fatalf("workspace filter gateway_key_id=%q, want empty", store.lastCostFilter.GatewayKeyID)
	}
}

func TestGatewayLimiterCheckRequestConcurrentAccess(t *testing.T) {
	t.Parallel()

	limiter := NewGatewayLimiter(nil, Config{
		PerKey: Policy{
			RequestsPerMinute: 20_000,
		},
		PerWorkspace: Policy{
			RequestsPerMinute: 20_000,
		},
	})
	limiter.nowFn = func() time.Time {
		return time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	}

	const goroutines = 32
	const requestsPerGoroutine = 200

	start := make(chan struct{})
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
			identity := &auth.Identity{
				OrgID:       "org-a",
				WorkspaceID: "workspace-a",
				KeyID:       "key-a",
			}

			<-start
			for j := 0; j < requestsPerGoroutine; j++ {
				result, err := limiter.CheckRequest(req, identity)
				if err != nil {
					errCh <- fmt.Errorf("goroutine %d request %d returned error: %w", i, j, err)
					return
				}
				if result != nil {
					errCh <- fmt.Errorf("goroutine %d request %d unexpectedly limited with code %q", i, j, result.Code)
					return
				}
			}
		}(i)
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestGatewayLimiterPrunesStaleRateState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 10, 0, 0, 0, time.UTC)
	limiter := NewGatewayLimiter(nil, Config{
		PerKey: Policy{
			RequestsPerMinute: 1000,
		},
		PerWorkspace: Policy{
			RequestsPerMinute: 1000,
		},
	})
	limiter.nowFn = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	for i := 0; i < 25; i++ {
		identity := &auth.Identity{
			OrgID:       "org-a",
			WorkspaceID: fmt.Sprintf("workspace-%d", i),
			KeyID:       fmt.Sprintf("key-%d", i),
		}
		if result, err := limiter.CheckRequest(req, identity); err != nil || result != nil {
			t.Fatalf("seed request %d result=%+v err=%v, want allow", i, result, err)
		}
	}
	if got := len(limiter.keyRequests); got != 25 {
		t.Fatalf("key request state size=%d, want 25", got)
	}
	if got := len(limiter.workspaceRequests); got != 25 {
		t.Fatalf("workspace request state size=%d, want 25", got)
	}

	now = now.Add(3 * time.Minute)
	if result, err := limiter.CheckRequest(req, &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-current",
		KeyID:       "key-current",
	}); err != nil || result != nil {
		t.Fatalf("post-sweep request result=%+v err=%v, want allow", result, err)
	}

	if got := len(limiter.keyRequests); got != 1 {
		t.Fatalf("key request state size after sweep=%d, want 1", got)
	}
	if got := len(limiter.workspaceRequests); got != 1 {
		t.Fatalf("workspace request state size after sweep=%d, want 1", got)
	}
}
