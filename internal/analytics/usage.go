package analytics

import (
	"context"

	"github.com/ongoingai/gateway/internal/trace"
)

type UsageService struct {
	store trace.TraceStore
}

func NewUsageService(store trace.TraceStore) *UsageService {
	return &UsageService{store: store}
}

func (s *UsageService) Summary(ctx context.Context, filter trace.AnalyticsFilter) (*trace.UsageSummary, error) {
	return s.store.GetUsageSummary(ctx, filter)
}
