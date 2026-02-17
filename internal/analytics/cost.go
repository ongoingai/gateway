package analytics

import (
	"context"

	"github.com/ongoingai/gateway/internal/trace"
)

type CostService struct {
	store trace.TraceStore
}

func NewCostService(store trace.TraceStore) *CostService {
	return &CostService{store: store}
}

func (s *CostService) Summary(ctx context.Context, filter trace.AnalyticsFilter) (*trace.CostSummary, error) {
	return s.store.GetCostSummary(ctx, filter)
}
