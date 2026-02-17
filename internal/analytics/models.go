package analytics

import (
	"context"

	"github.com/ongoingai/gateway/internal/trace"
)

type ModelService struct {
	store trace.TraceStore
}

func NewModelService(store trace.TraceStore) *ModelService {
	return &ModelService{store: store}
}

func (s *ModelService) Stats(ctx context.Context, filter trace.AnalyticsFilter) ([]trace.ModelStats, error) {
	return s.store.GetModelStats(ctx, filter)
}
