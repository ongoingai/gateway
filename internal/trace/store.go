package trace

import (
	"context"
	"errors"
	"time"
)

var ErrNotImplemented = errors.New("trace store method not implemented")
var ErrNotFound = errors.New("trace store record not found")
var ErrInvalidCursor = errors.New("trace cursor is invalid")

type TraceStore interface {
	WriteTrace(ctx context.Context, trace *Trace) error
	WriteBatch(ctx context.Context, traces []*Trace) error
	GetTrace(ctx context.Context, id string) (*Trace, error)
	QueryTraces(ctx context.Context, filter TraceFilter) (*TraceResult, error)
	GetUsageSummary(ctx context.Context, filter AnalyticsFilter) (*UsageSummary, error)
	GetUsageSeries(ctx context.Context, filter AnalyticsFilter, groupBy, bucket string) ([]UsagePoint, error)
	GetCostSummary(ctx context.Context, filter AnalyticsFilter) (*CostSummary, error)
	GetCostSeries(ctx context.Context, filter AnalyticsFilter, groupBy, bucket string) ([]CostPoint, error)
	GetModelStats(ctx context.Context, filter AnalyticsFilter) ([]ModelStats, error)
	GetKeyStats(ctx context.Context, filter AnalyticsFilter) ([]KeyStats, error)
	GetLatencyPercentiles(ctx context.Context, filter AnalyticsFilter, groupBy string) ([]LatencyStats, error)
	GetErrorRateBreakdown(ctx context.Context, filter AnalyticsFilter, groupBy string) ([]ErrorRateStats, error)
}

type TraceFilter struct {
	OrgID        string
	WorkspaceID  string
	TraceGroupID string
	ThreadID     string
	RunID        string
	Provider     string
	Model        string
	APIKeyHash   string
	StatusCode   int
	MinTokens    int
	MaxTokens    int
	From         time.Time
	To           time.Time
	Limit        int
	Cursor       string
}

type TraceResult struct {
	Items      []*Trace
	NextCursor string
}

type AnalyticsFilter struct {
	OrgID        string
	WorkspaceID  string
	GatewayKeyID string
	Provider     string
	Model        string
	From         time.Time
	To           time.Time
}

type UsageSummary struct {
	TotalInputTokens  int64
	TotalOutputTokens int64
	TotalTokens       int64
}

type CostSummary struct {
	TotalCostUSD float64
}

type UsagePoint struct {
	BucketStart  time.Time
	Group        string
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
}

type CostPoint struct {
	BucketStart  time.Time
	Group        string
	TotalCostUSD float64
	RequestCount int64
	AvgCostUSD   float64
}

type ModelStats struct {
	Model        string
	RequestCount int64
	AvgLatencyMS float64
	AvgTTFTMS    float64
	TotalTokens  int64
	TotalCostUSD float64
}

type KeyStats struct {
	APIKeyHash   string
	RequestCount int64
	TotalTokens  int64
	TotalCostUSD float64
	LastActiveAt time.Time
}

type LatencyStats struct {
	Group        string
	RequestCount int64
	AvgMS        float64
	MinMS        int64
	MaxMS        int64
	P50MS        float64
	P95MS        float64
	P99MS        float64
}

type ErrorRateStats struct {
	Group         string
	TotalRequests int64
	ErrorCount4xx int64
	ErrorCount5xx int64
	ErrorRate     float64
}
