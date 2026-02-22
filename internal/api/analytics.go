package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

type modelsResponse struct {
	Items []modelStatsResponse `json:"items"`
}

type keysResponse struct {
	Items []keyStatsResponse `json:"items"`
}

type modelStatsResponse struct {
	Model        string  `json:"model"`
	RequestCount int64   `json:"request_count"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
	AvgTTFTMS    float64 `json:"avg_ttft_ms"`
	TotalTokens  int64   `json:"total_tokens"`
	TotalCostUSD float64 `json:"total_cost_usd"`
}

type keyStatsResponse struct {
	APIKeyHash   string    `json:"api_key_hash"`
	RequestCount int64     `json:"request_count"`
	TotalTokens  int64     `json:"total_tokens"`
	TotalCostUSD float64   `json:"total_cost_usd"`
	LastActiveAt time.Time `json:"last_active_at,omitempty"`
}

type summaryResponse struct {
	TotalRequests     int64   `json:"total_requests"`
	TotalInputTokens  int64   `json:"total_input_tokens"`
	TotalOutputTokens int64   `json:"total_output_tokens"`
	TotalTokens       int64   `json:"total_tokens"`
	TotalCostUSD      float64 `json:"total_cost_usd"`
	ActiveKeys        int     `json:"active_keys"`
	TopModel          string  `json:"top_model,omitempty"`
}

type usageSeriesResponse struct {
	GroupBy string             `json:"group_by,omitempty"`
	Bucket  string             `json:"bucket"`
	Items   []usageSeriesPoint `json:"items"`
}

type usageSeriesPoint struct {
	BucketStart  time.Time `json:"bucket_start"`
	Group        string    `json:"group,omitempty"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	TotalTokens  int64     `json:"total_tokens"`
}

type costSeriesResponse struct {
	GroupBy string            `json:"group_by,omitempty"`
	Bucket  string            `json:"bucket"`
	Items   []costSeriesPoint `json:"items"`
}

type costSeriesPoint struct {
	BucketStart  time.Time `json:"bucket_start"`
	Group        string    `json:"group,omitempty"`
	TotalCostUSD float64   `json:"total_cost_usd"`
	RequestCount int64     `json:"request_count"`
	AvgCostUSD   float64   `json:"avg_cost_usd"`
}

type latencyResponse struct {
	GroupBy string              `json:"group_by,omitempty"`
	Items   []latencyStatsPoint `json:"items"`
}

type latencyStatsPoint struct {
	Group        string  `json:"group,omitempty"`
	RequestCount int64   `json:"request_count"`
	AvgMS        float64 `json:"avg_ms"`
	MinMS        int64   `json:"min_ms"`
	MaxMS        int64   `json:"max_ms"`
	P50MS        float64 `json:"p50_ms"`
	P95MS        float64 `json:"p95_ms"`
	P99MS        float64 `json:"p99_ms"`
}

type errorsResponse struct {
	GroupBy string           `json:"group_by,omitempty"`
	Items   []errorRatePoint `json:"items"`
}

type errorRatePoint struct {
	Group         string  `json:"group,omitempty"`
	TotalRequests int64   `json:"total_requests"`
	ErrorCount4xx int64   `json:"error_count_4xx"`
	ErrorCount5xx int64   `json:"error_count_5xx"`
	ErrorRate     float64 `json:"error_rate"`
}

func UsageHandler(store trace.TraceStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "trace store is not configured")
			return
		}

		filter, err := parseAnalyticsFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		groupBy, bucket, seriesMode, err := parseSeriesOptions(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if seriesMode {
			points, err := store.GetUsageSeries(r.Context(), filter, groupBy, bucket)
			if err != nil {
				handleAnalyticsError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, usageSeriesResponse{
				GroupBy: groupBy,
				Bucket:  bucket,
				Items:   toUsageSeriesPoints(points),
			})
			return
		}

		summary, err := store.GetUsageSummary(r.Context(), filter)
		if err != nil {
			handleAnalyticsError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, summary)
	})
}

func CostHandler(store trace.TraceStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "trace store is not configured")
			return
		}

		filter, err := parseAnalyticsFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		groupBy, bucket, seriesMode, err := parseSeriesOptions(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if seriesMode {
			points, err := store.GetCostSeries(r.Context(), filter, groupBy, bucket)
			if err != nil {
				handleAnalyticsError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, costSeriesResponse{
				GroupBy: groupBy,
				Bucket:  bucket,
				Items:   toCostSeriesPoints(points),
			})
			return
		}

		summary, err := store.GetCostSummary(r.Context(), filter)
		if err != nil {
			handleAnalyticsError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, summary)
	})
}

func ModelsHandler(store trace.TraceStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "trace store is not configured")
			return
		}

		filter, err := parseAnalyticsFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		items, err := store.GetModelStats(r.Context(), filter)
		if err != nil {
			handleAnalyticsError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, modelsResponse{Items: toModelStatsResponse(items)})
	})
}

func KeysHandler(store trace.TraceStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "trace store is not configured")
			return
		}

		filter, err := parseAnalyticsFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		items, err := store.GetKeyStats(r.Context(), filter)
		if err != nil {
			handleAnalyticsError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, keysResponse{Items: toKeyStatsResponse(items)})
	})
}

func LatencyHandler(store trace.TraceStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "trace store is not configured")
			return
		}

		filter, err := parseAnalyticsFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		groupBy, err := parseGroupByOption(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		items, err := store.GetLatencyPercentiles(r.Context(), filter, groupBy)
		if err != nil {
			handleAnalyticsError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, latencyResponse{
			GroupBy: groupBy,
			Items:   toLatencyStatsPoints(items),
		})
	})
}

func ErrorsHandler(store trace.TraceStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "trace store is not configured")
			return
		}

		filter, err := parseAnalyticsFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		groupBy, err := parseGroupByOption(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		items, err := store.GetErrorRateBreakdown(r.Context(), filter, groupBy)
		if err != nil {
			handleAnalyticsError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, errorsResponse{
			GroupBy: groupBy,
			Items:   toErrorRatePoints(items),
		})
	})
}

func SummaryHandler(store trace.TraceStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if store == nil {
			writeError(w, http.StatusServiceUnavailable, "trace store is not configured")
			return
		}

		filter, err := parseAnalyticsFilter(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		var (
			usage  *trace.UsageSummary
			cost   *trace.CostSummary
			models []trace.ModelStats
			keys   []trace.KeyStats
		)
		var (
			queryErr error
			mu       sync.Mutex
			wg       sync.WaitGroup
		)

		run := func(query func() error) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := query(); err != nil {
					mu.Lock()
					if queryErr == nil {
						queryErr = err
					}
					mu.Unlock()
				}
			}()
		}

		run(func() error {
			var err error
			usage, err = store.GetUsageSummary(r.Context(), filter)
			return err
		})
		run(func() error {
			var err error
			cost, err = store.GetCostSummary(r.Context(), filter)
			return err
		})
		run(func() error {
			var err error
			models, err = store.GetModelStats(r.Context(), filter)
			return err
		})
		run(func() error {
			var err error
			keys, err = store.GetKeyStats(r.Context(), filter)
			return err
		})
		wg.Wait()
		if queryErr != nil {
			handleAnalyticsError(w, queryErr)
			return
		}
		if usage == nil {
			usage = &trace.UsageSummary{}
		}
		if cost == nil {
			cost = &trace.CostSummary{}
		}

		totalRequests := int64(0)
		topModel := ""
		topRequests := int64(0)
		for _, model := range models {
			totalRequests += model.RequestCount
			if model.RequestCount > topRequests {
				topRequests = model.RequestCount
				topModel = model.Model
			}
		}

		writeJSON(w, http.StatusOK, summaryResponse{
			TotalRequests:     totalRequests,
			TotalInputTokens:  usage.TotalInputTokens,
			TotalOutputTokens: usage.TotalOutputTokens,
			TotalTokens:       usage.TotalTokens,
			TotalCostUSD:      cost.TotalCostUSD,
			ActiveKeys:        len(keys),
			TopModel:          topModel,
		})
	})
}

func parseAnalyticsFilter(r *http.Request) (trace.AnalyticsFilter, error) {
	query := r.URL.Query()
	from, err := parseTimeQuery(query.Get("from"), false)
	if err != nil {
		return trace.AnalyticsFilter{}, fmt.Errorf("invalid from: %w", err)
	}
	to, err := parseTimeQuery(query.Get("to"), true)
	if err != nil {
		return trace.AnalyticsFilter{}, fmt.Errorf("invalid to: %w", err)
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		return trace.AnalyticsFilter{}, fmt.Errorf("to must be greater than or equal to from")
	}

	filter := trace.AnalyticsFilter{
		Provider: strings.TrimSpace(query.Get("provider")),
		Model:    strings.TrimSpace(query.Get("model")),
		From:     from,
		To:       to,
	}
	applyAnalyticsTenantScope(r, &filter)
	return filter, nil
}

func handleAnalyticsError(w http.ResponseWriter, err error) {
	if errors.Is(err, trace.ErrNotImplemented) {
		writeError(w, http.StatusNotImplemented, "analytics query is not implemented")
		return
	}
	writeError(w, http.StatusInternalServerError, "failed to read analytics")
}

func parseSeriesOptions(r *http.Request) (groupBy string, bucket string, seriesMode bool, err error) {
	groupBy = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("group_by")))
	bucket = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("bucket")))

	switch groupBy {
	case "", "provider", "model":
	default:
		return "", "", false, fmt.Errorf("invalid group_by: %q", groupBy)
	}

	switch bucket {
	case "", "hour", "day", "week":
	default:
		return "", "", false, fmt.Errorf("invalid bucket: %q", bucket)
	}

	seriesMode = groupBy != "" || bucket != ""
	if !seriesMode {
		return "", "", false, nil
	}

	if bucket == "" {
		bucket = "day"
	}
	return groupBy, bucket, true, nil
}

func toModelStatsResponse(items []trace.ModelStats) []modelStatsResponse {
	out := make([]modelStatsResponse, 0, len(items))
	for _, item := range items {
		out = append(out, modelStatsResponse{
			Model:        item.Model,
			RequestCount: item.RequestCount,
			AvgLatencyMS: item.AvgLatencyMS,
			AvgTTFTMS:    item.AvgTTFTMS,
			TotalTokens:  item.TotalTokens,
			TotalCostUSD: item.TotalCostUSD,
		})
	}
	return out
}

func toKeyStatsResponse(items []trace.KeyStats) []keyStatsResponse {
	out := make([]keyStatsResponse, 0, len(items))
	for _, item := range items {
		out = append(out, keyStatsResponse{
			APIKeyHash:   item.APIKeyHash,
			RequestCount: item.RequestCount,
			TotalTokens:  item.TotalTokens,
			TotalCostUSD: item.TotalCostUSD,
			LastActiveAt: item.LastActiveAt,
		})
	}
	return out
}

func toUsageSeriesPoints(items []trace.UsagePoint) []usageSeriesPoint {
	out := make([]usageSeriesPoint, 0, len(items))
	for _, item := range items {
		out = append(out, usageSeriesPoint{
			BucketStart:  item.BucketStart,
			Group:        item.Group,
			InputTokens:  item.InputTokens,
			OutputTokens: item.OutputTokens,
			TotalTokens:  item.TotalTokens,
		})
	}
	return out
}

func toCostSeriesPoints(items []trace.CostPoint) []costSeriesPoint {
	out := make([]costSeriesPoint, 0, len(items))
	for _, item := range items {
		out = append(out, costSeriesPoint{
			BucketStart:  item.BucketStart,
			Group:        item.Group,
			TotalCostUSD: item.TotalCostUSD,
			RequestCount: item.RequestCount,
			AvgCostUSD:   item.AvgCostUSD,
		})
	}
	return out
}

func toLatencyStatsPoints(items []trace.LatencyStats) []latencyStatsPoint {
	out := make([]latencyStatsPoint, 0, len(items))
	for _, item := range items {
		out = append(out, latencyStatsPoint{
			Group:        item.Group,
			RequestCount: item.RequestCount,
			AvgMS:        item.AvgMS,
			MinMS:        item.MinMS,
			MaxMS:        item.MaxMS,
			P50MS:        item.P50MS,
			P95MS:        item.P95MS,
			P99MS:        item.P99MS,
		})
	}
	return out
}

func toErrorRatePoints(items []trace.ErrorRateStats) []errorRatePoint {
	out := make([]errorRatePoint, 0, len(items))
	for _, item := range items {
		out = append(out, errorRatePoint{
			Group:         item.Group,
			TotalRequests: item.TotalRequests,
			ErrorCount4xx: item.ErrorCount4xx,
			ErrorCount5xx: item.ErrorCount5xx,
			ErrorRate:     item.ErrorRate,
		})
	}
	return out
}

func parseGroupByOption(r *http.Request) (string, error) {
	groupBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("group_by")))
	switch groupBy {
	case "", "provider", "model", "route", "key":
		return groupBy, nil
	default:
		return "", fmt.Errorf("invalid group_by: %q", groupBy)
	}
}
