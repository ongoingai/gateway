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
		})
	}
	return out
}
