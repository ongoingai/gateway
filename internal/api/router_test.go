package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/configstore"
	"github.com/ongoingai/gateway/internal/trace"
)

type stubStore struct {
	mu                  sync.Mutex
	getByID             map[string]*trace.Trace
	getTraceErr         error
	queryResult         *trace.TraceResult
	queryErr            error
	usageSummary        *trace.UsageSummary
	usageSummaryErr     error
	usageSeries         []trace.UsagePoint
	usageSeriesErr      error
	costSummary         *trace.CostSummary
	costSummaryErr      error
	costSeries          []trace.CostPoint
	costSeriesErr       error
	modelStats          []trace.ModelStats
	modelStatsErr       error
	keyStats            []trace.KeyStats
	keyStatsErr         error
	lastTraceFilter     trace.TraceFilter
	lastAnalyticsFilter trace.AnalyticsFilter
	lastGroupBy         string
	lastBucket          string
}

type stubGatewayKeyStore struct {
	keys             []configstore.GatewayKey
	keysErr          error
	createResult     *configstore.GatewayKey
	createErr        error
	createCalls      int
	revokeErr        error
	rotateResult     *configstore.GatewayKey
	rotateErr        error
	rotateCalls      int
	lastFilter       configstore.GatewayKeyFilter
	lastCreate       configstore.GatewayKey
	lastRevokeID     string
	lastRevokeFilter configstore.GatewayKeyFilter
	lastRotateID     string
	lastRotateToken  string
	lastRotateFilter configstore.GatewayKeyFilter
}

type stubTracePipelineDiagnosticsReader struct {
	snapshot trace.TracePipelineDiagnostics
}

func (s *stubTracePipelineDiagnosticsReader) TracePipelineDiagnostics() trace.TracePipelineDiagnostics {
	if s == nil {
		return trace.TracePipelineDiagnostics{}
	}
	return s.snapshot
}

func (s *stubGatewayKeyStore) ListGatewayKeys(_ context.Context, filter configstore.GatewayKeyFilter) ([]configstore.GatewayKey, error) {
	s.lastFilter = filter
	if s.keysErr != nil {
		return nil, s.keysErr
	}
	out := make([]configstore.GatewayKey, 0, len(s.keys))
	for _, key := range s.keys {
		copyKey := key
		copyKey.Permissions = append([]string(nil), key.Permissions...)
		out = append(out, copyKey)
	}
	return out, nil
}

func (s *stubGatewayKeyStore) CreateGatewayKey(_ context.Context, key configstore.GatewayKey) (*configstore.GatewayKey, error) {
	s.createCalls++
	s.lastCreate = key
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.createResult != nil {
		out := *s.createResult
		out.Permissions = append([]string(nil), s.createResult.Permissions...)
		return &out, nil
	}
	out := key
	out.Permissions = append([]string(nil), key.Permissions...)
	return &out, nil
}

func (s *stubGatewayKeyStore) RevokeGatewayKey(_ context.Context, id string, filter configstore.GatewayKeyFilter) error {
	s.lastRevokeID = id
	s.lastRevokeFilter = filter
	return s.revokeErr
}

func (s *stubGatewayKeyStore) RotateGatewayKey(_ context.Context, id, token string, filter configstore.GatewayKeyFilter) (*configstore.GatewayKey, error) {
	s.rotateCalls++
	s.lastRotateID = id
	s.lastRotateToken = token
	s.lastRotateFilter = filter
	if s.rotateErr != nil {
		return nil, s.rotateErr
	}
	if s.rotateResult != nil {
		out := *s.rotateResult
		out.Permissions = append([]string(nil), s.rotateResult.Permissions...)
		return &out, nil
	}
	out := configstore.GatewayKey{
		ID:          id,
		Token:       token,
		OrgID:       filter.OrgID,
		WorkspaceID: filter.WorkspaceID,
		Role:        "developer",
	}
	return &out, nil
}

func (s *stubGatewayKeyStore) Close() error {
	return nil
}

func (s *stubStore) WriteTrace(_ context.Context, _ *trace.Trace) error   { return nil }
func (s *stubStore) WriteBatch(_ context.Context, _ []*trace.Trace) error { return nil }

func (s *stubStore) GetTrace(_ context.Context, id string) (*trace.Trace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.getTraceErr != nil {
		return nil, s.getTraceErr
	}
	if item, ok := s.getByID[id]; ok {
		return item, nil
	}
	return nil, trace.ErrNotFound
}

func (s *stubStore) QueryTraces(_ context.Context, filter trace.TraceFilter) (*trace.TraceResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastTraceFilter = filter
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	if s.queryResult != nil {
		return s.queryResult, nil
	}
	return &trace.TraceResult{}, nil
}

func (s *stubStore) GetUsageSummary(_ context.Context, filter trace.AnalyticsFilter) (*trace.UsageSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAnalyticsFilter = filter
	if s.usageSummaryErr != nil {
		return nil, s.usageSummaryErr
	}
	if s.usageSummary != nil {
		return s.usageSummary, nil
	}
	return &trace.UsageSummary{}, nil
}

func (s *stubStore) GetUsageSeries(_ context.Context, filter trace.AnalyticsFilter, groupBy, bucket string) ([]trace.UsagePoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAnalyticsFilter = filter
	s.lastGroupBy = groupBy
	s.lastBucket = bucket
	if s.usageSeriesErr != nil {
		return nil, s.usageSeriesErr
	}
	return s.usageSeries, nil
}

func (s *stubStore) GetCostSummary(_ context.Context, filter trace.AnalyticsFilter) (*trace.CostSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAnalyticsFilter = filter
	if s.costSummaryErr != nil {
		return nil, s.costSummaryErr
	}
	if s.costSummary != nil {
		return s.costSummary, nil
	}
	return &trace.CostSummary{}, nil
}

func (s *stubStore) GetCostSeries(_ context.Context, filter trace.AnalyticsFilter, groupBy, bucket string) ([]trace.CostPoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAnalyticsFilter = filter
	s.lastGroupBy = groupBy
	s.lastBucket = bucket
	if s.costSeriesErr != nil {
		return nil, s.costSeriesErr
	}
	return s.costSeries, nil
}

func (s *stubStore) GetModelStats(_ context.Context, filter trace.AnalyticsFilter) ([]trace.ModelStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAnalyticsFilter = filter
	if s.modelStatsErr != nil {
		return nil, s.modelStatsErr
	}
	return s.modelStats, nil
}

func (s *stubStore) GetKeyStats(_ context.Context, filter trace.AnalyticsFilter) ([]trace.KeyStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastAnalyticsFilter = filter
	if s.keyStatsErr != nil {
		return nil, s.keyStatsErr
	}
	return s.keyStats, nil
}

func TestRouterServesTracesListAndDetail(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 3, 0, 0, 0, time.UTC)
	store := &stubStore{
		getByID: map[string]*trace.Trace{
			"trace-1": {
				ID:                 "trace-1",
				TraceGroupID:       "group-1",
				OrgID:              "org-a",
				WorkspaceID:        "workspace-a",
				Timestamp:          now,
				Provider:           "openai",
				Model:              "gpt-4o-mini",
				RequestMethod:      "POST",
				RequestPath:        "/openai/v1/chat/completions",
				RequestHeaders:     `{"Content-Type":["application/json"]}`,
				RequestBody:        `{"model":"gpt-4o-mini"}`,
				ResponseStatus:     200,
				ResponseHeaders:    `{"Content-Type":["application/json"]}`,
				ResponseBody:       `{"id":"chatcmpl-1"}`,
				InputTokens:        10,
				OutputTokens:       20,
				TotalTokens:        30,
				LatencyMS:          123,
				TimeToFirstTokenMS: 25,
				TimeToFirstTokenUS: 25000,
				APIKeyHash:         "hash-1",
				EstimatedCostUSD:   0.001,
				Metadata:           `{"streaming":false,"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"checkpoint-1","lineage_parent_checkpoint_id":"checkpoint-0","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
				CreatedAt:          now,
			},
		},
		queryResult: &trace.TraceResult{
			Items: []*trace.Trace{
				{
					ID:                 "trace-1",
					OrgID:              "org-a",
					WorkspaceID:        "workspace-a",
					Timestamp:          now,
					Provider:           "openai",
					Model:              "gpt-4o-mini",
					RequestMethod:      "POST",
					RequestPath:        "/openai/v1/chat/completions",
					ResponseStatus:     200,
					InputTokens:        10,
					OutputTokens:       20,
					TotalTokens:        30,
					LatencyMS:          123,
					TimeToFirstTokenMS: 25,
					TimeToFirstTokenUS: 25000,
					APIKeyHash:         "hash-1",
					EstimatedCostUSD:   0.001,
					CreatedAt:          now,
				},
			},
			NextCursor: "next-cursor",
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion:    "dev",
		Store:         store,
		StorageDriver: "sqlite",
		StoragePath:   "./data/ongoingai.db",
	})

	listReq := httptest.NewRequest(
		http.MethodGet,
		"/api/traces?provider=openai&trace_group_id=group-1&thread_id=thread-1&run_id=run-1&limit=10",
		nil,
	)
	listReq = listReq.WithContext(auth.WithIdentity(listReq.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("list status=%d, want 200", listRec.Code)
	}
	if store.lastTraceFilter.Provider != "openai" || store.lastTraceFilter.Limit != 10 {
		t.Fatalf("list filter=%+v", store.lastTraceFilter)
	}
	if store.lastTraceFilter.TraceGroupID != "group-1" || store.lastTraceFilter.ThreadID != "thread-1" || store.lastTraceFilter.RunID != "run-1" {
		t.Fatalf("lineage filter=%+v", store.lastTraceFilter)
	}
	if store.lastTraceFilter.OrgID != "org-a" || store.lastTraceFilter.WorkspaceID != "workspace-a" {
		t.Fatalf("tenant filter=%+v", store.lastTraceFilter)
	}

	var listBody map[string]any
	if err := json.Unmarshal(listRec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	items, ok := listBody["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("list items=%v", listBody["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok || first["id"] != "trace-1" {
		t.Fatalf("unexpected list item=%v", items[0])
	}
	if listBody["next_cursor"] != "next-cursor" {
		t.Fatalf("next_cursor=%v, want next-cursor", listBody["next_cursor"])
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/traces/trace-1", nil)
	detailReq = detailReq.WithContext(auth.WithIdentity(detailReq.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)

	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status=%d, want 200", detailRec.Code)
	}

	var detailBody map[string]any
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detailBody); err != nil {
		t.Fatalf("decode detail response: %v", err)
	}
	if detailBody["id"] != "trace-1" || detailBody["provider"] != "openai" {
		t.Fatalf("unexpected detail response=%v", detailBody)
	}
	lineage, ok := detailBody["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("lineage type=%T, want object", detailBody["lineage"])
	}
	if lineage["group_id"] != "group-1" || lineage["thread_id"] != "thread-1" || lineage["run_id"] != "run-1" {
		t.Fatalf("lineage core ids=%v, want group-1/thread-1/run-1", lineage)
	}
	if lineage["checkpoint_id"] != "checkpoint-1" || lineage["parent_checkpoint_id"] != "checkpoint-0" {
		t.Fatalf("lineage checkpoints=%v, want checkpoint-1/checkpoint-0", lineage)
	}
	if lineage["checkpoint_seq"] != float64(2) {
		t.Fatalf("lineage checkpoint_seq=%v, want 2", lineage["checkpoint_seq"])
	}
	if lineage["immutable"] != true {
		t.Fatalf("lineage immutable=%v, want true", lineage["immutable"])
	}
	if _, ok := detailBody["request_headers"].(map[string]any); !ok {
		t.Fatalf("request_headers type=%T, want object", detailBody["request_headers"])
	}

	deniedReq := httptest.NewRequest(http.MethodGet, "/api/traces/trace-1", nil)
	deniedReq = deniedReq.WithContext(auth.WithIdentity(deniedReq.Context(), &auth.Identity{
		OrgID:       "org-b",
		WorkspaceID: "workspace-b",
	}))
	deniedRec := httptest.NewRecorder()
	handler.ServeHTTP(deniedRec, deniedReq)
	if deniedRec.Code != http.StatusNotFound {
		t.Fatalf("tenant-mismatched detail status=%d, want 404", deniedRec.Code)
	}
}

func TestRouterTraceReplayReturnsCheckpointHistory(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 2, 14, 1, 0, 0, 0, time.UTC)
	store := &stubStore{
		getByID: map[string]*trace.Trace{
			"trace-2": {
				ID:             "trace-2",
				TraceGroupID:   "group-1",
				OrgID:          "org-a",
				WorkspaceID:    "workspace-a",
				Timestamp:      base.Add(2 * time.Minute),
				Provider:       "openai",
				Model:          "gpt-4o-mini",
				RequestMethod:  "POST",
				RequestPath:    "/openai/v1/chat/completions",
				ResponseStatus: 200,
				TotalTokens:    30,
				LatencyMS:      120,
				Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-2","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
				CreatedAt:      base.Add(2 * time.Minute),
			},
		},
		queryResult: &trace.TraceResult{
			Items: []*trace.Trace{
				{
					ID:             "trace-2",
					TraceGroupID:   "group-1",
					OrgID:          "org-a",
					WorkspaceID:    "workspace-a",
					Timestamp:      base.Add(2 * time.Minute),
					Provider:       "openai",
					Model:          "gpt-4o-mini",
					RequestMethod:  "POST",
					RequestPath:    "/openai/v1/chat/completions",
					ResponseStatus: 200,
					TotalTokens:    30,
					LatencyMS:      120,
					Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-2","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
					CreatedAt:      base.Add(2 * time.Minute),
				},
				{
					ID:             "trace-1",
					TraceGroupID:   "group-1",
					OrgID:          "org-a",
					WorkspaceID:    "workspace-a",
					Timestamp:      base.Add(1 * time.Minute),
					Provider:       "openai",
					Model:          "gpt-4o-mini",
					RequestMethod:  "POST",
					RequestPath:    "/openai/v1/chat/completions",
					ResponseStatus: 200,
					TotalTokens:    20,
					LatencyMS:      100,
					Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-1","lineage_checkpoint_seq":1,"lineage_immutable":true}`,
					CreatedAt:      base.Add(1 * time.Minute),
				},
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/traces/trace-2/replay", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("replay status=%d, want 200", rec.Code)
	}
	if store.lastTraceFilter.TraceGroupID != "group-1" {
		t.Fatalf("replay group filter=%q, want group-1", store.lastTraceFilter.TraceGroupID)
	}
	if store.lastTraceFilter.ThreadID != "thread-1" || store.lastTraceFilter.RunID != "run-1" {
		t.Fatalf("replay thread/run filter=%q/%q, want thread-1/run-1", store.lastTraceFilter.ThreadID, store.lastTraceFilter.RunID)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if body["source_trace_id"] != "trace-2" || body["target_checkpoint_id"] != "trace-2" {
		t.Fatalf("unexpected replay ids=%v", body)
	}
	checkpoints, ok := body["checkpoints"].([]any)
	if !ok || len(checkpoints) != 2 {
		t.Fatalf("replay checkpoints=%v, want two checkpoints", body["checkpoints"])
	}
	first, _ := checkpoints[0].(map[string]any)
	second, _ := checkpoints[1].(map[string]any)
	if first["id"] != "trace-1" || second["id"] != "trace-2" {
		t.Fatalf("replay checkpoint order=%v", checkpoints)
	}
	target, ok := body["target_trace"].(map[string]any)
	if !ok || target["id"] != "trace-2" {
		t.Fatalf("target_trace=%v, want trace-2 detail", body["target_trace"])
	}
}

func TestRouterTraceReplayReconstructsOutOfOrderLineage(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 2, 14, 3, 0, 0, 0, time.UTC)
	store := &stubStore{
		getByID: map[string]*trace.Trace{
			"trace-3": {
				ID:             "trace-3",
				TraceGroupID:   "group-1",
				OrgID:          "org-a",
				WorkspaceID:    "workspace-a",
				Timestamp:      base,
				Provider:       "anthropic",
				Model:          "claude-sonnet-4-latest",
				RequestMethod:  "POST",
				RequestPath:    "/anthropic/v1/messages",
				ResponseStatus: 200,
				TotalTokens:    36,
				LatencyMS:      190,
				Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-3","lineage_parent_checkpoint_id":"trace-2","lineage_immutable":true}`,
				CreatedAt:      base,
			},
		},
		queryResult: &trace.TraceResult{
			Items: []*trace.Trace{
				{
					ID:             "trace-3",
					TraceGroupID:   "group-1",
					OrgID:          "org-a",
					WorkspaceID:    "workspace-a",
					Timestamp:      base,
					Provider:       "anthropic",
					Model:          "claude-sonnet-4-latest",
					RequestMethod:  "POST",
					RequestPath:    "/anthropic/v1/messages",
					ResponseStatus: 200,
					TotalTokens:    36,
					LatencyMS:      190,
					Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-3","lineage_parent_checkpoint_id":"trace-2","lineage_immutable":true}`,
					CreatedAt:      base,
				},
				{
					ID:             "trace-1",
					TraceGroupID:   "group-1",
					OrgID:          "org-a",
					WorkspaceID:    "workspace-a",
					Timestamp:      base.Add(4 * time.Minute),
					Provider:       "openai",
					Model:          "gpt-4o-mini",
					RequestMethod:  "POST",
					RequestPath:    "/openai/v1/chat/completions",
					ResponseStatus: 200,
					TotalTokens:    14,
					LatencyMS:      120,
					Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-1","lineage_immutable":true}`,
					CreatedAt:      base.Add(4 * time.Minute),
				},
				{
					ID:             "trace-2",
					TraceGroupID:   "group-1",
					OrgID:          "org-a",
					WorkspaceID:    "workspace-a",
					Timestamp:      base.Add(5 * time.Minute),
					Provider:       "openai",
					Model:          "gpt-4o",
					RequestMethod:  "POST",
					RequestPath:    "/openai/v1/chat/completions",
					ResponseStatus: 200,
					TotalTokens:    22,
					LatencyMS:      150,
					Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-2","lineage_parent_checkpoint_id":"trace-1","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
					CreatedAt:      base.Add(5 * time.Minute),
				},
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/traces/trace-3/replay?checkpoint_id=trace-3", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("replay status=%d, want 200", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode replay response: %v", err)
	}
	if body["source_trace_id"] != "trace-3" || body["target_checkpoint_id"] != "trace-3" {
		t.Fatalf("unexpected replay ids=%v", body)
	}
	checkpoints, ok := body["checkpoints"].([]any)
	if !ok || len(checkpoints) != 3 {
		t.Fatalf("replay checkpoints=%v, want three checkpoints", body["checkpoints"])
	}
	first, _ := checkpoints[0].(map[string]any)
	second, _ := checkpoints[1].(map[string]any)
	third, _ := checkpoints[2].(map[string]any)
	if first["id"] != "trace-1" || second["id"] != "trace-2" || third["id"] != "trace-3" {
		t.Fatalf("replay checkpoint order=%v", checkpoints)
	}
}

func TestRouterTraceForkReturnsLineageHeaders(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 14, 2, 0, 0, 0, time.UTC)
	store := &stubStore{
		getByID: map[string]*trace.Trace{
			"trace-2": {
				ID:             "trace-2",
				TraceGroupID:   "group-1",
				OrgID:          "org-a",
				WorkspaceID:    "workspace-a",
				Timestamp:      now,
				Provider:       "openai",
				Model:          "gpt-4o-mini",
				RequestMethod:  "POST",
				RequestPath:    "/openai/v1/chat/completions",
				ResponseStatus: 200,
				Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-2","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
				CreatedAt:      now,
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/traces/trace-2/fork", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("fork status=%d, want 200", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode fork response: %v", err)
	}
	if body["source_trace_id"] != "trace-2" || body["source_checkpoint_id"] != "trace-2" {
		t.Fatalf("unexpected fork ids=%v", body)
	}
	forkID, ok := body["fork_id"].(string)
	if !ok || !strings.HasPrefix(forkID, "fork_") {
		t.Fatalf("fork_id=%v, want fork_*", body["fork_id"])
	}
	lineage, ok := body["lineage"].(map[string]any)
	if !ok {
		t.Fatalf("lineage=%T, want object", body["lineage"])
	}
	if lineage["group_id"] != "group-1" || lineage["thread_id"] != "thread-1" {
		t.Fatalf("lineage=%v, want group-1/thread-1", lineage)
	}
	if lineage["parent_checkpoint_id"] != "trace-2" {
		t.Fatalf("parent_checkpoint_id=%v, want trace-2", lineage["parent_checkpoint_id"])
	}
	if lineage["checkpoint_seq"] != float64(3) {
		t.Fatalf("checkpoint_seq=%v, want 3", lineage["checkpoint_seq"])
	}
	if runID, _ := lineage["run_id"].(string); !strings.HasPrefix(runID, "run_") {
		t.Fatalf("run_id=%v, want generated run_*", lineage["run_id"])
	}

	headers, ok := body["headers"].(map[string]any)
	if !ok {
		t.Fatalf("headers=%T, want object", body["headers"])
	}
	if headers["X-OngoingAI-Trace-Group-ID"] != "group-1" {
		t.Fatalf("trace group header=%v, want group-1", headers["X-OngoingAI-Trace-Group-ID"])
	}
	if headers["X-OngoingAI-Parent-Checkpoint-ID"] != "trace-2" {
		t.Fatalf("parent checkpoint header=%v, want trace-2", headers["X-OngoingAI-Parent-Checkpoint-ID"])
	}
	if headers["X-OngoingAI-Checkpoint-Seq"] != "3" {
		t.Fatalf("checkpoint seq header=%v, want 3", headers["X-OngoingAI-Checkpoint-Seq"])
	}
}

func TestRouterTraceForkRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 14, 2, 0, 0, 0, time.UTC)
	store := &stubStore{
		getByID: map[string]*trace.Trace{
			"trace-2": {
				ID:             "trace-2",
				TraceGroupID:   "group-1",
				OrgID:          "org-a",
				WorkspaceID:    "workspace-a",
				Timestamp:      now,
				Provider:       "openai",
				Model:          "gpt-4o-mini",
				RequestMethod:  "POST",
				RequestPath:    "/openai/v1/chat/completions",
				ResponseStatus: 200,
				Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-2","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
				CreatedAt:      now,
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/traces/trace-2/fork", strings.NewReader(`{"unexpected":true}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("fork status=%d, want 400", rec.Code)
	}
}

func TestRouterTraceForkRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 14, 2, 0, 0, 0, time.UTC)
	store := &stubStore{
		getByID: map[string]*trace.Trace{
			"trace-2": {
				ID:             "trace-2",
				TraceGroupID:   "group-1",
				OrgID:          "org-a",
				WorkspaceID:    "workspace-a",
				Timestamp:      now,
				Provider:       "openai",
				Model:          "gpt-4o-mini",
				RequestMethod:  "POST",
				RequestPath:    "/openai/v1/chat/completions",
				ResponseStatus: 200,
				Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-2","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
				CreatedAt:      now,
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/traces/trace-2/fork", strings.NewReader(`{} {}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("fork status=%d, want 400", rec.Code)
	}
}

func TestRouterTraceForkRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 14, 2, 0, 0, 0, time.UTC)
	store := &stubStore{
		getByID: map[string]*trace.Trace{
			"trace-2": {
				ID:             "trace-2",
				TraceGroupID:   "group-1",
				OrgID:          "org-a",
				WorkspaceID:    "workspace-a",
				Timestamp:      now,
				Provider:       "openai",
				Model:          "gpt-4o-mini",
				RequestMethod:  "POST",
				RequestPath:    "/openai/v1/chat/completions",
				ResponseStatus: 200,
				Metadata:       `{"lineage_group_id":"group-1","lineage_thread_id":"thread-1","lineage_run_id":"run-1","lineage_checkpoint_id":"trace-2","lineage_checkpoint_seq":2,"lineage_immutable":true}`,
				CreatedAt:      now,
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	body := `{"thread_id":"` + strings.Repeat("a", traceForkBodyLimit) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/traces/trace-2/fork", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("fork status=%d, want 413", rec.Code)
	}
}

func TestRouterAnalyticsSummaryAndHealth(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "ongoingai.db")
	if err := os.WriteFile(dbPath, []byte("sqlite-content"), 0o644); err != nil {
		t.Fatalf("write db file: %v", err)
	}

	store := &stubStore{
		usageSummary: &trace.UsageSummary{
			TotalInputTokens:  11,
			TotalOutputTokens: 7,
			TotalTokens:       18,
		},
		costSummary: &trace.CostSummary{
			TotalCostUSD: 0.0042,
		},
		modelStats: []trace.ModelStats{
			{Model: "gpt-4o-mini", RequestCount: 4},
			{Model: "claude-haiku-4-5-20251001", RequestCount: 2},
		},
		keyStats: []trace.KeyStats{
			{APIKeyHash: "key-a"},
			{APIKeyHash: "key-b"},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion:    "dev",
		Store:         store,
		StorageDriver: "sqlite",
		StoragePath:   dbPath,
	})

	summaryReq := httptest.NewRequest(http.MethodGet, "/api/analytics/summary", nil)
	summaryRec := httptest.NewRecorder()
	handler.ServeHTTP(summaryRec, summaryReq)
	if summaryRec.Code != http.StatusOK {
		t.Fatalf("summary status=%d, want 200", summaryRec.Code)
	}

	var summaryBody map[string]any
	if err := json.Unmarshal(summaryRec.Body.Bytes(), &summaryBody); err != nil {
		t.Fatalf("decode summary response: %v", err)
	}
	if summaryBody["total_requests"] != float64(6) {
		t.Fatalf("total_requests=%v, want 6", summaryBody["total_requests"])
	}
	if summaryBody["top_model"] != "gpt-4o-mini" {
		t.Fatalf("top_model=%v, want gpt-4o-mini", summaryBody["top_model"])
	}
	if summaryBody["active_keys"] != float64(2) {
		t.Fatalf("active_keys=%v, want 2", summaryBody["active_keys"])
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("health status=%d, want 200", healthRec.Code)
	}

	var healthBody map[string]any
	if err := json.Unmarshal(healthRec.Body.Bytes(), &healthBody); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if healthBody["storage_driver"] != "sqlite" {
		t.Fatalf("storage_driver=%v, want sqlite", healthBody["storage_driver"])
	}
	if healthBody["trace_count"] != float64(6) {
		t.Fatalf("trace_count=%v, want 6", healthBody["trace_count"])
	}
	if healthBody["db_size_bytes"] == nil || healthBody["db_size_bytes"].(float64) <= 0 {
		t.Fatalf("db_size_bytes=%v, want > 0", healthBody["db_size_bytes"])
	}
}

func TestRouterTracePipelineDiagnostics(t *testing.T) {
	t.Parallel()

	lastQueueDrop := time.Date(2026, 2, 22, 3, 4, 5, 0, time.UTC)
	lastWriteDrop := time.Date(2026, 2, 22, 3, 5, 6, 0, time.UTC)
	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      &stubStore{},
		TracePipelineReader: &stubTracePipelineDiagnosticsReader{
			snapshot: trace.TracePipelineDiagnostics{
				QueueCapacity:                    1024,
				QueueDepth:                       16,
				QueueDepthHighWatermark:          900,
				QueueUtilizationPct:              1,
				QueueHighWatermarkUtilizationPct: 87,
				QueuePressureState:               trace.TraceQueuePressureOK,
				QueueHighWatermarkPressureState:  trace.TraceQueuePressureHigh,
				EnqueueAcceptedTotal:             500,
				EnqueueDroppedTotal:              4,
				WriteDroppedTotal:                2,
				TotalDroppedTotal:                6,
				LastEnqueueDropAt:                &lastQueueDrop,
				LastWriteDropAt:                  &lastWriteDrop,
				LastWriteDropOperation:           "write_batch_fallback",
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/trace-pipeline", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}

	var payload tracePipelineDiagnosticsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.SchemaVersion != tracePipelineDiagnosticsSchemaVersion {
		t.Fatalf("schema_version=%q, want %q", payload.SchemaVersion, tracePipelineDiagnosticsSchemaVersion)
	}
	if payload.Diagnostics.QueueCapacity != 1024 {
		t.Fatalf("queue_capacity=%d, want 1024", payload.Diagnostics.QueueCapacity)
	}
	if payload.Diagnostics.EnqueueDroppedTotal != 4 {
		t.Fatalf("enqueue_dropped_total=%d, want 4", payload.Diagnostics.EnqueueDroppedTotal)
	}
	if payload.Diagnostics.WriteDroppedTotal != 2 {
		t.Fatalf("write_dropped_total=%d, want 2", payload.Diagnostics.WriteDroppedTotal)
	}
	if payload.Diagnostics.TotalDroppedTotal != 6 {
		t.Fatalf("total_dropped_total=%d, want 6", payload.Diagnostics.TotalDroppedTotal)
	}
	if payload.Diagnostics.LastWriteDropOperation != "write_batch_fallback" {
		t.Fatalf("last_write_drop_operation=%q, want write_batch_fallback", payload.Diagnostics.LastWriteDropOperation)
	}
}

func TestRouterTracePipelineDiagnosticsUnavailable(t *testing.T) {
	t.Parallel()

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      &stubStore{},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/trace-pipeline", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rec.Body.String(), "trace pipeline diagnostics unavailable") {
		t.Fatalf("body=%q, want diagnostics unavailable error", rec.Body.String())
	}
}

func TestRouterCORSAndValidation(t *testing.T) {
	t.Parallel()

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      &stubStore{},
	})

	optionsReq := httptest.NewRequest(http.MethodOptions, "/api/traces", nil)
	optionsRec := httptest.NewRecorder()
	handler.ServeHTTP(optionsRec, optionsReq)
	if optionsRec.Code != http.StatusNoContent {
		t.Fatalf("options status=%d, want 204", optionsRec.Code)
	}
	if got := optionsRec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("cors allow origin=%q, want *", got)
	}
	if got := optionsRec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-OngoingAI-Gateway-Key") {
		t.Fatalf("cors allow headers=%q, want default gateway key header", got)
	}

	invalidReq := httptest.NewRequest(http.MethodGet, "/api/traces?limit=-1", nil)
	invalidRec := httptest.NewRecorder()
	handler.ServeHTTP(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid filter status=%d, want 400", invalidRec.Code)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/api/traces", nil)
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d, want 405", postRec.Code)
	}
}

func TestRouterCORSIncludesCustomGatewayHeader(t *testing.T) {
	t.Parallel()

	handler := NewRouter(RouterOptions{
		AppVersion:        "dev",
		Store:             &stubStore{},
		GatewayAuthHeader: "X-Team-Gateway-Key",
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/traces", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("options status=%d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-Team-Gateway-Key") {
		t.Fatalf("cors allow headers=%q, want custom gateway key header", got)
	}
}

func TestRouterUsageSeriesQuery(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		usageSeries: []trace.UsagePoint{
			{
				BucketStart:  time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC),
				Group:        "openai",
				InputTokens:  10,
				OutputTokens: 5,
				TotalTokens:  15,
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/analytics/usage?group_by=provider&bucket=day", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		OrgID:       "org-b",
		WorkspaceID: "workspace-b",
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("usage series status=%d, want 200", rec.Code)
	}
	if store.lastGroupBy != "provider" || store.lastBucket != "day" {
		t.Fatalf("usage series options group_by/bucket=%s/%s", store.lastGroupBy, store.lastBucket)
	}
	if store.lastAnalyticsFilter.OrgID != "org-b" || store.lastAnalyticsFilter.WorkspaceID != "workspace-b" {
		t.Fatalf("analytics tenant filter=%+v", store.lastAnalyticsFilter)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode usage series response: %v", err)
	}
	if body["bucket"] != "day" {
		t.Fatalf("usage series bucket=%v, want day", body["bucket"])
	}
	if body["group_by"] != "provider" {
		t.Fatalf("usage series group_by=%v, want provider", body["group_by"])
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("usage series items=%v", body["items"])
	}
}

func TestRouterCostSeriesModelsAndKeys(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 0, 0, 0, 0, time.UTC)
	store := &stubStore{
		costSeries: []trace.CostPoint{
			{
				BucketStart:  now,
				Group:        "gpt-4o-mini",
				TotalCostUSD: 0.0123,
			},
		},
		modelStats: []trace.ModelStats{
			{
				Model:        "gpt-4o-mini",
				RequestCount: 7,
				AvgLatencyMS: 150.5,
				AvgTTFTMS:    42.1,
				TotalTokens:  1234,
				TotalCostUSD: 0.056,
			},
		},
		keyStats: []trace.KeyStats{
			{
				APIKeyHash:   "hash-a",
				RequestCount: 3,
				TotalTokens:  321,
				TotalCostUSD: 0.007,
				LastActiveAt: now,
			},
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      store,
	})

	costReq := httptest.NewRequest(http.MethodGet, "/api/analytics/cost?group_by=model&bucket=hour", nil)
	costRec := httptest.NewRecorder()
	handler.ServeHTTP(costRec, costReq)
	if costRec.Code != http.StatusOK {
		t.Fatalf("cost series status=%d, want 200", costRec.Code)
	}
	if store.lastGroupBy != "model" || store.lastBucket != "hour" {
		t.Fatalf("cost series options group_by/bucket=%s/%s", store.lastGroupBy, store.lastBucket)
	}

	var costBody map[string]any
	if err := json.Unmarshal(costRec.Body.Bytes(), &costBody); err != nil {
		t.Fatalf("decode cost series response: %v", err)
	}
	if costBody["bucket"] != "hour" {
		t.Fatalf("cost series bucket=%v, want hour", costBody["bucket"])
	}
	costItems, ok := costBody["items"].([]any)
	if !ok || len(costItems) != 1 {
		t.Fatalf("cost series items=%v", costBody["items"])
	}
	firstCost, ok := costItems[0].(map[string]any)
	if !ok || firstCost["group"] != "gpt-4o-mini" {
		t.Fatalf("cost series first item=%v", costItems[0])
	}

	modelsReq := httptest.NewRequest(http.MethodGet, "/api/analytics/models", nil)
	modelsRec := httptest.NewRecorder()
	handler.ServeHTTP(modelsRec, modelsReq)
	if modelsRec.Code != http.StatusOK {
		t.Fatalf("models status=%d, want 200", modelsRec.Code)
	}
	var modelsBody map[string]any
	if err := json.Unmarshal(modelsRec.Body.Bytes(), &modelsBody); err != nil {
		t.Fatalf("decode models response: %v", err)
	}
	modelItems, ok := modelsBody["items"].([]any)
	if !ok || len(modelItems) != 1 {
		t.Fatalf("models items=%v", modelsBody["items"])
	}
	firstModel, ok := modelItems[0].(map[string]any)
	if !ok || firstModel["model"] != "gpt-4o-mini" {
		t.Fatalf("models first item=%v", modelItems[0])
	}

	keysReq := httptest.NewRequest(http.MethodGet, "/api/analytics/keys", nil)
	keysRec := httptest.NewRecorder()
	handler.ServeHTTP(keysRec, keysReq)
	if keysRec.Code != http.StatusOK {
		t.Fatalf("keys status=%d, want 200", keysRec.Code)
	}
	var keysBody map[string]any
	if err := json.Unmarshal(keysRec.Body.Bytes(), &keysBody); err != nil {
		t.Fatalf("decode keys response: %v", err)
	}
	keyItems, ok := keysBody["items"].([]any)
	if !ok || len(keyItems) != 1 {
		t.Fatalf("keys items=%v", keysBody["items"])
	}
	firstKey, ok := keyItems[0].(map[string]any)
	if !ok || firstKey["api_key_hash"] != "hash-a" {
		t.Fatalf("keys first item=%v", keyItems[0])
	}
}

func TestRouterAnalyticsErrorAndValidationPaths(t *testing.T) {
	t.Parallel()

	handlerNotImplemented := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store: &stubStore{
			costSummaryErr: trace.ErrNotImplemented,
		},
	})
	notImplReq := httptest.NewRequest(http.MethodGet, "/api/analytics/cost", nil)
	notImplRec := httptest.NewRecorder()
	handlerNotImplemented.ServeHTTP(notImplRec, notImplReq)
	if notImplRec.Code != http.StatusNotImplemented {
		t.Fatalf("not implemented status=%d, want 501", notImplRec.Code)
	}

	handlerInternal := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store: &stubStore{
			modelStatsErr: errors.New("db failure"),
		},
	})
	internalReq := httptest.NewRequest(http.MethodGet, "/api/analytics/models", nil)
	internalRec := httptest.NewRecorder()
	handlerInternal.ServeHTTP(internalRec, internalReq)
	if internalRec.Code != http.StatusInternalServerError {
		t.Fatalf("internal error status=%d, want 500", internalRec.Code)
	}

	handlerValidation := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      &stubStore{},
	})
	invalidGroupReq := httptest.NewRequest(http.MethodGet, "/api/analytics/usage?group_by=key", nil)
	invalidGroupRec := httptest.NewRecorder()
	handlerValidation.ServeHTTP(invalidGroupRec, invalidGroupReq)
	if invalidGroupRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid group_by status=%d, want 400", invalidGroupRec.Code)
	}

	invalidRangeReq := httptest.NewRequest(http.MethodGet, "/api/analytics/usage?from=2026-02-12&to=2026-02-11", nil)
	invalidRangeRec := httptest.NewRecorder()
	handlerValidation.ServeHTTP(invalidRangeRec, invalidRangeReq)
	if invalidRangeRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid date range status=%d, want 400", invalidRangeRec.Code)
	}
}

func TestRouterGatewayKeyCRUDAndTenantScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 12, 6, 0, 0, 0, time.UTC)
	lastUsed := now.Add(2 * time.Hour)
	auditEvents := make([]GatewayKeyAuditEvent, 0, 4)
	keyStore := &stubGatewayKeyStore{
		keys: []configstore.GatewayKey{
			{
				ID:          "key-a",
				OrgID:       "org-a",
				WorkspaceID: "workspace-a",
				Name:        "CLI key",
				Description: "used by local CLI",
				CreatedBy:   "manager-key",
				LastUsedAt:  lastUsed,
				Role:        "developer",
				Permissions: []string{"proxy:write"},
				CreatedAt:   now,
			},
		},
		createResult: &configstore.GatewayKey{
			ID:          "created-key",
			Token:       "created-token",
			OrgID:       "org-a",
			WorkspaceID: "workspace-a",
			Name:        "Build key",
			Description: "used by CI",
			CreatedBy:   "manager-key",
			Role:        "owner",
			Permissions: []string{"keys:manage"},
			CreatedAt:   now,
		},
		rotateResult: &configstore.GatewayKey{
			ID:          "created-key",
			Token:       "rotated-token",
			OrgID:       "org-a",
			WorkspaceID: "workspace-a",
			Role:        "owner",
			Permissions: []string{"keys:manage"},
			CreatedAt:   now,
		},
	}

	handler := NewRouter(RouterOptions{
		AppVersion:      "dev",
		Store:           &stubStore{},
		GatewayKeyStore: keyStore,
		GatewayKeyAuditRecorder: func(_ *http.Request, event GatewayKeyAuditEvent) {
			auditEvents = append(auditEvents, event)
		},
	})

	listReq := httptest.NewRequest(http.MethodGet, "/api/gateway-keys", nil)
	listReq = listReq.WithContext(auth.WithIdentity(listReq.Context(), &auth.Identity{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status=%d, want 200", listRec.Code)
	}
	if keyStore.lastFilter.OrgID != "org-a" || keyStore.lastFilter.WorkspaceID != "workspace-a" {
		t.Fatalf("list tenant filter=%+v", keyStore.lastFilter)
	}
	var listBody map[string]any
	if err := json.Unmarshal(listRec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	items, ok := listBody["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("list items=%v", listBody["items"])
	}
	firstItem, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("list first item=%v", items[0])
	}
	if firstItem["name"] != "CLI key" || firstItem["description"] != "used by local CLI" || firstItem["created_by"] != "manager-key" {
		t.Fatalf("list metadata fields=%v", firstItem)
	}
	if _, ok := firstItem["last_used_at"]; !ok {
		t.Fatalf("list metadata missing last_used_at=%v", firstItem)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/gateway-keys", strings.NewReader(`{"id":"created-key","token":"created-token","org_id":"org-z","workspace_id":"workspace-z","name":"Build key","description":"used by CI","role":"owner","permissions":["keys:manage"]}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq = createReq.WithContext(auth.WithIdentity(createReq.Context(), &auth.Identity{
		KeyID:       "manager-key",
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status=%d, want 201", createRec.Code)
	}
	if keyStore.lastCreate.OrgID != "org-a" || keyStore.lastCreate.WorkspaceID != "workspace-a" {
		t.Fatalf("create tenant scope=%+v", keyStore.lastCreate)
	}
	if keyStore.lastCreate.Token != "created-token" {
		t.Fatalf("create token=%q, want created-token", keyStore.lastCreate.Token)
	}
	if keyStore.lastCreate.Name != "Build key" || keyStore.lastCreate.Description != "used by CI" {
		t.Fatalf("create metadata name/description=%q/%q, want Build key/used by CI", keyStore.lastCreate.Name, keyStore.lastCreate.Description)
	}
	if keyStore.lastCreate.CreatedBy != "manager-key" {
		t.Fatalf("create created_by=%q, want manager-key", keyStore.lastCreate.CreatedBy)
	}

	var createBody map[string]any
	if err := json.Unmarshal(createRec.Body.Bytes(), &createBody); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createBody["id"] != "created-key" || createBody["token"] != "created-token" {
		t.Fatalf("unexpected create response=%v", createBody)
	}
	if createBody["name"] != "Build key" || createBody["description"] != "used by CI" || createBody["created_by"] != "manager-key" {
		t.Fatalf("create metadata response=%v", createBody)
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/api/gateway-keys/created-key/rotate", strings.NewReader(`{"token":"rotated-token"}`))
	rotateReq.Header.Set("Content-Type", "application/json")
	rotateReq = rotateReq.WithContext(auth.WithIdentity(rotateReq.Context(), &auth.Identity{
		KeyID:       "manager-key",
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	rotateRec := httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate status=%d, want 200", rotateRec.Code)
	}
	if keyStore.lastRotateID != "created-key" || keyStore.lastRotateToken != "rotated-token" {
		t.Fatalf("rotate request captured id/token=%q/%q", keyStore.lastRotateID, keyStore.lastRotateToken)
	}
	if keyStore.lastRotateFilter.OrgID != "org-a" || keyStore.lastRotateFilter.WorkspaceID != "workspace-a" {
		t.Fatalf("rotate tenant filter=%+v", keyStore.lastRotateFilter)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/gateway-keys/created-key", nil)
	revokeReq = revokeReq.WithContext(auth.WithIdentity(revokeReq.Context(), &auth.Identity{
		KeyID:       "manager-key",
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}))
	revokeRec := httptest.NewRecorder()
	handler.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d, want 204", revokeRec.Code)
	}
	if keyStore.lastRevokeID != "created-key" {
		t.Fatalf("revoke id=%q, want created-key", keyStore.lastRevokeID)
	}
	if keyStore.lastRevokeFilter.OrgID != "org-a" || keyStore.lastRevokeFilter.WorkspaceID != "workspace-a" {
		t.Fatalf("revoke tenant filter=%+v", keyStore.lastRevokeFilter)
	}
	if len(auditEvents) != 3 {
		t.Fatalf("audit events len=%d, want 3", len(auditEvents))
	}
	if auditEvents[0].Action != "create" || auditEvents[0].Outcome != "success" || auditEvents[0].ActorKeyID != "manager-key" {
		t.Fatalf("create audit event=%+v", auditEvents[0])
	}
	if auditEvents[1].Action != "rotate" || auditEvents[1].Outcome != "success" || auditEvents[1].ActorKeyID != "manager-key" {
		t.Fatalf("rotate audit event=%+v", auditEvents[1])
	}
	if auditEvents[2].Action != "revoke" || auditEvents[2].Outcome != "success" || auditEvents[2].ActorKeyID != "manager-key" {
		t.Fatalf("revoke audit event=%+v", auditEvents[2])
	}
	for _, event := range auditEvents {
		if event.OrgID != "org-a" || event.WorkspaceID != "workspace-a" || event.TargetKeyID != "created-key" {
			t.Fatalf("audit event tenant/target=%+v", event)
		}
	}
}

func TestRouterGatewayKeyErrorPaths(t *testing.T) {
	t.Parallel()

	handlerNoStore := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      &stubStore{},
	})
	noStoreReq := httptest.NewRequest(http.MethodGet, "/api/gateway-keys", nil)
	noStoreRec := httptest.NewRecorder()
	handlerNoStore.ServeHTTP(noStoreRec, noStoreReq)
	if noStoreRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no store status=%d, want 503", noStoreRec.Code)
	}

	handlerNotImplemented := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      &stubStore{},
		GatewayKeyStore: &stubGatewayKeyStore{
			createErr: configstore.ErrNotImplemented,
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/gateway-keys", nil)
	createRec := httptest.NewRecorder()
	handlerNotImplemented.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusNotImplemented {
		t.Fatalf("create not implemented status=%d, want 501", createRec.Code)
	}

	handlerNotFound := NewRouter(RouterOptions{
		AppVersion: "dev",
		Store:      &stubStore{},
		GatewayKeyStore: &stubGatewayKeyStore{
			revokeErr: configstore.ErrNotFound,
		},
	})
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/gateway-keys/missing", nil)
	revokeRec := httptest.NewRecorder()
	handlerNotFound.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusNotFound {
		t.Fatalf("revoke not found status=%d, want 404", revokeRec.Code)
	}
}

func TestRouterGatewayKeyMutationBodyValidation(t *testing.T) {
	t.Parallel()

	handlerWithStore := func(store *stubGatewayKeyStore) http.Handler {
		return NewRouter(RouterOptions{
			AppVersion:      "dev",
			Store:           &stubStore{},
			GatewayKeyStore: store,
		})
	}
	identity := &auth.Identity{
		KeyID:       "manager-key",
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
	}
	tooLargeJSON := `{"name":"` + strings.Repeat("a", int(gatewayKeyMutationBodyLimit)) + `"}`

	tests := []struct {
		name            string
		method          string
		path            string
		body            string
		wantStatus      int
		wantCreateCalls int
		wantRotateCalls int
	}{
		{
			name:            "rejects unknown create fields",
			method:          http.MethodPost,
			path:            "/api/gateway-keys",
			body:            `{"name":"build-key","unknown":true}`,
			wantStatus:      http.StatusBadRequest,
			wantCreateCalls: 0,
		},
		{
			name:            "rejects unknown rotate fields",
			method:          http.MethodPost,
			path:            "/api/gateway-keys/key-a/rotate",
			body:            `{"token":"rotated-token","unknown":true}`,
			wantStatus:      http.StatusBadRequest,
			wantRotateCalls: 0,
		},
		{
			name:            "rejects oversized create body",
			method:          http.MethodPost,
			path:            "/api/gateway-keys",
			body:            tooLargeJSON,
			wantStatus:      http.StatusRequestEntityTooLarge,
			wantCreateCalls: 0,
		},
		{
			name:            "rejects oversized rotate body",
			method:          http.MethodPost,
			path:            "/api/gateway-keys/key-a/rotate",
			body:            tooLargeJSON,
			wantStatus:      http.StatusRequestEntityTooLarge,
			wantRotateCalls: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store := &stubGatewayKeyStore{
				createResult: &configstore.GatewayKey{
					ID:          "created-key",
					Token:       "created-token",
					OrgID:       "org-a",
					WorkspaceID: "workspace-a",
				},
				rotateResult: &configstore.GatewayKey{
					ID:          "key-a",
					Token:       "rotated-token",
					OrgID:       "org-a",
					WorkspaceID: "workspace-a",
				},
			}
			handler := handlerWithStore(store)

			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(auth.WithIdentity(req.Context(), identity))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status=%d, want %d", rec.Code, tt.wantStatus)
			}
			if store.createCalls != tt.wantCreateCalls {
				t.Fatalf("create calls=%d, want %d", store.createCalls, tt.wantCreateCalls)
			}
			if store.rotateCalls != tt.wantRotateCalls {
				t.Fatalf("rotate calls=%d, want %d", store.rotateCalls, tt.wantRotateCalls)
			}
		})
	}
}
