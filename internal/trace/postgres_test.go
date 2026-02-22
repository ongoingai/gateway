package trace

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPostgresStoreWritesAndQueriesTraces(t *testing.T) {
	store := newPostgresTestStore(t)

	idPrefix := fmt.Sprintf("trace-pg-query-%d-", time.Now().UnixNano())
	cleanupPostgresTestTraces(t, store, idPrefix)

	base := time.Date(2026, 2, 12, 1, 0, 0, 0, time.UTC)
	traceA := idPrefix + "a"
	traceB := idPrefix + "b"
	traceC := idPrefix + "c"

	rows := []*Trace{
		{
			ID:                 traceA,
			TraceGroupID:       "group-1",
			OrgID:              "org-a",
			WorkspaceID:        "workspace-a",
			Timestamp:          base.Add(1 * time.Second),
			Provider:           "openai",
			Model:              "gpt-4o-mini",
			RequestMethod:      "POST",
			RequestPath:        "/openai/v1/chat/completions",
			ResponseStatus:     200,
			InputTokens:        10,
			OutputTokens:       20,
			TotalTokens:        30,
			LatencyMS:          100,
			TimeToFirstTokenMS: 11,
			EstimatedCostUSD:   0.001,
			Metadata:           `{"lineage_thread_id":"thread-1","lineage_run_id":"run-1"}`,
			CreatedAt:          base.Add(1 * time.Second),
		},
		{
			ID:               traceB,
			TraceGroupID:     "group-2",
			OrgID:            "org-b",
			WorkspaceID:      "workspace-b",
			Timestamp:        base.Add(2 * time.Second),
			Provider:         "anthropic",
			Model:            "claude-haiku-4-5-20251001",
			RequestMethod:    "POST",
			RequestPath:      "/anthropic/v1/messages",
			ResponseStatus:   500,
			InputTokens:      5,
			OutputTokens:     5,
			TotalTokens:      10,
			LatencyMS:        200,
			EstimatedCostUSD: 0.002,
			Metadata:         `{"lineage_thread_id":"thread-2","lineage_run_id":"run-2"}`,
			CreatedAt:        base.Add(2 * time.Second),
		},
		{
			ID:                 traceC,
			TraceGroupID:       "group-1",
			OrgID:              "org-a",
			WorkspaceID:        "workspace-a",
			Timestamp:          base.Add(3 * time.Second),
			Provider:           "openai",
			Model:              "gpt-4o-mini",
			RequestMethod:      "POST",
			RequestPath:        "/openai/v1/chat/completions",
			ResponseStatus:     200,
			InputTokens:        30,
			OutputTokens:       40,
			TotalTokens:        70,
			LatencyMS:          300,
			TimeToFirstTokenUS: 22123,
			EstimatedCostUSD:   0.003,
			Metadata:           `{"lineage_thread_id":"thread-1","lineage_run_id":"run-2"}`,
			CreatedAt:          base.Add(3 * time.Second),
		},
	}
	for _, row := range rows {
		if err := store.WriteTrace(context.Background(), row); err != nil {
			t.Fatalf("WriteTrace(%s) error: %v", row.ID, err)
		}
	}

	gotTrace, err := store.GetTrace(context.Background(), traceB)
	if err != nil {
		t.Fatalf("GetTrace(%s) error: %v", traceB, err)
	}
	if gotTrace.Provider != "anthropic" || gotTrace.ResponseStatus != 500 {
		t.Fatalf("GetTrace(%s) got provider/status=%s/%d", traceB, gotTrace.Provider, gotTrace.ResponseStatus)
	}

	firstPage, err := store.QueryTraces(context.Background(), TraceFilter{
		Provider: "openai",
		Limit:    1,
	})
	if err != nil {
		t.Fatalf("QueryTraces(first page) error: %v", err)
	}
	if len(firstPage.Items) != 1 {
		t.Fatalf("first page items=%d, want 1", len(firstPage.Items))
	}
	if firstPage.Items[0].ID != traceC {
		t.Fatalf("first page trace id=%s, want %s", firstPage.Items[0].ID, traceC)
	}
	if firstPage.NextCursor == "" {
		t.Fatal("first page next cursor should not be empty")
	}

	secondPage, err := store.QueryTraces(context.Background(), TraceFilter{
		Provider: "openai",
		Limit:    1,
		Cursor:   firstPage.NextCursor,
	})
	if err != nil {
		t.Fatalf("QueryTraces(second page) error: %v", err)
	}
	if len(secondPage.Items) != 1 {
		t.Fatalf("second page items=%d, want 1", len(secondPage.Items))
	}
	if secondPage.Items[0].ID != traceA {
		t.Fatalf("second page trace id=%s, want %s", secondPage.Items[0].ID, traceA)
	}
	if secondPage.NextCursor != "" {
		t.Fatalf("second page next cursor=%q, want empty", secondPage.NextCursor)
	}

	tokenFilter, err := store.QueryTraces(context.Background(), TraceFilter{
		MinTokens: 60,
	})
	if err != nil {
		t.Fatalf("QueryTraces(token filter) error: %v", err)
	}
	if len(tokenFilter.Items) != 1 || tokenFilter.Items[0].ID != traceC {
		t.Fatalf("token filter returned unexpected items: %#v", tokenFilter.Items)
	}

	groupFilter, err := store.QueryTraces(context.Background(), TraceFilter{
		TraceGroupID: "group-1",
	})
	if err != nil {
		t.Fatalf("QueryTraces(group filter) error: %v", err)
	}
	if len(groupFilter.Items) != 2 {
		t.Fatalf("group filter item count=%d, want 2", len(groupFilter.Items))
	}
	if groupFilter.Items[0].ID != traceC || groupFilter.Items[1].ID != traceA {
		t.Fatalf("group filter returned unexpected order/items: %#v", groupFilter.Items)
	}

	threadRunFilter, err := store.QueryTraces(context.Background(), TraceFilter{
		ThreadID: "thread-1",
		RunID:    "run-2",
	})
	if err != nil {
		t.Fatalf("QueryTraces(thread/run filter) error: %v", err)
	}
	if len(threadRunFilter.Items) != 1 || threadRunFilter.Items[0].ID != traceC {
		t.Fatalf("thread/run filter returned unexpected items: %#v", threadRunFilter.Items)
	}

	tenantFilter, err := store.QueryTraces(context.Background(), TraceFilter{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("QueryTraces(tenant filter) error: %v", err)
	}
	if len(tenantFilter.Items) != 2 {
		t.Fatalf("tenant filter item count=%d, want 2", len(tenantFilter.Items))
	}
	for _, item := range tenantFilter.Items {
		if item.OrgID != "org-a" || item.WorkspaceID != "workspace-a" {
			t.Fatalf("tenant filter returned cross-tenant item: %+v", item)
		}
	}

	_, err = store.QueryTraces(context.Background(), TraceFilter{
		Cursor: "not-a-cursor",
	})
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("invalid cursor error=%v, want ErrInvalidCursor", err)
	}
}

func TestPostgresStoreAnalyticsQueries(t *testing.T) {
	store := newPostgresTestStore(t)

	idPrefix := fmt.Sprintf("trace-pg-analytics-%d-", time.Now().UnixNano())
	cleanupPostgresTestTraces(t, store, idPrefix)

	base := time.Date(2026, 2, 12, 2, 0, 0, 0, time.UTC)
	rows := []*Trace{
		{
			ID:                 idPrefix + "1",
			Timestamp:          base.Add(1 * time.Second),
			Provider:           "openai",
			Model:              "gpt-4o-mini",
			RequestMethod:      "POST",
			RequestPath:        "/openai/v1/chat/completions",
			ResponseStatus:     200,
			InputTokens:        10,
			OutputTokens:       20,
			TotalTokens:        30,
			LatencyMS:          100,
			TimeToFirstTokenMS: 10,
			APIKeyHash:         "key-a",
			EstimatedCostUSD:   0.001,
			CreatedAt:          base.Add(1 * time.Second),
		},
		{
			ID:                 idPrefix + "2",
			Timestamp:          base.Add(2 * time.Second),
			Provider:           "openai",
			Model:              "gpt-4o-mini",
			RequestMethod:      "POST",
			RequestPath:        "/openai/v1/chat/completions",
			ResponseStatus:     200,
			InputTokens:        5,
			OutputTokens:       5,
			TotalTokens:        10,
			LatencyMS:          200,
			TimeToFirstTokenMS: 20,
			APIKeyHash:         "key-a",
			EstimatedCostUSD:   0.002,
			CreatedAt:          base.Add(2 * time.Second),
		},
		{
			ID:                 idPrefix + "3",
			Timestamp:          base.Add(3 * time.Second),
			Provider:           "anthropic",
			Model:              "claude-haiku-4-5-20251001",
			RequestMethod:      "POST",
			RequestPath:        "/anthropic/v1/messages",
			ResponseStatus:     200,
			InputTokens:        7,
			OutputTokens:       3,
			TotalTokens:        10,
			LatencyMS:          300,
			TimeToFirstTokenMS: 30,
			APIKeyHash:         "key-b",
			EstimatedCostUSD:   0.003,
			CreatedAt:          base.Add(3 * time.Second),
		},
	}
	for _, row := range rows {
		if err := store.WriteTrace(context.Background(), row); err != nil {
			t.Fatalf("WriteTrace(%s) error: %v", row.ID, err)
		}
	}

	usage, err := store.GetUsageSummary(context.Background(), AnalyticsFilter{Provider: "openai"})
	if err != nil {
		t.Fatalf("GetUsageSummary() error: %v", err)
	}
	if usage.TotalInputTokens != 15 || usage.TotalOutputTokens != 25 || usage.TotalTokens != 40 {
		t.Fatalf("usage=%+v, want input/output/total=15/25/40", usage)
	}

	cost, err := store.GetCostSummary(context.Background(), AnalyticsFilter{Provider: "openai"})
	if err != nil {
		t.Fatalf("GetCostSummary() error: %v", err)
	}
	if math.Abs(cost.TotalCostUSD-0.003) > 1e-12 {
		t.Fatalf("cost=%f, want 0.003", cost.TotalCostUSD)
	}

	models, err := store.GetModelStats(context.Background(), AnalyticsFilter{})
	if err != nil {
		t.Fatalf("GetModelStats() error: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("model stats count=%d, want 2", len(models))
	}
	if models[0].Model != "gpt-4o-mini" || models[0].RequestCount != 2 {
		t.Fatalf("first model stat=%+v", models[0])
	}
	if math.Abs(models[0].AvgLatencyMS-150.0) > 1e-12 || math.Abs(models[0].AvgTTFTMS-15.0) > 1e-12 {
		t.Fatalf("first model averages=%+v, want latency/ttft=150/15", models[0])
	}

	keys, err := store.GetKeyStats(context.Background(), AnalyticsFilter{})
	if err != nil {
		t.Fatalf("GetKeyStats() error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("key stats count=%d, want 2", len(keys))
	}
	if keys[0].APIKeyHash != "key-a" || keys[0].RequestCount != 2 {
		t.Fatalf("first key stat=%+v", keys[0])
	}
	if keys[0].LastActiveAt.IsZero() {
		t.Fatalf("expected key-a LastActiveAt to be set")
	}

	usageSeries, err := store.GetUsageSeries(context.Background(), AnalyticsFilter{}, "provider", "day")
	if err != nil {
		t.Fatalf("GetUsageSeries() error: %v", err)
	}
	if len(usageSeries) != 2 {
		t.Fatalf("usage series count=%d, want 2", len(usageSeries))
	}
	if usageSeries[0].Group != "anthropic" || usageSeries[0].TotalTokens != 10 {
		t.Fatalf("usage series first point=%+v", usageSeries[0])
	}
	if usageSeries[1].Group != "openai" || usageSeries[1].TotalTokens != 40 {
		t.Fatalf("usage series second point=%+v", usageSeries[1])
	}

	costSeries, err := store.GetCostSeries(context.Background(), AnalyticsFilter{}, "provider", "day")
	if err != nil {
		t.Fatalf("GetCostSeries() error: %v", err)
	}
	if len(costSeries) != 2 {
		t.Fatalf("cost series count=%d, want 2", len(costSeries))
	}
	if costSeries[0].Group != "anthropic" || math.Abs(costSeries[0].TotalCostUSD-0.003) > 1e-12 {
		t.Fatalf("cost series first point=%+v", costSeries[0])
	}
	if costSeries[1].Group != "openai" || math.Abs(costSeries[1].TotalCostUSD-0.003) > 1e-12 {
		t.Fatalf("cost series second point=%+v", costSeries[1])
	}
	if costSeries[0].RequestCount != 1 {
		t.Fatalf("cost series anthropic request_count=%d, want 1", costSeries[0].RequestCount)
	}
	if costSeries[1].RequestCount != 2 {
		t.Fatalf("cost series openai request_count=%d, want 2", costSeries[1].RequestCount)
	}
	if math.Abs(costSeries[1].AvgCostUSD-0.0015) > 1e-12 {
		t.Fatalf("cost series openai avg_cost=%f, want 0.0015", costSeries[1].AvgCostUSD)
	}

	// Latency percentiles
	latencyStats, err := store.GetLatencyPercentiles(context.Background(), AnalyticsFilter{}, "provider")
	if err != nil {
		t.Fatalf("GetLatencyPercentiles() error: %v", err)
	}
	if len(latencyStats) != 2 {
		t.Fatalf("latency stats count=%d, want 2", len(latencyStats))
	}
	// anthropic has 1 request (300ms), openai has 2 requests (100ms, 200ms)
	if latencyStats[0].Group != "openai" || latencyStats[0].RequestCount != 2 {
		t.Fatalf("first latency group=%+v, want openai with 2 requests", latencyStats[0])
	}
	if latencyStats[0].MinMS != 100 || latencyStats[0].MaxMS != 200 {
		t.Fatalf("openai latency min/max=%d/%d, want 100/200", latencyStats[0].MinMS, latencyStats[0].MaxMS)
	}
	if latencyStats[1].Group != "anthropic" || latencyStats[1].RequestCount != 1 {
		t.Fatalf("second latency group=%+v, want anthropic with 1 request", latencyStats[1])
	}

	// Error rate breakdown (all traces are 200 in this fixture, so no errors)
	errorStats, err := store.GetErrorRateBreakdown(context.Background(), AnalyticsFilter{}, "provider")
	if err != nil {
		t.Fatalf("GetErrorRateBreakdown() error: %v", err)
	}
	if len(errorStats) != 2 {
		t.Fatalf("error rate stats count=%d, want 2", len(errorStats))
	}
	for _, es := range errorStats {
		if es.ErrorCount4xx != 0 || es.ErrorCount5xx != 0 {
			t.Fatalf("error rate group=%+v, want 0 errors (all 200 status)", es)
		}
		if es.ErrorRate != 0 {
			t.Fatalf("error rate=%f, want 0", es.ErrorRate)
		}
	}
}

func TestPostgresStoreAnalyticsQueriesTenantIsolation(t *testing.T) {
	store := newPostgresTestStore(t)

	idPrefix := fmt.Sprintf("trace-pg-analytics-tenant-%d-", time.Now().UnixNano())
	cleanupPostgresTestTraces(t, store, idPrefix)

	base := time.Date(2026, 2, 12, 3, 0, 0, 0, time.UTC)
	rows := []*Trace{
		{
			ID:               idPrefix + "a-1",
			OrgID:            "org-analytics-a",
			WorkspaceID:      "workspace-analytics-a",
			Timestamp:        base.Add(1 * time.Second),
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			RequestMethod:    "POST",
			RequestPath:      "/openai/v1/chat/completions",
			ResponseStatus:   200,
			InputTokens:      5,
			OutputTokens:     5,
			TotalTokens:      10,
			LatencyMS:        100,
			GatewayKeyID:     "gw-a",
			EstimatedCostUSD: 0.001,
			CreatedAt:        base.Add(1 * time.Second),
		},
		{
			ID:               idPrefix + "a-2",
			OrgID:            "org-analytics-a",
			WorkspaceID:      "workspace-analytics-a",
			Timestamp:        base.Add(2 * time.Second),
			Provider:         "openai",
			Model:            "gpt-4o-mini",
			RequestMethod:    "POST",
			RequestPath:      "/openai/v1/chat/completions",
			ResponseStatus:   200,
			InputTokens:      10,
			OutputTokens:     10,
			TotalTokens:      20,
			LatencyMS:        100,
			GatewayKeyID:     "gw-c",
			EstimatedCostUSD: 0.002,
			CreatedAt:        base.Add(2 * time.Second),
		},
		{
			ID:               idPrefix + "b-1",
			OrgID:            "org-analytics-b",
			WorkspaceID:      "workspace-analytics-b",
			Timestamp:        base.Add(3 * time.Second),
			Provider:         "anthropic",
			Model:            "claude-haiku-4-5-20251001",
			RequestMethod:    "POST",
			RequestPath:      "/anthropic/v1/messages",
			ResponseStatus:   200,
			InputTokens:      30,
			OutputTokens:     30,
			TotalTokens:      60,
			LatencyMS:        100,
			GatewayKeyID:     "gw-b",
			EstimatedCostUSD: 0.009,
			CreatedAt:        base.Add(3 * time.Second),
		},
	}
	for _, row := range rows {
		if err := store.WriteTrace(context.Background(), row); err != nil {
			t.Fatalf("WriteTrace(%s) error: %v", row.ID, err)
		}
	}

	filter := AnalyticsFilter{
		OrgID:       "org-analytics-a",
		WorkspaceID: "workspace-analytics-a",
	}
	usage, err := store.GetUsageSummary(context.Background(), filter)
	if err != nil {
		t.Fatalf("GetUsageSummary() error: %v", err)
	}
	if usage.TotalTokens != 30 {
		t.Fatalf("usage total tokens=%d, want 30 (tenant-a only)", usage.TotalTokens)
	}
	usageByGatewayKey, err := store.GetUsageSummary(context.Background(), AnalyticsFilter{
		OrgID:        "org-analytics-a",
		WorkspaceID:  "workspace-analytics-a",
		GatewayKeyID: "gw-a",
	})
	if err != nil {
		t.Fatalf("GetUsageSummary(gateway key) error: %v", err)
	}
	if usageByGatewayKey.TotalTokens != 10 {
		t.Fatalf("gateway key usage total=%d, want 10", usageByGatewayKey.TotalTokens)
	}

	cost, err := store.GetCostSummary(context.Background(), filter)
	if err != nil {
		t.Fatalf("GetCostSummary() error: %v", err)
	}
	if math.Abs(cost.TotalCostUSD-0.003) > 1e-12 {
		t.Fatalf("cost=%f, want 0.003 (tenant-a only)", cost.TotalCostUSD)
	}

	models, err := store.GetModelStats(context.Background(), filter)
	if err != nil {
		t.Fatalf("GetModelStats() error: %v", err)
	}
	if len(models) != 1 || models[0].RequestCount != 2 {
		t.Fatalf("model stats=%+v, want one tenant-a model with 2 requests", models)
	}

	usageSeries, err := store.GetUsageSeries(context.Background(), filter, "provider", "day")
	if err != nil {
		t.Fatalf("GetUsageSeries() error: %v", err)
	}
	if len(usageSeries) != 1 || usageSeries[0].TotalTokens != 30 {
		t.Fatalf("usage series=%+v, want one tenant-a point with 30 tokens", usageSeries)
	}

	costSeries, err := store.GetCostSeries(context.Background(), filter, "provider", "day")
	if err != nil {
		t.Fatalf("GetCostSeries() error: %v", err)
	}
	if len(costSeries) != 1 || math.Abs(costSeries[0].TotalCostUSD-0.003) > 1e-12 {
		t.Fatalf("cost series=%+v, want one tenant-a point with 0.003 cost", costSeries)
	}
}

func TestPostgresStoreEnforcesTraceTenantForeignKeys(t *testing.T) {
	store := newPostgresTestStore(t)

	ctx := context.Background()
	const (
		traceID     = "trace-pg-fk-missing-workspace"
		orgID       = "org-trace-fk-test"
		workspaceID = "workspace-trace-fk-missing"
	)
	if _, err := store.db.ExecContext(ctx, `DELETE FROM traces WHERE id = $1`, traceID); err != nil {
		t.Fatalf("cleanup traces: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM workspaces WHERE id = $1`, workspaceID); err != nil {
		t.Fatalf("cleanup workspace: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, orgID); err != nil {
		t.Fatalf("cleanup organization: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM traces WHERE id = $1`, traceID)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM workspaces WHERE id = $1`, workspaceID)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id = $1`, orgID)
	})

	var constraintCount int
	if err := store.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM pg_constraint
WHERE conname = 'fk_traces_workspace_tenant'`).Scan(&constraintCount); err != nil {
		t.Fatalf("query trace tenant foreign key constraint: %v", err)
	}
	if constraintCount != 1 {
		t.Fatalf("trace tenant foreign key constraint count=%d, want 1", constraintCount)
	}

	if _, err := store.db.ExecContext(ctx, `
INSERT INTO organizations (id, name)
VALUES ($1, $1)
ON CONFLICT (id) DO NOTHING`, orgID); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO traces (
    id,
    org_id,
    workspace_id,
    timestamp,
    provider,
    model,
    request_method,
    request_path,
    created_at
) VALUES (
    $1,
    $2,
    $3,
    NOW(),
    'openai',
    'gpt-4o-mini',
    'POST',
    '/openai/v1/chat/completions',
    NOW()
)`,
		traceID,
		orgID,
		workspaceID,
	); !isPostgresForeignKeyViolation(err) {
		t.Fatalf("insert trace without workspace scope error=%v, want foreign-key violation", err)
	}
}

func TestPostgresStoreEnsureTenantScopeAllowsWorkspaceIDReuseAcrossOrgs(t *testing.T) {
	store := newPostgresTestStore(t)

	ctx := context.Background()
	const (
		workspaceID = "workspace-trace-shared-tenant-scope"
		orgA        = "org-trace-shared-tenant-scope-a"
		orgB        = "org-trace-shared-tenant-scope-b"
	)
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM workspaces WHERE id = $1 AND org_id IN ($2, $3)`, workspaceID, orgA, orgB)
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM organizations WHERE id IN ($1, $2)`, orgA, orgB)
	})

	if err := store.ensureTenantScope(ctx, orgA, workspaceID); err != nil {
		t.Fatalf("ensureTenantScope(%q/%q) error: %v", orgA, workspaceID, err)
	}
	if err := store.ensureTenantScope(ctx, orgB, workspaceID); err != nil {
		t.Fatalf("ensureTenantScope(%q/%q) error: %v", orgB, workspaceID, err)
	}

	var count int
	if err := store.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM workspaces
WHERE id = $1 AND org_id IN ($2, $3)`, workspaceID, orgA, orgB).Scan(&count); err != nil {
		t.Fatalf("count shared workspace rows: %v", err)
	}
	if count != 2 {
		t.Fatalf("shared workspace row count=%d, want 2", count)
	}
}

func newPostgresTestStore(t *testing.T) *PostgresStore {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close postgres store: %v", err)
		}
	})
	return store
}

func cleanupPostgresTestTraces(t *testing.T, store *PostgresStore, idPrefix string) {
	t.Helper()

	t.Cleanup(func() {
		if _, err := store.db.ExecContext(context.Background(), `DELETE FROM traces WHERE id LIKE $1`, idPrefix+"%"); err != nil {
			t.Fatalf("cleanup traces: %v", err)
		}
	})
}

func ensureTracesRLSActive(t *testing.T, tx *sql.Tx) {
	t.Helper()

	ctx := context.Background()
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT row_security_active('traces'::regclass)`).Scan(&active); err != nil {
		t.Fatalf("check row security state for traces: %v", err)
	}
	if active {
		return
	}

	// CI often connects as the postgres superuser, which bypasses RLS even with
	// FORCE RLS enabled. Switch to a non-bypass role before asserting policy behavior.
	if _, err := tx.ExecContext(ctx, `
DO $$
BEGIN
	CREATE ROLE ongoingai_rls_test_role;
EXCEPTION
	WHEN duplicate_object THEN
		NULL;
END $$;`); err != nil {
		t.Fatalf("create non-bypass role for RLS assertions: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `GRANT USAGE ON SCHEMA public TO ongoingai_rls_test_role`); err != nil {
		t.Fatalf("grant schema usage to RLS test role: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `GRANT SELECT ON traces TO ongoingai_rls_test_role`); err != nil {
		t.Fatalf("grant traces select to RLS test role: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `SET LOCAL ROLE ongoingai_rls_test_role`); err != nil {
		t.Fatalf("switch to RLS test role: %v", err)
	}

	if err := tx.QueryRowContext(ctx, `SELECT row_security_active('traces'::regclass)`).Scan(&active); err != nil {
		t.Fatalf("re-check row security state for traces: %v", err)
	}
	if !active {
		t.Fatal("row_security_active(traces)=false; cannot validate tenant RLS behavior")
	}
}

func TestPostgresStoreRLSBlocksCrossTenantUnfilteredTraceQueries(t *testing.T) {
	dsn := os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	const (
		traceAID = "trace-postgres-test-rls-a"
		traceBID = "trace-postgres-test-rls-b"
	)
	if _, err := store.db.ExecContext(ctx, `DELETE FROM traces WHERE id IN ($1, $2)`, traceAID, traceBID); err != nil {
		t.Fatalf("cleanup before insert: %v", err)
	}
	if err := store.WriteBatch(ctx, []*Trace{
		{
			ID:          traceAID,
			OrgID:       "org-rls-a",
			WorkspaceID: "workspace-rls-a",
			Provider:    "openai",
			Model:       "gpt-4o-mini",
			RequestPath: "/v1/chat/completions",
			RequestBody: `{"messages":[{"role":"user","content":"hello"}]}`,
		},
		{
			ID:          traceBID,
			OrgID:       "org-rls-b",
			WorkspaceID: "workspace-rls-b",
			Provider:    "openai",
			Model:       "gpt-4o-mini",
			RequestPath: "/v1/chat/completions",
			RequestBody: `{"messages":[{"role":"user","content":"world"}]}`,
		},
	}); err != nil {
		t.Fatalf("WriteBatch() error: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM traces WHERE id IN ($1, $2)`, traceAID, traceBID)
	})

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tenant-scoped tx: %v", err)
	}
	defer tx.Rollback()

	ensureTracesRLSActive(t, tx)

	if _, err := tx.ExecContext(ctx, `
SELECT
  set_config('ongoingai.org_id', $1, true),
  set_config('ongoingai.workspace_id', $2, true)`,
		"org-rls-a",
		"workspace-rls-a",
	); err != nil {
		t.Fatalf("set tenant session context: %v", err)
	}

	rows, err := tx.QueryContext(ctx, `
SELECT id, org_id, workspace_id
FROM traces
WHERE id IN ($1, $2)
ORDER BY id`, traceAID, traceBID)
	if err != nil {
		t.Fatalf("unfiltered traces query with tenant context: %v", err)
	}
	defer rows.Close()

	type seenRow struct {
		id          string
		orgID       string
		workspaceID string
	}
	seen := make([]seenRow, 0, 2)
	for rows.Next() {
		var item seenRow
		if err := rows.Scan(&item.id, &item.orgID, &item.workspaceID); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		seen = append(seen, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate rows: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("visible row count=%d, want 1 (cross-tenant row must be filtered by RLS)", len(seen))
	}
	if seen[0].id != traceAID || seen[0].orgID != "org-rls-a" || seen[0].workspaceID != "workspace-rls-a" {
		t.Fatalf("visible row=%+v, want tenant-a trace only", seen[0])
	}

	var leakedID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM traces WHERE id = $1`, traceBID).Scan(&leakedID)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-tenant trace lookup error=%v, want sql.ErrNoRows", err)
	}
}

func TestPostgresStoreWriteTraceConcurrentWriters(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("ONGOINGAI_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("ONGOINGAI_TEST_POSTGRES_DSN is not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}
	defer store.Close()

	idPrefix := fmt.Sprintf("trace-pg-concurrent-%d-", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM traces WHERE id LIKE $1`, idPrefix+"%")
	})

	const goroutines = 16
	const writesPerGoroutine = 15

	start := make(chan struct{})
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start

			for i := 0; i < writesPerGoroutine; i++ {
				traceID := fmt.Sprintf("%s%02d-%03d", idPrefix, g, i)
				if err := store.WriteTrace(context.Background(), &Trace{
					ID:             traceID,
					OrgID:          "org-concurrent",
					WorkspaceID:    "workspace-concurrent",
					Provider:       "openai",
					Model:          "gpt-4o-mini",
					RequestMethod:  "POST",
					RequestPath:    "/openai/v1/chat/completions",
					ResponseStatus: 200,
					CreatedAt:      time.Now().UTC(),
				}); err != nil {
					errCh <- fmt.Errorf("worker %d write %d: %w", g, i, err)
					return
				}

				if i%5 == 0 {
					if _, err := store.QueryTraces(context.Background(), TraceFilter{
						OrgID:       "org-concurrent",
						WorkspaceID: "workspace-concurrent",
						Provider:    "openai",
						Limit:       5,
					}); err != nil {
						errCh <- fmt.Errorf("worker %d query %d: %w", g, i, err)
						return
					}
				}
			}
		}(g)
	}

	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	var count int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM traces WHERE id LIKE $1`, idPrefix+"%").Scan(&count); err != nil {
		t.Fatalf("count concurrent traces: %v", err)
	}

	want := goroutines * writesPerGoroutine
	if count != want {
		t.Fatalf("trace count=%d, want %d", count, want)
	}
}
