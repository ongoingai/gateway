package trace

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRetrySQLiteBusyRetriesTransientContention(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := retrySQLiteBusy(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return errors.New("database is locked")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retrySQLiteBusy() error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("retry attempts=%d, want %d", attempts, 3)
	}
}

func TestRetrySQLiteBusyHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	attempts := 0
	err := retrySQLiteBusy(ctx, func() error {
		attempts++
		return errors.New("database is locked")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("retrySQLiteBusy() error=%v, want %v", err, context.Canceled)
	}
	if attempts != 1 {
		t.Fatalf("retry attempts=%d, want %d", attempts, 1)
	}
}

func TestSQLiteStoreConfiguresWALAndWritesTrace(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "ongoingai.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error: %v", err)
	}
	defer store.Close()

	var mode string
	if err := store.db.QueryRow(`PRAGMA journal_mode;`).Scan(&mode); err != nil {
		t.Fatalf("query journal_mode pragma: %v", err)
	}
	if strings.ToLower(mode) != "wal" {
		t.Fatalf("journal_mode=%q, want wal", mode)
	}

	row := &Trace{
		ID:                 "trace-1",
		Timestamp:          time.Now().UTC(),
		Provider:           "openai",
		Model:              "gpt-4o-mini",
		RequestMethod:      "POST",
		RequestPath:        "/openai/v1/chat/completions",
		RequestHeaders:     `{"Content-Type":["application/json"]}`,
		RequestBody:        `{"model":"gpt-4o-mini"}`,
		ResponseStatus:     200,
		ResponseBody:       `{"id":"chatcmpl-1"}`,
		InputTokens:        10,
		OutputTokens:       20,
		TotalTokens:        30,
		LatencyMS:          120,
		TimeToFirstTokenMS: 45,
		TimeToFirstTokenUS: 45000,
		CreatedAt:          time.Now().UTC(),
	}

	if err := store.WriteTrace(context.Background(), row); err != nil {
		t.Fatalf("WriteTrace() error: %v", err)
	}

	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM traces;`).Scan(&count); err != nil {
		t.Fatalf("count traces: %v", err)
	}
	if count != 1 {
		t.Fatalf("trace row count=%d, want 1", count)
	}

	var ttftMS, ttftUS int64
	if err := store.db.QueryRow(`SELECT time_to_first_token_ms, time_to_first_token_us FROM traces WHERE id = ?`, row.ID).Scan(&ttftMS, &ttftUS); err != nil {
		t.Fatalf("query ttft columns: %v", err)
	}
	if ttftMS != 45 {
		t.Fatalf("stored ttft_ms=%d, want 45", ttftMS)
	}
	if ttftUS != 45000 {
		t.Fatalf("stored ttft_us=%d, want 45000", ttftUS)
	}

	var orgID, workspaceID string
	if err := store.db.QueryRow(`SELECT org_id, workspace_id FROM traces WHERE id = ?`, row.ID).Scan(&orgID, &workspaceID); err != nil {
		t.Fatalf("query tenant columns: %v", err)
	}
	if orgID != "default" || workspaceID != "default" {
		t.Fatalf("stored org/workspace=%s/%s, want default/default", orgID, workspaceID)
	}
}

func TestNormalizeTraceFillsTTFTUnits(t *testing.T) {
	t.Parallel()

	rowFromUS := normalizeTrace(&Trace{TimeToFirstTokenUS: 42123})
	if rowFromUS.TimeToFirstTokenUS != 42123 || rowFromUS.TimeToFirstTokenMS != 43 {
		t.Fatalf("normalize from us produced ms/us=%d/%d, want 43/42123", rowFromUS.TimeToFirstTokenMS, rowFromUS.TimeToFirstTokenUS)
	}

	rowFromMS := normalizeTrace(&Trace{TimeToFirstTokenMS: 42})
	if rowFromMS.TimeToFirstTokenMS != 42 || rowFromMS.TimeToFirstTokenUS != 42000 {
		t.Fatalf("normalize from ms produced ms/us=%d/%d, want 42/42000", rowFromMS.TimeToFirstTokenMS, rowFromMS.TimeToFirstTokenUS)
	}
}

func TestSQLiteStoreAddsTTFTUSColumnForLegacySchema(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	legacyDB, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open legacy sqlite db: %v", err)
	}
	if _, err := legacyDB.Exec(`
CREATE TABLE traces (
    id TEXT PRIMARY KEY,
    trace_group_id TEXT,
    timestamp DATETIME NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    request_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    request_headers TEXT,
    request_body TEXT,
    response_status INTEGER,
    response_headers TEXT,
    response_body TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    total_tokens INTEGER,
    latency_ms INTEGER,
    time_to_first_token_ms INTEGER,
    api_key_hash TEXT,
    estimated_cost_usd REAL,
    metadata TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`); err != nil {
		_ = legacyDB.Close()
		t.Fatalf("create legacy schema: %v", err)
	}
	if err := legacyDB.Close(); err != nil {
		t.Fatalf("close legacy sqlite db: %v", err)
	}

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error: %v", err)
	}
	defer store.Close()

	if !sqliteHasColumn(t, store.db, "traces", "time_to_first_token_us") {
		t.Fatal("expected legacy schema to be upgraded with time_to_first_token_us column")
	}
	if !sqliteHasColumn(t, store.db, "traces", "org_id") {
		t.Fatal("expected legacy schema to be upgraded with org_id column")
	}
	if !sqliteHasColumn(t, store.db, "traces", "workspace_id") {
		t.Fatal("expected legacy schema to be upgraded with workspace_id column")
	}
	if !sqliteHasColumn(t, store.db, "traces", "gateway_key_id") {
		t.Fatal("expected legacy schema to be upgraded with gateway_key_id column")
	}
}

func TestSQLiteStoreCreatesQueryIndexes(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "indexes.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error: %v", err)
	}
	defer store.Close()

	indexNames := []string{
		"idx_traces_org_workspace_created_at_id",
		"idx_traces_org_workspace_timestamp",
		"idx_traces_created_at_id",
		"idx_traces_provider_created_at_id",
		"idx_traces_model_created_at_id",
		"idx_traces_api_key_hash_created_at_id",
		"idx_traces_response_status_created_at_id",
		"idx_traces_provider_timestamp",
		"idx_traces_model_timestamp",
		"idx_traces_api_key_hash_timestamp",
		"idx_traces_response_status_timestamp",
		"idx_traces_gateway_key_id",
		"idx_traces_org_workspace_gateway_key_timestamp",
	}
	for _, indexName := range indexNames {
		if !sqliteHasIndex(t, store.db, "traces", indexName) {
			t.Fatalf("expected sqlite index %q to exist", indexName)
		}
	}
}

func TestSQLiteStoreRecordsAppliedMigrations(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "migrations.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error: %v", err)
	}
	defer store.Close()

	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, "sqlite/001_create_traces.sql").Scan(&count); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if count != 1 {
		t.Fatalf("migration count=%d, want 1 for sqlite/001_create_traces.sql", count)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, "sqlite/002_add_gateway_key_id.sql").Scan(&count); err != nil {
		t.Fatalf("query schema_migrations for gateway key migration: %v", err)
	}
	if count != 1 {
		t.Fatalf("migration count=%d, want 1 for sqlite/002_add_gateway_key_id.sql", count)
	}
}

func sqliteHasColumn(t *testing.T, db *sql.DB, tableName, columnName string) bool {
	t.Helper()

	rows, err := db.Query(`PRAGMA table_info(` + tableName + `);`)
	if err != nil {
		t.Fatalf("query table_info(%s): %v", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid       int
			name      string
			typ       string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info(%s): %v", tableName, err)
		}
		if name == columnName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table_info(%s): %v", tableName, err)
	}
	return false
}

func sqliteHasIndex(t *testing.T, db *sql.DB, tableName, indexName string) bool {
	t.Helper()

	rows, err := db.Query(`PRAGMA index_list(` + tableName + `);`)
	if err != nil {
		t.Fatalf("query index_list(%s): %v", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			seq     int
			name    string
			unique  int
			origin  string
			partial int
		)
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index_list(%s): %v", tableName, err)
		}
		if name == indexName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate index_list(%s): %v", tableName, err)
	}
	return false
}

func TestSQLiteStoreGetTraceAndQueryTraces(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "query.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error: %v", err)
	}
	defer store.Close()

	base := time.Date(2026, 2, 12, 1, 0, 0, 0, time.UTC)
	rows := []*Trace{
		{
			ID:                 "trace-a",
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
			ID:                 "trace-b",
			TraceGroupID:       "group-2",
			OrgID:              "org-b",
			WorkspaceID:        "workspace-b",
			Timestamp:          base.Add(2 * time.Second),
			Provider:           "anthropic",
			Model:              "claude-haiku-4-5-20251001",
			RequestMethod:      "POST",
			RequestPath:        "/anthropic/v1/messages",
			ResponseStatus:     500,
			InputTokens:        5,
			OutputTokens:       5,
			TotalTokens:        10,
			LatencyMS:          200,
			TimeToFirstTokenMS: 0,
			EstimatedCostUSD:   0.002,
			Metadata:           `{"lineage_thread_id":"thread-2","lineage_run_id":"run-2"}`,
			CreatedAt:          base.Add(2 * time.Second),
		},
		{
			ID:                 "trace-c",
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

	gotTrace, err := store.GetTrace(context.Background(), "trace-b")
	if err != nil {
		t.Fatalf("GetTrace(trace-b) error: %v", err)
	}
	if gotTrace.Provider != "anthropic" || gotTrace.ResponseStatus != 500 {
		t.Fatalf("GetTrace(trace-b) got provider/status=%s/%d", gotTrace.Provider, gotTrace.ResponseStatus)
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
	if firstPage.Items[0].ID != "trace-c" {
		t.Fatalf("first page trace id=%s, want trace-c", firstPage.Items[0].ID)
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
	if secondPage.Items[0].ID != "trace-a" {
		t.Fatalf("second page trace id=%s, want trace-a", secondPage.Items[0].ID)
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
	if len(tokenFilter.Items) != 1 || tokenFilter.Items[0].ID != "trace-c" {
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
	if groupFilter.Items[0].ID != "trace-c" || groupFilter.Items[1].ID != "trace-a" {
		t.Fatalf("group filter returned unexpected order/items: %#v", groupFilter.Items)
	}

	threadRunFilter, err := store.QueryTraces(context.Background(), TraceFilter{
		ThreadID: "thread-1",
		RunID:    "run-2",
	})
	if err != nil {
		t.Fatalf("QueryTraces(thread/run filter) error: %v", err)
	}
	if len(threadRunFilter.Items) != 1 || threadRunFilter.Items[0].ID != "trace-c" {
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

func TestSQLiteStoreAnalyticsQueries(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "analytics.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error: %v", err)
	}
	defer store.Close()

	base := time.Date(2026, 2, 12, 2, 0, 0, 0, time.UTC)
	rows := []*Trace{
		{
			ID:                 "stats-1",
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
			GatewayKeyID:       "gw-a",
			EstimatedCostUSD:   0.001,
			CreatedAt:          base.Add(1 * time.Second),
		},
		{
			ID:                 "stats-2",
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
			GatewayKeyID:       "gw-a",
			EstimatedCostUSD:   0.002,
			CreatedAt:          base.Add(2 * time.Second),
		},
		{
			ID:                 "stats-3",
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
			GatewayKeyID:       "gw-b",
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
	usageByGatewayKey, err := store.GetUsageSummary(context.Background(), AnalyticsFilter{GatewayKeyID: "gw-a"})
	if err != nil {
		t.Fatalf("GetUsageSummary(gateway key) error: %v", err)
	}
	if usageByGatewayKey.TotalTokens != 40 {
		t.Fatalf("gateway key usage total=%d, want 40", usageByGatewayKey.TotalTokens)
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
}

func TestSQLiteStoreWriteTraceConcurrentWriters(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "concurrent-writes.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error: %v", err)
	}
	defer store.Close()

	store.db.SetMaxOpenConns(8)

	const goroutines = 24
	const writesPerGoroutine = 20

	start := make(chan struct{})
	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start

			for i := 0; i < writesPerGoroutine; i++ {
				traceID := fmt.Sprintf("concurrent-%02d-%03d", g, i)
				if err := store.WriteTrace(context.Background(), &Trace{
					ID:             traceID,
					Provider:       "openai",
					Model:          "gpt-4o-mini",
					RequestMethod:  "POST",
					RequestPath:    "/openai/v1/chat/completions",
					ResponseStatus: http.StatusOK,
					CreatedAt:      time.Now().UTC(),
				}); err != nil {
					errCh <- fmt.Errorf("worker %d write %d: %w", g, i, err)
					return
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
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM traces;`).Scan(&count); err != nil {
		t.Fatalf("count traces: %v", err)
	}

	want := goroutines * writesPerGoroutine
	if count != want {
		t.Fatalf("trace count=%d, want %d", count, want)
	}
}
