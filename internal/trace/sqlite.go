package trace

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ongoingai/gateway/migrations"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	Path string
	db   *sql.DB
	// SQLite allows only one writer at a time; serialize writes to avoid SQLITE_BUSY
	// contention when callers invoke WriteTrace/WriteBatch concurrently.
	writeMu sync.Mutex
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path cannot be empty")
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite directory %q: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database %q: %w", path, err)
	}

	store := &SQLiteStore{
		Path: path,
		db:   db,
	}

	if err := store.configure(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.ensureOptionalColumns(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) WriteTrace(ctx context.Context, trace *Trace) error {
	if trace == nil {
		return nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	row := normalizeTrace(trace)
	err := retrySQLiteBusy(ctx, func() error {
		_, err := s.db.ExecContext(ctx, `
	INSERT INTO traces (
	    id,
	    trace_group_id,
	    org_id,
	    workspace_id,
    timestamp,
    provider,
    model,
    request_method,
    request_path,
    request_headers,
    request_body,
    response_status,
    response_headers,
    response_body,
    input_tokens,
    output_tokens,
    total_tokens,
    latency_ms,
	    time_to_first_token_ms,
	    time_to_first_token_us,
	    api_key_hash,
	    gateway_key_id,
	    estimated_cost_usd,
	    metadata,
	    created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			row.ID,
			row.TraceGroupID,
			row.OrgID,
			row.WorkspaceID,
			row.Timestamp,
			row.Provider,
			row.Model,
			row.RequestMethod,
			row.RequestPath,
			row.RequestHeaders,
			row.RequestBody,
			row.ResponseStatus,
			row.ResponseHeaders,
			row.ResponseBody,
			row.InputTokens,
			row.OutputTokens,
			row.TotalTokens,
			row.LatencyMS,
			row.TimeToFirstTokenMS,
			row.TimeToFirstTokenUS,
			row.APIKeyHash,
			row.GatewayKeyID,
			row.EstimatedCostUSD,
			row.Metadata,
			row.CreatedAt,
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("write trace %q: %w", row.ID, err)
	}

	return nil
}

func (s *SQLiteStore) WriteBatch(ctx context.Context, traces []*Trace) error {
	if len(traces) == 0 {
		return nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	err := retrySQLiteBusy(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin sqlite batch transaction: %w", err)
		}
		defer func() {
			_ = tx.Rollback()
		}()

		stmt, err := tx.PrepareContext(ctx, `
INSERT INTO traces (
    id,
    trace_group_id,
    org_id,
    workspace_id,
    timestamp,
    provider,
    model,
    request_method,
    request_path,
    request_headers,
    request_body,
    response_status,
    response_headers,
    response_body,
    input_tokens,
    output_tokens,
    total_tokens,
    latency_ms,
	    time_to_first_token_ms,
	    time_to_first_token_us,
	    api_key_hash,
	    gateway_key_id,
	    estimated_cost_usd,
	    metadata,
	    created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return fmt.Errorf("prepare sqlite batch insert: %w", err)
		}
		defer stmt.Close()

		for _, trace := range traces {
			if trace == nil {
				continue
			}
			row := normalizeTrace(trace)
			if _, err := stmt.ExecContext(
				ctx,
				row.ID,
				row.TraceGroupID,
				row.OrgID,
				row.WorkspaceID,
				row.Timestamp,
				row.Provider,
				row.Model,
				row.RequestMethod,
				row.RequestPath,
				row.RequestHeaders,
				row.RequestBody,
				row.ResponseStatus,
				row.ResponseHeaders,
				row.ResponseBody,
				row.InputTokens,
				row.OutputTokens,
				row.TotalTokens,
				row.LatencyMS,
				row.TimeToFirstTokenMS,
				row.TimeToFirstTokenUS,
				row.APIKeyHash,
				row.GatewayKeyID,
				row.EstimatedCostUSD,
				row.Metadata,
				row.CreatedAt,
			); err != nil {
				return fmt.Errorf("write trace %q in batch: %w", row.ID, err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit sqlite batch transaction: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

const (
	sqliteBusyMaxRetries     = 12
	sqliteBusyInitialBackoff = 5 * time.Millisecond
	sqliteBusyMaxBackoff     = 250 * time.Millisecond
)

// retrySQLiteBusy retries transient lock contention so queued traces are not dropped during concurrent writes.
func retrySQLiteBusy(ctx context.Context, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}

	var (
		err   error
		timer *time.Timer
	)
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	defer stopTimer()

	for retries := 0; ; retries++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !isSQLiteBusyError(err) || retries >= sqliteBusyMaxRetries {
			return err
		}

		wait := sqliteBusyInitialBackoff << retries
		if wait > sqliteBusyMaxBackoff {
			wait = sqliteBusyMaxBackoff
		}

		if timer == nil {
			timer = time.NewTimer(wait)
		} else {
			stopTimer()
			timer.Reset(wait)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "sqlite_busy") || strings.Contains(value, "database is locked")
}

const traceSelectColumns = `
id,
trace_group_id,
org_id,
workspace_id,
CAST(timestamp AS TEXT),
provider,
model,
request_method,
request_path,
request_headers,
request_body,
response_status,
response_headers,
response_body,
input_tokens,
output_tokens,
total_tokens,
latency_ms,
time_to_first_token_ms,
time_to_first_token_us,
api_key_hash,
estimated_cost_usd,
metadata,
CAST(created_at AS TEXT)
`

func (s *SQLiteStore) GetTrace(ctx context.Context, id string) (*Trace, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+traceSelectColumns+" FROM traces WHERE id = ? LIMIT 1", id)
	traceRow, err := scanTraceRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get trace %q: %w", id, err)
	}
	return traceRow, nil
}

func (s *SQLiteStore) QueryTraces(ctx context.Context, filter TraceFilter) (*TraceResult, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	whereSQL, args, err := buildTraceWhere(filter)
	if err != nil {
		return nil, err
	}
	args = append(args, limit+1)

	query := "SELECT " + traceSelectColumns + " FROM traces WHERE " + whereSQL + " ORDER BY created_at DESC, id DESC LIMIT ?"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query traces: %w", err)
	}
	defer rows.Close()

	items := make([]*Trace, 0, limit+1)
	for rows.Next() {
		row, err := scanTraceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan trace row: %w", err)
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate trace rows: %w", err)
	}

	nextCursor := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		cursorTime := last.CreatedAt
		if cursorTime.IsZero() {
			cursorTime = last.Timestamp
		}
		nextCursor = encodeTraceCursor(cursorTime, last.ID)
	}

	return &TraceResult{
		Items:      items,
		NextCursor: nextCursor,
	}, nil
}

func (s *SQLiteStore) GetUsageSummary(ctx context.Context, filter AnalyticsFilter) (*UsageSummary, error) {
	whereSQL, args := buildAnalyticsWhere(filter)
	row := s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(total_tokens), 0) FROM traces WHERE "+whereSQL, args...)

	var summary UsageSummary
	if err := row.Scan(&summary.TotalInputTokens, &summary.TotalOutputTokens, &summary.TotalTokens); err != nil {
		return nil, fmt.Errorf("query usage summary: %w", err)
	}

	return &summary, nil
}

func (s *SQLiteStore) GetUsageSeries(ctx context.Context, filter AnalyticsFilter, groupBy, bucket string) ([]UsagePoint, error) {
	groupExpr, err := usageGroupExpression(groupBy)
	if err != nil {
		return nil, err
	}
	bucketExpr, err := usageBucketExpression(bucket)
	if err != nil {
		return nil, err
	}

	whereSQL, args := buildAnalyticsWhere(filter)
	query := `
SELECT
	` + bucketExpr + ` AS bucket_start,
	` + groupExpr + ` AS group_value,
	COALESCE(SUM(input_tokens), 0),
	COALESCE(SUM(output_tokens), 0),
	COALESCE(SUM(total_tokens), 0)
FROM traces
WHERE ` + whereSQL + `
GROUP BY bucket_start, group_value
ORDER BY bucket_start ASC, group_value ASC
`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query usage series: %w", err)
	}
	defer rows.Close()

	points := make([]UsagePoint, 0)
	for rows.Next() {
		var (
			bucketStartRaw sql.NullString
			groupValue     sql.NullString
			point          UsagePoint
		)
		if err := rows.Scan(&bucketStartRaw, &groupValue, &point.InputTokens, &point.OutputTokens, &point.TotalTokens); err != nil {
			return nil, fmt.Errorf("scan usage series row: %w", err)
		}
		if bucketStartRaw.Valid {
			parsedTime, err := parseSQLiteTimestamp(bucketStartRaw.String)
			if err != nil {
				return nil, fmt.Errorf("parse usage series bucket %q: %w", bucketStartRaw.String, err)
			}
			point.BucketStart = parsedTime
		}
		if groupValue.Valid {
			point.Group = groupValue.String
		}
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate usage series rows: %w", err)
	}

	return points, nil
}

func (s *SQLiteStore) GetCostSummary(ctx context.Context, filter AnalyticsFilter) (*CostSummary, error) {
	whereSQL, args := buildAnalyticsWhere(filter)
	row := s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(estimated_cost_usd), 0) FROM traces WHERE "+whereSQL, args...)

	var summary CostSummary
	if err := row.Scan(&summary.TotalCostUSD); err != nil {
		return nil, fmt.Errorf("query cost summary: %w", err)
	}

	return &summary, nil
}

func (s *SQLiteStore) GetCostSeries(ctx context.Context, filter AnalyticsFilter, groupBy, bucket string) ([]CostPoint, error) {
	groupExpr, err := usageGroupExpression(groupBy)
	if err != nil {
		return nil, err
	}
	bucketExpr, err := usageBucketExpression(bucket)
	if err != nil {
		return nil, err
	}

	whereSQL, args := buildAnalyticsWhere(filter)
	query := `
SELECT
	` + bucketExpr + ` AS bucket_start,
	` + groupExpr + ` AS group_value,
	COALESCE(SUM(estimated_cost_usd), 0)
FROM traces
WHERE ` + whereSQL + `
GROUP BY bucket_start, group_value
ORDER BY bucket_start ASC, group_value ASC
`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query cost series: %w", err)
	}
	defer rows.Close()

	points := make([]CostPoint, 0)
	for rows.Next() {
		var (
			bucketStartRaw sql.NullString
			groupValue     sql.NullString
			point          CostPoint
		)
		if err := rows.Scan(&bucketStartRaw, &groupValue, &point.TotalCostUSD); err != nil {
			return nil, fmt.Errorf("scan cost series row: %w", err)
		}
		if bucketStartRaw.Valid {
			parsedTime, err := parseSQLiteTimestamp(bucketStartRaw.String)
			if err != nil {
				return nil, fmt.Errorf("parse cost series bucket %q: %w", bucketStartRaw.String, err)
			}
			point.BucketStart = parsedTime
		}
		if groupValue.Valid {
			point.Group = groupValue.String
		}
		points = append(points, point)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cost series rows: %w", err)
	}

	return points, nil
}

func (s *SQLiteStore) GetModelStats(ctx context.Context, filter AnalyticsFilter) ([]ModelStats, error) {
	whereSQL, args := buildAnalyticsWhere(filter)
	query := `
SELECT
	model,
	COUNT(*) AS request_count,
	COALESCE(AVG(latency_ms), 0),
	COALESCE(AVG(time_to_first_token_ms), 0),
	COALESCE(SUM(total_tokens), 0),
	COALESCE(SUM(estimated_cost_usd), 0)
FROM traces
WHERE ` + whereSQL + `
GROUP BY model
ORDER BY request_count DESC, model ASC
`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query model stats: %w", err)
	}
	defer rows.Close()

	stats := make([]ModelStats, 0)
	for rows.Next() {
		var item ModelStats
		if err := rows.Scan(&item.Model, &item.RequestCount, &item.AvgLatencyMS, &item.AvgTTFTMS, &item.TotalTokens, &item.TotalCostUSD); err != nil {
			return nil, fmt.Errorf("scan model stats row: %w", err)
		}
		stats = append(stats, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate model stats rows: %w", err)
	}

	return stats, nil
}

func (s *SQLiteStore) GetKeyStats(ctx context.Context, filter AnalyticsFilter) ([]KeyStats, error) {
	whereSQL, args := buildAnalyticsWhere(filter)
	query := `
SELECT
	api_key_hash,
	COUNT(*) AS request_count,
	COALESCE(SUM(total_tokens), 0),
	COALESCE(SUM(estimated_cost_usd), 0),
	CAST(MAX(created_at) AS TEXT)
FROM traces
WHERE api_key_hash <> '' AND ` + whereSQL + `
GROUP BY api_key_hash
ORDER BY request_count DESC, api_key_hash ASC
`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query key stats: %w", err)
	}
	defer rows.Close()

	stats := make([]KeyStats, 0)
	for rows.Next() {
		var (
			item         KeyStats
			lastActiveAt sql.NullString
		)
		if err := rows.Scan(&item.APIKeyHash, &item.RequestCount, &item.TotalTokens, &item.TotalCostUSD, &lastActiveAt); err != nil {
			return nil, fmt.Errorf("scan key stats row: %w", err)
		}
		if lastActiveAt.Valid {
			parsedTime, err := parseSQLiteTimestamp(lastActiveAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse key stats timestamp %q: %w", lastActiveAt.String, err)
			}
			item.LastActiveAt = parsedTime
		}
		stats = append(stats, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate key stats rows: %w", err)
	}

	return stats, nil
}

func buildTraceWhere(filter TraceFilter) (string, []any, error) {
	where := make([]string, 0, 10)
	args := make([]any, 0, 10)

	if filter.OrgID != "" {
		where = append(where, "org_id = ?")
		args = append(args, filter.OrgID)
	}
	if filter.WorkspaceID != "" {
		where = append(where, "workspace_id = ?")
		args = append(args, filter.WorkspaceID)
	}
	if filter.TraceGroupID != "" {
		where = append(where, "trace_group_id = ?")
		args = append(args, filter.TraceGroupID)
	}
	if filter.ThreadID != "" {
		where = append(where, "json_extract(CASE WHEN json_valid(metadata) THEN metadata ELSE '{}' END, '$.lineage_thread_id') = ?")
		args = append(args, filter.ThreadID)
	}
	if filter.RunID != "" {
		where = append(where, "json_extract(CASE WHEN json_valid(metadata) THEN metadata ELSE '{}' END, '$.lineage_run_id') = ?")
		args = append(args, filter.RunID)
	}
	if filter.Provider != "" {
		where = append(where, "provider = ?")
		args = append(args, filter.Provider)
	}
	if filter.Model != "" {
		where = append(where, "model = ?")
		args = append(args, filter.Model)
	}
	if filter.APIKeyHash != "" {
		where = append(where, "api_key_hash = ?")
		args = append(args, filter.APIKeyHash)
	}
	if filter.StatusCode > 0 {
		where = append(where, "response_status = ?")
		args = append(args, filter.StatusCode)
	}
	if filter.MinTokens > 0 {
		where = append(where, "total_tokens >= ?")
		args = append(args, filter.MinTokens)
	}
	if filter.MaxTokens > 0 {
		where = append(where, "total_tokens <= ?")
		args = append(args, filter.MaxTokens)
	}
	if !filter.From.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, filter.From.UTC())
	}
	if !filter.To.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, filter.To.UTC())
	}
	if filter.Cursor != "" {
		createdAt, id, err := decodeTraceCursor(filter.Cursor)
		if err != nil {
			return "", nil, err
		}
		where = append(where, "(created_at < ? OR (created_at = ? AND id < ?))")
		args = append(args, createdAt.UTC(), createdAt.UTC(), id)
	}

	if len(where) == 0 {
		return "1=1", args, nil
	}
	return strings.Join(where, " AND "), args, nil
}

func buildAnalyticsWhere(filter AnalyticsFilter) (string, []any) {
	where := make([]string, 0, 7)
	args := make([]any, 0, 7)

	if filter.OrgID != "" {
		where = append(where, "org_id = ?")
		args = append(args, filter.OrgID)
	}
	if filter.WorkspaceID != "" {
		where = append(where, "workspace_id = ?")
		args = append(args, filter.WorkspaceID)
	}
	if filter.GatewayKeyID != "" {
		where = append(where, "gateway_key_id = ?")
		args = append(args, filter.GatewayKeyID)
	}
	if filter.Provider != "" {
		where = append(where, "provider = ?")
		args = append(args, filter.Provider)
	}
	if filter.Model != "" {
		where = append(where, "model = ?")
		args = append(args, filter.Model)
	}
	if !filter.From.IsZero() {
		where = append(where, "timestamp >= ?")
		args = append(args, filter.From.UTC())
	}
	if !filter.To.IsZero() {
		where = append(where, "timestamp <= ?")
		args = append(args, filter.To.UTC())
	}

	if len(where) == 0 {
		return "1=1", args
	}
	return strings.Join(where, " AND "), args
}

func usageGroupExpression(groupBy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(groupBy)) {
	case "", "none":
		return "''", nil
	case "provider":
		return "provider", nil
	case "model":
		return "model", nil
	default:
		return "", fmt.Errorf("invalid group_by: %q", groupBy)
	}
}

func usageBucketExpression(bucket string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "", "day":
		return "strftime('%Y-%m-%dT00:00:00Z', timestamp)", nil
	case "hour":
		return "strftime('%Y-%m-%dT%H:00:00Z', timestamp)", nil
	case "week":
		return "strftime('%Y-%m-%dT00:00:00Z', datetime(timestamp, '-' || ((CAST(strftime('%w', timestamp) AS INTEGER) + 6) % 7) || ' days'))", nil
	default:
		return "", fmt.Errorf("invalid bucket: %q", bucket)
	}
}

func encodeTraceCursor(createdAt time.Time, id string) string {
	if createdAt.IsZero() || id == "" {
		return ""
	}
	raw := createdAt.UTC().Format(time.RFC3339Nano) + "|" + id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeTraceCursor(cursor string) (time.Time, string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: decode base64 cursor", ErrInvalidCursor)
	}
	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return time.Time{}, "", fmt.Errorf("%w: missing id", ErrInvalidCursor)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(parts[0]))
	if err != nil {
		return time.Time{}, "", fmt.Errorf("%w: parse created_at", ErrInvalidCursor)
	}
	return createdAt.UTC(), strings.TrimSpace(parts[1]), nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanTraceRow(scanner rowScanner) (*Trace, error) {
	var (
		item               Trace
		traceGroupID       sql.NullString
		orgID              sql.NullString
		workspaceID        sql.NullString
		timestampText      sql.NullString
		requestHeaders     sql.NullString
		requestBody        sql.NullString
		responseStatus     sql.NullInt64
		responseHeaders    sql.NullString
		responseBody       sql.NullString
		inputTokens        sql.NullInt64
		outputTokens       sql.NullInt64
		totalTokens        sql.NullInt64
		latencyMS          sql.NullInt64
		timeToFirstTokenMS sql.NullInt64
		timeToFirstTokenUS sql.NullInt64
		apiKeyHash         sql.NullString
		estimatedCostUSD   sql.NullFloat64
		metadata           sql.NullString
		createdAtText      sql.NullString
	)

	if err := scanner.Scan(
		&item.ID,
		&traceGroupID,
		&orgID,
		&workspaceID,
		&timestampText,
		&item.Provider,
		&item.Model,
		&item.RequestMethod,
		&item.RequestPath,
		&requestHeaders,
		&requestBody,
		&responseStatus,
		&responseHeaders,
		&responseBody,
		&inputTokens,
		&outputTokens,
		&totalTokens,
		&latencyMS,
		&timeToFirstTokenMS,
		&timeToFirstTokenUS,
		&apiKeyHash,
		&estimatedCostUSD,
		&metadata,
		&createdAtText,
	); err != nil {
		return nil, err
	}

	if traceGroupID.Valid {
		item.TraceGroupID = traceGroupID.String
	}
	if orgID.Valid {
		item.OrgID = orgID.String
	}
	if workspaceID.Valid {
		item.WorkspaceID = workspaceID.String
	}

	if timestampText.Valid {
		parsedTimestamp, err := parseSQLiteTimestamp(timestampText.String)
		if err != nil {
			return nil, fmt.Errorf("parse timestamp %q: %w", timestampText.String, err)
		}
		item.Timestamp = parsedTimestamp
	}

	if requestHeaders.Valid {
		item.RequestHeaders = requestHeaders.String
	}
	if requestBody.Valid {
		item.RequestBody = requestBody.String
	}
	if responseStatus.Valid {
		item.ResponseStatus = int(responseStatus.Int64)
	}
	if responseHeaders.Valid {
		item.ResponseHeaders = responseHeaders.String
	}
	if responseBody.Valid {
		item.ResponseBody = responseBody.String
	}
	if inputTokens.Valid {
		item.InputTokens = int(inputTokens.Int64)
	}
	if outputTokens.Valid {
		item.OutputTokens = int(outputTokens.Int64)
	}
	if totalTokens.Valid {
		item.TotalTokens = int(totalTokens.Int64)
	}
	if latencyMS.Valid {
		item.LatencyMS = latencyMS.Int64
	}
	if timeToFirstTokenMS.Valid {
		item.TimeToFirstTokenMS = timeToFirstTokenMS.Int64
	}
	if timeToFirstTokenUS.Valid {
		item.TimeToFirstTokenUS = timeToFirstTokenUS.Int64
	}
	if apiKeyHash.Valid {
		item.APIKeyHash = apiKeyHash.String
	}
	if estimatedCostUSD.Valid {
		item.EstimatedCostUSD = estimatedCostUSD.Float64
	}
	if metadata.Valid {
		item.Metadata = metadata.String
	}
	if createdAtText.Valid {
		parsedCreatedAt, err := parseSQLiteTimestamp(createdAtText.String)
		if err != nil {
			return nil, fmt.Errorf("parse created_at %q: %w", createdAtText.String, err)
		}
		item.CreatedAt = parsedCreatedAt
	}

	if item.TimeToFirstTokenUS > 0 && item.TimeToFirstTokenMS == 0 {
		item.TimeToFirstTokenMS = (item.TimeToFirstTokenUS + 999) / 1000
	}
	if item.TimeToFirstTokenMS > 0 && item.TimeToFirstTokenUS == 0 {
		item.TimeToFirstTokenUS = item.TimeToFirstTokenMS * 1000
	}
	if item.OrgID == "" {
		item.OrgID = "default"
	}
	if item.WorkspaceID == "" {
		item.WorkspaceID = "default"
	}

	return &item, nil
}

func parseSQLiteTimestamp(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}

	withTZLayouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05 -0700 MST",
	}
	for _, layout := range withTZLayouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}

	withoutTZLayouts := []string{
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
	}
	for _, layout := range withoutTZLayouts {
		if parsed, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported sqlite datetime format")
}

func (s *SQLiteStore) configure() error {
	if _, err := s.db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		return fmt.Errorf("enable sqlite WAL mode: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA synchronous = NORMAL;`); err != nil {
		return fmt.Errorf("set sqlite synchronous mode: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		return fmt.Errorf("set sqlite busy timeout: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ensureSchema() error {
	if err := migrations.Apply(context.Background(), s.db, migrations.DriverSQLite); err != nil {
		return fmt.Errorf("ensure sqlite schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ensureOptionalColumns() error {
	exists, err := s.hasTracesTable()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	columns := map[string]bool{}
	rows, err := s.db.Query(`PRAGMA table_info(traces);`)
	if err != nil {
		return fmt.Errorf("read traces table info: %w", err)
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
			return fmt.Errorf("scan traces table info: %w", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate traces table info: %w", err)
	}

	if !columns["time_to_first_token_us"] {
		if _, err := s.db.Exec(`ALTER TABLE traces ADD COLUMN time_to_first_token_us INTEGER;`); err != nil {
			return fmt.Errorf("add time_to_first_token_us column: %w", err)
		}
	}
	if !columns["org_id"] {
		if _, err := s.db.Exec(`ALTER TABLE traces ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';`); err != nil {
			return fmt.Errorf("add org_id column: %w", err)
		}
	}
	if !columns["workspace_id"] {
		if _, err := s.db.Exec(`ALTER TABLE traces ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default';`); err != nil {
			return fmt.Errorf("add workspace_id column: %w", err)
		}
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_created_at_id ON traces(org_id, workspace_id, created_at DESC, id DESC);`); err != nil {
		return fmt.Errorf("create org/workspace created_at index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_timestamp ON traces(org_id, workspace_id, timestamp);`); err != nil {
		return fmt.Errorf("create org/workspace timestamp index: %w", err)
	}

	return nil
}

func (s *SQLiteStore) hasTracesTable() (bool, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'traces'`).Scan(&count); err != nil {
		return false, fmt.Errorf("check sqlite traces table existence: %w", err)
	}
	return count > 0, nil
}

func normalizeTrace(in *Trace) *Trace {
	row := *in
	now := time.Now().UTC()

	if row.Timestamp.IsZero() {
		row.Timestamp = now
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = now
	}
	if row.Model == "" {
		row.Model = "unknown"
	}
	if row.Provider == "" {
		row.Provider = "unknown"
	}
	if row.OrgID == "" {
		row.OrgID = "default"
	}
	if row.WorkspaceID == "" {
		row.WorkspaceID = "default"
	}
	if row.RequestMethod == "" {
		row.RequestMethod = "UNKNOWN"
	}
	if row.RequestPath == "" {
		row.RequestPath = "/"
	}
	if row.TotalTokens == 0 {
		row.TotalTokens = row.InputTokens + row.OutputTokens
	}
	if row.GatewayKeyID == "" {
		row.GatewayKeyID = extractGatewayKeyIDFromMetadata(row.Metadata)
	}
	if row.TimeToFirstTokenUS > 0 && row.TimeToFirstTokenMS == 0 {
		row.TimeToFirstTokenMS = (row.TimeToFirstTokenUS + 999) / 1000
	}
	if row.TimeToFirstTokenMS > 0 && row.TimeToFirstTokenUS == 0 {
		row.TimeToFirstTokenUS = row.TimeToFirstTokenMS * 1000
	}

	return &row
}

func extractGatewayKeyIDFromMetadata(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return ""
	}
	value, _ := payload["gateway_key_id"].(string)
	return strings.TrimSpace(value)
}
