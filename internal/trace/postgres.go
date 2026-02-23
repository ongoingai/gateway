package trace

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ongoingai/gateway/migrations"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresStore struct {
	DSN string
	db  *sql.DB
}

func NewPostgresStore(dsn string) (*PostgresStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("postgres dsn cannot be empty")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres database: %w", err)
	}

	store := &PostgresStore{
		DSN: dsn,
		db:  db,
	}
	if err := store.configure(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.ensureOptionalColumns(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *PostgresStore) WriteTrace(ctx context.Context, trace *Trace) error {
	if trace == nil {
		return nil
	}

	row := normalizeTrace(trace)
	if err := s.writeTraceRow(ctx, row); err != nil {
		if !isPostgresForeignKeyViolation(err) {
			return fmt.Errorf("write trace %q: %w", row.ID, err)
		}
		if ensureErr := s.ensureTenantScope(ctx, row.OrgID, row.WorkspaceID); ensureErr != nil {
			return fmt.Errorf("ensure tenant scope for trace %q: %w", row.ID, ensureErr)
		}
		if retryErr := s.writeTraceRow(ctx, row); retryErr != nil {
			return fmt.Errorf("write trace %q after tenant scope ensure: %w", row.ID, retryErr)
		}
	}

	return nil
}

func (s *PostgresStore) writeTraceRow(ctx context.Context, row *Trace) error {
	if row == nil {
		return nil
	}

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
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    NULLIF($10, '')::jsonb,
    $11,
    $12,
    NULLIF($13, '')::jsonb,
    $14,
    $15,
    $16,
	    $17,
	    $18,
	    $19,
	    $20,
	    $21,
	    $22,
	    $23,
	    NULLIF($24, '')::jsonb,
	    $25
	)`,
		row.ID,
		nullIfEmpty(row.TraceGroupID),
		row.OrgID,
		row.WorkspaceID,
		row.Timestamp.UTC(),
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
		row.CreatedAt.UTC(),
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgresStore) WriteBatch(ctx context.Context, traces []*Trace) error {
	if len(traces) == 0 {
		return nil
	}

	rows := make([]*Trace, 0, len(traces))
	tenantPairs := map[string][2]string{}
	for _, trace := range traces {
		if trace == nil {
			continue
		}
		row := normalizeTrace(trace)
		rows = append(rows, row)
		key := row.OrgID + "\x00" + row.WorkspaceID
		tenantPairs[key] = [2]string{row.OrgID, row.WorkspaceID}
	}
	if len(rows) == 0 {
		return nil
	}
	if err := s.writeBatchRows(ctx, rows); err != nil {
		if !isPostgresForeignKeyViolation(err) {
			return fmt.Errorf("write postgres trace batch: %w", err)
		}
		for _, tenantPair := range tenantPairs {
			if ensureErr := s.ensureTenantScope(ctx, tenantPair[0], tenantPair[1]); ensureErr != nil {
				return fmt.Errorf("ensure tenant scope %q/%q for batch write: %w", tenantPair[0], tenantPair[1], ensureErr)
			}
		}
		if retryErr := s.writeBatchRows(ctx, rows); retryErr != nil {
			return fmt.Errorf("write postgres trace batch after tenant scope ensure: %w", retryErr)
		}
	}
	return nil
}

func (s *PostgresStore) writeBatchRows(ctx context.Context, rows []*Trace) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres batch transaction: %w", err)
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
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    NULLIF($10, '')::jsonb,
    $11,
    $12,
    NULLIF($13, '')::jsonb,
    $14,
    $15,
    $16,
    $17,
    $18,
    $19,
    $20,
    $21,
    $22,
    $23,
    NULLIF($24, '')::jsonb,
    $25
)`)
	if err != nil {
		return fmt.Errorf("prepare postgres batch insert: %w", err)
	}
	defer stmt.Close()

	for _, row := range rows {
		if _, err := stmt.ExecContext(
			ctx,
			row.ID,
			nullIfEmpty(row.TraceGroupID),
			row.OrgID,
			row.WorkspaceID,
			row.Timestamp.UTC(),
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
			row.CreatedAt.UTC(),
		); err != nil {
			return fmt.Errorf("write trace %q in batch: %w", row.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres batch transaction: %w", err)
	}

	return nil
}

const postgresTraceSelectColumns = `
id,
trace_group_id,
org_id,
workspace_id,
timestamp,
provider,
model,
request_method,
request_path,
COALESCE(request_headers::text, ''),
COALESCE(request_body, ''),
response_status,
COALESCE(response_headers::text, ''),
COALESCE(response_body, ''),
input_tokens,
output_tokens,
total_tokens,
latency_ms,
	time_to_first_token_ms,
	time_to_first_token_us,
	COALESCE(api_key_hash, ''),
	COALESCE(gateway_key_id, ''),
	COALESCE(estimated_cost_usd, 0),
	COALESCE(metadata::text, ''),
	created_at
`

func (s *PostgresStore) GetTrace(ctx context.Context, id string) (*Trace, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+postgresTraceSelectColumns+" FROM traces WHERE id = $1 LIMIT 1", id)
	traceRow, err := scanPostgresTraceRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get trace %q: %w", id, err)
	}
	return traceRow, nil
}

func (s *PostgresStore) QueryTraces(ctx context.Context, filter TraceFilter) (*TraceResult, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	whereSQL, args, err := buildPostgresTraceWhere(filter)
	if err != nil {
		return nil, err
	}
	limitPlaceholder := fmt.Sprintf("$%d", len(args)+1)
	args = append(args, limit+1)

	query := "SELECT " + postgresTraceSelectColumns + " FROM traces WHERE " + whereSQL + " ORDER BY created_at DESC, id DESC LIMIT " + limitPlaceholder
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query traces: %w", err)
	}
	defer rows.Close()

	items := make([]*Trace, 0, limit+1)
	for rows.Next() {
		row, err := scanPostgresTraceRow(rows)
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

func (s *PostgresStore) GetUsageSummary(ctx context.Context, filter AnalyticsFilter) (*UsageSummary, error) {
	whereSQL, args := buildPostgresAnalyticsWhere(filter)
	row := s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(total_tokens), 0) FROM traces WHERE "+whereSQL, args...)

	var summary UsageSummary
	if err := row.Scan(&summary.TotalInputTokens, &summary.TotalOutputTokens, &summary.TotalTokens); err != nil {
		return nil, fmt.Errorf("query usage summary: %w", err)
	}

	return &summary, nil
}

func (s *PostgresStore) GetUsageSeries(ctx context.Context, filter AnalyticsFilter, groupBy, bucket string) ([]UsagePoint, error) {
	groupExpr, err := postgresUsageGroupExpression(groupBy)
	if err != nil {
		return nil, err
	}
	bucketExpr, err := postgresUsageBucketExpression(bucket)
	if err != nil {
		return nil, err
	}

	whereSQL, args := buildPostgresAnalyticsWhere(filter)
	query := `
SELECT
	` + bucketExpr + ` AS bucket_start,
	` + groupExpr + ` AS group_value,
	COALESCE(SUM(input_tokens), 0),
	COALESCE(SUM(output_tokens), 0),
	COALESCE(SUM(total_tokens), 0)
FROM traces
WHERE ` + whereSQL + `
GROUP BY 1, 2
ORDER BY 1 ASC, 2 ASC
`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query usage series: %w", err)
	}
	defer rows.Close()

	points := make([]UsagePoint, 0)
	for rows.Next() {
		var (
			bucketStart time.Time
			groupValue  sql.NullString
			point       UsagePoint
		)
		if err := rows.Scan(&bucketStart, &groupValue, &point.InputTokens, &point.OutputTokens, &point.TotalTokens); err != nil {
			return nil, fmt.Errorf("scan usage series row: %w", err)
		}
		point.BucketStart = bucketStart.UTC()
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

func (s *PostgresStore) GetCostSummary(ctx context.Context, filter AnalyticsFilter) (*CostSummary, error) {
	whereSQL, args := buildPostgresAnalyticsWhere(filter)
	row := s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(estimated_cost_usd), 0) FROM traces WHERE "+whereSQL, args...)

	var summary CostSummary
	if err := row.Scan(&summary.TotalCostUSD); err != nil {
		return nil, fmt.Errorf("query cost summary: %w", err)
	}

	return &summary, nil
}

func (s *PostgresStore) GetCostSeries(ctx context.Context, filter AnalyticsFilter, groupBy, bucket string) ([]CostPoint, error) {
	groupExpr, err := postgresUsageGroupExpression(groupBy)
	if err != nil {
		return nil, err
	}
	bucketExpr, err := postgresUsageBucketExpression(bucket)
	if err != nil {
		return nil, err
	}

	whereSQL, args := buildPostgresAnalyticsWhere(filter)
	query := `
SELECT
	` + bucketExpr + ` AS bucket_start,
	` + groupExpr + ` AS group_value,
	COALESCE(SUM(estimated_cost_usd), 0),
	COUNT(*),
	COALESCE(AVG(estimated_cost_usd), 0)
FROM traces
WHERE ` + whereSQL + `
GROUP BY 1, 2
ORDER BY 1 ASC, 2 ASC
`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query cost series: %w", err)
	}
	defer rows.Close()

	points := make([]CostPoint, 0)
	for rows.Next() {
		var (
			bucketStart time.Time
			groupValue  sql.NullString
			point       CostPoint
		)
		if err := rows.Scan(&bucketStart, &groupValue, &point.TotalCostUSD, &point.RequestCount, &point.AvgCostUSD); err != nil {
			return nil, fmt.Errorf("scan cost series row: %w", err)
		}
		point.BucketStart = bucketStart.UTC()
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

func (s *PostgresStore) GetModelStats(ctx context.Context, filter AnalyticsFilter) ([]ModelStats, error) {
	whereSQL, args := buildPostgresAnalyticsWhere(filter)
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

func (s *PostgresStore) GetKeyStats(ctx context.Context, filter AnalyticsFilter) ([]KeyStats, error) {
	whereSQL, args := buildPostgresAnalyticsWhere(filter)
	query := `
SELECT
	api_key_hash,
	COUNT(*) AS request_count,
	COALESCE(SUM(total_tokens), 0),
	COALESCE(SUM(estimated_cost_usd), 0),
	MAX(created_at)
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
			lastActiveAt sql.NullTime
		)
		if err := rows.Scan(&item.APIKeyHash, &item.RequestCount, &item.TotalTokens, &item.TotalCostUSD, &lastActiveAt); err != nil {
			return nil, fmt.Errorf("scan key stats row: %w", err)
		}
		if lastActiveAt.Valid {
			item.LastActiveAt = lastActiveAt.Time.UTC()
		}
		stats = append(stats, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate key stats rows: %w", err)
	}

	return stats, nil
}

func (s *PostgresStore) GetLatencyPercentiles(ctx context.Context, filter AnalyticsFilter, groupBy string) ([]LatencyStats, error) {
	groupExpr, err := postgresAnalyticsGroupExpression(groupBy)
	if err != nil {
		return nil, err
	}

	whereSQL, args := buildPostgresAnalyticsWhere(filter)
	query := `
SELECT ` + groupExpr + ` AS group_value,
	COUNT(*),
	COALESCE(AVG(latency_ms), 0),
	COALESCE(MIN(latency_ms), 0),
	COALESCE(MAX(latency_ms), 0),
	COALESCE(percentile_cont(0.50) WITHIN GROUP (ORDER BY latency_ms), 0),
	COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms), 0),
	COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms), 0)
FROM traces
WHERE ` + whereSQL + `
GROUP BY group_value
ORDER BY 2 DESC, 1 ASC
`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query latency percentiles: %w", err)
	}
	defer rows.Close()

	stats := make([]LatencyStats, 0)
	for rows.Next() {
		var (
			groupValue sql.NullString
			item       LatencyStats
		)
		if err := rows.Scan(&groupValue, &item.RequestCount, &item.AvgMS, &item.MinMS, &item.MaxMS, &item.P50MS, &item.P95MS, &item.P99MS); err != nil {
			return nil, fmt.Errorf("scan latency percentile row: %w", err)
		}
		if groupValue.Valid {
			item.Group = groupValue.String
		}
		stats = append(stats, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate latency percentile rows: %w", err)
	}

	return stats, nil
}

func (s *PostgresStore) GetErrorRateBreakdown(ctx context.Context, filter AnalyticsFilter, groupBy string) ([]ErrorRateStats, error) {
	groupExpr, err := postgresAnalyticsGroupExpression(groupBy)
	if err != nil {
		return nil, err
	}

	whereSQL, args := buildPostgresAnalyticsWhere(filter)
	query := `
SELECT ` + groupExpr + ` AS group_value,
	COUNT(*) AS total_requests,
	SUM(CASE WHEN response_status >= 400 AND response_status < 500 THEN 1 ELSE 0 END),
	SUM(CASE WHEN response_status >= 500 THEN 1 ELSE 0 END)
FROM traces
WHERE ` + whereSQL + `
GROUP BY group_value
ORDER BY total_requests DESC, group_value ASC
`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query error rate breakdown: %w", err)
	}
	defer rows.Close()

	stats := make([]ErrorRateStats, 0)
	for rows.Next() {
		var (
			groupValue sql.NullString
			item       ErrorRateStats
		)
		if err := rows.Scan(&groupValue, &item.TotalRequests, &item.ErrorCount4xx, &item.ErrorCount5xx); err != nil {
			return nil, fmt.Errorf("scan error rate row: %w", err)
		}
		if groupValue.Valid {
			item.Group = groupValue.String
		}
		if item.TotalRequests > 0 {
			item.ErrorRate = float64(item.ErrorCount4xx+item.ErrorCount5xx) / float64(item.TotalRequests)
		}
		stats = append(stats, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate error rate rows: %w", err)
	}

	return stats, nil
}

func buildPostgresTraceWhere(filter TraceFilter) (string, []any, error) {
	builder := newPostgresWhereBuilder()

	if filter.OrgID != "" {
		builder.addComparison("org_id", "=", filter.OrgID)
	}
	if filter.WorkspaceID != "" {
		builder.addComparison("workspace_id", "=", filter.WorkspaceID)
	}
	if filter.TraceGroupID != "" {
		builder.addComparison("trace_group_id", "=", filter.TraceGroupID)
	}
	if filter.ThreadID != "" {
		builder.addComparison("metadata ->> 'lineage_thread_id'", "=", filter.ThreadID)
	}
	if filter.RunID != "" {
		builder.addComparison("metadata ->> 'lineage_run_id'", "=", filter.RunID)
	}
	if filter.Provider != "" {
		builder.addComparison("provider", "=", filter.Provider)
	}
	if filter.Model != "" {
		builder.addComparison("model", "=", filter.Model)
	}
	if filter.APIKeyHash != "" {
		builder.addComparison("api_key_hash", "=", filter.APIKeyHash)
	}
	if filter.StatusCode > 0 {
		builder.addComparison("response_status", "=", filter.StatusCode)
	}
	if filter.MinTokens > 0 {
		builder.addComparison("total_tokens", ">=", filter.MinTokens)
	}
	if filter.MaxTokens > 0 {
		builder.addComparison("total_tokens", "<=", filter.MaxTokens)
	}
	if !filter.From.IsZero() {
		builder.addComparison("timestamp", ">=", filter.From.UTC())
	}
	if !filter.To.IsZero() {
		builder.addComparison("timestamp", "<=", filter.To.UTC())
	}
	if filter.Cursor != "" {
		createdAt, id, err := decodeTraceCursor(filter.Cursor)
		if err != nil {
			return "", nil, err
		}
		p1 := builder.addArg(createdAt.UTC())
		p2 := builder.addArg(createdAt.UTC())
		p3 := builder.addArg(id)
		builder.addCondition("(created_at < " + p1 + " OR (created_at = " + p2 + " AND id < " + p3 + "))")
	}

	return builder.where(), builder.args, nil
}

func buildPostgresAnalyticsWhere(filter AnalyticsFilter) (string, []any) {
	builder := newPostgresWhereBuilder()

	if filter.OrgID != "" {
		builder.addComparison("org_id", "=", filter.OrgID)
	}
	if filter.WorkspaceID != "" {
		builder.addComparison("workspace_id", "=", filter.WorkspaceID)
	}
	if filter.GatewayKeyID != "" {
		builder.addComparison("gateway_key_id", "=", filter.GatewayKeyID)
	}
	if filter.Provider != "" {
		builder.addComparison("provider", "=", filter.Provider)
	}
	if filter.Model != "" {
		builder.addComparison("model", "=", filter.Model)
	}
	if !filter.From.IsZero() {
		builder.addComparison("timestamp", ">=", filter.From.UTC())
	}
	if !filter.To.IsZero() {
		builder.addComparison("timestamp", "<=", filter.To.UTC())
	}

	return builder.where(), builder.args
}

func postgresUsageGroupExpression(groupBy string) (string, error) {
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

func postgresAnalyticsGroupExpression(groupBy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(groupBy)) {
	case "", "none":
		return "''", nil
	case "provider":
		return "provider", nil
	case "model":
		return "model", nil
	case "route":
		return "request_path", nil
	case "key":
		return "gateway_key_id", nil
	default:
		return "", fmt.Errorf("invalid group_by: %q", groupBy)
	}
}

func postgresUsageBucketExpression(bucket string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(bucket)) {
	case "", "day":
		return "date_trunc('day', timestamp)", nil
	case "hour":
		return "date_trunc('hour', timestamp)", nil
	case "week":
		return "date_trunc('week', timestamp)", nil
	default:
		return "", fmt.Errorf("invalid bucket: %q", bucket)
	}
}

type postgresWhereBuilder struct {
	conditions []string
	args       []any
}

func newPostgresWhereBuilder() *postgresWhereBuilder {
	return &postgresWhereBuilder{
		conditions: make([]string, 0, 8),
		args:       make([]any, 0, 8),
	}
}

func (b *postgresWhereBuilder) addArg(value any) string {
	b.args = append(b.args, value)
	return fmt.Sprintf("$%d", len(b.args))
}

func (b *postgresWhereBuilder) addComparison(column, operator string, value any) {
	placeholder := b.addArg(value)
	b.conditions = append(b.conditions, column+" "+operator+" "+placeholder)
}

func (b *postgresWhereBuilder) addCondition(condition string) {
	b.conditions = append(b.conditions, condition)
}

func (b *postgresWhereBuilder) where() string {
	if len(b.conditions) == 0 {
		return "1=1"
	}
	return strings.Join(b.conditions, " AND ")
}

func scanPostgresTraceRow(scanner rowScanner) (*Trace, error) {
	var (
		item               Trace
		traceGroupID       sql.NullString
		orgID              sql.NullString
		workspaceID        sql.NullString
		timestamp          sql.NullTime
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
		gatewayKeyID       sql.NullString
		estimatedCostUSD   sql.NullFloat64
		metadata           sql.NullString
		createdAt          sql.NullTime
	)

	if err := scanner.Scan(
		&item.ID,
		&traceGroupID,
		&orgID,
		&workspaceID,
		&timestamp,
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
		&gatewayKeyID,
		&estimatedCostUSD,
		&metadata,
		&createdAt,
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
	if timestamp.Valid {
		item.Timestamp = timestamp.Time.UTC()
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
	if gatewayKeyID.Valid {
		item.GatewayKeyID = gatewayKeyID.String
	}
	if estimatedCostUSD.Valid {
		item.EstimatedCostUSD = estimatedCostUSD.Float64
	}
	if metadata.Valid {
		item.Metadata = metadata.String
	}
	if createdAt.Valid {
		item.CreatedAt = createdAt.Time.UTC()
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

func (s *PostgresStore) configure() error {
	if s.db == nil {
		return fmt.Errorf("postgres database is not initialized")
	}

	s.db.SetMaxOpenConns(20)
	s.db.SetMaxIdleConns(10)
	s.db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

func (s *PostgresStore) ensureSchema() error {
	if err := migrations.Apply(context.Background(), s.db, migrations.DriverPostgres); err != nil {
		return fmt.Errorf("ensure postgres schema: %w", err)
	}
	return nil
}

func (s *PostgresStore) ensureOptionalColumns() error {
	exists, err := s.hasTracesTable()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	statements := []string{
		`ALTER TABLE traces ADD COLUMN IF NOT EXISTS org_id TEXT NOT NULL DEFAULT 'default';`,
		`ALTER TABLE traces ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'default';`,
		`ALTER TABLE traces ADD COLUMN IF NOT EXISTS gateway_key_id TEXT;`,
		`UPDATE traces SET gateway_key_id = NULLIF(metadata ->> 'gateway_key_id', '') WHERE gateway_key_id IS NULL;`,
		`CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_created_at_id ON traces(org_id, workspace_id, created_at DESC, id DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_timestamp ON traces(org_id, workspace_id, timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_traces_gateway_key_id ON traces(gateway_key_id);`,
		`CREATE INDEX IF NOT EXISTS idx_traces_org_workspace_gateway_key_timestamp ON traces(org_id, workspace_id, gateway_key_id, timestamp);`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres optional schema component: %w", err)
		}
	}
	if err := s.ensureTenantSchema(); err != nil {
		return err
	}
	if err := s.ensureTenantRLS(); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) ensureTenantScope(ctx context.Context, orgID, workspaceID string) error {
	orgID = tenantValue(orgID)
	workspaceID = tenantValue(workspaceID)

	if _, err := s.db.ExecContext(ctx, `
INSERT INTO organizations (id, name)
VALUES ($1, $2)
ON CONFLICT (id) DO NOTHING`, orgID, orgID); err != nil {
		return fmt.Errorf("ensure organization %q exists: %w", orgID, err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO workspaces (id, org_id, name)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, id) DO NOTHING`, workspaceID, orgID, workspaceID); err != nil {
		return fmt.Errorf("ensure workspace %q/%q exists: %w", orgID, workspaceID, err)
	}
	return nil
}

func (s *PostgresStore) ensureTenantSchema() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
		`CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
		`CREATE INDEX IF NOT EXISTS idx_workspaces_org_id ON workspaces(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_workspaces_id ON workspaces(id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_org_id_id ON workspaces(org_id, id)`,
		`DO $$
DECLARE
	pk_cols TEXT[];
BEGIN
	SELECT array_agg(att.attname ORDER BY ord.n)
	INTO pk_cols
	FROM pg_constraint con
	JOIN pg_class rel ON rel.oid = con.conrelid
	JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
	JOIN unnest(con.conkey) WITH ORDINALITY AS ord(attnum, n) ON TRUE
	JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = ord.attnum
	WHERE con.contype = 'p'
	  AND nsp.nspname = 'public'
	  AND rel.relname = 'workspaces';

	IF pk_cols = ARRAY['id'] THEN
		ALTER TABLE workspaces DROP CONSTRAINT workspaces_pkey;
	END IF;
END $$;`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres tenant schema component: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) ensureTenantRLS() error {
	// RLS acts as a defensive tenant boundary in multi-instance mode. Session tenant
	// settings restrict visibility when present while preserving legacy/default
	// behavior when tenant context is not set.
	statements := []string{
		`ALTER TABLE traces ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE traces FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS traces_tenant_scope ON traces;`,
		`CREATE POLICY traces_tenant_scope ON traces
USING (
    (NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
        OR org_id = NULLIF(current_setting('ongoingai.org_id', true), ''))
    AND
    (NULLIF(current_setting('ongoingai.workspace_id', true), '') IS NULL
        OR workspace_id = NULLIF(current_setting('ongoingai.workspace_id', true), ''))
)
WITH CHECK (
    (NULLIF(current_setting('ongoingai.org_id', true), '') IS NULL
        OR org_id = NULLIF(current_setting('ongoingai.org_id', true), ''))
    AND
    (NULLIF(current_setting('ongoingai.workspace_id', true), '') IS NULL
        OR workspace_id = NULLIF(current_setting('ongoingai.workspace_id', true), ''))
);`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("ensure postgres traces rls policy: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) hasTracesTable() (bool, error) {
	var exists bool
	if err := s.db.QueryRow(`
SELECT EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'traces'
)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("check postgres traces table existence: %w", err)
	}
	return exists, nil
}

func isPostgresForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func tenantValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return value
}

func nullIfEmpty(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}
