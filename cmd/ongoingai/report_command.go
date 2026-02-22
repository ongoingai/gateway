package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/trace"
)

const (
	defaultReportFormat = "text"
	defaultReportLimit  = 10
	maxReportLimit      = 200
	reportSchemaVersion = "report.v1"
)

type reportDocument struct {
	SchemaVersion string               `json:"schema_version"`
	GeneratedAt   time.Time            `json:"generated_at"`
	Storage       reportStorageInfo    `json:"storage"`
	Filters       reportFilterInfo     `json:"filters"`
	Summary       reportSummaryInfo    `json:"summary"`
	Providers     []reportProviderInfo `json:"providers"`
	Models        []reportModelInfo    `json:"models"`
	APIKeys       []reportKeyInfo      `json:"api_keys"`
	Recent        []reportTraceInfo    `json:"recent_traces"`
}

type reportStorageInfo struct {
	Driver string `json:"driver"`
	Path   string `json:"path,omitempty"`
}

type reportFilterInfo struct {
	Provider string     `json:"provider,omitempty"`
	Model    string     `json:"model,omitempty"`
	From     *time.Time `json:"from,omitempty"`
	To       *time.Time `json:"to,omitempty"`
	Limit    int        `json:"limit"`
}

type reportSummaryInfo struct {
	TotalRequests     int64   `json:"total_requests"`
	TotalInputTokens  int64   `json:"total_input_tokens"`
	TotalOutputTokens int64   `json:"total_output_tokens"`
	TotalTokens       int64   `json:"total_tokens"`
	TotalCostUSD      float64 `json:"total_cost_usd"`
	ActiveKeys        int     `json:"active_keys"`
	TopModel          string  `json:"top_model,omitempty"`
}

type reportProviderInfo struct {
	Provider     string  `json:"provider"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	TotalTokens  int64   `json:"total_tokens"`
	TotalCostUSD float64 `json:"total_cost_usd"`
}

type reportModelInfo struct {
	Model        string  `json:"model"`
	RequestCount int64   `json:"request_count"`
	AvgLatencyMS float64 `json:"avg_latency_ms"`
	AvgTTFTMS    float64 `json:"avg_ttft_ms"`
	TotalTokens  int64   `json:"total_tokens"`
	TotalCostUSD float64 `json:"total_cost_usd"`
}

type reportKeyInfo struct {
	APIKeyHash   string    `json:"api_key_hash"`
	RequestCount int64     `json:"request_count"`
	TotalTokens  int64     `json:"total_tokens"`
	TotalCostUSD float64   `json:"total_cost_usd"`
	LastActiveAt time.Time `json:"last_active_at,omitempty"`
}

type reportTraceInfo struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Provider       string    `json:"provider"`
	Model          string    `json:"model"`
	ResponseStatus int       `json:"response_status"`
	TotalTokens    int       `json:"total_tokens"`
	EstimatedCost  float64   `json:"estimated_cost_usd"`
	LatencyMS      int64     `json:"latency_ms"`
	RequestPath    string    `json:"request_path"`
}

func runReport(args []string, out io.Writer, errOut io.Writer) int {
	flagSet := flag.NewFlagSet("report", flag.ContinueOnError)
	flagSet.SetOutput(errOut)

	configPath := flagSet.String("config", defaultConfigPath, "Path to config file")
	format := flagSet.String("format", defaultReportFormat, "Output format: text or json")
	fromRaw := flagSet.String("from", "", "Report start time (RFC3339 or YYYY-MM-DD)")
	toRaw := flagSet.String("to", "", "Report end time (RFC3339 or YYYY-MM-DD)")
	provider := flagSet.String("provider", "", "Provider filter")
	model := flagSet.String("model", "", "Model filter")
	limit := flagSet.Int("limit", defaultReportLimit, "Recent trace count (1-200)")

	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if flagSet.NArg() != 0 {
		fmt.Fprintln(errOut, "report does not accept positional arguments")
		return 2
	}

	normalizedFormat, err := normalizeTextJSONFormat("report", *format, defaultReportFormat)
	if err != nil {
		fmt.Fprintln(errOut, err.Error())
		return 2
	}
	if *limit <= 0 || *limit > maxReportLimit {
		fmt.Fprintf(errOut, "limit must be between 1 and %d\n", maxReportLimit)
		return 2
	}

	from, err := parseReportTime(*fromRaw, false)
	if err != nil {
		fmt.Fprintf(errOut, "invalid from: %v\n", err)
		return 2
	}
	to, err := parseReportTime(*toRaw, true)
	if err != nil {
		fmt.Fprintf(errOut, "invalid to: %v\n", err)
		return 2
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		fmt.Fprintln(errOut, "invalid range: to must be greater than or equal to from")
		return 2
	}

	cfg, stage, err := loadAndValidateConfig(*configPath)
	if err != nil {
		if stage == configStageLoad {
			fmt.Fprintf(errOut, "failed to load config: %v\n", err)
		} else {
			fmt.Fprintf(errOut, "config is invalid: %v\n", err)
		}
		return 1
	}

	store, err := openTraceStore(cfg)
	if err != nil {
		fmt.Fprintf(errOut, "failed to initialize trace store: %v\n", err)
		return 1
	}
	defer closeTraceStoreWithWarning(store, errOut)

	analyticsFilter := trace.AnalyticsFilter{
		Provider: strings.TrimSpace(*provider),
		Model:    strings.TrimSpace(*model),
		From:     from,
		To:       to,
	}
	traceFilter := trace.TraceFilter{
		Provider: analyticsFilter.Provider,
		Model:    analyticsFilter.Model,
		From:     analyticsFilter.From,
		To:       analyticsFilter.To,
		Limit:    *limit,
	}

	report, err := buildReport(context.Background(), store, cfg, analyticsFilter, traceFilter)
	if err != nil {
		fmt.Fprintf(errOut, "failed to build report: %v\n", err)
		return 1
	}

	if err := writeReport(out, normalizedFormat, report); err != nil {
		fmt.Fprintf(errOut, "failed to write report: %v\n", err)
		return 1
	}

	return 0
}

func parseReportTime(raw string, endOfDay bool) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02",
	}
	for _, layout := range layouts {
		if layout == "2006-01-02" {
			parsed, err := time.ParseInLocation(layout, value, time.UTC)
			if err == nil {
				if endOfDay {
					return parsed.Add(24*time.Hour - time.Nanosecond), nil
				}
				return parsed, nil
			}
			continue
		}
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD")
}

func buildReport(
	ctx context.Context,
	store trace.TraceStore,
	cfg config.Config,
	analyticsFilter trace.AnalyticsFilter,
	traceFilter trace.TraceFilter,
) (reportDocument, error) {
	var (
		usage       *trace.UsageSummary
		cost        *trace.CostSummary
		models      []trace.ModelStats
		keys        []trace.KeyStats
		usageSeries []trace.UsagePoint
		costSeries  []trace.CostPoint
		recent      *trace.TraceResult
	)

	var (
		queryErr error
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	runQuery := func(fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				mu.Lock()
				if queryErr == nil {
					queryErr = err
				}
				mu.Unlock()
			}
		}()
	}

	runQuery(func() error {
		var err error
		usage, err = store.GetUsageSummary(ctx, analyticsFilter)
		return err
	})
	runQuery(func() error {
		var err error
		cost, err = store.GetCostSummary(ctx, analyticsFilter)
		return err
	})
	runQuery(func() error {
		var err error
		models, err = store.GetModelStats(ctx, analyticsFilter)
		return err
	})
	runQuery(func() error {
		var err error
		keys, err = store.GetKeyStats(ctx, analyticsFilter)
		return err
	})
	runQuery(func() error {
		var err error
		usageSeries, err = store.GetUsageSeries(ctx, analyticsFilter, "provider", "day")
		return err
	})
	runQuery(func() error {
		var err error
		costSeries, err = store.GetCostSeries(ctx, analyticsFilter, "provider", "day")
		return err
	})
	runQuery(func() error {
		var err error
		recent, err = store.QueryTraces(ctx, traceFilter)
		return err
	})

	wg.Wait()
	if queryErr != nil {
		return reportDocument{}, queryErr
	}
	if usage == nil {
		usage = &trace.UsageSummary{}
	}
	if cost == nil {
		cost = &trace.CostSummary{}
	}
	if recent == nil {
		recent = &trace.TraceResult{}
	}

	totalRequests := int64(0)
	topModel := ""
	topModelRequests := int64(0)
	modelRows := make([]reportModelInfo, 0, len(models))
	for _, model := range models {
		totalRequests += model.RequestCount
		if model.RequestCount > topModelRequests || (model.RequestCount == topModelRequests && strings.TrimSpace(model.Model) < strings.TrimSpace(topModel)) {
			topModelRequests = model.RequestCount
			topModel = model.Model
		}
		modelRows = append(modelRows, reportModelInfo{
			Model:        model.Model,
			RequestCount: model.RequestCount,
			AvgLatencyMS: model.AvgLatencyMS,
			AvgTTFTMS:    model.AvgTTFTMS,
			TotalTokens:  model.TotalTokens,
			TotalCostUSD: model.TotalCostUSD,
		})
	}

	keyRows := make([]reportKeyInfo, 0, len(keys))
	for _, key := range keys {
		keyRows = append(keyRows, reportKeyInfo{
			APIKeyHash:   key.APIKeyHash,
			RequestCount: key.RequestCount,
			TotalTokens:  key.TotalTokens,
			TotalCostUSD: key.TotalCostUSD,
			LastActiveAt: key.LastActiveAt,
		})
	}

	providerRows := aggregateProviderRows(usageSeries, costSeries)
	recentRows := make([]reportTraceInfo, 0, len(recent.Items))
	for _, item := range recent.Items {
		if item == nil {
			continue
		}
		timestamp := item.Timestamp
		if timestamp.IsZero() {
			timestamp = item.CreatedAt
		}
		recentRows = append(recentRows, reportTraceInfo{
			ID:             item.ID,
			Timestamp:      timestamp,
			Provider:       item.Provider,
			Model:          item.Model,
			ResponseStatus: item.ResponseStatus,
			TotalTokens:    item.TotalTokens,
			EstimatedCost:  item.EstimatedCostUSD,
			LatencyMS:      item.LatencyMS,
			RequestPath:    item.RequestPath,
		})
	}
	sortReportModelRows(modelRows)
	sortReportKeyRows(keyRows)
	sortReportRecentRows(recentRows)

	storagePath := ""
	if strings.TrimSpace(cfg.Storage.Driver) == "sqlite" {
		storagePath = cfg.Storage.Path
	}

	return reportDocument{
		SchemaVersion: reportSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Storage: reportStorageInfo{
			Driver: cfg.Storage.Driver,
			Path:   storagePath,
		},
		Filters: reportFilterInfo{
			Provider: analyticsFilter.Provider,
			Model:    analyticsFilter.Model,
			From:     reportOptionalTime(analyticsFilter.From),
			To:       reportOptionalTime(analyticsFilter.To),
			Limit:    traceFilter.Limit,
		},
		Summary: reportSummaryInfo{
			TotalRequests:     totalRequests,
			TotalInputTokens:  usage.TotalInputTokens,
			TotalOutputTokens: usage.TotalOutputTokens,
			TotalTokens:       usage.TotalTokens,
			TotalCostUSD:      cost.TotalCostUSD,
			ActiveKeys:        len(keyRows),
			TopModel:          topModel,
		},
		Providers: providerRows,
		Models:    modelRows,
		APIKeys:   keyRows,
		Recent:    recentRows,
	}, nil
}

func aggregateProviderRows(usageSeries []trace.UsagePoint, costSeries []trace.CostPoint) []reportProviderInfo {
	byProvider := make(map[string]*reportProviderInfo)
	ensureProvider := func(raw string) *reportProviderInfo {
		provider := strings.TrimSpace(raw)
		if provider == "" {
			provider = "(unknown)"
		}
		item, ok := byProvider[provider]
		if !ok {
			item = &reportProviderInfo{Provider: provider}
			byProvider[provider] = item
		}
		return item
	}

	for _, point := range usageSeries {
		item := ensureProvider(point.Group)
		item.InputTokens += point.InputTokens
		item.OutputTokens += point.OutputTokens
		item.TotalTokens += point.TotalTokens
	}
	for _, point := range costSeries {
		item := ensureProvider(point.Group)
		item.TotalCostUSD += point.TotalCostUSD
	}

	rows := make([]reportProviderInfo, 0, len(byProvider))
	for _, item := range byProvider {
		rows = append(rows, *item)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalTokens != rows[j].TotalTokens {
			return rows[i].TotalTokens > rows[j].TotalTokens
		}
		if rows[i].TotalCostUSD != rows[j].TotalCostUSD {
			return rows[i].TotalCostUSD > rows[j].TotalCostUSD
		}
		return strings.TrimSpace(rows[i].Provider) < strings.TrimSpace(rows[j].Provider)
	})
	return rows
}

func sortReportModelRows(rows []reportModelInfo) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RequestCount != rows[j].RequestCount {
			return rows[i].RequestCount > rows[j].RequestCount
		}
		return strings.TrimSpace(rows[i].Model) < strings.TrimSpace(rows[j].Model)
	})
}

func sortReportKeyRows(rows []reportKeyInfo) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RequestCount != rows[j].RequestCount {
			return rows[i].RequestCount > rows[j].RequestCount
		}
		return strings.TrimSpace(rows[i].APIKeyHash) < strings.TrimSpace(rows[j].APIKeyHash)
	})
}

func sortReportRecentRows(rows []reportTraceInfo) {
	sort.Slice(rows, func(i, j int) bool {
		left := reportRecentTime(rows[i])
		right := reportRecentTime(rows[j])
		if !left.Equal(right) {
			return left.After(right)
		}
		return strings.TrimSpace(rows[i].ID) > strings.TrimSpace(rows[j].ID)
	})
}

func reportRecentTime(row reportTraceInfo) time.Time {
	if row.Timestamp.IsZero() {
		return time.Time{}
	}
	return row.Timestamp.UTC()
}

func writeReport(out io.Writer, format string, report reportDocument) error {
	switch format {
	case "json":
		return writeReportJSON(out, report)
	default:
		return writeReportText(out, report)
	}
}

func writeReportJSON(out io.Writer, report reportDocument) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func writeReportText(out io.Writer, report reportDocument) error {
	fmt.Fprintln(out, "OngoingAI Report")

	metadataWriter := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(metadataWriter, "Schema version\t%s\n", report.SchemaVersion)
	fmt.Fprintf(metadataWriter, "Generated at\t%s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(metadataWriter, "Storage driver\t%s\n", report.Storage.Driver)
	if strings.TrimSpace(report.Storage.Path) != "" {
		fmt.Fprintf(metadataWriter, "Storage path\t%s\n", report.Storage.Path)
	}
	fmt.Fprintf(metadataWriter, "Filter provider\t%s\n", valueOr(report.Filters.Provider, "(all)"))
	fmt.Fprintf(metadataWriter, "Filter model\t%s\n", valueOr(report.Filters.Model, "(all)"))
	fmt.Fprintf(metadataWriter, "Filter from\t%s\n", timePtrOr(report.Filters.From, "(all)"))
	fmt.Fprintf(metadataWriter, "Filter to\t%s\n", timePtrOr(report.Filters.To, "(all)"))
	fmt.Fprintf(metadataWriter, "Filter limit\t%d\n", report.Filters.Limit)
	if err := metadataWriter.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out, "\nSummary")
	summaryWriter := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(summaryWriter, "Total requests\t%d\n", report.Summary.TotalRequests)
	fmt.Fprintf(summaryWriter, "Total input tokens\t%d\n", report.Summary.TotalInputTokens)
	fmt.Fprintf(summaryWriter, "Total output tokens\t%d\n", report.Summary.TotalOutputTokens)
	fmt.Fprintf(summaryWriter, "Total tokens\t%d\n", report.Summary.TotalTokens)
	fmt.Fprintf(summaryWriter, "Estimated cost (USD)\t%.6f\n", report.Summary.TotalCostUSD)
	fmt.Fprintf(summaryWriter, "Active API keys\t%d\n", report.Summary.ActiveKeys)
	fmt.Fprintf(summaryWriter, "Top model\t%s\n", valueOr(report.Summary.TopModel, "(none)"))
	if err := summaryWriter.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out, "\nProviders")
	if len(report.Providers) == 0 {
		fmt.Fprintln(out, "(no provider data)")
	} else {
		providerWriter := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(providerWriter, "PROVIDER\tINPUT_TOKENS\tOUTPUT_TOKENS\tTOTAL_TOKENS\tTOTAL_COST_USD")
		for _, row := range report.Providers {
			fmt.Fprintf(providerWriter, "%s\t%d\t%d\t%d\t%.6f\n", row.Provider, row.InputTokens, row.OutputTokens, row.TotalTokens, row.TotalCostUSD)
		}
		if err := providerWriter.Flush(); err != nil {
			return err
		}
	}

	fmt.Fprintln(out, "\nModels")
	if len(report.Models) == 0 {
		fmt.Fprintln(out, "(no model data)")
	} else {
		modelWriter := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(modelWriter, "MODEL\tREQUESTS\tTOTAL_TOKENS\tTOTAL_COST_USD\tAVG_LATENCY_MS\tAVG_TTFT_MS")
		for _, row := range report.Models {
			fmt.Fprintf(modelWriter, "%s\t%d\t%d\t%.6f\t%.2f\t%.2f\n", valueOr(row.Model, "(unknown)"), row.RequestCount, row.TotalTokens, row.TotalCostUSD, row.AvgLatencyMS, row.AvgTTFTMS)
		}
		if err := modelWriter.Flush(); err != nil {
			return err
		}
	}

	fmt.Fprintln(out, "\nAPI Keys")
	if len(report.APIKeys) == 0 {
		fmt.Fprintln(out, "(no API key data)")
	} else {
		keyWriter := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(keyWriter, "API_KEY_HASH\tREQUESTS\tTOTAL_TOKENS\tTOTAL_COST_USD\tLAST_ACTIVE_AT")
		for _, row := range report.APIKeys {
			fmt.Fprintf(
				keyWriter,
				"%s\t%d\t%d\t%.6f\t%s\n",
				row.APIKeyHash,
				row.RequestCount,
				row.TotalTokens,
				row.TotalCostUSD,
				timeOr(row.LastActiveAt, "(none)"),
			)
		}
		if err := keyWriter.Flush(); err != nil {
			return err
		}
	}

	fmt.Fprintln(out, "\nRecent Traces")
	if len(report.Recent) == 0 {
		fmt.Fprintln(out, "(no traces)")
		return nil
	}
	traceWriter := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(traceWriter, "TIMESTAMP\tPROVIDER\tMODEL\tSTATUS\tTOTAL_TOKENS\tESTIMATED_COST_USD\tLATENCY_MS\tREQUEST_PATH\tTRACE_ID")
	for _, row := range report.Recent {
		fmt.Fprintf(
			traceWriter,
			"%s\t%s\t%s\t%d\t%d\t%.6f\t%d\t%s\t%s\n",
			timeOr(row.Timestamp, "(unknown)"),
			valueOr(row.Provider, "(unknown)"),
			valueOr(row.Model, "(unknown)"),
			row.ResponseStatus,
			row.TotalTokens,
			row.EstimatedCost,
			row.LatencyMS,
			valueOr(row.RequestPath, "(unknown)"),
			row.ID,
		)
	}
	return traceWriter.Flush()
}

func reportOptionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}
