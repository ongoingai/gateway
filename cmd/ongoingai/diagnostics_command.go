package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ongoingai/gateway/internal/trace"
)

const (
	defaultDiagnosticsFormat     = "text"
	defaultDiagnosticsTarget     = "trace-pipeline"
	defaultDiagnosticsTimeout    = 5 * time.Second
	defaultGatewayAuthHeaderName = "X-OngoingAI-Gateway-Key"
)

type tracePipelineDiagnosticsDocument struct {
	SchemaVersion string                         `json:"schema_version"`
	GeneratedAt   time.Time                      `json:"generated_at"`
	Diagnostics   trace.TracePipelineDiagnostics `json:"diagnostics"`
}

func runDiagnostics(args []string, out io.Writer, errOut io.Writer) int {
	flagSet := flag.NewFlagSet("diagnostics", flag.ContinueOnError)
	flagSet.SetOutput(errOut)

	configPath := flagSet.String("config", defaultConfigPath, "Path to config file")
	baseURL := flagSet.String("base-url", "", "Gateway base URL (defaults to value derived from config)")
	gatewayKey := flagSet.String("gateway-key", "", "Gateway key token for protected diagnostics route access")
	authHeader := flagSet.String("auth-header", "", "Gateway key header name (defaults to config auth.header)")
	format := flagSet.String("format", defaultDiagnosticsFormat, "Output format: text or json")
	timeout := flagSet.Duration("timeout", defaultDiagnosticsTimeout, "HTTP timeout duration")

	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if flagSet.NArg() > 1 {
		fmt.Fprintln(errOut, `diagnostics accepts at most one positional argument: "trace-pipeline"`)
		return 2
	}

	target := defaultDiagnosticsTarget
	if flagSet.NArg() == 1 {
		target = strings.TrimSpace(flagSet.Arg(0))
	}
	if target != defaultDiagnosticsTarget {
		fmt.Fprintf(errOut, "unsupported diagnostics target %q: expected %q\n", target, defaultDiagnosticsTarget)
		return 2
	}

	normalizedFormat, err := normalizeTextJSONFormat("diagnostics", *format, defaultDiagnosticsFormat)
	if err != nil {
		fmt.Fprintln(errOut, err.Error())
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintf(errOut, "invalid diagnostics timeout %q: must be greater than 0\n", timeout.String())
		return 2
	}

	resolvedBaseURL, resolvedAuthHeader, err := resolveDiagnosticsConnection(strings.TrimSpace(*configPath), strings.TrimSpace(*baseURL), strings.TrimSpace(*authHeader))
	if err != nil {
		fmt.Fprintf(errOut, "failed to resolve diagnostics endpoint: %v\n", err)
		return 1
	}

	document, err := fetchTracePipelineDiagnostics(resolvedBaseURL, resolvedAuthHeader, strings.TrimSpace(*gatewayKey), *timeout)
	if err != nil {
		fmt.Fprintf(errOut, "failed to read diagnostics: %v\n", err)
		return 1
	}
	if err := writeTracePipelineDiagnostics(out, normalizedFormat, document, resolvedBaseURL); err != nil {
		fmt.Fprintf(errOut, "failed to write diagnostics output: %v\n", err)
		return 1
	}
	return 0
}

func resolveDiagnosticsConnection(configPath, baseURL, authHeader string) (string, string, error) {
	resolvedBaseURL := strings.TrimSpace(baseURL)
	resolvedAuthHeader := strings.TrimSpace(authHeader)
	needsConfig := resolvedBaseURL == "" || resolvedAuthHeader == ""

	if needsConfig {
		cfg, stage, err := loadAndValidateConfig(configPath)
		if err != nil {
			if resolvedBaseURL == "" {
				if stage == configStageLoad {
					return "", "", fmt.Errorf("load config: %w", err)
				}
				return "", "", fmt.Errorf("config validation failed: %w", err)
			}
		} else {
			if resolvedBaseURL == "" {
				resolvedBaseURL = gatewayBaseURL(cfg)
			}
			if resolvedAuthHeader == "" {
				resolvedAuthHeader = strings.TrimSpace(cfg.Auth.Header)
			}
		}
	}

	if resolvedBaseURL == "" {
		resolvedBaseURL = "http://localhost:8080"
	}
	normalizedBaseURL, err := normalizeDiagnosticsBaseURL(resolvedBaseURL)
	if err != nil {
		return "", "", err
	}

	if resolvedAuthHeader == "" {
		resolvedAuthHeader = defaultGatewayAuthHeaderName
	}
	return normalizedBaseURL, resolvedAuthHeader, nil
}

func normalizeDiagnosticsBaseURL(rawBaseURL string) (string, error) {
	value := strings.TrimSpace(rawBaseURL)
	if value == "" {
		return "", fmt.Errorf("base URL is empty")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("base URL must include http or https scheme")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", fmt.Errorf("base URL must include host")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
}

func fetchTracePipelineDiagnostics(baseURL, authHeader, gatewayKey string, timeout time.Duration) (tracePipelineDiagnosticsDocument, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	endpoint := strings.TrimRight(baseURL, "/") + "/api/diagnostics/trace-pipeline"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return tracePipelineDiagnosticsDocument{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if gatewayKey != "" {
		req.Header.Set(authHeader, gatewayKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tracePipelineDiagnosticsDocument{}, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tracePipelineDiagnosticsDocument{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(body))
		var errorPayload map[string]any
		if err := json.Unmarshal(body, &errorPayload); err == nil {
			if value, ok := errorPayload["error"].(string); ok && strings.TrimSpace(value) != "" {
				message = strings.TrimSpace(value)
			}
		}
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return tracePipelineDiagnosticsDocument{}, fmt.Errorf("status %d: %s", resp.StatusCode, message)
	}

	var document tracePipelineDiagnosticsDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return tracePipelineDiagnosticsDocument{}, fmt.Errorf("decode response: %w", err)
	}
	if strings.TrimSpace(document.SchemaVersion) == "" {
		return tracePipelineDiagnosticsDocument{}, fmt.Errorf("missing schema_version in diagnostics response")
	}
	return document, nil
}

func writeTracePipelineDiagnostics(out io.Writer, format string, document tracePipelineDiagnosticsDocument, baseURL string) error {
	switch format {
	case "json":
		return writeTracePipelineDiagnosticsJSON(out, document)
	default:
		return writeTracePipelineDiagnosticsText(out, document, baseURL)
	}
}

func writeTracePipelineDiagnosticsJSON(out io.Writer, document tracePipelineDiagnosticsDocument) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func writeTracePipelineDiagnosticsText(out io.Writer, document tracePipelineDiagnosticsDocument, baseURL string) error {
	fmt.Fprintln(out, "OngoingAI Diagnostics")

	meta := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(meta, "Schema version\t%s\n", document.SchemaVersion)
	fmt.Fprintf(meta, "Generated at\t%s\n", document.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(meta, "Source\t%s\n", strings.TrimRight(strings.TrimSpace(baseURL), "/")+"/api/diagnostics/trace-pipeline")
	fmt.Fprintf(meta, "Queue pressure\t%s\n", strings.ToUpper(strings.TrimSpace(document.Diagnostics.QueuePressureState)))
	fmt.Fprintf(meta, "High watermark pressure\t%s\n", strings.ToUpper(strings.TrimSpace(document.Diagnostics.QueueHighWatermarkPressureState)))
	if err := meta.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out, "\nQueue")
	queue := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(queue, "Capacity\t%d\n", document.Diagnostics.QueueCapacity)
	fmt.Fprintf(queue, "Depth\t%d\n", document.Diagnostics.QueueDepth)
	fmt.Fprintf(queue, "Depth high watermark\t%d\n", document.Diagnostics.QueueDepthHighWatermark)
	fmt.Fprintf(queue, "Utilization (pct)\t%d\n", document.Diagnostics.QueueUtilizationPct)
	fmt.Fprintf(queue, "High watermark utilization (pct)\t%d\n", document.Diagnostics.QueueHighWatermarkUtilizationPct)
	fmt.Fprintf(queue, "Enqueue accepted total\t%d\n", document.Diagnostics.EnqueueAcceptedTotal)
	if err := queue.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out, "\nDrops")
	drops := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(drops, "Enqueue dropped total\t%d\n", document.Diagnostics.EnqueueDroppedTotal)
	fmt.Fprintf(drops, "Write dropped total\t%d\n", document.Diagnostics.WriteDroppedTotal)
	fmt.Fprintf(drops, "Total dropped\t%d\n", document.Diagnostics.TotalDroppedTotal)
	fmt.Fprintf(drops, "Last enqueue drop at\t%s\n", diagnosticsTimePtrOr(document.Diagnostics.LastEnqueueDropAt, "(none)"))
	fmt.Fprintf(drops, "Last write drop at\t%s\n", diagnosticsTimePtrOr(document.Diagnostics.LastWriteDropAt, "(none)"))
	fmt.Fprintf(drops, "Last write drop operation\t%s\n", diagnosticsValueOr(document.Diagnostics.LastWriteDropOperation, "(none)"))
	return drops.Flush()
}

func diagnosticsTimePtrOr(value *time.Time, fallback string) string {
	if value == nil {
		return fallback
	}
	return value.UTC().Format(time.RFC3339)
}

func diagnosticsValueOr(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
