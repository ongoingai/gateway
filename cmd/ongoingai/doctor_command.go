package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ongoingai/gateway/internal/auth"
	"github.com/ongoingai/gateway/internal/config"
	"github.com/ongoingai/gateway/internal/pathutil"
	"github.com/ongoingai/gateway/internal/proxy"
	"github.com/ongoingai/gateway/internal/trace"
)

const defaultDoctorFormat = "text"

const (
	doctorStatusPass = "pass"
	doctorStatusWarn = "warn"
	doctorStatusFail = "fail"
	doctorStatusSkip = "skip"
)

type doctorDocument struct {
	GeneratedAt   time.Time     `json:"generated_at"`
	ConfigPath    string        `json:"config_path"`
	OverallStatus string        `json:"overall_status"`
	Checks        []doctorCheck `json:"checks"`
}

type doctorCheck struct {
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
}

func runDoctor(args []string, out io.Writer, errOut io.Writer) int {
	flagSet := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flagSet.SetOutput(errOut)

	configPath := flagSet.String("config", defaultConfigPath, "Path to config file")
	format := flagSet.String("format", defaultDoctorFormat, "Output format: text or json")

	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if flagSet.NArg() != 0 {
		fmt.Fprintln(errOut, "doctor does not accept positional arguments")
		return 2
	}

	normalizedFormat := strings.ToLower(strings.TrimSpace(*format))
	if normalizedFormat == "" {
		normalizedFormat = defaultDoctorFormat
	}
	if normalizedFormat != "text" && normalizedFormat != "json" {
		fmt.Fprintf(errOut, "invalid doctor format %q: expected text or json\n", *format)
		return 2
	}

	document := buildDoctorDocument(strings.TrimSpace(*configPath))
	if err := writeDoctor(out, normalizedFormat, document); err != nil {
		fmt.Fprintf(errOut, "failed to write doctor output: %v\n", err)
		return 1
	}
	if document.OverallStatus == doctorStatusFail {
		return 1
	}
	return 0
}

func buildDoctorDocument(configPath string) doctorDocument {
	doc := doctorDocument{
		GeneratedAt: time.Now().UTC(),
		ConfigPath:  configPath,
		Checks:      make([]doctorCheck, 0, 4),
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		doc.Checks = append(doc.Checks,
			doctorCheck{
				Name:    "config",
				Status:  doctorStatusFail,
				Summary: "failed to load config",
				Details: []string{err.Error()},
			},
			doctorSkippedCheck("storage", "skipped: config failed to load"),
			doctorSkippedCheck("route_wiring", "skipped: config failed to load"),
			doctorSkippedCheck("auth_posture", "skipped: config failed to load"),
		)
		doc.OverallStatus = doctorOverallStatus(doc.Checks)
		return doc
	}

	if err := config.Validate(cfg); err != nil {
		doc.Checks = append(doc.Checks,
			doctorCheck{
				Name:    "config",
				Status:  doctorStatusFail,
				Summary: "config is invalid",
				Details: []string{err.Error()},
			},
			doctorSkippedCheck("storage", "skipped: config validation failed"),
			doctorSkippedCheck("route_wiring", "skipped: config validation failed"),
			doctorSkippedCheck("auth_posture", "skipped: config validation failed"),
		)
		doc.OverallStatus = doctorOverallStatus(doc.Checks)
		return doc
	}

	doc.Checks = append(doc.Checks, doctorCheck{
		Name:    "config",
		Status:  doctorStatusPass,
		Summary: "loaded and validated configuration",
		Details: []string{fmt.Sprintf("config path: %s", nonEmpty(configPath, "(default lookup)"))},
	})
	doc.Checks = append(doc.Checks, runDoctorStorageCheck(cfg))
	doc.Checks = append(doc.Checks, runDoctorRouteCheck(cfg))
	doc.Checks = append(doc.Checks, runDoctorAuthPostureCheck(cfg))
	doc.OverallStatus = doctorOverallStatus(doc.Checks)
	return doc
}

func doctorSkippedCheck(name, summary string) doctorCheck {
	return doctorCheck{
		Name:    name,
		Status:  doctorStatusSkip,
		Summary: summary,
	}
}

func runDoctorStorageCheck(cfg config.Config) doctorCheck {
	check := doctorCheck{Name: "storage"}
	store, err := openReportTraceStore(cfg)
	if err != nil {
		check.Status = doctorStatusFail
		check.Summary = "failed to initialize trace storage"
		check.Details = []string{err.Error()}
		return check
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.QueryTraces(ctx, trace.TraceFilter{Limit: 1}); err != nil {
		check.Status = doctorStatusFail
		check.Summary = "trace storage connectivity check failed"
		check.Details = []string{err.Error()}
		if closeErr := closeTraceStore(store); closeErr != nil {
			check.Details = append(check.Details, fmt.Sprintf("close trace store: %v", closeErr))
		}
		return check
	}

	check.Status = doctorStatusPass
	driver := strings.TrimSpace(cfg.Storage.Driver)
	switch driver {
	case "sqlite":
		path := strings.TrimSpace(cfg.Storage.Path)
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		check.Summary = "connected to sqlite trace storage"
		check.Details = []string{fmt.Sprintf("path: %s", path)}
	case "postgres":
		check.Summary = "connected to postgres trace storage"
	default:
		check.Summary = "connected to trace storage"
	}
	closeErr := closeTraceStore(store)
	if closeErr != nil {
		check.Status = doctorStatusWarn
		check.Summary = "trace storage connectivity succeeded with close warning"
		check.Details = append(check.Details, fmt.Sprintf("close trace store: %v", closeErr))
	}
	return check
}

func runDoctorRouteCheck(cfg config.Config) doctorCheck {
	check := doctorCheck{Name: "route_wiring"}

	openAIPrefix := pathutil.NormalizePrefix(cfg.Providers.OpenAI.Prefix)
	anthropicPrefix := pathutil.NormalizePrefix(cfg.Providers.Anthropic.Prefix)
	apiPrefix := "/api"

	if openAIPrefix == "/" || anthropicPrefix == "/" {
		check.Status = doctorStatusFail
		check.Summary = "provider prefixes must not be root ('/')"
		check.Details = []string{fmt.Sprintf("openai=%q anthropic=%q", openAIPrefix, anthropicPrefix)}
		return check
	}
	if prefixesOverlap(openAIPrefix, anthropicPrefix) {
		check.Status = doctorStatusFail
		check.Summary = "provider route prefixes overlap"
		check.Details = []string{fmt.Sprintf("openai=%q anthropic=%q", openAIPrefix, anthropicPrefix)}
		return check
	}
	if prefixesOverlap(openAIPrefix, apiPrefix) || prefixesOverlap(anthropicPrefix, apiPrefix) {
		check.Status = doctorStatusFail
		check.Summary = "provider prefixes must not overlap with /api routes"
		check.Details = []string{fmt.Sprintf("openai=%q anthropic=%q api=%q", openAIPrefix, anthropicPrefix, apiPrefix)}
		return check
	}

	_, err := proxy.NewHandlerWithOptions([]proxy.Route{
		{Prefix: cfg.Providers.OpenAI.Prefix, Upstream: cfg.Providers.OpenAI.Upstream},
		{Prefix: cfg.Providers.Anthropic.Prefix, Upstream: cfg.Providers.Anthropic.Upstream},
	}, nil, http.NotFoundHandler(), proxy.HandlerOptions{})
	if err != nil {
		check.Status = doctorStatusFail
		check.Summary = "failed to build proxy handler with configured routes"
		check.Details = []string{err.Error()}
		return check
	}

	check.Status = doctorStatusPass
	check.Summary = "provider and API route wiring looks valid"
	check.Details = []string{
		fmt.Sprintf("openai: %s -> %s", openAIPrefix, strings.TrimSpace(cfg.Providers.OpenAI.Upstream)),
		fmt.Sprintf("anthropic: %s -> %s", anthropicPrefix, strings.TrimSpace(cfg.Providers.Anthropic.Upstream)),
		"api routes: /api/*",
	}
	return check
}

func runDoctorAuthPostureCheck(cfg config.Config) doctorCheck {
	check := doctorCheck{Name: "auth_posture"}
	protectedRules := countProtectedAuthorizationRules(auth.AuthorizationMatrix())
	header := strings.TrimSpace(cfg.Auth.Header)

	if headerConflictsWithProviderCredential(header) {
		check.Status = doctorStatusFail
		check.Summary = "auth header conflicts with provider credential headers"
		check.Details = []string{fmt.Sprintf("auth.header=%q conflicts with Authorization/X-API-Key", header)}
		return check
	}

	if !cfg.Auth.Enabled {
		check.Status = doctorStatusWarn
		check.Summary = "gateway auth is disabled"
		check.Details = []string{
			fmt.Sprintf("auth.enabled=false (header: %s)", header),
			fmt.Sprintf("%d protected authorization rules are bypassed", protectedRules),
		}
		return check
	}

	gatewayKeyStore, err := newGatewayKeyStore(cfg)
	if err != nil {
		check.Status = doctorStatusFail
		check.Summary = "failed to initialize gateway key store"
		check.Details = []string{err.Error()}
		return check
	}

	keys, err := loadGatewayAuthKeys(context.Background(), cfg, nil, gatewayKeyStore)
	if err != nil {
		check.Status = doctorStatusFail
		check.Summary = "failed to resolve gateway auth keys"
		check.Details = []string{err.Error()}
		if closeErr := gatewayKeyStore.Close(); closeErr != nil {
			check.Details = append(check.Details, fmt.Sprintf("close gateway key store: %v", closeErr))
		}
		return check
	}

	if _, err := auth.NewAuthorizer(auth.Options{
		Enabled: true,
		Header:  header,
		Keys:    keys,
	}); err != nil {
		check.Status = doctorStatusFail
		check.Summary = "gateway auth configuration is not runnable"
		check.Details = []string{err.Error()}
		if closeErr := gatewayKeyStore.Close(); closeErr != nil {
			check.Details = append(check.Details, fmt.Sprintf("close gateway key store: %v", closeErr))
		}
		return check
	}

	check.Status = doctorStatusPass
	check.Summary = "gateway auth posture is healthy"
	check.Details = []string{
		fmt.Sprintf("auth header: %s", header),
		fmt.Sprintf("active gateway keys: %d", len(keys)),
		fmt.Sprintf("protected authorization rules: %d", protectedRules),
	}
	closeErr := gatewayKeyStore.Close()
	if closeErr != nil {
		check.Status = doctorStatusWarn
		check.Summary = "gateway auth posture is healthy with close warning"
		check.Details = append(check.Details, fmt.Sprintf("close gateway key store: %v", closeErr))
	}
	return check
}

func headerConflictsWithProviderCredential(header string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	return strings.EqualFold(header, "Authorization") || strings.EqualFold(header, "X-API-Key")
}

func countProtectedAuthorizationRules(rules []auth.AuthorizationRule) int {
	count := 0
	for _, rule := range rules {
		if !rule.Public {
			count++
		}
	}
	return count
}

func closeTraceStore(store trace.TraceStore) error {
	if store == nil {
		return nil
	}
	if closer, ok := store.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func prefixesOverlap(left, right string) bool {
	left = pathutil.NormalizePrefix(left)
	right = pathutil.NormalizePrefix(right)
	return pathutil.HasPathPrefix(left, right) || pathutil.HasPathPrefix(right, left)
}

func doctorOverallStatus(checks []doctorCheck) string {
	hasWarn := false
	for _, check := range checks {
		switch check.Status {
		case doctorStatusFail:
			return doctorStatusFail
		case doctorStatusWarn:
			hasWarn = true
		}
	}
	if hasWarn {
		return doctorStatusWarn
	}
	return doctorStatusPass
}

func writeDoctor(out io.Writer, format string, doc doctorDocument) error {
	switch format {
	case "json":
		return writeDoctorJSON(out, doc)
	default:
		return writeDoctorText(out, doc)
	}
}

func writeDoctorJSON(out io.Writer, doc doctorDocument) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(doc)
}

func writeDoctorText(out io.Writer, doc doctorDocument) error {
	fmt.Fprintln(out, "OngoingAI Doctor")

	meta := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(meta, "Generated at\t%s\n", doc.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(meta, "Config path\t%s\n", nonEmpty(doc.ConfigPath, defaultConfigPath))
	fmt.Fprintf(meta, "Overall status\t%s\n", strings.ToUpper(doc.OverallStatus))
	if err := meta.Flush(); err != nil {
		return err
	}

	fmt.Fprintln(out, "\nChecks")
	for _, check := range doc.Checks {
		fmt.Fprintf(out, "- [%s] %s: %s\n", strings.ToUpper(check.Status), check.Name, check.Summary)
		for _, detail := range check.Details {
			fmt.Fprintf(out, "  %s\n", detail)
		}
	}
	return nil
}
