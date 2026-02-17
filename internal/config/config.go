package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/ongoingai/gateway/internal/pathutil"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Storage       StorageConfig       `yaml:"storage"`
	Providers     ProvidersConfig     `yaml:"providers"`
	Tracing       TracingConfig       `yaml:"tracing"`
	Observability ObservabilityConfig `yaml:"observability"`
	PII           PIIConfig           `yaml:"pii"`
	Auth          AuthConfig          `yaml:"auth"`
	Limits        LimitsConfig        `yaml:"limits"`
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

type StorageConfig struct {
	Driver string `yaml:"driver"`
	Path   string `yaml:"path"`
	DSN    string `yaml:"dsn"`
}

type ProvidersConfig struct {
	OpenAI    ProviderConfig `yaml:"openai"`
	Anthropic ProviderConfig `yaml:"anthropic"`
}

type ProviderConfig struct {
	Upstream string `yaml:"upstream"`
	Prefix   string `yaml:"prefix"`
}

type TracingConfig struct {
	CaptureBodies bool `yaml:"capture_bodies"`
	BodyMaxSize   int  `yaml:"body_max_size"`
}

type ObservabilityConfig struct {
	OTel OTelConfig `yaml:"otel"`
}

type OTelConfig struct {
	Enabled                bool    `yaml:"enabled"`
	Endpoint               string  `yaml:"endpoint"`
	Insecure               bool    `yaml:"insecure"`
	ServiceName            string  `yaml:"service_name"`
	TracesEnabled          bool    `yaml:"traces_enabled"`
	MetricsEnabled         bool    `yaml:"metrics_enabled"`
	SamplingRatio          float64 `yaml:"sampling_ratio"`
	ExportTimeoutMS        int     `yaml:"export_timeout_ms"`
	MetricExportIntervalMS int     `yaml:"metric_export_interval_ms"`
}

const (
	PIIModeOff            = "off"
	PIIModeRedactStorage  = "redact_storage"
	PIIModeRedactUpstream = "redact_upstream"
	PIIModeBlock          = "block"
)

const (
	defaultOTELEndpoint               = "localhost:4318"
	defaultOTELServiceName            = "ongoingai-gateway"
	defaultOTELSamplingRatio          = 1.0
	defaultOTELExportTimeoutMS        = 3000
	defaultOTELMetricExportIntervalMS = 10000
)

type PIIConfig struct {
	Mode        string               `yaml:"mode"`
	PolicyID    string               `yaml:"policy_id"`
	Stages      PIIStagesConfig      `yaml:"stages"`
	Detectors   PIIDetectorsConfig   `yaml:"detectors"`
	Headers     PIIHeadersConfig     `yaml:"headers"`
	Body        PIIBodyConfig        `yaml:"body"`
	Replacement PIIReplacementConfig `yaml:"replacement"`
	Scopes      []PIIScopeConfig     `yaml:"scopes"`
}

type PIIStagesConfig struct {
	RequestHeaders  bool `yaml:"request_headers"`
	RequestBody     bool `yaml:"request_body"`
	ResponseHeaders bool `yaml:"response_headers"`
	ResponseBody    bool `yaml:"response_body"`
}

type PIIDetectorsConfig struct {
	Email     bool `yaml:"email"`
	Phone     bool `yaml:"phone"`
	SSN       bool `yaml:"ssn"`
	TokenLike bool `yaml:"token_like"`
}

type PIIHeadersConfig struct {
	Denylist []string `yaml:"denylist"`
}

type PIIBodyConfig struct {
	KeyDenylist []string `yaml:"key_denylist"`
}

type PIIReplacementConfig struct {
	Format   string `yaml:"format"`
	HashSalt string `yaml:"hash_salt"`
}

type PIIScopeConfig struct {
	Match    PIIScopeMatchConfig `yaml:"match"`
	Mode     string              `yaml:"mode"`
	PolicyID string              `yaml:"policy_id"`
}

type PIIScopeMatchConfig struct {
	OrgID       string `yaml:"org_id"`
	WorkspaceID string `yaml:"workspace_id"`
	KeyID       string `yaml:"key_id"`
	Provider    string `yaml:"provider"`
	RoutePrefix string `yaml:"route_prefix"`
}

type PIIScopeInput struct {
	OrgID       string
	WorkspaceID string
	KeyID       string
	Provider    string
	Route       string
}

func (cfg Config) EffectivePIIMode() string {
	mode := strings.ToLower(strings.TrimSpace(cfg.PII.Mode))
	if mode != "" {
		return mode
	}
	if cfg.Tracing.CaptureBodies {
		return PIIModeRedactStorage
	}
	return PIIModeOff
}

func (cfg Config) ResolvePIIPolicy(input PIIScopeInput) PIIConfig {
	resolved := cfg.PII
	resolved.Mode = cfg.EffectivePIIMode()
	if strings.TrimSpace(resolved.PolicyID) == "" {
		resolved.PolicyID = "default/v1"
	}
	if len(cfg.PII.Scopes) == 0 {
		return resolved
	}

	bestIdx := -1
	bestSpecificity := -1
	for idx, scope := range cfg.PII.Scopes {
		if !piiScopeMatches(scope.Match, input) {
			continue
		}
		specificity := piiScopeSpecificity(scope.Match)
		if specificity > bestSpecificity {
			bestSpecificity = specificity
			bestIdx = idx
		}
	}
	if bestIdx < 0 {
		return resolved
	}

	scope := cfg.PII.Scopes[bestIdx]
	if mode := strings.ToLower(strings.TrimSpace(scope.Mode)); mode != "" {
		resolved.Mode = mode
	}
	if policyID := strings.TrimSpace(scope.PolicyID); policyID != "" {
		resolved.PolicyID = policyID
	}

	return resolved
}

func piiScopeMatches(match PIIScopeMatchConfig, input PIIScopeInput) bool {
	if expected := strings.TrimSpace(match.OrgID); expected != "" && strings.TrimSpace(input.OrgID) != expected {
		return false
	}
	if expected := strings.TrimSpace(match.WorkspaceID); expected != "" && strings.TrimSpace(input.WorkspaceID) != expected {
		return false
	}
	if expected := strings.TrimSpace(match.KeyID); expected != "" && strings.TrimSpace(input.KeyID) != expected {
		return false
	}
	if expected := strings.ToLower(strings.TrimSpace(match.Provider)); expected != "" {
		if strings.ToLower(strings.TrimSpace(input.Provider)) != expected {
			return false
		}
	}
	if prefix := strings.TrimSpace(match.RoutePrefix); prefix != "" {
		if !pathutil.HasPathPrefix(input.Route, prefix) {
			return false
		}
	}
	return true
}

func piiScopeSpecificity(match PIIScopeMatchConfig) int {
	score := 0
	if strings.TrimSpace(match.OrgID) != "" {
		score++
	}
	if strings.TrimSpace(match.WorkspaceID) != "" {
		score++
	}
	if strings.TrimSpace(match.KeyID) != "" {
		score++
	}
	if strings.TrimSpace(match.Provider) != "" {
		score++
	}
	if strings.TrimSpace(match.RoutePrefix) != "" {
		score++
	}
	return score
}

type AuthConfig struct {
	Enabled bool               `yaml:"enabled"`
	Header  string             `yaml:"header"`
	Keys    []GatewayKeyConfig `yaml:"keys"`
}

type LimitsConfig struct {
	PerKey       UsageLimitConfig `yaml:"per_key"`
	PerWorkspace UsageLimitConfig `yaml:"per_workspace"`
}

type UsageLimitConfig struct {
	RequestsPerMinute int     `yaml:"requests_per_minute"`
	MaxTokensPerDay   int64   `yaml:"max_tokens_per_day"`
	MaxCostUSDPerDay  float64 `yaml:"max_cost_usd_per_day"`
}

type GatewayKeyConfig struct {
	ID          string   `yaml:"id"`
	Token       string   `yaml:"token"`
	OrgID       string   `yaml:"org_id"`
	WorkspaceID string   `yaml:"workspace_id"`
	Team        string   `yaml:"team"` // Backward-compatible alias for workspace_id.
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	CreatedBy   string   `yaml:"created_by"`
	Role        string   `yaml:"role"`
	Permissions []string `yaml:"permissions"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Storage: StorageConfig{
			Driver: "sqlite",
			Path:   "./data/ongoingai.db",
		},
		Providers: ProvidersConfig{
			OpenAI: ProviderConfig{
				Upstream: "https://api.openai.com",
				Prefix:   "/openai",
			},
			Anthropic: ProviderConfig{
				Upstream: "https://api.anthropic.com",
				Prefix:   "/anthropic",
			},
		},
		Tracing: TracingConfig{
			CaptureBodies: false,
			BodyMaxSize:   1 << 20,
		},
		Observability: ObservabilityConfig{
			OTel: OTelConfig{
				Enabled:                false,
				Endpoint:               defaultOTELEndpoint,
				Insecure:               true,
				ServiceName:            defaultOTELServiceName,
				TracesEnabled:          true,
				MetricsEnabled:         true,
				SamplingRatio:          defaultOTELSamplingRatio,
				ExportTimeoutMS:        defaultOTELExportTimeoutMS,
				MetricExportIntervalMS: defaultOTELMetricExportIntervalMS,
			},
		},
		PII: PIIConfig{
			PolicyID: "default/v1",
			Stages: PIIStagesConfig{
				RequestHeaders:  true,
				RequestBody:     true,
				ResponseHeaders: true,
				ResponseBody:    true,
			},
			Detectors: PIIDetectorsConfig{
				Email:     true,
				Phone:     true,
				SSN:       true,
				TokenLike: true,
			},
			Headers: PIIHeadersConfig{
				Denylist: []string{
					"authorization",
					"cookie",
					"set-cookie",
					"x-api-key",
					"x-ongoingai-gateway-key",
				},
			},
			Body: PIIBodyConfig{
				KeyDenylist: []string{
					"email",
					"phone",
					"password",
					"token",
					"secret",
					"ssn",
					"api_key",
					"authorization",
				},
			},
			Replacement: PIIReplacementConfig{
				Format: "[{type}_REDACTED:{hash}]",
			},
		},
		Auth: AuthConfig{
			Enabled: false,
			Header:  "X-OngoingAI-Gateway-Key",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			decoder := yaml.NewDecoder(bytes.NewReader(data))
			decoder.KnownFields(true)
			decodeErr := decoder.Decode(&cfg)
			if errors.Is(decodeErr, io.EOF) {
				decodeErr = nil
			}
			if decodeErr != nil {
				return Config{}, fmt.Errorf("parse yaml %q: %w", path, decodeErr)
			}
			// Reject multi-document configs to keep runtime configuration
			// unambiguous and avoid hidden trailing documents.
			var trailing any
			trailingErr := decoder.Decode(&trailing)
			if trailingErr != nil && !errors.Is(trailingErr, io.EOF) {
				return Config{}, fmt.Errorf("parse yaml %q: %w", path, trailingErr)
			}
			if trailing != nil {
				return Config{}, fmt.Errorf("parse yaml %q: multiple yaml documents are not supported", path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate checks configuration invariants required at runtime.
func Validate(cfg Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535 (got %d)", cfg.Server.Port)
	}

	driver := strings.TrimSpace(cfg.Storage.Driver)
	switch driver {
	case "sqlite":
		if strings.TrimSpace(cfg.Storage.Path) == "" {
			return errors.New("storage.path is required when storage.driver=sqlite")
		}
	case "postgres":
		if strings.TrimSpace(cfg.Storage.DSN) == "" {
			return errors.New("storage.dsn is required when storage.driver=postgres")
		}
	default:
		return fmt.Errorf("storage.driver must be one of sqlite, postgres (got %q)", cfg.Storage.Driver)
	}

	if err := validateProvider("providers.openai", cfg.Providers.OpenAI); err != nil {
		return err
	}
	if err := validateProvider("providers.anthropic", cfg.Providers.Anthropic); err != nil {
		return err
	}

	if strings.TrimSpace(cfg.Auth.Header) == "" {
		return errors.New("auth.header must not be empty")
	}

	switch mode := cfg.EffectivePIIMode(); mode {
	case PIIModeOff, PIIModeRedactStorage, PIIModeRedactUpstream, PIIModeBlock:
	default:
		return fmt.Errorf("pii.mode must be one of off, redact_storage, redact_upstream, block (got %q)", cfg.PII.Mode)
	}
	if err := validatePIIScopes(cfg.PII.Scopes); err != nil {
		return err
	}
	if err := validateOTelConfig(cfg.Observability.OTel); err != nil {
		return err
	}

	return nil
}

func validatePIIScopes(scopes []PIIScopeConfig) error {
	for idx, scope := range scopes {
		name := fmt.Sprintf("pii.scopes[%d]", idx)
		if piiScopeSpecificity(scope.Match) == 0 {
			return fmt.Errorf("%s.match must set at least one selector: org_id, workspace_id, key_id, provider, or route_prefix", name)
		}
		if provider := strings.TrimSpace(scope.Match.Provider); provider != "" {
			normalized := strings.ToLower(provider)
			if normalized != provider {
				return fmt.Errorf("%s.match.provider must be lowercase when set (got %q)", name, scope.Match.Provider)
			}
		}
		if routePrefix := strings.TrimSpace(scope.Match.RoutePrefix); routePrefix != "" && !strings.HasPrefix(routePrefix, "/") {
			return fmt.Errorf("%s.match.route_prefix must start with '/' (got %q)", name, scope.Match.RoutePrefix)
		}
		if mode := strings.ToLower(strings.TrimSpace(scope.Mode)); mode != "" {
			switch mode {
			case PIIModeOff, PIIModeRedactStorage, PIIModeRedactUpstream, PIIModeBlock:
			default:
				return fmt.Errorf("%s.mode must be one of off, redact_storage, redact_upstream, block (got %q)", name, scope.Mode)
			}
		}
	}
	return nil
}

func validateOTelConfig(cfg OTelConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return errors.New("observability.otel.endpoint is required when observability.otel.enabled=true")
	}
	if strings.TrimSpace(cfg.ServiceName) == "" {
		return errors.New("observability.otel.service_name is required when observability.otel.enabled=true")
	}
	if !cfg.TracesEnabled && !cfg.MetricsEnabled {
		return errors.New("observability.otel requires traces_enabled and/or metrics_enabled when enabled")
	}
	if cfg.SamplingRatio < 0 || cfg.SamplingRatio > 1 {
		return fmt.Errorf("observability.otel.sampling_ratio must be between 0 and 1 (got %f)", cfg.SamplingRatio)
	}
	if cfg.ExportTimeoutMS <= 0 {
		return fmt.Errorf("observability.otel.export_timeout_ms must be > 0 (got %d)", cfg.ExportTimeoutMS)
	}
	if cfg.MetricExportIntervalMS <= 0 {
		return fmt.Errorf("observability.otel.metric_export_interval_ms must be > 0 (got %d)", cfg.MetricExportIntervalMS)
	}
	return nil
}

func validateProvider(name string, provider ProviderConfig) error {
	prefix := strings.TrimSpace(provider.Prefix)
	if prefix == "" {
		return fmt.Errorf("%s.prefix is required", name)
	}
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("%s.prefix must start with '/' (got %q)", name, provider.Prefix)
	}

	upstream := strings.TrimSpace(provider.Upstream)
	if upstream == "" {
		return fmt.Errorf("%s.upstream is required", name)
	}
	parsed, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("parse %s.upstream: %w", name, err)
	}
	if strings.TrimSpace(parsed.Scheme) == "" || strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("%s.upstream must include scheme and host (got %q)", name, provider.Upstream)
	}

	return nil
}

func applyEnv(cfg *Config) error {
	if host := os.Getenv("ONGOINGAI_HOST"); host != "" {
		cfg.Server.Host = host
	}

	if port := os.Getenv("ONGOINGAI_PORT"); port != "" {
		v, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("invalid ONGOINGAI_PORT: %w", err)
		}
		cfg.Server.Port = v
	}

	if storageDriver := os.Getenv("ONGOINGAI_STORAGE_DRIVER"); storageDriver != "" {
		cfg.Storage.Driver = storageDriver
	}
	if storagePath := os.Getenv("ONGOINGAI_STORAGE_PATH"); storagePath != "" {
		cfg.Storage.Path = storagePath
	}
	if storageDSN := os.Getenv("ONGOINGAI_STORAGE_DSN"); storageDSN != "" {
		cfg.Storage.DSN = storageDSN
	}

	if openAIUpstream := os.Getenv("ONGOINGAI_OPENAI_UPSTREAM"); openAIUpstream != "" {
		cfg.Providers.OpenAI.Upstream = openAIUpstream
	}
	if anthropicUpstream := os.Getenv("ONGOINGAI_ANTHROPIC_UPSTREAM"); anthropicUpstream != "" {
		cfg.Providers.Anthropic.Upstream = anthropicUpstream
	}

	if captureBodies := os.Getenv("ONGOINGAI_CAPTURE_BODIES"); captureBodies != "" {
		v, err := strconv.ParseBool(captureBodies)
		if err != nil {
			return fmt.Errorf("invalid ONGOINGAI_CAPTURE_BODIES: %w", err)
		}
		cfg.Tracing.CaptureBodies = v
	}

	if bodyMaxSize := os.Getenv("ONGOINGAI_BODY_MAX_SIZE"); bodyMaxSize != "" {
		v, err := strconv.Atoi(bodyMaxSize)
		if err != nil {
			return fmt.Errorf("invalid ONGOINGAI_BODY_MAX_SIZE: %w", err)
		}
		cfg.Tracing.BodyMaxSize = v
	}
	otelConfigured := false
	otelSDKDisabledSet := false
	if sdkDisabled := strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")); sdkDisabled != "" {
		v, err := strconv.ParseBool(sdkDisabled)
		if err != nil {
			return fmt.Errorf("invalid OTEL_SDK_DISABLED: %w", err)
		}
		cfg.Observability.OTel.Enabled = !v
		otelSDKDisabledSet = true
		otelConfigured = true
	}
	if endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); endpoint != "" {
		cfg.Observability.OTel.Endpoint = endpoint
		otelConfigured = true
	}
	if insecure := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_INSECURE")); insecure != "" {
		v, err := strconv.ParseBool(insecure)
		if err != nil {
			return fmt.Errorf("invalid OTEL_EXPORTER_OTLP_INSECURE: %w", err)
		}
		cfg.Observability.OTel.Insecure = v
		otelConfigured = true
	}
	if serviceName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); serviceName != "" {
		cfg.Observability.OTel.ServiceName = serviceName
		otelConfigured = true
	}
	if tracesExporter := strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")); tracesExporter != "" {
		enabled, err := otelExporterEnabled(tracesExporter)
		if err != nil {
			return fmt.Errorf("invalid OTEL_TRACES_EXPORTER: %w", err)
		}
		cfg.Observability.OTel.TracesEnabled = enabled
		otelConfigured = true
	}
	if metricsExporter := strings.TrimSpace(os.Getenv("OTEL_METRICS_EXPORTER")); metricsExporter != "" {
		enabled, err := otelExporterEnabled(metricsExporter)
		if err != nil {
			return fmt.Errorf("invalid OTEL_METRICS_EXPORTER: %w", err)
		}
		cfg.Observability.OTel.MetricsEnabled = enabled
		otelConfigured = true
	}
	if samplingRatio := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")); samplingRatio != "" {
		v, err := strconv.ParseFloat(samplingRatio, 64)
		if err != nil {
			return fmt.Errorf("invalid OTEL_TRACES_SAMPLER_ARG: %w", err)
		}
		cfg.Observability.OTel.SamplingRatio = v
		otelConfigured = true
	}
	if exportTimeout := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TIMEOUT")); exportTimeout != "" {
		v, err := strconv.Atoi(exportTimeout)
		if err != nil {
			return fmt.Errorf("invalid OTEL_EXPORTER_OTLP_TIMEOUT: %w", err)
		}
		cfg.Observability.OTel.ExportTimeoutMS = v
		otelConfigured = true
	}
	if metricExportInterval := strings.TrimSpace(os.Getenv("OTEL_METRIC_EXPORT_INTERVAL")); metricExportInterval != "" {
		v, err := strconv.Atoi(metricExportInterval)
		if err != nil {
			return fmt.Errorf("invalid OTEL_METRIC_EXPORT_INTERVAL: %w", err)
		}
		cfg.Observability.OTel.MetricExportIntervalMS = v
		otelConfigured = true
	}
	if otelConfigured && !otelSDKDisabledSet {
		cfg.Observability.OTel.Enabled = true
	}

	if piiMode := os.Getenv("ONGOINGAI_PII_MODE"); piiMode != "" {
		cfg.PII.Mode = piiMode
	}
	if piiPolicyID := os.Getenv("ONGOINGAI_PII_POLICY_ID"); piiPolicyID != "" {
		cfg.PII.PolicyID = piiPolicyID
	}
	if piiHashSalt := os.Getenv("ONGOINGAI_PII_HASH_SALT"); piiHashSalt != "" {
		cfg.PII.Replacement.HashSalt = piiHashSalt
	}

	if authEnabled := os.Getenv("ONGOINGAI_AUTH_ENABLED"); authEnabled != "" {
		v, err := strconv.ParseBool(authEnabled)
		if err != nil {
			return fmt.Errorf("invalid ONGOINGAI_AUTH_ENABLED: %w", err)
		}
		cfg.Auth.Enabled = v
	}
	if authHeader := os.Getenv("ONGOINGAI_AUTH_HEADER"); authHeader != "" {
		cfg.Auth.Header = authHeader
	}

	return nil
}

func otelExporterEnabled(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "otlp":
		return true, nil
	case "none":
		return false, nil
	default:
		return false, fmt.Errorf("must be one of otlp, none (got %q)", value)
	}
}
