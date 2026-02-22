package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Fatalf("server.host=%q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.Port != 8080 {
		t.Fatalf("server.port=%d, want 8080", cfg.Server.Port)
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Fatalf("storage.driver=%q, want sqlite", cfg.Storage.Driver)
	}
	if cfg.Tracing.CaptureBodies {
		t.Fatalf("tracing.capture_bodies=%v, want false", cfg.Tracing.CaptureBodies)
	}
	if cfg.Observability.OTel.Enabled {
		t.Fatalf("observability.otel.enabled=%v, want false", cfg.Observability.OTel.Enabled)
	}
	if cfg.Observability.OTel.Endpoint != "localhost:4318" {
		t.Fatalf("observability.otel.endpoint=%q, want %q", cfg.Observability.OTel.Endpoint, "localhost:4318")
	}
	if cfg.Observability.OTel.ServiceName != "ongoingai-gateway" {
		t.Fatalf("observability.otel.service_name=%q, want %q", cfg.Observability.OTel.ServiceName, "ongoingai-gateway")
	}
	if cfg.Auth.Enabled {
		t.Fatalf("auth.enabled=%v, want false", cfg.Auth.Enabled)
	}
	if cfg.Auth.Header != "X-OngoingAI-Gateway-Key" {
		t.Fatalf("auth.header=%q, want X-OngoingAI-Gateway-Key", cfg.Auth.Header)
	}
	if cfg.EffectivePIIMode() != PIIModeOff {
		t.Fatalf("pii mode=%q, want %q", cfg.EffectivePIIMode(), PIIModeOff)
	}
	if got := cfg.PII.Replacement.Format; got != "[{type}_REDACTED:{hash}]" {
		t.Fatalf("pii.replacement.format=%q, want default placeholder format", got)
	}
	if cfg.Server.Address() != "0.0.0.0:8080" {
		t.Fatalf("server address=%q, want 0.0.0.0:8080", cfg.Server.Address())
	}
}

func TestLoadAppliesYAMLAndEnvOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "ongoingai.yaml")
	configYAML := `server:
  host: 127.0.0.1
  port: 9090
storage:
  driver: sqlite
  path: /tmp/custom.db
providers:
  openai:
    upstream: https://example-openai.local
    prefix: /oa
  anthropic:
    upstream: https://example-anthropic.local
    prefix: /anth
tracing:
  capture_bodies: false
  body_max_size: 12345
observability:
  otel:
    enabled: false
    endpoint: localhost:4318
    insecure: true
    service_name: yaml-gateway
    traces_enabled: true
    metrics_enabled: true
    sampling_ratio: 0.25
    export_timeout_ms: 2000
    metric_export_interval_ms: 15000
pii:
  mode: off
  policy_id: yaml-policy
  replacement:
    hash_salt: yaml-salt
auth:
  enabled: false
  header: X-Test-Gateway-Key
  keys:
    - id: team-a-dev-1
      token: gwk-test
      org_id: org-a
      workspace_id: workspace-a
      role: developer
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("ONGOINGAI_PORT", "7070")
	t.Setenv("ONGOINGAI_CAPTURE_BODIES", "true")
	t.Setenv("ONGOINGAI_OPENAI_UPSTREAM", "https://api.openai.com")
	t.Setenv("ONGOINGAI_AUTH_ENABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4318")
	t.Setenv("OTEL_SERVICE_NAME", "env-gateway")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.75")
	t.Setenv("ONGOINGAI_PII_MODE", "redact_storage")
	t.Setenv("ONGOINGAI_PII_POLICY_ID", "env-policy")
	t.Setenv("ONGOINGAI_PII_HASH_SALT", "env-salt")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Fatalf("server.host=%q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 7070 {
		t.Fatalf("server.port=%d, want 7070 (env override)", cfg.Server.Port)
	}
	if cfg.Tracing.CaptureBodies != true {
		t.Fatalf("capture_bodies=%v, want true (env override)", cfg.Tracing.CaptureBodies)
	}
	if cfg.Providers.OpenAI.Upstream != "https://api.openai.com" {
		t.Fatalf("openai.upstream=%q, want env override", cfg.Providers.OpenAI.Upstream)
	}
	if cfg.Providers.Anthropic.Upstream != "https://example-anthropic.local" {
		t.Fatalf("anthropic.upstream=%q, want yaml value", cfg.Providers.Anthropic.Upstream)
	}
	if !cfg.Observability.OTel.Enabled {
		t.Fatalf("observability.otel.enabled=%v, want true (env override)", cfg.Observability.OTel.Enabled)
	}
	if cfg.Observability.OTel.Endpoint != "collector:4318" {
		t.Fatalf("observability.otel.endpoint=%q, want env override", cfg.Observability.OTel.Endpoint)
	}
	if cfg.Observability.OTel.ServiceName != "env-gateway" {
		t.Fatalf("observability.otel.service_name=%q, want env override", cfg.Observability.OTel.ServiceName)
	}
	if cfg.Observability.OTel.SamplingRatio != 0.75 {
		t.Fatalf("observability.otel.sampling_ratio=%v, want env override", cfg.Observability.OTel.SamplingRatio)
	}
	if !cfg.Auth.Enabled {
		t.Fatalf("auth.enabled=%v, want true (env override)", cfg.Auth.Enabled)
	}
	if cfg.EffectivePIIMode() != PIIModeRedactStorage {
		t.Fatalf("pii mode=%q, want %q", cfg.EffectivePIIMode(), PIIModeRedactStorage)
	}
	if cfg.PII.PolicyID != "env-policy" {
		t.Fatalf("pii.policy_id=%q, want env-policy", cfg.PII.PolicyID)
	}
	if cfg.PII.Replacement.HashSalt != "env-salt" {
		t.Fatalf("pii.replacement.hash_salt=%q, want env-salt", cfg.PII.Replacement.HashSalt)
	}
	if cfg.Auth.Header != "X-Test-Gateway-Key" {
		t.Fatalf("auth.header=%q, want yaml value", cfg.Auth.Header)
	}
	if len(cfg.Auth.Keys) != 1 {
		t.Fatalf("auth.keys len=%d, want 1", len(cfg.Auth.Keys))
	}
	if cfg.Auth.Keys[0].OrgID != "org-a" || cfg.Auth.Keys[0].WorkspaceID != "workspace-a" {
		t.Fatalf("auth key org/workspace=%s/%s, want org-a/workspace-a", cfg.Auth.Keys[0].OrgID, cfg.Auth.Keys[0].WorkspaceID)
	}
}

func TestLoadInvalidYAMLReturnsError(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(configPath, []byte("server: ["), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatalf("Load() error=nil, want parse error")
	}
	if !strings.Contains(err.Error(), "parse yaml") {
		t.Fatalf("error=%q, want parse yaml message", err.Error())
	}
}

func TestLoadRejectsUnknownYAMLField(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "invalid-field.yaml")
	configYAML := `auth:
  enabled: true
  header: X-OngoingAI-Gateway-Key
  unexpected_field: true
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatalf("Load() error=nil, want unknown-field parse error")
	}
	if !strings.Contains(err.Error(), "field unexpected_field not found") {
		t.Fatalf("error=%q, want unknown-field message", err.Error())
	}
}

func TestLoadRejectsMultiDocumentYAML(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "multi-doc.yaml")
	configYAML := `server:
  host: 127.0.0.1
---
auth:
  enabled: true
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatalf("Load() error=nil, want multi-document parse error")
	}
	if !strings.Contains(err.Error(), "multiple yaml documents are not supported") {
		t.Fatalf("error=%q, want multi-document message", err.Error())
	}
}

func TestLoadInvalidEnvReturnsError(t *testing.T) {
	t.Setenv("ONGOINGAI_PORT", "not-a-number")

	_, err := Load("")
	if err == nil {
		t.Fatalf("Load() error=nil, want invalid env error")
	}
	if !strings.Contains(err.Error(), "invalid ONGOINGAI_PORT") {
		t.Fatalf("error=%q, want ONGOINGAI_PORT validation message", err.Error())
	}
}

func TestLoadInvalidOTELEnvReturnsError(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "not-a-number")

	_, err := Load("")
	if err == nil {
		t.Fatalf("Load() error=nil, want invalid env error")
	}
	if !strings.Contains(err.Error(), "invalid OTEL_TRACES_SAMPLER_ARG") {
		t.Fatalf("error=%q, want OTEL_TRACES_SAMPLER_ARG validation message", err.Error())
	}
}

func TestLoadAppliesStandardOTELEnvOverrides(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel-collector:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "false")
	t.Setenv("OTEL_SERVICE_NAME", "otel-service-name")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.35")
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	t.Setenv("OTEL_METRICS_EXPORTER", "otlp")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !cfg.Observability.OTel.Enabled {
		t.Fatalf("observability.otel.enabled=%v, want true when OTEL_* vars are configured", cfg.Observability.OTel.Enabled)
	}
	if cfg.Observability.OTel.Endpoint != "https://otel-collector:4318" {
		t.Fatalf("observability.otel.endpoint=%q, want OTEL_EXPORTER_OTLP_ENDPOINT override", cfg.Observability.OTel.Endpoint)
	}
	if cfg.Observability.OTel.Insecure {
		t.Fatalf("observability.otel.insecure=%v, want false from OTEL_EXPORTER_OTLP_INSECURE", cfg.Observability.OTel.Insecure)
	}
	if cfg.Observability.OTel.ServiceName != "otel-service-name" {
		t.Fatalf("observability.otel.service_name=%q, want OTEL_SERVICE_NAME fallback", cfg.Observability.OTel.ServiceName)
	}
	if cfg.Observability.OTel.SamplingRatio != 0.35 {
		t.Fatalf("observability.otel.sampling_ratio=%v, want OTEL_TRACES_SAMPLER_ARG fallback", cfg.Observability.OTel.SamplingRatio)
	}
	if cfg.Observability.OTel.TracesEnabled {
		t.Fatalf("observability.otel.traces_enabled=%v, want false from OTEL_TRACES_EXPORTER=none", cfg.Observability.OTel.TracesEnabled)
	}
	if !cfg.Observability.OTel.MetricsEnabled {
		t.Fatalf("observability.otel.metrics_enabled=%v, want true from OTEL_METRICS_EXPORTER=otlp", cfg.Observability.OTel.MetricsEnabled)
	}
}

func TestLoadAppliesOTELSDKDisabledOverride(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4318")
	t.Setenv("OTEL_SDK_DISABLED", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Observability.OTel.Enabled {
		t.Fatalf("observability.otel.enabled=%v, want false from OTEL_SDK_DISABLED=true", cfg.Observability.OTel.Enabled)
	}
}

func TestLoadRejectsInvalidStandardOTELExporterEnv(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "zipkin")

	_, err := Load("")
	if err == nil {
		t.Fatalf("Load() error=nil, want OTEL_TRACES_EXPORTER validation error")
	}
	if !strings.Contains(err.Error(), "invalid OTEL_TRACES_EXPORTER") {
		t.Fatalf("error=%q, want OTEL_TRACES_EXPORTER validation message", err.Error())
	}
}

func TestValidateDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate(default) error: %v", err)
	}
}

func TestValidateRequiresPostgresDSN(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Storage.Driver = "postgres"
	cfg.Storage.DSN = ""

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want postgres dsn validation error")
	}
	if !strings.Contains(err.Error(), "storage.dsn is required") {
		t.Fatalf("error=%q, want storage.dsn validation message", err.Error())
	}
}

func TestValidateRejectsProviderPrefixWithoutSlash(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Providers.OpenAI.Prefix = "openai"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want provider prefix validation error")
	}
	if !strings.Contains(err.Error(), "providers.openai.prefix must start with '/'") {
		t.Fatalf("error=%q, want provider prefix validation message", err.Error())
	}
}

func TestValidateRejectsInvalidPIIMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.PII.Mode = "unknown"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want pii.mode validation error")
	}
	if !strings.Contains(err.Error(), "pii.mode must be one of") {
		t.Fatalf("error=%q, want pii.mode validation message", err.Error())
	}
}

func TestEffectivePIIModeDefaultsToRedactStorageWhenBodyCaptureEnabled(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Tracing.CaptureBodies = true
	cfg.PII.Mode = ""

	if got := cfg.EffectivePIIMode(); got != PIIModeRedactStorage {
		t.Fatalf("EffectivePIIMode()=%q, want %q", got, PIIModeRedactStorage)
	}
}

func TestValidateAcceptsSupportedPIIModes(t *testing.T) {
	t.Parallel()

	cases := []string{PIIModeOff, PIIModeRedactStorage, PIIModeRedactUpstream, PIIModeBlock}
	for _, mode := range cases {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			cfg := Default()
			cfg.PII.Mode = mode

			if err := Validate(cfg); err != nil {
				t.Fatalf("Validate() error=%v, want nil for supported mode %q", err, mode)
			}
		})
	}
}

func TestResolvePIIPolicyDefaultsWithoutMatchingScope(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.PII.Mode = PIIModeOff
	cfg.PII.PolicyID = "global/v1"
	cfg.PII.Scopes = []PIIScopeConfig{
		{
			Match: PIIScopeMatchConfig{
				WorkspaceID: "workspace-a",
				Provider:    "openai",
			},
			Mode:     PIIModeBlock,
			PolicyID: "workspace-a/v1",
		},
	}

	policy := cfg.ResolvePIIPolicy(PIIScopeInput{
		WorkspaceID: "workspace-b",
		Provider:    "openai",
		Route:       "/openai/v1/chat/completions",
	})
	if policy.Mode != PIIModeOff {
		t.Fatalf("resolved mode=%q, want %q", policy.Mode, PIIModeOff)
	}
	if policy.PolicyID != "global/v1" {
		t.Fatalf("resolved policy_id=%q, want %q", policy.PolicyID, "global/v1")
	}
}

func TestResolvePIIPolicyAppliesMostSpecificMatchingScope(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.PII.Mode = PIIModeRedactStorage
	cfg.PII.PolicyID = "default/v1"
	cfg.PII.Scopes = []PIIScopeConfig{
		{
			Match: PIIScopeMatchConfig{
				Provider:    "openai",
				RoutePrefix: "/openai",
			},
			Mode:     PIIModeBlock,
			PolicyID: "provider/v1",
		},
		{
			Match: PIIScopeMatchConfig{
				OrgID:       "org-a",
				WorkspaceID: "workspace-a",
				KeyID:       "key-a",
				Provider:    "openai",
				RoutePrefix: "/openai/v1/chat",
			},
			Mode:     PIIModeRedactUpstream,
			PolicyID: "strict-key/v1",
		},
	}

	policy := cfg.ResolvePIIPolicy(PIIScopeInput{
		OrgID:       "org-a",
		WorkspaceID: "workspace-a",
		KeyID:       "key-a",
		Provider:    "openai",
		Route:       "/openai/v1/chat/completions",
	})
	if policy.Mode != PIIModeRedactUpstream {
		t.Fatalf("resolved mode=%q, want %q", policy.Mode, PIIModeRedactUpstream)
	}
	if policy.PolicyID != "strict-key/v1" {
		t.Fatalf("resolved policy_id=%q, want %q", policy.PolicyID, "strict-key/v1")
	}
}

func TestValidateRejectsPIIScopeWithoutSelectors(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.PII.Scopes = []PIIScopeConfig{
		{Mode: PIIModeBlock},
	}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want scope selector validation error")
	}
	if !strings.Contains(err.Error(), "pii.scopes[0].match must set at least one selector") {
		t.Fatalf("error=%q, want scope selector validation message", err.Error())
	}
}

func TestValidateRejectsPIIScopeInvalidRoutePrefix(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.PII.Scopes = []PIIScopeConfig{
		{
			Match: PIIScopeMatchConfig{
				RoutePrefix: "openai/v1",
			},
			Mode: PIIModeBlock,
		},
	}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want route prefix validation error")
	}
	if !strings.Contains(err.Error(), "pii.scopes[0].match.route_prefix must start with '/'") {
		t.Fatalf("error=%q, want route prefix validation message", err.Error())
	}
}

func TestValidateRejectsPIIScopeInvalidMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.PII.Scopes = []PIIScopeConfig{
		{
			Match: PIIScopeMatchConfig{
				WorkspaceID: "workspace-a",
			},
			Mode: "invalid-mode",
		},
	}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want scope mode validation error")
	}
	if !strings.Contains(err.Error(), "pii.scopes[0].mode must be one of") {
		t.Fatalf("error=%q, want scope mode validation message", err.Error())
	}
}

func TestValidateRejectsPIIScopeUppercaseProvider(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.PII.Scopes = []PIIScopeConfig{
		{
			Match: PIIScopeMatchConfig{
				Provider: "OpenAI",
			},
			Mode: PIIModeBlock,
		},
	}

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want scope provider validation error")
	}
	if !strings.Contains(err.Error(), "pii.scopes[0].match.provider must be lowercase") {
		t.Fatalf("error=%q, want lowercase provider validation message", err.Error())
	}
}

func TestValidateRejectsInvalidOTelSamplingRatio(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Observability.OTel.Enabled = true
	cfg.Observability.OTel.SamplingRatio = 1.5

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want observability.otel.sampling_ratio validation error")
	}
	if !strings.Contains(err.Error(), "observability.otel.sampling_ratio") {
		t.Fatalf("error=%q, want sampling ratio validation message", err.Error())
	}
}

func TestValidateRejectsOTelEnabledWithoutSignals(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Observability.OTel.Enabled = true
	cfg.Observability.OTel.TracesEnabled = false
	cfg.Observability.OTel.MetricsEnabled = false
	cfg.Observability.OTel.PrometheusEnabled = false

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want observability.otel traces/metrics validation error")
	}
	if !strings.Contains(err.Error(), "observability.otel requires") {
		t.Fatalf("error=%q, want signal validation message", err.Error())
	}
}

func TestValidateRejectsOTelEnabledWithoutEndpoint(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Observability.OTel.Enabled = true
	cfg.Observability.OTel.Endpoint = ""

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want observability.otel.endpoint validation error")
	}
	if !strings.Contains(err.Error(), "observability.otel.endpoint is required") {
		t.Fatalf("error=%q, want endpoint validation message", err.Error())
	}
}

func TestDefaultPrometheusConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if cfg.Observability.OTel.PrometheusEnabled {
		t.Fatal("default prometheus_enabled should be false")
	}
	if cfg.Observability.OTel.PrometheusPath != "/metrics" {
		t.Fatalf("default prometheus_path=%q, want /metrics", cfg.Observability.OTel.PrometheusPath)
	}
}

func TestValidateAcceptsPrometheusOnlyConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Observability.OTel.Enabled = true
	cfg.Observability.OTel.TracesEnabled = false
	cfg.Observability.OTel.MetricsEnabled = false
	cfg.Observability.OTel.PrometheusEnabled = true

	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate() error=%v, want nil for prometheus-only config", err)
	}
}

func TestValidateRejectsPrometheusPathWithoutSlash(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Observability.OTel.Enabled = true
	cfg.Observability.OTel.PrometheusEnabled = true
	cfg.Observability.OTel.PrometheusPath = "metrics"

	err := Validate(cfg)
	if err == nil {
		t.Fatal("Validate() error=nil, want prometheus_path validation error")
	}
	if !strings.Contains(err.Error(), "prometheus_path must start with '/'") {
		t.Fatalf("error=%q, want prometheus_path validation message", err.Error())
	}
}

func TestValidateRejectsPrometheusPathCollidingWithReservedPrefixes(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/api/metrics", "/openai/metrics", "/anthropic/metrics"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			cfg := Default()
			cfg.Observability.OTel.Enabled = true
			cfg.Observability.OTel.PrometheusEnabled = true
			cfg.Observability.OTel.PrometheusPath = path

			err := Validate(cfg)
			if err == nil {
				t.Fatalf("Validate() error=nil, want prometheus_path collision error for %q", path)
			}
			if !strings.Contains(err.Error(), "must not overlap") {
				t.Fatalf("error=%q, want overlap validation message", err.Error())
			}
		})
	}
}

func TestLoadPrometheusEnvOverrides(t *testing.T) {
	t.Setenv("ONGOINGAI_PROMETHEUS_ENABLED", "true")
	t.Setenv("ONGOINGAI_PROMETHEUS_PATH", "/prom")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !cfg.Observability.OTel.PrometheusEnabled {
		t.Fatal("prometheus_enabled should be true from env override")
	}
	if cfg.Observability.OTel.PrometheusPath != "/prom" {
		t.Fatalf("prometheus_path=%q, want /prom from env override", cfg.Observability.OTel.PrometheusPath)
	}
	if !cfg.Observability.OTel.Enabled {
		t.Fatal("otel.enabled should be true when prometheus env is configured")
	}
}

func TestLoadMetricsExporterPrometheusEnv(t *testing.T) {
	t.Setenv("OTEL_METRICS_EXPORTER", "prometheus")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !cfg.Observability.OTel.PrometheusEnabled {
		t.Fatal("prometheus_enabled should be true from OTEL_METRICS_EXPORTER=prometheus")
	}
	if cfg.Observability.OTel.MetricsEnabled {
		t.Fatal("metrics_enabled should be false when OTEL_METRICS_EXPORTER=prometheus")
	}
	if !cfg.Observability.OTel.Enabled {
		t.Fatal("otel.enabled should be true when OTEL_METRICS_EXPORTER is configured")
	}
}
