package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDoctorPassesWithValidAuthConfig(t *testing.T) {
	t.Parallel()

	configPath := writeDoctorTestConfig(t, doctorTestConfigOptions{
		authEnabled: true,
		includeKey:  true,
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDoctor() code=%d, want 0 (stderr=%q)", code, stderr.String())
	}
	body := stdout.String()
	if !strings.Contains(body, "OngoingAI Doctor") {
		t.Fatalf("stdout=%q, want doctor header", body)
	}
	if !strings.Contains(body, "Overall status") || !strings.Contains(body, "PASS") {
		t.Fatalf("stdout=%q, want overall PASS status", body)
	}
	if !strings.Contains(body, "[PASS] route_wiring") || !strings.Contains(body, "[PASS] auth_posture") {
		t.Fatalf("stdout=%q, want route/auth pass checks", body)
	}
}

func TestRunDoctorWarnsWhenAuthDisabled(t *testing.T) {
	t.Parallel()

	configPath := writeDoctorTestConfig(t, doctorTestConfigOptions{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDoctor() code=%d, want 0 (stderr=%q)", code, stderr.String())
	}
	body := stdout.String()
	if !strings.Contains(body, "Overall status") || !strings.Contains(body, "WARN") {
		t.Fatalf("stdout=%q, want overall WARN status", body)
	}
	if !strings.Contains(body, "[WARN] auth_posture") {
		t.Fatalf("stdout=%q, want auth warning", body)
	}
	if !strings.Contains(body, "auth.enabled=false") {
		t.Fatalf("stdout=%q, want disabled auth detail", body)
	}
}

func TestRunDoctorFailsWhenProviderPrefixOverlapsAPI(t *testing.T) {
	t.Parallel()

	configPath := writeDoctorTestConfig(t, doctorTestConfigOptions{
		openAIPrefix: "/api",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"--config", configPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDoctor() code=%d, want 1", code)
	}
	body := stdout.String()
	if !strings.Contains(body, "[FAIL] route_wiring") {
		t.Fatalf("stdout=%q, want route wiring failure", body)
	}
	if !strings.Contains(body, "must not overlap with /api routes") {
		t.Fatalf("stdout=%q, want route overlap detail", body)
	}
}

func TestRunDoctorFailsWhenAuthEnabledWithoutKeys(t *testing.T) {
	t.Parallel()

	configPath := writeDoctorTestConfig(t, doctorTestConfigOptions{
		authEnabled: true,
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"--config", configPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDoctor() code=%d, want 1", code)
	}
	body := stdout.String()
	if !strings.Contains(body, "[FAIL] auth_posture") {
		t.Fatalf("stdout=%q, want auth posture failure", body)
	}
	if !strings.Contains(body, "no gateway keys are configured") {
		t.Fatalf("stdout=%q, want missing key detail", body)
	}
}

func TestRunDoctorFailsWhenAuthHeaderConflictsWithProviderCredential(t *testing.T) {
	t.Parallel()

	configPath := writeDoctorTestConfig(t, doctorTestConfigOptions{
		authEnabled: true,
		includeKey:  true,
		authHeader:  "Authorization",
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"--config", configPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runDoctor() code=%d, want 1", code)
	}
	body := stdout.String()
	if !strings.Contains(body, "[FAIL] auth_posture") {
		t.Fatalf("stdout=%q, want auth posture failure", body)
	}
	if !strings.Contains(body, "conflicts with Authorization/X-API-Key") {
		t.Fatalf("stdout=%q, want conflicting header detail", body)
	}
}

func TestRunDoctorJSONOutput(t *testing.T) {
	t.Parallel()

	configPath := writeDoctorTestConfig(t, doctorTestConfigOptions{
		authEnabled: true,
		includeKey:  true,
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"--config", configPath, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDoctor() code=%d, want 0 (stderr=%q)", code, stderr.String())
	}

	var payload doctorDocument
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode doctor json: %v\nbody=%s", err, stdout.String())
	}
	if payload.OverallStatus != doctorStatusPass {
		t.Fatalf("overall_status=%q, want %q", payload.OverallStatus, doctorStatusPass)
	}
	if len(payload.Checks) != 4 {
		t.Fatalf("check_count=%d, want 4", len(payload.Checks))
	}
	got := map[string]string{}
	for _, check := range payload.Checks {
		got[check.Name] = check.Status
	}
	if got["config"] != doctorStatusPass || got["storage"] != doctorStatusPass || got["route_wiring"] != doctorStatusPass || got["auth_posture"] != doctorStatusPass {
		t.Fatalf("check statuses=%v, want all pass", got)
	}
}

func TestRunDoctorRejectsInvalidFormat(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"--format", "yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runDoctor() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "expected text or json") {
		t.Fatalf("stderr=%q, want invalid format message", stderr.String())
	}
}

func TestRunDoctorRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor([]string{"extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runDoctor() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%q, want positional argument message", stderr.String())
	}
}

type doctorTestConfigOptions struct {
	openAIPrefix    string
	anthropicPrefix string
	authEnabled     bool
	includeKey      bool
	authHeader      string
}

func writeDoctorTestConfig(t *testing.T, options doctorTestConfigOptions) string {
	t.Helper()

	openAIPrefix := options.openAIPrefix
	if strings.TrimSpace(openAIPrefix) == "" {
		openAIPrefix = "/openai"
	}
	anthropicPrefix := options.anthropicPrefix
	if strings.TrimSpace(anthropicPrefix) == "" {
		anthropicPrefix = "/anthropic"
	}
	authHeader := strings.TrimSpace(options.authHeader)
	if authHeader == "" {
		authHeader = "X-OngoingAI-Gateway-Key"
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "doctor.db")
	configPath := filepath.Join(tempDir, "ongoingai.yaml")

	body := fmt.Sprintf(`storage:
  driver: sqlite
  path: %s
providers:
  openai:
    upstream: https://api.openai.com
    prefix: %s
  anthropic:
    upstream: https://api.anthropic.com
    prefix: %s
auth:
  enabled: %t
  header: %s
`, dbPath, openAIPrefix, anthropicPrefix, options.authEnabled, authHeader)
	if options.includeKey {
		body += `  keys:
    - id: key-dev
      token: token-dev
      org_id: org-dev
      workspace_id: workspace-dev
`
	}

	if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}
