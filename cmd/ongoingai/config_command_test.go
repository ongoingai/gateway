package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfigValidateValidConfig(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "ongoingai.yaml")
	if err := os.WriteFile(configPath, []byte(""), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfigValidate([]string{"--config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runConfigValidate() code=%d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "config is valid: "+configPath) {
		t.Fatalf("stdout=%q, want success message with config path", stdout.String())
	}
}

func TestRunConfigValidateReportsInvalidConfig(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "ongoingai.yaml")
	configBody := `storage:
  driver: postgres
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfigValidate([]string{"--config", configPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runConfigValidate() code=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "config is invalid: storage.dsn is required") {
		t.Fatalf("stderr=%q, want validation error message", stderr.String())
	}
}

func TestRunConfigValidateRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfigValidate([]string{"extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runConfigValidate() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%q, want positional argument error", stderr.String())
	}
}

func TestRunConfigUnknownSubcommand(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfig([]string{"unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("runConfig() code=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "ongoingai config validate") {
		t.Fatalf("stderr=%q, want config usage", stderr.String())
	}
}
