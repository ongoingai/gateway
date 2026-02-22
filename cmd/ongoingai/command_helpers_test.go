package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeTextJSONFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		command       string
		raw           string
		defaultValue  string
		want          string
		wantErrSubstr string
	}{
		{
			name:         "default text",
			command:      "report",
			raw:          "",
			defaultValue: "text",
			want:         "text",
		},
		{
			name:         "normalizes case and whitespace",
			command:      "debug",
			raw:          " JSON ",
			defaultValue: "text",
			want:         "json",
		},
		{
			name:          "rejects unsupported format",
			command:       "doctor",
			raw:           "yaml",
			defaultValue:  "text",
			wantErrSubstr: `invalid doctor format "yaml": expected text or json`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeTextJSONFormat(tt.command, tt.raw, tt.defaultValue)
			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Fatalf("error=%q, want substring %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeTextJSONFormat() error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeTextJSONFormat()=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadAndValidateConfigStages(t *testing.T) {
	t.Parallel()

	t.Run("load stage", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(t.TempDir(), "invalid-syntax.yaml")
		if err := os.WriteFile(configPath, []byte("server: ["), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}

		_, stage, err := loadAndValidateConfig(configPath)
		if err == nil {
			t.Fatal("expected load error")
		}
		if stage != configStageLoad {
			t.Fatalf("stage=%q, want %q", stage, configStageLoad)
		}
	})

	t.Run("validate stage", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(t.TempDir(), "invalid.yaml")
		body := `server:
  host: 127.0.0.1
  port: 70000
storage:
  driver: sqlite
  path: ./data/ongoingai.db
providers:
  openai:
    upstream: https://api.openai.com
    prefix: /openai
  anthropic:
    upstream: https://api.anthropic.com
    prefix: /anthropic
`
		if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
			t.Fatalf("write config: %v", err)
		}

		_, stage, err := loadAndValidateConfig(configPath)
		if err == nil {
			t.Fatal("expected validate error")
		}
		if stage != configStageValidate {
			t.Fatalf("stage=%q, want %q", stage, configStageValidate)
		}
	})
}
