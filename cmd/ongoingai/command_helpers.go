package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/ongoingai/gateway/internal/config"
)

const (
	configStageLoad     = "load"
	configStageValidate = "validate"
)

// normalizeTextJSONFormat validates command output format flags with shared semantics.
func normalizeTextJSONFormat(command, rawValue, defaultValue string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(rawValue))
	if normalized == "" {
		normalized = strings.TrimSpace(defaultValue)
	}
	switch normalized {
	case "text", "json":
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid %s format %q: expected text or json", strings.TrimSpace(command), rawValue)
	}
}

// loadAndValidateConfig resolves config and reports which stage failed.
func loadAndValidateConfig(configPath string) (config.Config, string, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return config.Config{}, configStageLoad, err
	}
	if err := config.Validate(cfg); err != nil {
		return config.Config{}, configStageValidate, err
	}
	return cfg, "", nil
}

// valueOr returns the trimmed value if non-empty, otherwise the fallback.
func valueOr(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

// timeOr formats a time as RFC3339 UTC, or returns the fallback if zero.
func timeOr(value time.Time, fallback string) string {
	if value.IsZero() {
		return fallback
	}
	return value.UTC().Format(time.RFC3339)
}

// timePtrOr formats a *time.Time as RFC3339 UTC, or returns the fallback if nil/zero.
func timePtrOr(value *time.Time, fallback string) string {
	if value == nil || value.IsZero() {
		return fallback
	}
	return value.UTC().Format(time.RFC3339)
}
