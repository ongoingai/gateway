package providers

import (
	"encoding/json"
	"strings"
)

func parseJSONMap(raw []byte) (map[string]any, bool) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return nil, false
	}

	var out map[string]any
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return nil, false
	}
	return out, true
}

func parseSSEPayload(chunk []byte) []byte {
	lines := strings.Split(string(chunk), "\n")
	dataLines := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if value == "" || value == "[DONE]" {
			continue
		}
		dataLines = append(dataLines, value)
	}
	if len(dataLines) == 0 {
		return nil
	}
	// A transport chunk can contain multiple SSE events. Prefer the last JSON
	// payload so callers can still parse useful model/usage fields.
	for i := len(dataLines) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(dataLines[i]), "{") {
			return []byte(dataLines[i])
		}
	}
	return []byte(dataLines[len(dataLines)-1])
}

func firstInt(values map[string]any, keys ...string) int {
	for _, key := range keys {
		raw, ok := values[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case float64:
			return int(typed)
		case int:
			return typed
		}
	}
	return 0
}

func extractUsage(payload map[string]any) (int, int, int) {
	if payload == nil {
		return 0, 0, 0
	}
	usage, ok := payload["usage"].(map[string]any)
	if !ok {
		return 0, 0, 0
	}

	input := firstInt(usage, "prompt_tokens", "input_tokens")
	output := firstInt(usage, "completion_tokens", "output_tokens")
	total := firstInt(usage, "total_tokens")
	if total == 0 {
		total = input + output
	}
	return input, output, total
}

func extractModel(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	model, _ := payload["model"].(string)
	return strings.TrimSpace(model)
}
