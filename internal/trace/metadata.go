package trace

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// DecodeMetadataMap decodes a JSON metadata string into a generic map.
// Returns nil for empty input or JSON parse errors.
func DecodeMetadataMap(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	decoded := make(map[string]any)
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil
	}
	return decoded
}

// MetadataString extracts a trimmed string value from a metadata map.
func MetadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	raw, ok := metadata[key]
	if !ok {
		return ""
	}
	value, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// CoerceInt64 converts a loosely-typed value to int64, handling float64,
// float32, int, int64, int32, json.Number, and string representations.
func CoerceInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case float32:
		return int64(typed), true
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

// MetadataInt64 extracts an int64 value from a metadata map key.
func MetadataInt64(metadata map[string]any, key string) (int64, bool) {
	if len(metadata) == 0 {
		return 0, false
	}
	raw, ok := metadata[key]
	if !ok {
		return 0, false
	}
	return CoerceInt64(raw)
}

// MetadataBool extracts a boolean value from a metadata map key,
// handling native bools and "true"/"false" strings.
func MetadataBool(metadata map[string]any, key string) (bool, bool) {
	if len(metadata) == 0 {
		return false, false
	}
	raw, ok := metadata[key]
	if !ok {
		return false, false
	}
	switch typed := raw.(type) {
	case bool:
		return typed, true
	case string:
		value := strings.ToLower(strings.TrimSpace(typed))
		if value == "true" {
			return true, true
		}
		if value == "false" {
			return false, true
		}
	}
	return false, false
}

// OrderTime returns the canonical ordering timestamp for a trace,
// preferring CreatedAt over Timestamp.
func OrderTime(item *Trace) time.Time {
	if item == nil {
		return time.Time{}
	}
	if !item.CreatedAt.IsZero() {
		return item.CreatedAt.UTC()
	}
	return item.Timestamp.UTC()
}
