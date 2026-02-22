package trace

import (
	"encoding/json"
	"testing"
)

func TestCoerceInt64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  any
		want   int64
		wantOK bool
	}{
		{name: "float64", input: float64(42.9), want: 42, wantOK: true},
		{name: "float32", input: float32(17.3), want: 17, wantOK: true},
		{name: "int", input: int(9), want: 9, wantOK: true},
		{name: "int64", input: int64(99), want: 99, wantOK: true},
		{name: "int32", input: int32(31), want: 31, wantOK: true},
		{name: "json number", input: json.Number("123"), want: 123, wantOK: true},
		{name: "json number invalid", input: json.Number("1.5"), want: 0, wantOK: false},
		{name: "string", input: "456", want: 456, wantOK: true},
		{name: "string trimmed", input: "  -12  ", want: -12, wantOK: true},
		{name: "string invalid", input: "abc", want: 0, wantOK: false},
		{name: "unsupported bool", input: true, want: 0, wantOK: false},
		{name: "unsupported nil", input: nil, want: 0, wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := CoerceInt64(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("CoerceInt64() ok=%t, want %t", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("CoerceInt64()=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestMetadataBool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		meta   map[string]any
		key    string
		want   bool
		wantOK bool
	}{
		{name: "nil metadata", meta: nil, key: "flag", want: false, wantOK: false},
		{name: "missing key", meta: map[string]any{}, key: "flag", want: false, wantOK: false},
		{name: "bool true", meta: map[string]any{"flag": true}, key: "flag", want: true, wantOK: true},
		{name: "bool false", meta: map[string]any{"flag": false}, key: "flag", want: false, wantOK: true},
		{name: "string true", meta: map[string]any{"flag": "true"}, key: "flag", want: true, wantOK: true},
		{name: "string false", meta: map[string]any{"flag": "false"}, key: "flag", want: false, wantOK: true},
		{name: "string mixed case", meta: map[string]any{"flag": "TrUe"}, key: "flag", want: true, wantOK: true},
		{name: "string trimmed", meta: map[string]any{"flag": "  FALSE  "}, key: "flag", want: false, wantOK: true},
		{name: "string invalid", meta: map[string]any{"flag": "1"}, key: "flag", want: false, wantOK: false},
		{name: "unsupported type", meta: map[string]any{"flag": 1}, key: "flag", want: false, wantOK: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := MetadataBool(tt.meta, tt.key)
			if ok != tt.wantOK {
				t.Fatalf("MetadataBool() ok=%t, want %t", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("MetadataBool()=%t, want %t", got, tt.want)
			}
		})
	}
}
