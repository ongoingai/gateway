package providers

import (
	"math"
	"testing"
)

func TestAnthropicProviderParseResponse(t *testing.T) {
	t.Parallel()

	provider := AnthropicProvider{}

	tests := []struct {
		name             string
		statusCode       int
		body             string
		wantModel        string
		wantInputTokens  int
		wantOutputTokens int
		wantTotalTokens  int
	}{
		{
			name:             "parses anthropic usage fields",
			statusCode:       200,
			body:             `{"model":"claude-haiku-4-5-20251001","usage":{"input_tokens":9,"output_tokens":4}}`,
			wantModel:        "claude-haiku-4-5-20251001",
			wantInputTokens:  9,
			wantOutputTokens: 4,
			wantTotalTokens:  13,
		},
		{
			name:             "keeps status on malformed body",
			statusCode:       503,
			body:             `{"usage":`,
			wantModel:        "",
			wantInputTokens:  0,
			wantOutputTokens: 0,
			wantTotalTokens:  0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			traceData, err := provider.ParseResponse(tt.statusCode, nil, []byte(tt.body))
			if err != nil {
				t.Fatalf("ParseResponse() error: %v", err)
			}
			if traceData == nil {
				t.Fatal("ParseResponse() returned nil trace data")
			}
			if traceData.StatusCode != tt.statusCode {
				t.Fatalf("status=%d, want %d", traceData.StatusCode, tt.statusCode)
			}
			if traceData.Model != tt.wantModel {
				t.Fatalf("model=%q, want %q", traceData.Model, tt.wantModel)
			}
			if traceData.InputTokens != tt.wantInputTokens {
				t.Fatalf("input_tokens=%d, want %d", traceData.InputTokens, tt.wantInputTokens)
			}
			if traceData.OutputTokens != tt.wantOutputTokens {
				t.Fatalf("output_tokens=%d, want %d", traceData.OutputTokens, tt.wantOutputTokens)
			}
			if traceData.TotalTokens != tt.wantTotalTokens {
				t.Fatalf("total_tokens=%d, want %d", traceData.TotalTokens, tt.wantTotalTokens)
			}
		})
	}
}

func TestAnthropicProviderParseStreamChunk(t *testing.T) {
	t.Parallel()

	provider := AnthropicProvider{}

	tests := []struct {
		name            string
		chunk           string
		wantModel       string
		wantDeltaTokens int
	}{
		{
			name:            "parses message delta chunk",
			chunk:           "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":3}}\n\n",
			wantModel:       "",
			wantDeltaTokens: 3,
		},
		{
			name:            "parses message_start model",
			chunk:           "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-20250514\"}}\n\n",
			wantModel:       "claude-sonnet-4-20250514",
			wantDeltaTokens: 0,
		},
		{
			name:            "ignores done marker",
			chunk:           "data: [DONE]\n\n",
			wantModel:       "",
			wantDeltaTokens: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			streamData, err := provider.ParseStreamChunk([]byte(tt.chunk))
			if err != nil {
				t.Fatalf("ParseStreamChunk() error: %v", err)
			}
			if streamData == nil {
				t.Fatal("ParseStreamChunk() returned nil stream data")
			}
			if streamData.Model != tt.wantModel {
				t.Fatalf("model=%q, want %q", streamData.Model, tt.wantModel)
			}
			if streamData.DeltaTokens != tt.wantDeltaTokens {
				t.Fatalf("delta_tokens=%d, want %d", streamData.DeltaTokens, tt.wantDeltaTokens)
			}
		})
	}
}

func TestAnthropicEstimateCostKnownModel(t *testing.T) {
	t.Parallel()

	provider := AnthropicProvider{}
	got := provider.EstimateCost("claude-haiku-4-5-20251001", 1000, 500)
	want := 0.0035

	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("cost=%f, want=%f", got, want)
	}
}

func TestAnthropicEstimateCostPrefixFallback(t *testing.T) {
	t.Parallel()

	provider := AnthropicProvider{}
	got := provider.EstimateCost("claude-opus-4-6-20260220", 2000, 1000)
	want := 0.035

	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("cost=%f, want=%f", got, want)
	}
}

func TestAnthropicEstimateCostUnknownModel(t *testing.T) {
	t.Parallel()

	provider := AnthropicProvider{}
	if got := provider.EstimateCost("unknown-model", 1000, 1000); got != 0 {
		t.Fatalf("cost=%f, want 0", got)
	}
}

func TestAnthropicProviderName(t *testing.T) {
	t.Parallel()

	provider := AnthropicProvider{}
	if provider.Name() != "anthropic" {
		t.Fatalf("Name()=%q, want %q", provider.Name(), "anthropic")
	}
}
