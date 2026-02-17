package providers

import (
	"math"
	"testing"
)

func TestOpenAIProviderParseResponse(t *testing.T) {
	t.Parallel()

	provider := OpenAIProvider{}

	tests := []struct {
		name            string
		statusCode      int
		body            string
		wantModel       string
		wantInputTokens int
		wantOutputToken int
		wantTotalTokens int
	}{
		{
			name:            "parses standard usage fields",
			statusCode:      200,
			body:            `{"model":"gpt-4o-mini","usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`,
			wantModel:       "gpt-4o-mini",
			wantInputTokens: 11,
			wantOutputToken: 7,
			wantTotalTokens: 18,
		},
		{
			name:            "parses input output usage aliases",
			statusCode:      201,
			body:            `{"model":"gpt-4o","usage":{"input_tokens":5,"output_tokens":3}}`,
			wantModel:       "gpt-4o",
			wantInputTokens: 5,
			wantOutputToken: 3,
			wantTotalTokens: 8,
		},
		{
			name:            "keeps status on malformed body",
			statusCode:      202,
			body:            `{"usage":`,
			wantModel:       "",
			wantInputTokens: 0,
			wantOutputToken: 0,
			wantTotalTokens: 0,
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
			if traceData.OutputTokens != tt.wantOutputToken {
				t.Fatalf("output_tokens=%d, want %d", traceData.OutputTokens, tt.wantOutputToken)
			}
			if traceData.TotalTokens != tt.wantTotalTokens {
				t.Fatalf("total_tokens=%d, want %d", traceData.TotalTokens, tt.wantTotalTokens)
			}
		})
	}
}

func TestOpenAIProviderParseStreamChunk(t *testing.T) {
	t.Parallel()

	provider := OpenAIProvider{}

	tests := []struct {
		name            string
		chunk           string
		wantModel       string
		wantDeltaTokens int
	}{
		{
			name:            "parses raw json chunk",
			chunk:           `{"model":"gpt-4o-mini","usage":{"completion_tokens":4}}`,
			wantModel:       "gpt-4o-mini",
			wantDeltaTokens: 4,
		},
		{
			name:            "parses sse data chunk",
			chunk:           "event: message\ndata: {\"model\":\"gpt-4o\",\"usage\":{\"completion_tokens\":2}}\n\n",
			wantModel:       "gpt-4o",
			wantDeltaTokens: 2,
		},
		{
			name:            "ignores done marker",
			chunk:           "data: [DONE]\n\n",
			wantModel:       "",
			wantDeltaTokens: 0,
		},
		{
			name:            "ignores malformed chunk",
			chunk:           "data: {oops}\n\n",
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

func TestOpenAIProviderEstimateCost(t *testing.T) {
	t.Parallel()

	provider := OpenAIProvider{}

	if got := provider.EstimateCost("unknown-model", 1000, 1000); got != 0 {
		t.Fatalf("unknown model cost=%f, want 0", got)
	}

	got := provider.EstimateCost("gpt-4o", 1000, 500)
	want := 0.0125
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("gpt-4o cost=%f, want=%f", got, want)
	}

	got = provider.EstimateCost("gpt-4o-mini", 1000, 1000)
	want = 0.00075
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("gpt-4o-mini cost=%f, want=%f", got, want)
	}
}

func TestOpenAIProviderName(t *testing.T) {
	t.Parallel()

	provider := OpenAIProvider{}
	if provider.Name() != "openai" {
		t.Fatalf("Name()=%q, want %q", provider.Name(), "openai")
	}
}

func TestRegistryDefaultProvidersAndNames(t *testing.T) {
	t.Parallel()

	registry := DefaultRegistry()
	names := registry.Names()

	if len(names) != 2 {
		t.Fatalf("Names() len=%d, want 2", len(names))
	}
	if names[0] != "anthropic" || names[1] != "openai" {
		t.Fatalf("Names()=%v, want [anthropic openai]", names)
	}

	if _, ok := registry.Get("openai"); !ok {
		t.Fatalf("Get(openai)=missing")
	}
	if _, ok := registry.Get("anthropic"); !ok {
		t.Fatalf("Get(anthropic)=missing")
	}
	if _, ok := registry.Get("missing"); ok {
		t.Fatalf("Get(missing)=found, want not found")
	}
}
