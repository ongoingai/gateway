package providers

import "net/http"

type TraceData struct {
	StatusCode   int
	Model        string
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

type StreamChunkData struct {
	Model       string
	DeltaTokens int
}

type Provider interface {
	Name() string
	ParseResponse(statusCode int, headers http.Header, body []byte) (*TraceData, error)
	ParseStreamChunk(chunk []byte) (*StreamChunkData, error)
	EstimateCost(model string, inputTokens, outputTokens int) float64
}
