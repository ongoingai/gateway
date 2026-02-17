package providers

import "net/http"

type OpenAIProvider struct{}

func (OpenAIProvider) Name() string {
	return "openai"
}

func (OpenAIProvider) ParseResponse(statusCode int, _ http.Header, body []byte) (*TraceData, error) {
	traceData := &TraceData{StatusCode: statusCode}

	payload, ok := parseJSONMap(body)
	if !ok {
		return traceData, nil
	}

	traceData.Model = extractModel(payload)
	traceData.InputTokens, traceData.OutputTokens, traceData.TotalTokens = extractUsage(payload)
	return traceData, nil
}

func (OpenAIProvider) ParseStreamChunk(chunk []byte) (*StreamChunkData, error) {
	streamData := &StreamChunkData{}

	payloadBytes := chunk
	if ssePayload := parseSSEPayload(chunk); len(ssePayload) > 0 {
		payloadBytes = ssePayload
	}

	payload, ok := parseJSONMap(payloadBytes)
	if !ok {
		return streamData, nil
	}

	streamData.Model = extractModel(payload)
	_, outputTokens, totalTokens := extractUsage(payload)
	if outputTokens > 0 {
		streamData.DeltaTokens = outputTokens
	} else if totalTokens > 0 {
		streamData.DeltaTokens = totalTokens
	}
	return streamData, nil
}

func (OpenAIProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	pricing := map[string]struct {
		inputPer1K  float64
		outputPer1K float64
	}{
		"gpt-4o":      {inputPer1K: 0.005, outputPer1K: 0.015},
		"gpt-4o-mini": {inputPer1K: 0.00015, outputPer1K: 0.0006},
	}

	rates, ok := pricing[model]
	if !ok {
		return 0
	}

	return (float64(inputTokens)/1000)*rates.inputPer1K + (float64(outputTokens)/1000)*rates.outputPer1K
}
