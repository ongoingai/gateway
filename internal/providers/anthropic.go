package providers

import (
	"net/http"
	"strings"
)

type AnthropicProvider struct{}

func (AnthropicProvider) Name() string {
	return "anthropic"
}

func (AnthropicProvider) ParseResponse(statusCode int, _ http.Header, body []byte) (*TraceData, error) {
	traceData := &TraceData{StatusCode: statusCode}

	payload, ok := parseJSONMap(body)
	if !ok {
		return traceData, nil
	}

	traceData.Model = extractModel(payload)
	traceData.InputTokens, traceData.OutputTokens, traceData.TotalTokens = extractUsage(payload)
	return traceData, nil
}

func (AnthropicProvider) ParseStreamChunk(chunk []byte) (*StreamChunkData, error) {
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
	if streamData.Model == "" {
		if message, ok := payload["message"].(map[string]any); ok {
			streamData.Model = extractModel(message)
		}
	}

	_, outputTokens, totalTokens := extractUsage(payload)
	if outputTokens > 0 {
		streamData.DeltaTokens = outputTokens
	} else if totalTokens > 0 {
		streamData.DeltaTokens = totalTokens
	}
	return streamData, nil
}

func (AnthropicProvider) EstimateCost(model string, inputTokens, outputTokens int) float64 {
	rates, ok := anthropicPricingForModel(model)
	if !ok {
		return 0
	}

	return (float64(inputTokens)/1000)*rates.inputPer1K + (float64(outputTokens)/1000)*rates.outputPer1K
}

type anthropicPricing struct {
	inputPer1K  float64
	outputPer1K float64
}

type anthropicPricingRule struct {
	prefix string
	rates  anthropicPricing
}

var anthropicExactPricing = map[string]anthropicPricing{
	// USD per 1K tokens.
	"claude-opus-4-1":           {inputPer1K: 0.015, outputPer1K: 0.075},
	"claude-opus-4-6":           {inputPer1K: 0.005, outputPer1K: 0.025},
	"claude-sonnet-4-20250514":  {inputPer1K: 0.003, outputPer1K: 0.015},
	"claude-haiku-4-5-20251001": {inputPer1K: 0.001, outputPer1K: 0.005},
	"claude-3-5-haiku-20241022": {inputPer1K: 0.0008, outputPer1K: 0.004},
}

var anthropicPrefixPricing = []anthropicPricingRule{
	{prefix: "claude-opus-4-6-", rates: anthropicPricing{inputPer1K: 0.005, outputPer1K: 0.025}},
	{prefix: "claude-opus-4-1-", rates: anthropicPricing{inputPer1K: 0.015, outputPer1K: 0.075}},
	{prefix: "claude-opus-4-", rates: anthropicPricing{inputPer1K: 0.015, outputPer1K: 0.075}},
	{prefix: "claude-sonnet-4-6-", rates: anthropicPricing{inputPer1K: 0.003, outputPer1K: 0.015}},
	{prefix: "claude-sonnet-4-", rates: anthropicPricing{inputPer1K: 0.003, outputPer1K: 0.015}},
	{prefix: "claude-haiku-4-6-", rates: anthropicPricing{inputPer1K: 0.001, outputPer1K: 0.005}},
	{prefix: "claude-haiku-4-5-", rates: anthropicPricing{inputPer1K: 0.001, outputPer1K: 0.005}},
	{prefix: "claude-haiku-4-", rates: anthropicPricing{inputPer1K: 0.001, outputPer1K: 0.005}},
	{prefix: "claude-3-7-sonnet-", rates: anthropicPricing{inputPer1K: 0.003, outputPer1K: 0.015}},
	{prefix: "claude-3-5-sonnet-", rates: anthropicPricing{inputPer1K: 0.003, outputPer1K: 0.015}},
	{prefix: "claude-3-5-haiku-", rates: anthropicPricing{inputPer1K: 0.0008, outputPer1K: 0.004}},
	{prefix: "claude-3-opus-", rates: anthropicPricing{inputPer1K: 0.015, outputPer1K: 0.075}},
	{prefix: "claude-3-sonnet-", rates: anthropicPricing{inputPer1K: 0.003, outputPer1K: 0.015}},
	{prefix: "claude-3-haiku-", rates: anthropicPricing{inputPer1K: 0.00025, outputPer1K: 0.00125}},
}

func anthropicPricingForModel(model string) (anthropicPricing, bool) {
	model = strings.TrimSpace(strings.ToLower(model))
	if model == "" {
		return anthropicPricing{}, false
	}

	if rates, ok := anthropicExactPricing[model]; ok {
		return rates, true
	}

	for _, rule := range anthropicPrefixPricing {
		if strings.HasPrefix(model, rule.prefix) {
			return rule.rates, true
		}
	}

	return anthropicPricing{}, false
}
