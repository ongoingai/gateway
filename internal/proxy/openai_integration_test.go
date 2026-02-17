package proxy_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/ongoingai/gateway/internal/proxy"
)

func TestOpenAISDKRequestPassesThroughGateway(t *testing.T) {
	t.Parallel()

	type upstreamRequest struct {
		Path          string
		Authorization string
		Body          string
	}

	upstreamReqCh := make(chan upstreamRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream request body: %v", err)
		}

		upstreamReqCh <- upstreamRequest{
			Path:          r.URL.Path,
			Authorization: r.Header.Get("Authorization"),
			Body:          string(body),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-test",
			"object":"chat.completion",
			"created":1700000000,
			"model":"gpt-4o-mini",
			"choices":[
				{
					"index":0,
					"message":{"role":"assistant","content":"hello from upstream"},
					"finish_reason":"stop"
				}
			],
			"usage":{"prompt_tokens":5,"completion_tokens":4,"total_tokens":9}
		}`))
	}))
	defer upstream.Close()

	proxyHandler, err := proxy.NewHandler([]proxy.Route{
		{Prefix: "/openai", Upstream: upstream.URL},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), http.NotFoundHandler())
	if err != nil {
		t.Fatalf("create proxy handler: %v", err)
	}

	gateway := httptest.NewServer(proxyHandler)
	defer gateway.Close()

	cfg := openai.DefaultConfig("sk-test-key")
	cfg.BaseURL = gateway.URL + "/openai/v1"
	client := openai.NewClientWithConfig(cfg)

	resp, err := client.CreateChatCompletion(context.Background(), openai.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "say hello"},
		},
	})
	if err != nil {
		t.Fatalf("chat completion request through gateway: %v", err)
	}

	if len(resp.Choices) != 1 {
		t.Fatalf("choices len=%d, want %d", len(resp.Choices), 1)
	}
	if got := resp.Choices[0].Message.Content; got != "hello from upstream" {
		t.Fatalf("assistant message=%q, want %q", got, "hello from upstream")
	}

	select {
	case got := <-upstreamReqCh:
		if got.Path != "/v1/chat/completions" {
			t.Fatalf("upstream path=%q, want %q", got.Path, "/v1/chat/completions")
		}
		if got.Authorization != "Bearer sk-test-key" {
			t.Fatalf("upstream auth=%q, want %q", got.Authorization, "Bearer sk-test-key")
		}
		if !strings.Contains(got.Body, `"model":"gpt-4o-mini"`) {
			t.Fatalf("upstream body missing model field: %s", got.Body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request")
	}
}
