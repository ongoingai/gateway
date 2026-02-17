package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ongoingai/gateway/internal/config"
)

func TestShellInitScriptUsesLocalhostForWildcardHost(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 8080

	got := shellInitScript(cfg)
	want := "export OPENAI_BASE_URL=http://localhost:8080/openai/v1\n" +
		"export ANTHROPIC_BASE_URL=http://localhost:8080/anthropic\n"
	if got != want {
		t.Fatalf("shellInitScript()=\n%s\nwant:\n%s", got, want)
	}
}

func TestShellInitScriptUsesConfiguredHostAndPrefixes(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = 9090
	cfg.Providers.OpenAI.Prefix = "/gateway/openai"
	cfg.Providers.Anthropic.Prefix = "anthropic-api"

	got := shellInitScript(cfg)
	want := "export OPENAI_BASE_URL=http://127.0.0.1:9090/gateway/openai/v1\n" +
		"export ANTHROPIC_BASE_URL=http://127.0.0.1:9090/anthropic-api\n"
	if got != want {
		t.Fatalf("shellInitScript()=\n%s\nwant:\n%s", got, want)
	}
}

func TestGatewayCommandEnvOverridesProviderURLs(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 8080

	env := gatewayCommandEnv(cfg, []string{
		"FOO=bar",
		"OPENAI_BASE_URL=http://old.local/openai/v1",
		"ANTHROPIC_BASE_URL=http://old.local/anthropic",
	})
	got := toEnvMap(env)

	if got["FOO"] != "bar" {
		t.Fatalf("FOO=%q, want bar", got["FOO"])
	}
	if got["OPENAI_BASE_URL"] != "http://localhost:8080/openai/v1" {
		t.Fatalf("OPENAI_BASE_URL=%q", got["OPENAI_BASE_URL"])
	}
	if got["ANTHROPIC_BASE_URL"] != "http://localhost:8080/anthropic" {
		t.Fatalf("ANTHROPIC_BASE_URL=%q", got["ANTHROPIC_BASE_URL"])
	}
}

func TestRunWrappedCommandSetsProviderURLs(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = 8088

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWrappedCommand(cfg, []string{"sh", "-c", `printf "%s|%s" "$OPENAI_BASE_URL" "$ANTHROPIC_BASE_URL"`}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runWrappedCommand() code=%d, stderr=%q", code, stderr.String())
	}

	got := stdout.String()
	want := "http://127.0.0.1:8088/openai/v1|http://127.0.0.1:8088/anthropic"
	if got != want {
		t.Fatalf("stdout=%q, want %q", got, want)
	}
}

func TestRunWrappedCommandPropagatesExitCode(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runWrappedCommand(cfg, []string{"sh", "-c", "exit 7"}, &stdout, &stderr)
	if code != 7 {
		t.Fatalf("runWrappedCommand() code=%d, want 7", code)
	}
}

func TestRunWrappedCommandReportsStartFailure(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := runWrappedCommand(cfg, []string{"definitely-not-a-real-command-ongoingai"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runWrappedCommand() code=%d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to start command") {
		t.Fatalf("stderr=%q, want start failure message", stderr.String())
	}
}

func toEnvMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		out[parts[0]] = parts[1]
	}
	return out
}
