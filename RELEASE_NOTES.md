# Release Notes

## v1.0.0

First public release of OngoingAI Gateway.

### Scope

Headless AI gateway runtime and APIs. No web UI in this repository.

### Proxy and streaming

- Reverse proxy routing for OpenAI and Anthropic provider prefixes.
- Streaming pass-through with chunk capture for trace assembly.
- Middleware-based request/response capture with configurable body limits.
- Provider-specific parsing for usage, model extraction, and cost estimation.

### Tracing and storage

- Trace domain model with token, cost, latency, and streaming metadata fields.
- SQLite trace store with embedded migrations and local-first defaults.
- Postgres trace store with migration support and tenant-safe query behavior.
- Async trace writer with configurable batch size, bounded queue semantics, and
  shutdown flush handling.
- Write-path boundary (`TraceStore` interface) so trace ingestion transport can
  evolve without proxy-path changes.
- Write-failure signaling and logging for dropped trace records.

### Trace lineage and replay

- Trace lineage state model with group, thread, run, and checkpoint correlation.
- Immutable checkpoint sequencing for reproducible debugging.
- Replay API to inspect chronologically ordered checkpoint history.
- Fork API to branch debug runs from any checkpoint without mutating original
  records.
- Tenant-scoped lineage queries in both SQLite and Postgres backends.

### API and analytics

- Health endpoint with version, uptime, storage driver, and trace count.
- Trace list, detail, replay, and fork endpoints.
- Usage, cost, model, key, and summary analytics queries.
- Cursor-based pagination for trace export.
- OpenAPI schema for documented API routes.

### Auth, keys, and tenancy

- Gateway key authentication with RBAC-style permission checks.
- Deny-by-default protected-route policy mapping.
- Gateway key lifecycle APIs (create, list, revoke, rotate).
- Role-based permission defaults (owner, admin, developer, member, viewer).
- Workspace and org scoping in trace, analytics, and key access paths.
- Tenant isolation and row-level security coverage in Postgres.

### PII and redaction

- Four guardrail modes: `off`, `redact_storage`, `redact_upstream`, and `block`.
- `redact_storage` redacts sensitive data before trace persistence while
  preserving proxy availability.
- `redact_upstream` redacts PII in request bodies before forwarding to upstream
  providers.
- `block` rejects requests containing detected PII with HTTP 403.
- Mode-specific failure semantics: `redact_storage` drops body persistence on
  error but continues proxy traffic; `redact_upstream` and `block` fail closed
  on policy uncertainty.
- Deterministic detector bundles for email, phone, SSN, and token-like secrets.
- Field-name and header denylists for targeted redaction.
- Stable hashed redaction placeholders with tenant-scoped salt and configurable
  replacement format.
- Auditable policy decision records in trace metadata: mode, policy ID, applied
  flag, detector counts, and storage-drop indicators.
- Scoped policy controls by org, workspace, key, provider, and route prefix
  with specificity-based matching.
- Per-stage controls for request headers, request body, response headers, and
  response body redaction.

### OpenTelemetry and Prometheus

- OTLP HTTP export for distributed traces and gateway metrics.
- Native Prometheus `/metrics` scrape endpoint with dual-export support
  (Prometheus and OTLP push can run simultaneously).
- 12 metric instruments across trace pipeline, provider, and proxy dimensions.
- Custom histogram bucket boundaries optimized for AI API latencies (5ms-10s)
  and storage writes (1ms-1s).
- Histogram exemplars on proxy and provider latency metrics for
  metrics-to-traces correlation (click a latency spike, open the trace).
- 6 span types: inbound server, upstream proxy client, auth evaluation,
  provider routing, trace enqueue, and trace write.
- Tenant identity attributes on spans: `gateway.org_id`, `gateway.workspace_id`,
  `gateway.key_id`, `gateway.role`.
- Logs-to-traces correlation: structured JSON logs include `trace_id` and
  `span_id` from the active request span.
- W3C Trace Context propagation.
- Configurable sampling ratio with parent-based sampling.
- Go runtime metrics registered automatically (`go_memory_*`,
  `go_goroutine_*`, `go_gc_*`).
- Credential scrubbing on all span attributes before export with zero
  allocation overhead for clean spans.
- Standard `OTEL_*` environment variable support with auto-enable behavior.
- Graceful flush on shutdown for both trace and metric providers.

### Security and reliability

- Fail-closed auth and tenant-scope enforcement on protected routes.
- Sensitive-header redaction in all trace capture paths.
- Provider API key pass-through model with non-persistence guarantees.
- Error semantics with actionable context across proxy, auth, and storage
  boundaries.
- Graceful server shutdown with trace-writer and OTEL flush windows.
- Regression coverage for credential handling, tenant isolation, and redaction
  bypass resistance.
- Startup and migration validation across SQLite and Postgres modes.

### Distribution and developer experience

- Single-binary local runtime with default SQLite mode.
- Config file with env var override support.
- Shell helper (`shell-init`) and command wrapper (`wrap`).
- Multi-platform build and release workflows (linux/amd64, linux/arm64,
  darwin/amd64, darwin/arm64, windows/amd64).
- Multi-arch Docker images published to GHCR.
- CI enforcement for formatting, `go vet`, tests, and race detection.

### Documentation

- Self-hosting quickstart with install, configure, and validate steps.
- Configuration reference with field defaults, validation rules, and examples.
- Environment variable reference.
- REST API reference.
- Authorization reference with role and permission matrix.
- Architecture, privacy model, traces and audit model, and tenancy concepts.
- Capability guides for routing, auth, limits, analytics, storage, streaming,
  PII, tracing, and integrations.
- OpenTelemetry integration guide.
- Troubleshooting, FAQ, security policy, and contributing guides.

### Upgrade impact

This is the initial public release. No upgrade path from prior versions.

### Notes

- Historical milestone checklists are tracked in `ROADMAP.md` with per-item
  completion status.
