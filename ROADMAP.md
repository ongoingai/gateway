# OngoingAI Gateway Roadmap

## Product Scope

OngoingAI Gateway is a headless AI gateway.

- It provides HTTP proxying, authorization, policy enforcement, tracing, analytics APIs, and operator tooling.
- It does not include a web UI in this repository.
- UI/user-session features are out of scope here.

## Planning Model

This roadmap is organized as priority-ordered phases.

- Phases are intent-based, not date-based.
- No week-by-week schedule is maintained in this file.
- Completed delivery history is tracked in `RELEASE_NOTES.md`.

## Phase Status Snapshot

- Phase 0: Completed (15/15)
- Phase 1: Completed (20/20)
- Phase 2: Planned (1/16)

## Phase 0: Foundation And Initial Setup (Completed)

Focus: establish a self-hosted baseline gateway with core proxy, trace, auth, and operator workflows.

Planned work:

- [x] Define repository structure and package boundaries for proxy, auth, providers, trace, config, and API layers.
- [x] Implement single-binary runtime and CLI entrypoints (`serve`, `config validate`, `shell-init`, and `wrap`).
- [x] Implement core config schema with defaults, env-var overrides, and startup validation.
- [x] Ship SQLite trace storage with migrations and local-first defaults.
- [x] Ship Postgres trace/config store support with migration compatibility for team deployments.
- [x] Implement provider proxy routing for OpenAI and Anthropic prefixes.
- [x] Preserve streaming pass-through semantics while capturing chunks for trace assembly.
- [x] Implement provider parsing for usage/model extraction and baseline cost estimation.
- [x] Implement trace domain model plus async write pipeline with bounded queue/drop behavior and shutdown flush.
- [x] Expose foundational APIs for health, traces, analytics, and gateway key lifecycle operations.
- [x] Implement gateway key authentication, permission enforcement, and deny-by-default protected route mapping.
- [x] Enforce org/workspace tenant scoping across trace and key access paths, including Postgres isolation coverage.
- [x] Preserve provider credential pass-through model with non-persistence guarantees.
- [x] Establish operator/developer workflows (`Makefile`, container build, cross-build/release automation, and CI gates).
- [x] Publish self-hosting quickstart, configuration reference, security guidance, and troubleshooting docs.

Exit criteria:

1. Gateway runs as a single binary with default SQLite in local/self-hosted mode.
2. Proxy routing and streaming behavior are stable for the initial provider set.
3. Trace capture, storage, and retrieval APIs work end-to-end in SQLite and Postgres modes.
4. Gateway auth, key lifecycle, and tenant boundaries are enforceable and auditable.
5. Provider credentials are forwarded upstream without local persistence in stores, logs, or config.
6. CI and release workflows are in place for repeatable builds and quality checks.
7. Documentation is sufficient for install, configure, run, and troubleshoot first production-like deployments.

## Phase 1: Core Hardening (1.0 Release, Completed)

Focus: ship a credible public release with the security, data governance, and traceability baseline that security teams require.

Planned work:

- [x] Tighten error semantics across proxy/auth/storage boundaries.
- [x] Expand regression coverage for sensitive-data handling and tenant isolation edge cases.
- [x] Validate startup/shutdown/migration behavior across SQLite and Postgres modes.
- [x] Add a write-path boundary (`TraceSink`) so trace ingestion transport can evolve without proxy-path rewrites.
- [x] Add configurable trace write batching and flush controls with explicit bounded-backpressure semantics.
- [x] Add basic health and readiness endpoints.
- [x] OpenTelemetry integration for distributed traces and gateway metrics.
- [x] Introduce policy-driven redaction controls for request/response capture paths.
- [x] Add explicit PII guardrail modes with deterministic semantics: `redact_storage` (default when body capture is enabled), opt-in `redact_upstream`, and opt-in `block`.
- [x] Define mode-specific failure semantics so `redact_storage` preserves proxy availability while `redact_upstream`/`block` fail closed on policy uncertainty.
- [x] Add deterministic detector bundles and field/path rules for high-confidence sensitive classes (for example email, phone, SSN, token-like secrets).
- [x] Add stable hashed redaction placeholders with tenant-scoped salt handling and rotation guidance.
- [x] Add auditable policy decision records with low-overhead observability.
- [x] Support scoped policy controls by org/workspace/key/provider/route.
- [x] Add an API-level state model for trace lineage (group/thread/run correlation and immutable checkpoints) suitable for reproducible debugging.
- [x] Add replay/time-travel APIs to inspect prior checkpointed states and fork debug runs without mutating original records.
- [x] Finalize API and config contract documentation, including operational defaults.
- [x] Add targeted operator guidance for backpressure, dropped traces, and recovery behavior.
- [x] Document storage driver guidance: SQLite for local/single-node use, Postgres for team and multi-user deployments.
- [x] Publish self-hosting quickstart and configuration reference.

Exit criteria:

1. Critical-path tests and failure-mode tests are green in CI for SQLite and Postgres.
2. Security-sensitive behavior has explicit regression tests.
3. PII redaction is deterministic and tested for bypass resistance across all guardrail modes.
4. Policy decisions are auditable without logging sensitive material.
5. Trace lineage and replay/time-travel APIs are deterministic, tenant-scoped, and auditable.
6. API and config contracts are documented and stable.
7. Self-hosting guide covers setup, configuration, storage driver selection, and basic troubleshooting.
8. Write-path architecture allows backend transition (direct DB -> ingest service) with minimal gateway surface changes.

## Phase 2: Debugging, Development Velocity, And Trace Intelligence (Planned)

Focus: make local and production troubleshooting faster while improving trace fidelity, lineage clarity, and day-to-day developer workflows.

Planned work:

- [x] Ship offline-first CLI debugging workflow as a first-class operator path (`report` and `debug`) so post-incident analysis does not depend on a live gateway process.
- [ ] Add focused trace drill-down CLI commands for direct trace inspection by `trace_id`, `trace_group_id`, `thread_id`, and `run_id`.
- [ ] Add redaction-safe checkpoint diff tooling to compare trace request/response/metadata changes across lineage steps.
- [ ] Add reproducible debug bundle export (`json` + metadata manifest) for support escalation and CI artifact capture.
- [ ] Add CLI filtering and output controls for scripting (`--format json`, deterministic ordering, stable field contracts).
- [ ] Add a local developer diagnostics command (`dev doctor`) to validate config, storage connectivity, route wiring, and auth posture in one pass.
- [ ] Publish deterministic local demo/test harnesses with mock OpenAI/Anthropic upstreams for repeatable debugging demos.
- [ ] Add end-to-end tests that assert report/debug outputs against seeded trace fixtures for SQLite and Postgres.
- [ ] Strengthen lineage reconstruction guarantees for out-of-order writes and partial lineage metadata.
- [ ] Improve streaming trace assembly coverage for malformed chunks, partial usage payloads, and mixed provider event formats.
- [ ] Record explicit upstream failure classification and retry context in trace metadata to speed root-cause analysis.
- [ ] Add correlation identifiers across logs, OpenTelemetry spans, and stored traces for one-hop pivoting during incidents.
- [ ] Add explicit queue-pressure and dropped-trace diagnostics surfaces suitable for both API and CLI consumption.
- [ ] Optimize trace query/index strategy for lineage-heavy debugging queries in both SQLite and Postgres backends.
- [ ] Add performance guardrails and benchmarks for trace capture/debug instrumentation overhead on proxy hot paths.
- [ ] Expand operational playbooks for incident triage, lineage replay/fork workflows, and redaction-policy debugging.

Exit criteria:

1. Operators can generate actionable report + debug-chain output from local storage with the gateway process offline.
2. Debug outputs are deterministic and scriptable across SQLite and Postgres backends.
3. Trace chain queries (`trace_group_id`/`thread_id`/`run_id`) remain tenant-scoped and auditable.
4. Regression tests cover report/debug workflows, lineage reconstruction, and streaming edge cases.
5. Correlation identifiers reliably connect logs, spans, and persisted traces for the same request lifecycle.
6. Queue-pressure and dropped-trace diagnostics are observable without inspecting raw database tables.
7. Benchmark baselines show added debugging/tracing instrumentation does not materially regress proxy latency targets.
8. Documentation includes practical operator runbooks for local debugging and production incident response.

## What's Next

Priorities will be shaped by real usage, but the following areas are natural extensions of the current gateway:

- **Provider expansion.** Add support for Gemini, Mistral, and OpenAI-compatible endpoints. Harden provider-specific parsing for streaming, usage extraction, and cost estimation.
- **Org/workspace key management and rotation.** Managed credential lifecycle at the org and workspace level, including automated rotation and revocation controls.
- **LLM failover and routing.** Provider-aware failover so requests can be rerouted when an upstream is degraded or unavailable.
- **Deeper observability.** Richer metrics for queue pressure, write failures, provider health, and cost trends. Broader OpenTelemetry coverage and Prometheus export support.
- **Multi-instance hardening.** Stronger consistency, deployment safety, and operational tooling for Postgres-backed multi-instance environments.

## Explicit Non-Goals For This Repository

- Building or shipping a web UI.
- Browser-based login, user sessions, or end-user account management.
- Replacing downstream application logic outside gateway enforcement and observability.
