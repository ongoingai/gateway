# PII Handling Strategy

## Purpose

Define a practical, policy-driven approach for handling sensitive data in OngoingAI Gateway while preserving proxy correctness and low latency.

## Design Principles

- Default-safe: reduce accidental sensitive-data persistence.
- Fail-closed for policy uncertainty on protected paths when enforcement mutates or blocks traffic.
- Preserve proxy transparency by default (do not mutate upstream traffic unless explicitly configured).
- Keep behavior deterministic and testable.
- Preserve tenant isolation for all detection, redaction, and audit outputs.
- Preserve proxy availability when storage-only redaction paths fail.

## Scope

This document covers PII handling for gateway-captured request/response data and related metadata.

Out of scope for initial implementation:

- Browser/session UI concerns.
- LLM-based redaction/detection.
- Broad low-confidence classifiers with high false-positive rates.

## Policy Modes

PII handling should be policy-driven and scoped by org/workspace/key/provider/route.

1. `off`
- No additional body redaction beyond existing credential/header protections.

2. `redact_storage` (default when body capture is enabled)
- Forward request/response unchanged.
- Redact only the captured copy before persistence.
- If redaction execution fails, drop body persistence for that trace, emit audit/metrics, and continue proxy traffic.

3. `redact_upstream` (opt-in)
- Redact selected request/response fields before forwarding upstream.
- Use only with explicit customer intent because this can change model behavior.
- If policy evaluation or redaction is unavailable, deny protected requests (fail-closed).

4. `block` (opt-in)
- Deny request when protected patterns are detected.
- Emit explicit audit events and stable error semantics.
- If policy evaluation is unavailable, deny protected requests (fail-closed).

## Pipeline Placement

Default behavior should use capture-time transformation:

`proxy forward -> capture copy -> redact copy -> persist`

This keeps forwarding behavior stable while protecting stored traces.

## Failure Semantics

Define mode-specific failure behavior explicitly:

- `redact_storage`: fail-open for proxy forwarding, fail-closed for persistence of sensitive bodies (drop/redact-only metadata, never store raw body on redaction error).
- `redact_upstream`: fail-closed for protected routes when policy/redaction components are unavailable.
- `block`: fail-closed for protected routes when policy evaluation is unavailable.

## Detection and Redaction Rules

Use deterministic detectors and field rules.

High-confidence defaults:

- Headers (request and response): `authorization`, `cookie`, `set-cookie`, `x-api-key`.
- Body patterns: email, phone (conservative), SSN, token-like secrets.
- Field-name redaction: `email`, `phone`, `password`, `token`, `secret`, `ssn`, `api_key`, `authorization`.

Guidance:

- Keep address detection off by default (high false-positive risk).
- Prefer field/path-based rules over blind free-text rewriting.
- Do not depend on LLM calls for policy enforcement.
- Apply header matching case-insensitively after canonicalization.

## Replacement Format

Use stable placeholders for debuggability:

- Example: `[EMAIL_REDACTED:<hash>]`

Hashing requirements:

- Use SHA-256 over `tenant_salt + original_value`.
- Salt scope should be workspace-level so values correlate within a workspace but not across tenants.

Salt lifecycle requirements:

- Generate salts with CSPRNG (minimum 32 bytes).
- Store salts in control-plane/config infrastructure with least-privilege access.
- Support rotation with explicit operator impact: rotation breaks forward correlation for newly redacted values.
- Never expose raw salts in logs, traces, or errors.

## Large Payload Considerations

For very large inputs/outputs:

- Keep strict capture caps (`body_max_size`).
- Perform redaction in streaming/chunked form where practical.
- Track truncation explicitly in metadata so operators understand analysis limits.

Coverage guarantees:

- Redaction guarantees apply to all captured bytes written to storage.
- Bytes outside the capture window must never be persisted.
- If truncation occurs, mark `redaction_truncated=true` so operators understand coverage boundaries.

## Storage and Audit Metadata

Persist redaction outcomes without sensitive values:

- `redaction_applied` (bool)
- `redaction_counts` (by detector type)
- `redaction_policy_id` (string/version)
- `redaction_truncated` (bool, if applicable)

Do not store original sensitive values in logs, traces, or errors.

## Minimal v1 Rollout

1. Keep body capture opt-in.
2. If body capture is enabled, default to `redact_storage`.
3. Implement high-confidence header/body/field redaction.
4. Emit redaction summary metadata per trace.
5. Add regression tests for failure paths and streaming paths.

Defer to later phases:

- `redact_upstream`
- `block`
- user-defined regex bundles
- low-confidence detectors (for example street addresses)

## Recommended Config Shape

```yaml
pii:
  mode: redact_storage # off | redact_storage | redact_upstream | block
  detectors:
    email: true
    phone: true
    ssn: true
    token_like: true
    address: false
  headers:
    denylist: ["authorization", "cookie", "set-cookie", "x-api-key"]
  body:
    key_denylist: ["email", "phone", "password", "token", "secret", "ssn", "api_key", "authorization"]
  replacement:
    format: "[{type}_REDACTED:{hash}]"
    hash: sha256
    salt_scope: workspace
scopes:
  - match:
      org_id: org-default
      workspace_id: workspace-default
      route_prefix: /openai/v1
    pii:
      mode: redact_storage
  - match:
      org_id: acme
      workspace_id: acme-compliance
      route_prefix: /openai/v1/chat/completions
    pii:
      mode: block
      detectors:
        email: true
        phone: true
        ssn: true
```

## Test Requirements

- PII is never persisted in traces under normal, error, retry, and partial-stream scenarios.
- Redaction is deterministic and stable for identical inputs in the same workspace.
- Cross-tenant hash correlation is not possible.
- Request and response credential headers are always redacted (case-insensitive key matching).
- Policy-scoped behavior (org/workspace/route/provider) is enforced correctly.
- `redact_storage` failures never block proxy forwarding and never persist raw captured bodies.
- Truncation behavior is explicit: uncaptured bytes are not stored and `redaction_truncated` is set.

## Operational Metrics

Track and expose:

- Redactions applied count (total and by detector type)
- Redaction failures
- Policy-evaluation failures (by mode and route)
- Truncation rate
- Blocked-request count (when `block` mode is enabled)

These metrics are required for enterprise auditability and operator trust.
