# Security Policy

## Reporting a Vulnerability

Please do not open public issues for suspected security vulnerabilities.

Use GitHub's private vulnerability reporting (Security Advisories) for this repository.
Include:

- Affected version/commit
- Reproduction steps
- Impact assessment
- Suggested remediation (if available)

## What to Expect

- We will acknowledge valid reports as quickly as possible.
- We will prioritize fixes for credential exposure, tenant isolation, and auth bypass risks.
- We will coordinate disclosure timing with reporters when appropriate.

## Scope Priorities

Highest priority classes in this project:

- Gateway auth bypass or privilege escalation
- Cross-tenant data access (`org_id` / `workspace_id` boundary violations)
- Upstream provider API key leakage in logs, traces, config stores, or error paths
- Proxy/request smuggling or header-confusion issues
- Trace tampering or audit integrity breaks
