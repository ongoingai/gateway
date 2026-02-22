# Authorization Model

OngoingAI gateway authorization is machine-to-machine and key-based.

Core hierarchy:

1. Organization
2. Workspace
3. Gateway Key

Gateway keys are scoped to a workspace. Traces and analytics are read in workspace scope. Key-management operations are workspace-scoped and require elevated permission.

## Permission Matrix

| Resource | Action | Scope | Methods | Routes | Required Permission |
|----------|--------|-------|---------|--------|---------------------|
| `health` | `read` | `public` | `GET`, `HEAD` | `/api/health` | none |
| `traces` | `read` | `workspace` | `GET`, `HEAD` | `/api/traces`, `/api/traces/:id` | `analytics:read` |
| `diagnostics` | `read` | `workspace` | `GET`, `HEAD` | `/api/diagnostics/trace-pipeline` | `analytics:read` |
| `analytics` | `read` | `workspace` | `GET`, `HEAD` | `/api/analytics/*` | `analytics:read` |
| `gateway_keys` | `manage` | `workspace` | `GET`, `POST`, `DELETE` | `/api/gateway-keys*` | `keys:manage` |
| `proxy` | `forward` | `workspace` | `*` | `/openai/*`, `/anthropic/*` | `proxy:write` |

Notes:

- CORS preflight (`OPTIONS`) is allowed on protected prefixes.
- Protected routes also require a valid gateway key in the configured gateway header.
- Proxy routes also require provider credentials (`Authorization` or `X-API-Key`) from the client request.

## Role Matrix

| Role | Default Permissions |
|------|---------------------|
| `owner` | `proxy:write`, `analytics:read`, `keys:manage` |
| `admin` | `proxy:write`, `analytics:read`, `keys:manage` |
| `developer` | `proxy:write`, `analytics:read` |
| `member` | `proxy:write`, `analytics:read` |
| `viewer` | `analytics:read` |

Unknown roles receive no implicit permissions.

Custom permissions in key config are additive and can grant specific permissions explicitly.

## Deny-by-default

For protected prefixes (`/api`, provider proxy prefixes), unmapped actions are denied with HTTP 403.

Examples:

- `/api/internal/debug` -> denied (`action_unmapped`)
- `GET /api/gateway-keys/:id/rotate` -> denied (rotate is only `POST`)

This keeps authorization fail-closed whenever an endpoint is added without an explicit policy mapping.
