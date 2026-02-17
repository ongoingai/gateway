## Summary

What this PR does and why.

## Checklist

- [ ] Security-sensitive paths remain fail-closed (auth, tenant scoping, key handling).
- [ ] No secrets or raw API key material are logged or persisted.
- [ ] Tenant boundaries are enforced (`org_id`, `workspace_id`).
- [ ] Tests added or updated for behavior changes.
- [ ] Docs and config examples updated when behavior changes.
- [ ] `make fmt && make test && go test -race ./...` passes locally.
