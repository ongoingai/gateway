# Contributing

Thanks for contributing to OngoingAI Gateway.

## Development Setup

1. Install Go (use the version in `go.mod`).
2. Clone the repo.
3. Run:

```bash
make build
make test
```

Optional Postgres-backed tests:

```bash
export ONGOINGAI_TEST_POSTGRES_DSN='postgres://postgres:postgres@localhost:5432/ongoingai_test?sslmode=disable'
go test ./internal/configstore ./internal/trace
```

## Documentation Contributions

Documentation is part of product quality. If behavior changes, docs should change
in the same PR.

### Docs location and format

- Product docs live under `docs/`.
- Product docs must use `.mdx`.
- Routes come from file-system structure.
  - Example: `docs/get-started/quickstart.mdx` maps to `/gateway/get-started/quickstart`.

### Required page metadata

Each docs page must include frontmatter:

```yaml
---
title: Page title
description: One to two sentence page summary.
---
```

Optional metadata:

- `nav_title`
- `related`
- `source`
- `version`

### Docs workflow

1. Choose the target page under `docs/` or create a new `.mdx` page.
2. Follow the [Google developer documentation style guide](https://developers.google.com/style).
3. Keep examples copy/paste-ready and realistic.
4. Use frontmatter metadata on every page.
5. Avoid duplicated content. Use `source`-based shared pages when content must stay in sync.

### Local preview tips

If your editor does not preview `.mdx` by default, associate `*.mdx` with markdown.

VS Code `settings.json` example:

```json
{
  "files.associations": {
    "*.mdx": "markdown"
  }
}
```

### Docs PR checklist

- Docs files under `docs/` use `.mdx`.
- New pages include `title` and `description` frontmatter.
- Commands and code examples are runnable or clearly marked as partial snippets.
- Links and slugs are consistent with file-system routes.
- Wording is clear, direct, and follows the [Google developer documentation style guide](https://developers.google.com/style).

## Workflow

1. Create a branch from `main`.
2. Keep changes scoped to one concern when possible.
3. Add or update tests for any behavior change.
4. Run before opening a PR:

```bash
make fmt
make test
go test -race ./...
```

## PR Checklist

- Security-sensitive paths remain fail-closed (`auth`, tenant scoping, key handling).
- No secrets or raw API key material are logged or persisted.
- Tenant boundaries are enforced (`org_id`, `workspace_id`).
- Docs/config examples are updated when behavior changes.
- CI is green.

## Commit Style

Use clear, imperative commit messages. Example:

- `auth: deny unmapped api routes`
- `trace: add sqlite busy retry backoff`

## Questions

Open an issue or discussion with reproduction steps, expected behavior, and actual behavior.
