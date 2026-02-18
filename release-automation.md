# Release Automation

This project uses GitHub Actions workflows for CI, tagging, and release publishing.

## Workflows

### `.github/workflows/ci.yml`

- Runs on pull requests and pushes to `main`.
- Validates formatting, runs tests, runs race tests, and runs `go vet`.
- Builds cross-platform artifacts on pushes to `main` after test jobs pass.

### `.github/workflows/auto-tag.yml`

- Runs after successful CI for pushes to `main`.
- Reads `release/version.conf` (`base_version=X.Y`).
- Creates the next patch tag automatically:
  - `base_version=1.1` -> `v1.1.0`, `v1.1.1`, `v1.1.2`, ...
  - `base_version=1.2` -> `v1.2.0`, `v1.2.1`, ...

### `.github/workflows/release.yml`

- Runs on version tags (`v*`).
- Builds cross-platform binaries and generates `dist/checksums.txt`.
- Publishes release artifacts to GitHub Releases.
- Builds and pushes multi-arch Docker images (`linux/amd64`, `linux/arm64`) to GHCR with `latest`, `major.minor`, and full version tags.

## Version Stream Config

Set the active major/minor stream in `release/version.conf`.

Example:

```bash
base_version=1.1
```

Check the next tag locally:

```bash
make version-next
```

## Repository Setting Required

In GitHub repository settings, set Actions workflow permissions to `Read and write permissions` so `auto-tag.yml` can push tags.
