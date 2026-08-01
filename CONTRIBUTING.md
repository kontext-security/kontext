# Contributing

Thanks for helping improve Kontext CLI.

## Ground rules

- Keep changes small, direct, and production-ready.
- Use conventional commits. Release automation depends on them.
- Do not add compatibility shims unless they are required for a safe production migration.
- Prefer the standard library and existing dependencies over new packages.

## Local setup

```bash
go mod download
go test ./...
go test -race ./...
go vet ./...
gofmt -w ./cmd ./internal
```

## Pull requests

- Include tests for behavior changes.
- Update the README when user-facing behavior changes.
- Keep generated code, docs, and release notes in sync with the code.
- Public PRs also run `dependency-review`, so dependency changes must pass both CI and GitHub advisory checks.

## Release flow

- `release-please` opens release PRs and calculates semver bumps from conventional commits.
- GitHub Releases are built with GoReleaser.
- Homebrew publishing is handled from the release workflow.
