# Contributing

Thanks for helping improve Kontext.

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
- macOS binaries are signed with a Developer ID certificate and notarized when the `MACOS_SIGN_P12`, `MACOS_SIGN_PASSWORD`, `MACOS_NOTARY_ISSUER_ID`, `MACOS_NOTARY_KEY_ID` and `MACOS_NOTARY_KEY` secrets are set (`.p12` and `.p8` base64-encoded). Without them the release ships ad-hoc signed binaries.
- Homebrew publishing is handled from the release workflow.
