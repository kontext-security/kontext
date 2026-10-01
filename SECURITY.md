# Security Policy

## Supported versions

- `main`
- The latest released version

Older releases may not receive fixes.

## Build origin

Our GitHub release archives are built by this repository's release workflow (GoReleaser).
`checksums.txt` on each GitHub release covers those archives.

Homebrew installs of `kontext` from homebrew-core are compiled by Homebrew from our tagged source, so their binaries do not match our checksums.
`kontext --version` shows `built by Homebrew` for those builds.

Managed deployments should use the macOS pkg we provide rather than Homebrew.

## Reporting a vulnerability

- Use GitHub private vulnerability reporting for this repository when it is available.
- If private reporting is not available yet, contact a maintainer directly.
- Do not open public issues for security reports.

Please include:

- A clear description of the issue
- Steps to reproduce it
- The affected version or commit
- Any proof-of-concept or logs that help confirm impact

We will triage reports as quickly as we can and coordinate a fix before public disclosure.
