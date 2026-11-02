#!/bin/sh
# Runs the Codex proxy end to end: a real Codex binary sends its turns through
# the proxy to a mock backend, and a fake daemon decides the printed parts.
# Nothing needs credentials, nothing calls a model, and a Seatbelt profile
# refuses every connection off the machine. macOS only.
#
# Usage: scripts/codex-proxy-e2e.sh /path/to/codex [--launchd]
#
# The ChatGPT app's binary works as is
# (/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex);
# a release CLI needs codex-code-mode-host from the same release next to it.
#
# With --launchd, it also loads the proxy's real launchd job, under a label of
# its own, from a temporary home: the proxy answers through socket
# activation, Codex keeps working through it after a downgrade replaced the
# daemon's binary, and the job takes Codex's route away once no daemon holds
# it. KONTEXT_DOWNGRADE_E2E_BIN may name an older kontext build to downgrade
# to. ~/.codex and a job already loaded are never touched.
set -eu
codex=${1:?usage: scripts/codex-proxy-e2e.sh /path/to/codex [--launchd]}
cd "$(dirname "$0")/.."
KONTEXT_CODEX_E2E_BIN=$codex go test -count=1 -run TestCodexEndToEnd -v ./internal/codexproxy/
if [ "${2:-}" = "--launchd" ]; then
	binary=$(mktemp -d)/kontext
	go build -o "$binary" ./cmd/kontext
	KONTEXT_LAUNCHD_E2E_BIN=$binary go test -count=1 -run TestRealLaunchdJob -v ./internal/codexroute/
	KONTEXT_CODEX_E2E_BIN=$codex KONTEXT_LAUNCHD_E2E_BIN=$binary go test -count=1 -run TestCodexAfterDowngrade -v ./internal/codexproxy/
fi
