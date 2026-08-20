#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <version> <checksums-file> [--staging]" >&2
  echo "" >&2
  echo "  default     renders the prod Formula/kontext.rb (public kontext releases)" >&2
  echo "  --staging   renders Formula/kontext-staging.rb (private kontext-staging-releases" >&2
  echo "              repo, token-gated download strategy, conflicts_with prod formula)" >&2
  exit 1
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
fi

version="$1"
checksums_file="$2"
staging=false
if [[ $# -eq 3 ]]; then
  if [[ "$3" == "--staging" ]]; then
    staging=true
  else
    usage
  fi
fi

if [[ ! -f "$checksums_file" ]]; then
  echo "checksums file not found: $checksums_file" >&2
  exit 1
fi

sha_for() {
  local archive="$1"
  local sha

  sha="$(awk -v archive="$archive" '$2 == archive { print $1; exit }' "$checksums_file")"
  if [[ -z "$sha" ]]; then
    echo "missing checksum for $archive" >&2
    exit 1
  fi

  printf '%s\n' "$sha"
}

darwin_amd64_archive="kontext_${version}_darwin_amd64.tar.gz"
darwin_arm64_archive="kontext_${version}_darwin_arm64.tar.gz"
linux_amd64_archive="kontext_${version}_linux_amd64.tar.gz"
linux_arm64_archive="kontext_${version}_linux_arm64.tar.gz"

darwin_amd64_sha="$(sha_for "$darwin_amd64_archive")"
darwin_arm64_sha="$(sha_for "$darwin_arm64_archive")"
linux_amd64_sha="$(sha_for "$linux_amd64_archive")"
linux_arm64_sha="$(sha_for "$linux_arm64_archive")"

if [[ "$staging" == true ]]; then
  formula_class="KontextStaging"
  strategy_class="KontextStagingGitHubPrivateRepositoryReleaseDownloadStrategy"
  release_repo="kontext-security/kontext-staging-releases"
  tag="v${version}"
  conflicts_line=$'  conflicts_with "kontext"\n'
else
  formula_class="Kontext"
  release_repo="kontext-security/kontext"
  tag="v${version}"
  conflicts_line=$'  conflicts_with "kontext-staging"\n'
fi

# Staging formulae download from a private repo. Private release assets 404
# on the github.com/.../releases/download browser URL even with a token, so
# the strategy resolves the asset id through the GitHub API and downloads it
# with Accept: application/octet-stream (same approach as Homebrew's retired
# GitHubPrivateRepositoryReleaseDownloadStrategy).
download_strategy_preamble=""
url_suffix=""
if [[ "$staging" == true ]]; then
  download_strategy_preamble=$(cat <<EOF
require "download_strategy"
require "json"
require "utils/curl"

class ${strategy_class} < CurlDownloadStrategy
  def initialize(url, name, version, **meta)
    super
    match = url.match(%r{^https://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/(.+)\$})
    raise CurlDownloadStrategyError, "unexpected release URL: #{url}" unless match
    @owner, @repo, @tag, @asset_name = match.captures
    @token = ENV["HOMEBREW_GITHUB_API_TOKEN"].to_s.strip
    odie <<~EOS if @token.empty?
      HOMEBREW_GITHUB_API_TOKEN is required to install kontext-staging: release
      assets live in the private ${release_repo} repository.

      Authenticate with GitHub CLI (your account must have read access to that
      repo) and retry:
        HOMEBREW_GITHUB_API_TOKEN="\$(gh auth token)" brew install kontext-security/tap/kontext-staging
    EOS
  end

  private

  def _fetch(url:, resolved_url:, timeout:)
    curl_download "https://api.github.com/repos/#{@owner}/#{@repo}/releases/assets/#{asset_id}",
                  "--header", "Accept: application/octet-stream",
                  "--header", "Authorization: Bearer #{@token}",
                  to: temporary_path, timeout: timeout
  end

  def asset_id
    release = JSON.parse(Utils::Curl.curl_output(
      "--fail", "--silent", "--location",
      "--header", "Accept: application/vnd.github+json",
      "--header", "Authorization: Bearer #{@token}",
      "https://api.github.com/repos/#{@owner}/#{@repo}/releases/tags/#{@tag}"
    ).stdout)
    asset = release.fetch("assets", []).find { |a| a["name"] == @asset_name }
    odie "asset #{@asset_name} not found on #{@owner}/#{@repo} release #{@tag}" unless asset
    asset["id"]
  end
end
EOF
)
  # Command substitution strips trailing newlines; restore the separator
  # (blank line between the strategy class and the formula class).
  download_strategy_preamble+=$'\n\n'
  url_suffix=",
          using: ${strategy_class}"
fi

caveats_block=""
if [[ "$staging" == true ]]; then
  caveats_block=$(cat <<'EOF'

  def caveats
    <<~EOS
      This is the STAGING build of kontext, for testing against the staging
      backend. It conflicts with the prod formula (brew uninstall kontext
      first, or vice versa).

      Point it at the staging backend before setup:
        export KONTEXT_API_URL=https://api.staging.kontext.security
        kontext setup --cloud-url https://api.staging.kontext.security --token <staging-token>

      If installation fails with a GitHub authentication error, retry with:
        HOMEBREW_GITHUB_API_TOKEN="$(gh auth token)" brew install kontext-security/tap/kontext-staging
    EOS
  end
EOF
)
  caveats_block+=$'\n'
fi

cat <<EOF
# typed: false
# frozen_string_literal: true

# This file was generated by the Kontext release workflow. DO NOT EDIT.
${download_strategy_preamble}class ${formula_class} < Formula
  desc "Identity, credentials, and governance for AI agents"
  homepage "https://kontext.security"
  version "${version}"
  license "MIT"

  depends_on "llama.cpp"
${conflicts_line}
  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/${release_repo}/releases/download/${tag}/${darwin_amd64_archive}"${url_suffix}
      sha256 "${darwin_amd64_sha}"
    end
    if Hardware::CPU.arm?
      url "https://github.com/${release_repo}/releases/download/${tag}/${darwin_arm64_archive}"${url_suffix}
      sha256 "${darwin_arm64_sha}"
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "https://github.com/${release_repo}/releases/download/${tag}/${linux_amd64_archive}"${url_suffix}
      sha256 "${linux_amd64_sha}"
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/${release_repo}/releases/download/${tag}/${linux_arm64_archive}"${url_suffix}
      sha256 "${linux_arm64_sha}"
    end
  end

  def install
    bin.install "kontext"
  end
${caveats_block}
  test do
    system bin/"kontext", "--version"
  end
end
EOF
