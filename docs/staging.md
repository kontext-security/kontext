# Staging CLI builds

A staging channel for testing a CLI branch against the **staging backend**
before the branch lands on `main` and becomes a prod release.

> **Two separate things.** Pointing the CLI at the staging *backend* is a
> [profile](profiles.md) switch — `kontext profile use staging` — and needs no
> reinstall, because the released binary can talk to either backend. Running a
> *branch build* is what this document is about, and that does need a different
> binary. Reach for the staging channel only when you need unreleased code; to
> test released code against staging, add a profile.

- **Prod:** `brew install kontext-security/tap/kontext` — built from `main`
  by release-please, public assets on this repo's releases.
- **Staging:** `brew install kontext-security/tap/kontext-staging` — built
  on demand from any branch by the `Staging Release` workflow in the
  **private** `kontext-security/kontext-cli-staging-releases` repo (org
  members only). Staging tags are valid SemVer prereleases such as
  `v0.0.0-staging.20260721.4`. They are published only to the separate
  staging-releases repo, so release-please in the source repo never sees them.

The staging formula installs the same `kontext` binary as prod, so the two
formulae `conflicts_with` each other — uninstall one before installing the
other.

## Publishing a staging build

Prerequisites (one-time, repo admins, configured in the private release repo):

1. Its `main` branch contains the `Staging Release` workflow.
2. Its `HOMEBREW_TAP_TOKEN` Actions secret has Contents: write access to
   `kontext-security/homebrew-tap`. Releases use the private repository's own
   short-lived `GITHUB_TOKEN` and need no cross-repository release credential.

Then, from any branch:

```bash
gh workflow run staging-release.yml \
  -R kontext-security/kontext-cli-staging-releases \
  -f ref=my-feature-branch
```

(or open `kontext-cli-staging-releases` → Actions → Staging Release → Run
workflow). A credential-free job builds the selected CLI ref. A fresh runner
then publishes its four archives as a private prerelease and updates
`Formula/kontext-staging.rb` in `kontext-security/homebrew-tap`. Re-run it to
publish a newer build; the version (`0.0.0-staging.YYYYMMDD.RUN`) increases
monotonically so `brew upgrade kontext-staging` picks it up.

## Installing and testing

Requires a GitHub account with read access to the private staging-releases
repo (org members). Homebrew needs that account's token to download assets:

```bash
# one-time
gh auth login

brew uninstall kontext 2>/dev/null || true   # conflicts_with prod
HOMEBREW_GITHUB_API_TOKEN="$(gh auth token)" \
  brew install kontext-security/tap/kontext-staging

# point the CLI at the staging backend
kontext profile add staging \
  --cloud-url https://api.staging.kontext.security \
  --token <staging-token> \
  --use
```

The install token must be one created in the **staging** dashboard; a production
token will not authenticate against the staging backend. Switch back and forth
with `kontext profile use <name>` — the profiles keep separate tokens, identities,
and ledger caches, so staging events are never exported to production.

`HOMEBREW_GITHUB_API_TOKEN` must be set on every `install`/`upgrade` — the
formula's error message repeats the incantation if you forget.

To go back to the prod *backend*, switch profiles — no reinstall:

```bash
kontext profile use prod
```

To go back to the prod *binary*:

```bash
brew uninstall kontext-staging
brew install kontext-security/tap/kontext
```

## Promoting to prod

There is no separate promote step: merge the tested branch to `main` as usual
and release-please cuts the next prod release. Staging prereleases accumulate
in the private repo as throwaway artifacts; prune old ones occasionally.

## Caveats

- The binary still defaults to production. A `staging` profile persists the
  staging URL for both the CLI and the managed background agent, which is why it
  is preferred over the older `KONTEXT_API_URL` export — that variable is not
  inherited by the LaunchAgent, so it never reached the daemon.
- Both formulae install a binary named `kontext`, so the staging and prod
  channels `conflicts_with` each other. Profiles are per-machine state and
  survive swapping the binary underneath them.
- The staging backend hostname is not secret — it appears in this public
  repo. The private-releases mechanism only gates the binaries, not the
  topology.
