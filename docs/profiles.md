# Profiles (internal)

> **Internal development tool, not a product feature.** `kontext profile` is a
> hidden command — it does not appear in `kontext --help` and is not part of the
> supported surface. It exists for people who need one Mac to talk to several
> workspaces or backends (prod, staging, a local API) without reinstalling.
>
> The code ships in the released binary because it has to: profiles change how the
> daemon resolves its config, and the daemon is the same binary. An install that
> never runs a profile command resolves exactly the paths it always did.
>
> If profiles ever become customer-facing, un-hide the command in
> `cmd/kontext/profile.go`, and say so here.

A **profile** binds one workspace on one backend to its own config, installation
identity, install token, and ledger cache. Exactly one profile is active at a
time, and switching takes one command:

```bash
kontext profile use staging
```

No reinstall, no re-pasting a token. This replaces the older workflow where
pointing the CLI at a different backend or workspace meant re-running
`kontext setup` with a fresh `--cloud-url` and token.

## Commands

```bash
kontext profile ls                       # list; * marks the active one
kontext profile ls --json                # machine-readable
kontext profile add staging              # endpoint inferred, see below
kontext profile use staging
kontext profile rename old new
kontext profile rm staging
kontext profile migrate                  # one-time, see below
```

`profile add` runs the same setup `kontext setup` does, but writes into the named
profile. The install token must come from the dashboard **for the backend you are
pointing at** — a staging token will not authenticate against production. Pass
`--use` to switch to the profile as soon as it is created.

### Environments and workspaces

They are separate axes:

- the **environment** is which backend a profile talks to — there are three
- the **workspace** is which install token it uses — unlimited, within an
  environment

So several profiles can share an environment while pointing at different
workspaces. Choose the environment with `--env`:

```bash
kontext profile add --env staging          # name derived from the workspace
kontext profile add staging-hasan --env staging   # or name it yourself
```

The name is optional. It is only a handle — a directory and what `profile use`
takes — and after the token is validated the workspace and environment are both
known, which is enough to derive one: the environment when it is free
(`staging`), otherwise qualified by the workspace (`staging-acme-corp`). The
chosen name is printed.

`profile add` always prints the backend it resolved before asking for a token,
because a token from the wrong environment is rejected with an error that names
neither the cause nor the fix.

`profile ls --json` reports each profile's `environment` (`production`,
`staging`, `local`, or absent for anything else), so a consumer can group by it
without hardcoding the URLs.

To pass a token without it appearing in the process list — `--token` is a
command-line argument, visible to every process on the machine via `ps` — read it
from stdin instead:

```bash
printf '%s' "$TOKEN" | kontext profile add staging-hasan --env staging --token-stdin
```

### Known environments

`--env` accepts these, and a profile NAMED after one gets it without `--env`:

| Name | Endpoint |
| --- | --- |
| `prod`, `production` | `https://api.kontext.security` |
| `staging`, `stg` | `https://api.staging.kontext.security` |
| `local`, `localdev`, `dev` | `http://localhost:4000`, with plaintext loopback enabled |

```bash
kontext profile add prod       # no --cloud-url needed
kontext profile add localdev   # no --allow-http-loopback needed either
```

Precedence, most explicit first: `--cloud-url`, then `--env`, then a preset
matching the profile name. A name matching nothing falls back to production —
which is why the backend is always printed. Only the local presets enable
plaintext loopback; a preset can never turn it on for a hosted backend.

### One profile per workspace

`profile add` refuses a workspace that is already bound on the same backend:

```
Error: workspace Acme Corp (org_1) is already set up as profile "staging" on
https://api.staging.kontext.security
```

Two profiles for one workspace would hold its records in two ledgers and present
it two device identities — no purpose, and confusing to inherit.

The rule is per **workspace**, not per environment: several workspaces on one
backend is exactly what workspaces are for. The same organization id on two
different backends is likewise two different workspaces, and both are allowed.

The check lives in the CLI because the workspace is only known once the hosted
API answers the token — nothing earlier can tell two tokens apart.

### Renaming

```bash
kontext profile rename default staging
```

Mostly useful after `migrate`, which has to name the migrated install `default`
before it can know which backend that install pointed at.

The install token is not touched. A profile's token is located by the reference
recorded in its config, not by its directory name, so a rename needs no keychain
access and produces no authorization prompt. Renaming the *active* profile
restarts the background agent, since its resolved paths change; renaming an
inactive one touches nothing the daemon is reading and leaves it alone.

`kontext setup` still works and is unchanged for anyone who never touches
profiles. On a machine that has profiles, it rotates the *active* profile's
token.

## Local development

To point at a backend running on your own machine, opt into plaintext http. The
`localdev` preset does both for you:

```bash
kontext profile add localdev --use
```

Which is equivalent to spelling it out:

```bash
kontext profile add localdev \
  --cloud-url http://localhost:4000 \
  --allow-http-loopback
kontext profile use localdev
```

The permission is recorded in the profile's `managed.json`, not taken from the
environment. That matters: a LaunchAgent does not inherit a shell's environment,
so the older `KONTEXT_MANAGED_ALLOW_HTTP_LOCALHOST` variable was invisible to the
background agent. A config the terminal accepted would be rejected by the daemon
that had to serve it — everything looked fine while nothing was reported. With the
permission on disk, the CLI, the daemon, and the menu bar app all read the same
answer.

That environment variable still works, for setups that already rely on it.

Two bounds on the relaxation:

- **Loopback only.** It widens the accepted *scheme*, and only for `localhost`,
  `127.0.0.1`, or `::1`. Setting it alongside a routable host is still refused, so
  it can never send records in plaintext off the machine.
- **Never under MDM.** A system-scope config carrying it is refused outright
  rather than served.

`kontext doctor` states the posture explicitly when it is on, so a leftover
local-dev profile is obvious rather than something to infer from the URL.

## Layout

```text
~/Library/Application Support/Kontext/
  active                     # the active profile's name — the only thing a switch writes
  profiles/
    default/
      managed.json           # cloud_url, mode, install token ref, loopback opt-in
      installation.json      # this profile's ins_* device identity
      workspace.json         # cached workspace label, for display only
      managed-observe/
        guard.db             # ledger cache (+ -wal/-shm)
        stream-state.json    # export cursor
    staging/
      ...
```

Each profile also gets its own login-keychain item,
`kontext-install-token.<profile>`. The profile's `managed.json` names it, so the
daemon resolves whatever the active config points at and a switch needs no
keychain work at all.

## What a switch does

1. Validates the target profile's config parses and its install token is
   readable. A failure here leaves the current profile active and serving.
2. Stops the background agent.
3. Rewrites `active`.
4. Starts the background agent and waits for it to report in.

The agent is **restarted rather than reloaded**, deliberately. Only part of its
configuration is re-read at runtime: the export stream re-reads the cloud URL and
token on every flush tick, but the Cedar policy client and the endpoint-config
client are built once at startup. Reloading config alone would leave policy
decisions being evaluated against the old backend while events streamed to the
new one.

Expect a switch to take a second or two.

## Per-profile ledger caches

Each profile has its own `guard.db`, and the export cursor lives beside its
database. That is not incidental tidiness — it is what stops an export backlog
captured for one workspace from being flushed to another. Ledger rows carry no
workspace of their own, and the streamer sends whatever is pending to whatever
the active config names, so separate databases are the boundary.

## Identity

Each profile has its own `installation.json`. A Mac enrolled in two workspaces
appears as two endpoints, one per workspace, rather than one endpoint reporting
to both. Switching away and back reuses the same identity rather than minting a
new one, so a profile does not spawn a phantom device each time you return to it.

## Migrating an existing install

Installs made before profiles existed keep their state directly under
`~/Library/Application Support/Kontext`. They keep working untouched: with no
`active` pointer, every path resolves exactly as it always did.

To make such an install switchable, move it into the `default` profile:

```bash
kontext profile migrate
```

This stops the agent, moves `managed.json`, `installation.json`, and
`managed-observe/` into `profiles/default/`, points `active` at it, and starts
the agent again. The install token is not touched — the migrated config keeps
naming the original unsuffixed keychain item, so no keychain prompt appears.

`kontext profile add` runs the migration first if it is needed, so the original
install never becomes unreachable by name.

The migration moves state rather than copying it. After it runs the legacy paths
are empty, so anything still resolving them fails closed instead of quietly
operating on a stale copy of the config.

## Organization-managed Macs

An MDM config under `/Library` still wins over everything user-scoped, profiles
included. A self-serve profile cannot re-point an organization-managed Mac. On
such a machine `kontext doctor` reports the system config as authoritative and
profile switching has no effect on it.

## Checking state

```bash
kontext doctor           # names the active profile alongside daemon and hook health
kontext doctor --json    # same findings, machine-readable
```

`doctor --json` exits zero even when unhealthy — read `healthy` from the payload.
It cannot be combined with `--fix`.

Together, `profile ls --json` and `doctor --json` are the two surfaces intended
for programmatic consumers; neither touches the network, and `profile ls` never
touches the keychain, so both are safe to poll.

If `active` is ever corrupted by hand, path resolution falls back to the legacy
paths. That fails closed rather than open — post-migration nothing is there, so
the daemon parks instead of streaming with the wrong workspace's credentials —
and `kontext doctor` names the bad pointer explicitly rather than reporting the
machine as unconfigured.

## Uninstalling

`kontext setup --uninstall` removes every profile's config and keychain item, not
just the active one, and clears the `active` pointer. It keeps installation
identities and ledger data, as it always has, and prints where they are.

## Development

`KONTEXT_PROFILE_ROOT` overrides the root directory for both layouts at once, so
tests and local experiments never touch a real install. The LaunchAgent never
sets it: a switch must not depend on an environment variable the daemon does not
inherit.
