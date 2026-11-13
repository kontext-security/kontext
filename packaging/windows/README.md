# Windows MSI

`Package.wxs` builds a per-machine MSI for x64 and arm64 with WiX v7. `.github/workflows/windows-package.yml` builds both from `.goreleaser.windows.yaml` and uploads them as the `kontext-windows-msi` artifact, to check the package on pull requests. A release gets its MSIs from `.github/workflows/windows-msi-release.yml`, which builds them from the programs in that release's Windows zips and attaches `kontext_<version>_windows_amd64.msi`, `kontext_<version>_windows_arm64.msi` and `checksums_windows_msi.txt`. The MSIs are not signed yet.

## Properties

| Property | Required | Meaning |
|---|---|---|
| `CLOUD_URL` | on a first install | Kontext cloud URL: `https://<host>`, at most with a port. A path, query or anything else after the host fails the install, as the daemon would refuse it. |
| `INSTALL_TOKEN` | no | Install token, written to the `InstallToken` policy value. Hidden: Windows Installer keeps it out of its log. Optional when an MDM sets that value, for example Intune through an ingested ADMX; a value the installer didn't write stays on uninstall. |
| `MODE` | no, default `observe` | `observe` or `enforce`. |

An upgrade or repair without `CLOUD_URL` or `INSTALL_TOKEN` keeps what was written before. Given again, they replace it; a new `MODE` takes effect only together with `CLOUD_URL`.

## What gets installed

| Path | What | Access |
|---|---|---|
| `%ProgramFiles%\Kontext\kontext.exe` | CLI and hook command, built without the step-safety model | inherited from Program Files |
| `%ProgramFiles%\Kontext\kontextw.exe` | the same program with the model and without a console window, for the logon task that runs the daemon | inherited |
| `%ProgramFiles%\Kontext\kontext-daemon-task.xml` | task definition the installer registers | inherited |
| `%ProgramData%\Kontext\` | system configuration folder | owner Administrators; SYSTEM and Administrators full control; Users read and list; nothing inherited from ProgramData |
| `%ProgramData%\Kontext\managed.json` | `cloud_url`, `mode`, `"install_token_ref": "registry:InstallToken"` | inherited: SYSTEM and Administrators full control, Users read |
| `HKLM\SOFTWARE\Policies\Kontext`, value `InstallToken` (REG_SZ, 64-bit view) | the install token | the key's default: administrators and SYSTEM write, Users read |
| `%LOCALAPPDATA%\Kontext\daemon.log`, per user | what the daemon started by the task would print, crashes included; a daemon that starts and finds it past 10 MB moves it to `daemon.log.1` | the user's own folder; not installed, written by the daemon |
| `%ProgramData%\OpenAI\Codex\` | Codex's system folder, created only if missing and left in place on uninstall | owner Administrators; SYSTEM and Administrators full control; Users read and execute |

On install, upgrade and repair the installer also runs, as LocalSystem:

- `kontext.exe hooks install --scope system --binary "<install folder>\kontext.exe"`;
- registers the scheduled task `\Kontext\Kontext Daemon`: at the logon of any member of Users, as that user with least privilege, it starts `kontextw.exe managed-observe-daemon`. One instance per user, no time limit, runs on battery, restarts every minute on failure (up to 999 times), normal priority. An install or upgrade also starts it right away for everyone already signed in.

A full uninstall stops the daemons the task started, deletes the task, runs `kontext.exe hooks remove --scope system`, deletes `managed.json`, and the `InstallToken` value if the installer wrote it, then the policy key and `%ProgramData%\Kontext` if nothing else is left in them. It keeps what it removes until it commits, so a cancelled or failed uninstall puts everything back. If it can't remove the configuration or the token, for instance because the policy key can't be read, the uninstall fails and rolls back rather than leave the token behind; removing the task and the hooks never stops an uninstall.

An upgrade keeps the configuration, the token, the hooks and the task. It stops the running daemons, removes the old version and installs the new one in one transaction, and starts the daemons again. A failed upgrade restores the old version, and the logon task's restart on failure starts the daemons on it within about a minute. A failed first install rolls everything back.

`managed.json`, the token value and the task are written by `kontext-install.js`, a JScript custom action inside the MSI, so the token passes through no command line and no installer log.

## Install and uninstall

From an elevated prompt:

```
msiexec /i kontext_<version>_windows_amd64.msi /qn /norestart /l*v kontext-install.log CLOUD_URL=https://<cloud host> INSTALL_TOKEN=<token> MODE=observe
```

```
msiexec /x kontext_<version>_windows_amd64.msi /qn /norestart /l*v kontext-uninstall.log
```

`/x` also takes the product code instead of the file. Exit code 0 is success, 3010 success with a restart pending.

## Build locally

On Windows with the .NET SDK, from the repository root:

```
goreleaser build --snapshot --clean --config .goreleaser.windows.yaml
dotnet tool install wix --version 7.0.1 --tool-path %TEMP%\wix
%TEMP%\wix\wix build packaging\windows\Package.wxs -arch x64 -d ProductVersion=1.19.0 -d BinDir=%CD%\dist\windows_amd64 -acceptEula wix7 -o kontext.msi
%TEMP%\wix\wix msi validate -acceptEula wix7 kontext.msi
```

`-acceptEula wix7` accepts the WiX v7 OSMF EULA.
