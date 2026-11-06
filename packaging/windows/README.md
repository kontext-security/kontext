# Windows MSI

`Package.wxs` builds a per-machine MSI for x64 and arm64 with WiX v7. `.github/workflows/windows-package.yml` builds both from `.goreleaser.windows.yaml` and uploads them as the `kontext-windows-msi` artifact. Releases do not ship it yet, and it is not signed.

## Properties

| Property | Required | Meaning |
|---|---|---|
| `CLOUD_URL` | on a first install | Kontext cloud URL, `https://` only. |
| `INSTALL_TOKEN` | no | Install token, written to the `InstallToken` policy value. Hidden: Windows Installer keeps it out of its log. Optional when an MDM sets that value, for example Intune through an ingested ADMX. |
| `MODE` | no, default `observe` | `observe` or `enforce`. |

An upgrade or repair without `CLOUD_URL` or `INSTALL_TOKEN` keeps what was written before. Given again, they replace it; a new `MODE` takes effect only together with `CLOUD_URL`.

## What gets installed

| Path | What | Access |
|---|---|---|
| `%ProgramFiles%\Kontext\kontext.exe` | CLI and hook command | inherited from Program Files |
| `%ProgramFiles%\Kontext\kontextw.exe` | the same program without a console window, for the logon task | inherited |
| `%ProgramFiles%\Kontext\kontext-daemon-task.xml` | task definition the installer registers | inherited |
| `%ProgramData%\Kontext\` | system configuration folder | owner Administrators; SYSTEM and Administrators full control; Users read and list; nothing inherited from ProgramData |
| `%ProgramData%\Kontext\managed.json` | `cloud_url`, `mode`, `"install_token_ref": "registry:InstallToken"` | inherited: SYSTEM and Administrators full control, Users read |
| `HKLM\SOFTWARE\Policies\Kontext`, value `InstallToken` (REG_SZ, 64-bit view) | the install token | the key's default: administrators and SYSTEM write, Users read |
| `%ProgramData%\OpenAI\Codex\` | Codex's system folder, created only if missing and left in place on uninstall | owner Administrators; SYSTEM and Administrators full control; Users read and execute |

On install, upgrade and repair the installer also runs, as LocalSystem:

- `kontext.exe hooks install --scope system --binary "<install folder>\kontext.exe"`;
- registers the scheduled task `\Kontext\Kontext Daemon`: at the logon of any member of Users, as that user with least privilege, it starts `kontextw.exe managed-observe-daemon`. One instance per user, no time limit, runs on battery, restarts every minute on failure (up to 999 times), normal priority.

A full uninstall stops the daemons the task started, deletes the task, runs `kontext.exe hooks remove --scope system`, deletes `managed.json` and the `InstallToken` value, and the policy key if nothing else is left in it. A major upgrade keeps all of them. A failed first install rolls them back.

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
