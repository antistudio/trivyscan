# Installation Guide

## Requirements

- **Linux/macOS**: `bash` 3.2+, `curl` or `wget`, `tar`, `sha256sum` or `shasum`
- **Windows**: PowerShell 5.1+
- **Trivy**: installed automatically when missing or too old
- Trivy **v0.70.0+** is required

---

## Install

### Linux / macOS — per-user (recommended)

No sudo, no root-owned files:

```bash
curl -fsSL https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.sh | bash
```

Default paths:

```text
~/.local/bin/trivyscan
~/.local/bin/trivy
~/.local/share/trivyscan/install.env
```

The installer adds `~/.local/bin` to your shell profile if needed. Use `--no-modify-path` to skip that.

### Linux / macOS — system-wide

```bash
curl -fsSL https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.sh | sudo bash -s -- --system
```

Installs to `/usr/local/bin` and `/usr/local/share/trivyscan`.

### Windows — per-user (recommended)

No admin required:

```powershell
irm https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.ps1 | iex
```

Default paths:

```text
%LOCALAPPDATA%\Programs\TrivyScan\trivyscan.exe
%LOCALAPPDATA%\Programs\TrivyScan\trivy.exe
%LOCALAPPDATA%\Programs\TrivyScan\install.json
```

### Windows — system-wide

`-System` needs a file, not `irm | iex`:

```powershell
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.ps1 -OutFile "$env:TEMP\install.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TEMP\install.ps1" -System
```

Installs `trivyscan.exe` to `%ProgramFiles%\TrivyScan` and updates `trivy.exe` in `%ProgramFiles%\Trivy` (legacy layout preserved).

### From a release archive (manual)

```bash
sha256sum --ignore-missing -c trivyscan_<version>_checksums.txt   # macOS: shasum -a 256 --ignore-missing -c ...
tar -xzf trivyscan_<version>_linux_amd64.tar.gz
cd trivyscan_<version>_linux_amd64
./install.sh
```

When `trivyscan` sits next to `install.sh`, that local binary is installed; remote downloads are still checksum-verified.

---

## What the installer does

1. Resolves the latest stable TrivyScan and Trivy releases (or uses your pinned versions).
2. Compares with installed versions:
   - older → update
   - equal → skip download
   - newer → keep, unless you pin a version or pass `--force`/`-Force`
3. Downloads with retries and verifies every remote asset against the release `checksums.txt`.
4. Installs atomically, verifies `--version`, and rolls back on failure.
5. Adds the install directory to PATH idempotently.
6. Runs `trivyscan -u` to update the vulnerability databases.
7. Stops at a summary and waits for Enter in interactive PowerShell; use `-NonInteractive` for automation.

Checksums are mandatory for remote downloads. `TRIVYSCAN_SKIP_CHECKSUM` is no longer supported.

---

## Options

### `install.sh`

| Option | Meaning |
|---|---|
| `--system` | Install to `/usr/local` (root/sudo) |
| `--prefix DIR` | Install prefix (default `$HOME/.local` or `/usr/local`) |
| `--trivyscan-version V` | Pin TrivyScan version |
| `--trivy-version V` | Pin Trivy version |
| `--skip-db-update` | Do not run `trivyscan -u` |
| `--strict` | Exit 1 if the DB update fails |
| `--no-modify-path` | Do not edit the shell profile |
| `--force`, `-f` | Reinstall even when unchanged |
| `--uninstall`, `-u` | Remove managed files |
| `--purge` | With `--uninstall`, remove the Trivy DB cache |
| `--help`, `-h` | Usage |

Environment equivalents: `TRIVYSCAN_VERSION`, `TRIVY_VERSION`, `TRIVYSCAN_PREFIX`,
`TRIVYSCAN_SKIP_DB_UPDATE=1`, `TRIVYSCAN_STRICT=1`, `TRIVYSCAN_NO_PATH=1`.

### `install.ps1`

| Option | Meaning |
|---|---|
| `-System` | Install system-wide (admin; run from a file) |
| `-InstallDir DIR` | Install directory override |
| `-TrivyScanVersion V` | Pin TrivyScan version |
| `-TrivyVersion V` | Pin Trivy version |
| `-SkipDbUpdate` | Do not run `trivyscan -u` |
| `-Strict` | Exit 1 if the DB update fails |
| `-NoPath` | Do not update PATH |
| `-Force` | Reinstall even when unchanged |
| `-Uninstall` | Remove managed files |
| `-Purge` | With `-Uninstall`, remove the Trivy DB cache |
| `-NoPause` | Do not wait for Enter |
| `-NonInteractive` | No pause; return an exit code |
| `-Help` | Usage |

---

## PATH and Trivy resolution

- Unix: the installer writes a marked `PATH` block to `~/.zshrc`, `~/.bash_profile`,
  `~/.bashrc`, or `~/.profile` when needed. System-wide installs only warn.
- Windows: the User PATH registry value is edited without expanding `%VAR%`; system installs
  edit Machine PATH. `WM_SETTINGCHANGE` is broadcast.
- `trivyscan` resolves Trivy dynamically:
  1. `TRIVY_BIN`
  2. `which trivy` / PATH
  3. a sibling `trivy` next to `trivyscan`
  4. `trivy`

This keeps `which trivy` authoritative while allowing portable/per-user installs to use a sibling fallback.

---

## Windows ARM64

Trivy currently publishes only a Windows x64 build. On Windows ARM64, the installer installs
TrivyScan natively and Trivy x64 under emulation. This requires Windows 11 x64 emulation;
otherwise the installer fails with an explicit error. Use WSL or install Trivy manually if needed.

---

## Windows Application Control

Error:

```text
An Application Control policy has blocked this file
```

means Windows (WDAC / AppLocker / Smart App Control) blocked the executable, not a TrivyScan bug.

Application Control handling is built into `install.ps1`:

```powershell
# Only diagnose; do not install
.\install.ps1 -DiagnoseOnly

# Default: install, then auto-apply AppLocker hash rules if local AppLocker is blocking and you are admin
.\install.ps1

# Install, but preview AppLocker policy changes only
.\install.ps1 -WhatIf

# Explicit modes
.\install.ps1 -AppLockerHash
.\install.ps1 -AppLockerPath
.\install.ps1 -WdacDraft -BasePolicyPath .\Base.xml -SigningCertPath .\codesign.cer
.\install.ps1 -Unblock
```

Behavior:

- **AppLocker local** — creates/merges hash rules for `trivyscan.exe` and `trivy.exe`, backs up
  the previous policy, verifies, and rolls back on failure. Hash rules must be re-applied after
  each update. Domain GPOs cannot be overridden locally; ask IT.
- **WDAC / App Control for Business** — generate a supplemental policy draft. It must be signed
  and deployed by IT; the script refuses Windows-managed/SAC policies.
- **Smart App Control** — no per-app allow list. The durable fix is Authenticode-signing both
  binaries. Turning SAC off is a one-way manual action and is not automated by this script.
- `-Unblock` only removes Mark-of-the-Web; it does not bypass Application Control.

Diagnostic commands:

```powershell
Get-AuthenticodeSignature .\trivyscan.exe
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 20
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 20
Get-AppLockerPolicy -Effective -Xml
CiTool.exe -lp -json
```

Do not disable WDAC/AppLocker/Smart App Control to work around this. Sign the binaries or use an
IT-approved policy exception.

---

## Verify

```bash
trivy --version
trivyscan --version
```

Open a new terminal after PATH changes.

---

## Uninstall

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.sh | bash -s -- --uninstall
```

System-wide:

```bash
curl -fsSL https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.sh | sudo bash -s -- --system --uninstall
```

Add `--purge` to remove `~/.cache/trivy`.

### Windows

```powershell
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.ps1 -OutFile "$env:TEMP\install.ps1"
powershell -ExecutionPolicy Bypass -File "$env:TEMP\install.ps1" -Uninstall
```

Add `-Purge` to remove the Trivy DB cache. The installer only removes binaries it recorded in
`install.json` / `install.env`; an unmanaged Trivy installation is left alone.

---

## Troubleshooting

**Command not found (Linux/macOS)** — open a new terminal or:

```bash
source ~/.zshrc   # or ~/.bashrc
```

**Command not found (Windows)** — open a new terminal after PATH changes.

**Database update failed** — installation still succeeded. Run:

```bash
trivyscan -u
```

Use `--strict`/`-Strict` if automation must fail when the DB cannot be updated.

**Checksum mismatch** — the release asset is corrupted or tampered with. Delete it and retry;
do not bypass checksum verification.

**Application Control blocked** — see the Windows Application Control section above.

**“Unmanaged TrivyScan found”** — an existing install lives outside the managed
prefix. Use `--system`/`-System` to update it system-wide, or remove the old copy
before doing a per-user install.

**`trivyscan` uses the wrong Trivy** — check:

```bash
which -a trivy
trivy --version
```

Set `TRIVY_BIN` to the desired executable if needed.

---

## Links

- Trivy docs: https://aquasecurity.github.io/trivy/
- Microsoft AppLocker: https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/
- Smart App Control: https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview
