# Installation Guide

## Requirements

- **Trivy** — installed automatically if not present
- **Linux/macOS**: `curl` or `wget`
- **Windows**: PowerShell 5.1+

---

## Download

Each release has one archive per OS and CPU, plus a checksums file:

| Archive | For |
|---|---|
| `trivyscan_<version>_linux_amd64.tar.gz` | Linux, Intel / AMD |
| `trivyscan_<version>_linux_arm64.tar.gz` | Linux, ARM servers |
| `trivyscan_<version>_darwin_amd64.tar.gz` | macOS, Intel |
| `trivyscan_<version>_darwin_arm64.tar.gz` | macOS, Apple Silicon |
| `trivyscan_<version>_windows_amd64.zip` | Windows, Intel / AMD |
| `trivyscan_<version>_windows_arm64.zip` | Windows, ARM |
| `trivyscan_<version>_checksums.txt` | SHA-256 of every archive |

> Releases up to v1.2.5 used two archives (`trivyscan_<version>_amd64.zip` / `_arm64.zip`) containing every OS.
> The install scripts of newer releases expect the per-OS names above.

---

## Archive contents

```
trivyscan_<version>_linux_amd64.tar.gz      trivyscan_<version>_windows_amd64.zip
├── trivyscan      ← binary                  ├── trivyscan.exe   ← binary
├── install.sh     ← installer               ├── install.ps1     ← installer
├── INSTALL.md                               ├── INSTALL.md
└── LICENSE                                  └── LICENSE
```

---

## Install

The installers verify every download (Trivy and TrivyScan) against the release's SHA-256 checksums file
and stop if a checksum does not match or cannot be computed (`sha256sum` or `shasum` is required on Linux/macOS).
Set `TRIVYSCAN_SKIP_CHECKSUM=1` to skip verification on purpose (not recommended).

### Linux / macOS (remote — one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/anhnmt/trivyscan/main/scripts/install.sh | sudo bash
```

Downloads the latest release for your OS/CPU and installs Trivy + TrivyScan to `/usr/local/bin`.

### Linux / macOS (manual)

```bash
# optional: verify the archive yourself
sha256sum --ignore-missing -c trivyscan_<version>_checksums.txt   # macOS: shasum -a 256 --ignore-missing -c ...

tar -xzf trivyscan_<version>_linux_amd64.tar.gz
sudo ./install.sh
```

When `trivyscan` is next to `install.sh`, that binary is installed instead of downloading one.

### Windows (remote — one-liner)

Open PowerShell as **Administrator** and run:

```powershell
irm https://raw.githubusercontent.com/anhnmt/trivyscan/main/scripts/install.ps1 | iex
```

This downloads the latest release and installs everything automatically.

### Windows (manual)

**Step 1:** Unzip `trivyscan_<version>_windows_amd64.zip`

**Step 2:** Open PowerShell as Administrator
- Press `Win + X` and select "Windows PowerShell (Admin)" or "Terminal (Admin)"
- Or right-click the Start button → "Windows PowerShell (Admin)"

**Step 3:** Navigate to the extracted folder and run:

```powershell
cd path\to\extracted\folder
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

**Alternative:** Double-click `install.ps1` (may require execution policy adjustment)

> **Note:** Administrator privileges are required to install to `C:\Program Files\` and modify system PATH.

---

## What it does

1. Checks if Trivy is installed — downloads the latest version, verifies its checksum and installs it if not
2. Installs TrivyScan: the binary next to the script, or the latest release for your OS/CPU (checksum verified)
3. Adds both to `PATH`
4. Verifies installation

---

## Install paths

| | Trivy | TrivyScan |
|---|---|---|
| Linux / macOS | `/usr/local/bin/trivy` | `/usr/local/bin/trivyscan` |
| Windows | `C:\Program Files\Trivy\` | `C:\Program Files\TrivyScan\` |

---

## Verify

```bash
trivy --version
trivyscan --version
```

---

## Usage

```bash
# Scan a single image
trivyscan -i image.tar -o reports/

# Scan image references (comma-separated, repeated -i, or a list file with -l)
trivyscan -i nginx:latest,redis:7 -o reports/

# Scan a directory of tar files → reports/json/, reports/html/, reports/summary.html
trivyscan -i ./images/ -o reports/

# Custom severity (render-time filter, no rescan needed)
trivyscan -i image.tar -o reports/ -s CRITICAL,HIGH

# Force a rescan of unchanged images
trivyscan -i ./images/ -o reports/ --force
```

---

## Uninstall

### Linux / macOS

```bash
sudo rm /usr/local/bin/trivyscan /usr/local/bin/trivy
```

### Windows

```powershell
Remove-Item "C:\Program Files\TrivyScan" -Recurse -Force
Remove-Item "C:\Program Files\Trivy"     -Recurse -Force
```

---

## Troubleshooting

**Command not found (Linux/macOS)** — restart terminal or run:
```bash
source ~/.bashrc  # or ~/.zshrc
```

**Command not found (Windows)** — restart terminal after install.

**Permission denied (Linux/macOS)**:
```bash
sudo ./install.sh
```

---

## Links

- Trivy docs: https://aquasecurity.github.io/trivy/
