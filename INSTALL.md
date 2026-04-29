# Installation Guide

## Requirements

- **Trivy** — installed automatically if not present
- **Linux/macOS**: `curl` or `wget`
- **Windows**: PowerShell 5.1+

---

## Download

Two archives are available, choose based on your CPU:

| Archive | CPU |
|---|---|
| `trivyscan_<version>_amd64.zip` | Intel / AMD (most computers) |
| `trivyscan_<version>_arm64.zip` | Apple Silicon, ARM servers |

Each archive contains binaries for **all OS** (Linux, macOS, Windows) — the install script detects your OS automatically.

---

## Archive contents

```
trivyscan_<version>_amd64.zip
├── trivyscan_linux_amd64       ← Linux binary
├── trivyscan_darwin_amd64      ← macOS binary
├── trivyscan_windows_amd64.exe ← Windows binary
├── install.sh                  ← Linux / macOS installer
├── install.ps1                 ← Windows installer
├── update.sh                   ← Linux / macOS updater
├── update.ps1                  ← Windows updater
└── INSTALL.md
```

---

## Install

### Linux / macOS

```bash
unzip trivyscan_<version>_amd64.zip
chmod +x install.sh
./install.sh
```

### Windows

```
Unzip trivyscan_<version>_amd64.zip
Double-click install.ps1
```

_(auto-elevates to Administrator)_

---

## What it does

1. Checks if Trivy is installed — fetches and installs latest version if not
2. Detects OS, copies the correct binary to system directory
3. Adds both to `PATH`
4. Verifies installation

---

## Install paths

| | Trivy | TrivyScan |
|---|---|---|
| Linux / macOS | `/usr/local/bin/trivy` | `/usr/local/bin/trivyscan` |
| Windows | `C:\Program Files\Trivy\` | `C:\Program Files\TrivyScan\` |

---

## Update

Download the latest archive, extract, then run the update script. It will fetch the latest Trivy from GitHub and replace the TrivyScan binary from the local file.

### Linux / macOS

```bash
chmod +x update.sh
./update.sh
```

### Windows

```
Double-click update.ps1
```

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

# Scan a directory of tar files
trivyscan -i ./images/ -o reports/

# Custom severity
trivyscan -i image.tar -o reports/ -s CRITICAL,HIGH

# Set concurrency
trivyscan -i ./images/ -o reports/ -c 5
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
