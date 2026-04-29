# Installation Guide

## Requirements

- **Trivy** — installed automatically if not present
- **Linux/macOS**: `curl` or `wget`
- **Windows**: PowerShell 5.1+

---

## Install

### Linux / macOS

```bash
chmod +x install.sh
./install.sh
```

### Windows

Double-click `install.ps1`
_(auto-elevates to Administrator)_

---

## What it does

1. Checks if Trivy is installed — installs latest version if not
2. Copies `trivyscan` binary to system directory
3. Adds both to `PATH`
4. Verifies installation

---

## Archive contents

**Linux / macOS**
```
trivyscan_<version>_<os>_<arch>.zip
├── trivyscan       ← binary
├── install.sh      ← install script
├── update.sh       ← update script
└── README.md
```

**Windows**
```
trivyscan_<version>_windows_<arch>.zip
├── trivyscan.exe   ← binary
├── install.ps1     ← install script
├── update.ps1      ← update script
└── README.md
```

---

## Install paths

| OS | Trivy | TrivyScan |
|---|---|---|
| Linux / macOS | `/usr/local/bin/trivy` | `/usr/local/bin/trivyscan` |
| Windows | `C:\Program Files\Trivy\` | `C:\Program Files\TrivyScan\` |

---

## Update

### Linux / macOS

```bash
chmod +x update.sh
./update.sh
```

### Windows

Double-click `update.ps1`

The update script fetches the latest versions from GitHub, skips if already up to date, and verifies after updating.

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
