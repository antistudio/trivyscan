# TrivyScan Installation Guide

TrivyScan provides automated installation scripts that will install both TrivyScan and Trivy (automatically fetching the latest version) on your system.

## Quick Installation

### Linux / macOS

```bash
# Extract the release
unzip trivyscan_<VERSION>_<OS>_<ARCH>.zip

# Run installation (may require sudo)
chmod +x install.sh
./install.sh
```

**Example for Linux AMD64:**
```bash
unzip trivyscan_v1.0.0_linux_amd64.zip
chmod +x install.sh
./install.sh
```

### Windows

**Simply double-click the .bat file:**
```cmd
# Download and extract, then:
# Double-click install.bat
# (Or right-click -> Run as Administrator)
```

**Or run from Command Prompt:**
```cmd
# Run Command Prompt as Administrator, then:
install.bat
```

**Example install:**
```powershell
# Extract
Expand-Archive -Path "trivyscan.zip" -DestinationPath "."

# Install - just double-click install.bat!
```

## What the Installation Script Does

The installation scripts will:

1. ✅ **Auto-fetch latest Trivy version** from GitHub releases
2. ✅ Check if Trivy is already installed
3. ✅ Install Trivy automatically if not present:
   - **Linux**: APT (Debian/Ubuntu) or YUM (RHEL/CentOS) or manual download
   - **macOS**: Homebrew or manual download
   - **Windows**: Chocolatey or manual download
4. ✅ Install TrivyScan binary to system directory
5. ✅ Add installation directories to system PATH
6. ✅ Verify both installations

## Archive Contents

### Linux / macOS archives contain:
```
trivyscan_v1.0.0_linux_amd64.zip
├── trivyscan         # TrivyScan binary
├── install.sh        # Installation script (auto-detects latest Trivy)
├── update.sh         # Update script (updates both Trivy and TrivyScan)
├── README.md         # Main documentation
└── LICENSE           # License file
```

### Windows archives contain:
```
trivyscan_v1.0.0_windows_amd64.zip
├── trivyscan.exe     # TrivyScan binary
├── install.bat       # Installation script (pure batch, no PowerShell needed)
├── update.bat        # Update script (pure batch, no PowerShell needed)
├── README.md         # Main documentation
└── LICENSE           # License file
```

## Installation Directories

### Linux / macOS
- **Install Location**: `/usr/local/bin/`
- **Trivy**: `/usr/local/bin/trivy`
- **TrivyScan**: `/usr/local/bin/trivyscan`

### Windows
- **Install Location**: `C:\Program Files\TrivyScan\` and `C:\Program Files\Trivy\`
- **Trivy**: `C:\Program Files\Trivy\trivy.exe`
- **TrivyScan**: `C:\Program Files\TrivyScan\trivyscan.exe`

## Features

### 🚀 Automatic Latest Trivy Version
The installation scripts automatically fetch and install the latest stable version of Trivy from GitHub. No need to manually update version numbers!

### 🎯 Smart Package Manager Detection
- **Linux**: Tries APT → YUM → manual download
- **macOS**: Tries Homebrew → manual download
- **Windows**: Tries Chocolatey → manual download

### 🔐 Automatic Privilege Handling
- **Linux/macOS**: Uses `sudo` only when needed
- **Windows**: Checks for Administrator privileges

### ✅ Verification
Both installations are verified after completion to ensure everything works correctly.

## Verify Installation

After installation, verify that both tools are working:

```bash
# Check Trivy
trivy --version

# Check TrivyScan
trivyscan --version
```

## Usage

```bash
# Basic usage
trivyscan -i image.tar -o reports/

# With custom severity levels
trivyscan -i image.tar -o reports/ -s CRITICAL,HIGH

# Scan directory of tar files with 5 concurrent workers
trivyscan -i ./tar-files/ -o reports/ -c 5

# Show help
trivyscan --help
```

## Update to Latest Version

### Linux / macOS

```bash
# Navigate to installation directory or download update script
chmod +x update.sh
./update.sh
```

The update script will:
1. ✅ Check current versions of Trivy and TrivyScan
2. ✅ Fetch latest versions from GitHub
3. ✅ Compare versions and prompt for update/downgrade
4. ✅ Update Trivy (priority) using package manager or manual download
5. ✅ Update TrivyScan using GitHub releases
6. ✅ Verify installations

### Windows

**Simply double-click update.bat:**
```cmd
# Double-click update.bat
# (Or right-click -> Run as Administrator)
```

The update script will:
1. ✅ Check current versions of Trivy and TrivyScan
2. ✅ Fetch latest versions from GitHub
3. ✅ Compare versions and skip if already up to date
4. ✅ Update Trivy (priority) using Chocolatey or manual download
5. ✅ Update TrivyScan using GitHub releases
6. ✅ Verify installations

### Update Features

- **Auto-detect latest versions** from GitHub releases
- **Smart version comparison** - skip if already up to date
- **Downgrade option** - prompts if installed version is newer
- **Package manager priority** - uses Homebrew/APT/YUM/Chocolatey when available
- **Trivy priority** - always updates Trivy first to ensure compatibility

## Troubleshooting

### Command not found after installation

**Linux/macOS:**
1. Restart your terminal
2. Or manually refresh PATH:
   ```bash
   export PATH="$PATH:/usr/local/bin"
   ```

**Windows:**
1. Restart your PowerShell/Command Prompt
2. Or add to PATH manually via System Properties > Environment Variables

### Permission denied (Linux/macOS)

```bash
chmod +x install.sh
sudo ./install.sh
```

### Administrator rights required (Windows)

Right-click the .bat file and select "Run as Administrator".

## Uninstallation

### Linux / macOS
```bash
sudo rm /usr/local/bin/trivyscan
sudo rm /usr/local/bin/trivy
```

### Windows
```powershell
Remove-Item "C:\Program Files\TrivyScan" -Recurse -Force
Remove-Item "C:\Program Files\Trivy" -Recurse -Force
```

## Support
- **Trivy Documentation**: https://aquasecurity.github.io/trivy/

## License

MIT License
