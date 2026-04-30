#!/bin/bash

# =========================================
# Config
# =========================================
TRIVY_INSTALL_DIR="/usr/local/bin"
TRIVYSCAN_INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =========================================
# Args
# =========================================
FORCE=false
UNINSTALL=false
for arg in "$@"; do
    case "$arg" in
        --force|-f) FORCE=true ;;
        --uninstall|-u) UNINSTALL=true ;;
        --help|-h) 
            echo "Usage: ./install.sh [OPTIONS]"
            echo "  --force, -f     Force reinstall"
            echo "  --uninstall, -u Uninstall both"
            echo "  --help, -h      Show this help"
            exit 0
            ;;
    esac
done

# =========================================
# Helper
# =========================================
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    else sudo "$@"
    fi
}

# =========================================
# Uninstall
# =========================================
if [ "$UNINSTALL" = true ]; then
    echo ""
    echo "[INFO] Uninstalling..."

    # Remove binaries
    if [ -f "$TRIVY_INSTALL_DIR/trivy" ]; then
        run_privileged rm -f "$TRIVY_INSTALL_DIR/trivy"
        echo "[OK] Removed $TRIVY_INSTALL_DIR/trivy"
    fi

    if [ -f "$TRIVYSCAN_INSTALL_DIR/trivyscan" ]; then
        run_privileged rm -f "$TRIVYSCAN_INSTALL_DIR/trivyscan"
        echo "[OK] Removed $TRIVYSCAN_INSTALL_DIR/trivyscan"
    fi

    echo ""
    echo "[SUCCESS] Uninstall complete! Restart your terminal."
    exit 0
fi

# =========================================
# Detect OS + Arch
# =========================================
OS=$(uname -s)
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)        ARCH_GO="amd64"; ARCH_TRIVY="64bit" ;;
    aarch64|arm64) ARCH_GO="arm64"; ARCH_TRIVY="ARM64" ;;
    *)
        echo "[ERROR] Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

case "$OS" in
    Linux)  OS_GO="linux";  OS_TRIVY="Linux"  ;;
    Darwin) OS_GO="darwin"; OS_TRIVY="macOS"  ;;
    *)
        echo "[ERROR] Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "========================================="
echo "      Trivy + TrivyScan Installer"
echo "========================================="
echo "[INFO] OS: $OS | Arch: $ARCH_GO"

trivy_updated=false
trivyscan_updated=false

# =========================================
# Step 1: Install/Update Trivy
# =========================================
echo ""
echo "[INFO] Checking Trivy..."

current_trivy=""
if command -v trivy &>/dev/null; then
    current_trivy=$(trivy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

# Get latest version from GitHub
latest_trivy=""
if command -v curl &>/dev/null; then
    latest_trivy=$(curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
        | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
elif command -v wget &>/dev/null; then
    latest_trivy=$(wget -qO- "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
        | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
fi

if [ -z "$latest_trivy" ]; then
    echo "[WARN] Cannot fetch Trivy version - skipping"
elif ! $FORCE && [ -n "$current_trivy" ] && [ "$current_trivy" = "$latest_trivy" ]; then
    echo "[OK] Trivy already up to date (v$current_trivy)"
else
    if [ -n "$current_trivy" ]; then
        echo "[INFO] Current version: $current_trivy, updating to v$latest_trivy..."
    else
        echo "[INFO] Trivy not found, installing v$latest_trivy..."
    fi

    url="https://github.com/aquasecurity/trivy/releases/download/v${latest_trivy}/trivy_${latest_trivy}_${OS_TRIVY}-${ARCH_TRIVY}.tar.gz"
    tmp_archive="/tmp/trivy.tar.gz"
    tmp_dir="/tmp/trivy_extract"

    echo "[INFO] Downloading from: $url"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$tmp_archive"
    else
        wget -q "$url" -O "$tmp_archive"
    fi

    if [ ! -f "$tmp_archive" ]; then
        echo "[ERROR] Download failed"
    else
        echo "[INFO] Extracting..."
        rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
        tar -xzf "$tmp_archive" -C "$tmp_dir"
        rm -f "$tmp_archive"

        if [ ! -f "$tmp_dir/trivy" ]; then
            echo "[ERROR] trivy binary not found after extraction"
        else
            run_privileged cp "$tmp_dir/trivy" "$TRIVY_INSTALL_DIR/trivy"
            run_privileged chmod 755 "$TRIVY_INSTALL_DIR/trivy"
            rm -rf "$tmp_dir"
            echo "[OK] Trivy installed/updated to v$latest_trivy"
            trivy_updated=true
        fi
    fi
fi

# =========================================
# Step 2: Install/Update TrivyScan
# =========================================
echo ""
echo "[INFO] Checking TrivyScan..."

source_bin="$SCRIPT_DIR/trivyscan_${OS_GO}"

current_trivyscan=""
if [ -f "$TRIVYSCAN_INSTALL_DIR/trivyscan" ]; then
    current_trivyscan=$($TRIVYSCAN_INSTALL_DIR/trivyscan --version 2>/dev/null | head -1)
fi

if [ ! -f "$source_bin" ]; then
    echo "[ERROR] Binary not found: trivyscan_${OS_GO}"
    echo "        Available files in current directory:"
    ls "$SCRIPT_DIR"/trivyscan_* 2>/dev/null || echo "        (none found)"
elif ! $FORCE && [ -n "$current_trivyscan" ]; then
    echo "[OK] TrivyScan already installed"
else
    if [ -n "$current_trivyscan" ]; then
        echo "[INFO] Reinstalling TrivyScan..."
    else
        echo "[INFO] TrivyScan not found, installing..."
    fi

    run_privileged cp "$source_bin" "$TRIVYSCAN_INSTALL_DIR/trivyscan"
    run_privileged chmod 755 "$TRIVYSCAN_INSTALL_DIR/trivyscan"

    if [ ! -f "$TRIVYSCAN_INSTALL_DIR/trivyscan" ]; then
        echo "[ERROR] Failed to install TrivyScan"
    else
        echo "[OK] TrivyScan installed"
        trivyscan_updated=true
    fi
fi

# =========================================
# Step 3: Update PATH
# =========================================
echo ""
echo "[INFO] Checking PATH..."

for dir in "$TRIVY_INSTALL_DIR" "$TRIVYSCAN_INSTALL_DIR"; do
    if echo "$PATH" | grep -q "$dir"; then
        echo "[OK] $dir already in PATH"
    else
        echo "[WARN] $dir is not in PATH"
        if [ -n "$ZSH_VERSION" ]; then
            echo "export PATH=\"\$PATH:$dir\"" >> "$HOME/.zshrc"
            echo "[OK] Added to ~/.zshrc"
        elif [ -n "$BASH_VERSION" ]; then
            echo "export PATH=\"\$PATH:$dir\"" >> "$HOME/.bashrc"
            echo "[OK] Added to ~/.bashrc"
        else
            echo "[INFO] Add manually: export PATH=\"\$PATH:$dir\""
        fi
    fi
done

# =========================================
# Step 4: Verify
# =========================================
echo ""
echo "[INFO] Verifying..."

command -v trivy    &>/dev/null && trivy --version
command -v trivyscan &>/dev/null && trivyscan --version

# =========================================
# Summary
# =========================================
echo ""
echo "========================================="
if [ -z "$latest_trivy" ]; then
    echo "[--] Trivy     -> skipped (cannot fetch version)"
elif $trivy_updated; then
    echo "[OK] Trivy     -> installed/updated to v$latest_trivy"
else
    echo "[OK] Trivy     -> already up to date (v$current_trivy)"
fi

if [ ! -f "$source_bin" ]; then
    echo "[--] TrivyScan -> skipped (binary not found)"
elif $trivyscan_updated; then
    echo "[OK] TrivyScan -> installed/updated"
elif [ -n "$current_trivyscan" ]; then
    echo "[OK] TrivyScan -> already installed"
else
    echo "[--] TrivyScan -> install failed"
fi

echo "========================================="
echo " Install complete! Run: source ~/.bashrc (or ~/.zshrc)"
echo "========================================="
