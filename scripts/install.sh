#!/bin/bash

# =========================================
# Config
# =========================================
TRIVY_INSTALL_DIR="/usr/local/bin"
TRIVYSCAN_INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# =========================================
# Helper
# =========================================
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    else sudo "$@"
    fi
}

# =========================================
# Step 1: Install Trivy
# =========================================
echo ""
echo "[INFO] Checking Trivy..."

if command -v trivy &>/dev/null; then
    echo "[OK] Trivy already installed - skipping"
else
    echo "[INFO] Fetching latest Trivy version..."

    if command -v curl &>/dev/null; then
        version=$(curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
            | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    elif command -v wget &>/dev/null; then
        version=$(wget -qO- "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
            | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    else
        echo "[ERROR] curl or wget is required"
        exit 1
    fi

    if [ -z "$version" ]; then
        echo "[ERROR] Cannot fetch latest Trivy version"
        exit 1
    fi

    echo "[OK] Latest Trivy version: $version"

    url="https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${OS_TRIVY}-${ARCH_TRIVY}.tar.gz"
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
        exit 1
    fi

    echo "[INFO] Extracting..."
    rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
    tar -xzf "$tmp_archive" -C "$tmp_dir"
    rm -f "$tmp_archive"

    if [ ! -f "$tmp_dir/trivy" ]; then
        echo "[ERROR] trivy binary not found after extraction"
        exit 1
    fi

    run_privileged cp "$tmp_dir/trivy" "$TRIVY_INSTALL_DIR/trivy"
    run_privileged chmod 755 "$TRIVY_INSTALL_DIR/trivy"
    rm -rf "$tmp_dir"

    echo "[OK] Trivy installed"
fi

# =========================================
# Step 2: Install TrivyScan (detect binary)
# =========================================
echo ""
echo "[INFO] Installing TrivyScan..."

# Find the correct binary for this OS/arch inside the zip
source_bin="$SCRIPT_DIR/trivyscan_${OS_GO}_${ARCH_GO}"

if [ ! -f "$source_bin" ]; then
    echo "[ERROR] Binary not found: trivyscan_${OS_GO}_${ARCH_GO}"
    echo "        Available files in current directory:"
    ls "$SCRIPT_DIR"/trivyscan_* 2>/dev/null || echo "        (none found)"
    exit 1
fi

run_privileged cp "$source_bin" "$TRIVYSCAN_INSTALL_DIR/trivyscan"
run_privileged chmod 755 "$TRIVYSCAN_INSTALL_DIR/trivyscan"

if [ ! -f "$TRIVYSCAN_INSTALL_DIR/trivyscan" ]; then
    echo "[ERROR] Failed to install trivyscan"
    exit 1
fi

echo "[OK] TrivyScan installed"

# =========================================
# Step 3: Update PATH
# =========================================
echo ""
echo "[INFO] Checking PATH..."

if echo "$PATH" | grep -q "$TRIVYSCAN_INSTALL_DIR"; then
    echo "[OK] $TRIVYSCAN_INSTALL_DIR already in PATH"
else
    echo "[WARN] $TRIVYSCAN_INSTALL_DIR is not in PATH"
    if [ -n "$ZSH_VERSION" ]; then
        echo "export PATH=\"\$PATH:$TRIVYSCAN_INSTALL_DIR\"" >> "$HOME/.zshrc"
        echo "[OK] Added to ~/.zshrc"
    elif [ -n "$BASH_VERSION" ]; then
        echo "export PATH=\"\$PATH:$TRIVYSCAN_INSTALL_DIR\"" >> "$HOME/.bashrc"
        echo "[OK] Added to ~/.bashrc"
    else
        echo "[INFO] Add manually: export PATH=\"\$PATH:$TRIVYSCAN_INSTALL_DIR\""
    fi
fi

# =========================================
# Step 4: Verify
# =========================================
echo ""
echo "[INFO] Verifying..."

"$TRIVY_INSTALL_DIR/trivy" --version
"$TRIVYSCAN_INSTALL_DIR/trivyscan" --version

echo ""
echo "========================================="
echo "[SUCCESS] Installation complete!"
echo "         Run: source ~/.bashrc (or ~/.zshrc)"
echo "========================================="
