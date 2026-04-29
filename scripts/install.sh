#!/bin/bash

# =========================================
# Config
# =========================================
INSTALL_DIR="/usr/local/bin"
TRIVYSCAN_REPO="anhnmt/trivyscan"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OS=$(uname -s)
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)  ARCH_GO="amd64"; ARCH_TRIVY="64bit" ;;
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

# =========================================
# Helper: require root or sudo
# =========================================
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
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
    # Fetch latest version
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

    # Download
    url="https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${OS_TRIVY}-${ARCH_TRIVY}.tar.gz"
    tmp_archive="/tmp/trivy.tar.gz"
    tmp_dir="/tmp/trivy_extract"

    echo "[INFO] Downloading Trivy from: $url"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$tmp_archive"
    else
        wget -q "$url" -O "$tmp_archive"
    fi

    if [ ! -f "$tmp_archive" ]; then
        echo "[ERROR] Download failed"
        exit 1
    fi

    echo "[OK] Downloaded"

    # Extract
    echo "[INFO] Extracting Trivy..."
    rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"
    tar -xzf "$tmp_archive" -C "$tmp_dir"
    rm -f "$tmp_archive"

    if [ ! -f "$tmp_dir/trivy" ]; then
        echo "[ERROR] trivy binary not found after extraction"
        exit 1
    fi

    # Install
    run_privileged cp "$tmp_dir/trivy" "$INSTALL_DIR/trivy"
    run_privileged chmod 755 "$INSTALL_DIR/trivy"
    rm -rf "$tmp_dir"

    echo "[OK] Trivy installed"
fi

# =========================================
# Step 2: Install TrivyScan
# =========================================
echo ""
echo "[INFO] Installing TrivyScan..."

source_bin="$SCRIPT_DIR/trivyscan"

if [ ! -f "$source_bin" ]; then
    echo "[ERROR] trivyscan not found next to script"
    exit 1
fi

run_privileged cp "$source_bin" "$INSTALL_DIR/trivyscan"
run_privileged chmod 755 "$INSTALL_DIR/trivyscan"

if [ ! -f "$INSTALL_DIR/trivyscan" ]; then
    echo "[ERROR] Failed to install trivyscan"
    exit 1
fi

echo "[OK] TrivyScan installed"

# =========================================
# Step 3: Verify PATH
# =========================================
echo ""
echo "[INFO] Checking PATH..."

if echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "[OK] $INSTALL_DIR already in PATH"
else
    echo "[WARN] $INSTALL_DIR is not in PATH"
    shell_rc=""
    if [ -n "$ZSH_VERSION" ]; then
        shell_rc="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ]; then
        shell_rc="$HOME/.bashrc"
    fi

    if [ -n "$shell_rc" ]; then
        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$shell_rc"
        echo "[OK] Added to $shell_rc"
    else
        echo "[INFO] Add manually: export PATH=\"\$PATH:$INSTALL_DIR\""
    fi
fi

# =========================================
# Step 4: Verify
# =========================================
echo ""
echo "[INFO] Verifying..."

"$INSTALL_DIR/trivy" --version
"$INSTALL_DIR/trivyscan" --version

echo ""
echo "========================================="
echo "[SUCCESS] Installation complete!"
echo "         Run: source ~/.bashrc (or ~/.zshrc)"
echo "========================================="
