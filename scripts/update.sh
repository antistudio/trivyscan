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
echo "      Trivy + TrivyScan Updater"
echo "========================================="
echo "[INFO] OS: $OS | Arch: $ARCH_GO"

trivy_updated=false
trivyscan_updated=false

# =========================================
# Helper
# =========================================
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    else sudo "$@"
    fi
}

# =========================================
# Step 1: Update Trivy
# =========================================
echo ""
echo "[INFO] Fetching latest Trivy version..."

if command -v curl &>/dev/null; then
    latest_trivy=$(curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
        | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
elif command -v wget &>/dev/null; then
    latest_trivy=$(wget -qO- "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
        | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
fi

if [ -z "$latest_trivy" ]; then
    echo "[WARN] Cannot fetch Trivy version - skipping"
else
    echo "[OK] Latest Trivy version: $latest_trivy"

    current_trivy=""
    if command -v trivy &>/dev/null; then
        current_trivy=$(trivy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo "[INFO] Installed version: $current_trivy"
    fi

    if [ "$current_trivy" = "$latest_trivy" ]; then
        echo "[OK] Trivy is already up to date"
    else
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
                echo "[OK] Trivy updated to v$latest_trivy"
                trivy_updated=true
            fi
        fi
    fi
fi

# =========================================
# Step 2: Update TrivyScan (from local binary)
# =========================================
echo ""
echo "[INFO] Updating TrivyScan..."

source_bin="$SCRIPT_DIR/trivyscan_${OS_GO}"

if [ ! -f "$source_bin" ]; then
    echo "[ERROR] Binary not found: trivyscan_${OS_GO}"
else
    run_privileged cp "$source_bin" "$TRIVYSCAN_INSTALL_DIR/trivyscan"
    run_privileged chmod 755 "$TRIVYSCAN_INSTALL_DIR/trivyscan"

    if [ ! -f "$TRIVYSCAN_INSTALL_DIR/trivyscan" ]; then
        echo "[ERROR] Failed to update TrivyScan"
    else
        echo "[OK] TrivyScan updated"
        trivyscan_updated=true
    fi
fi

# =========================================
# Step 3: Verify
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
if $trivy_updated;     then echo "[OK] Trivy     -> updated to v$latest_trivy"
else                        echo "[--] Trivy     -> already up to date"
fi
if $trivyscan_updated; then echo "[OK] TrivyScan -> updated"
else                        echo "[--] TrivyScan -> update failed or skipped"
fi
echo "========================================="
