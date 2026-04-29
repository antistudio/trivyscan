#!/bin/bash

# =========================================
# Config
# =========================================
INSTALL_DIR="/usr/local/bin"
TRIVYSCAN_REPO="anhnmt/trivyscan"

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
echo "      Trivy + TrivyScan Updater"
echo "========================================="

trivy_updated=false
trivyscan_updated=false

# =========================================
# Helper
# =========================================
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

fetch_latest_version() {
    local repo="$1"
    local version=""

    if command -v curl &>/dev/null; then
        version=$(curl -s "https://api.github.com/repos/$repo/releases/latest" \
            | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    elif command -v wget &>/dev/null; then
        version=$(wget -qO- "https://api.github.com/repos/$repo/releases/latest" \
            | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
    fi

    echo "$version"
}

# =========================================
# Step 1: Update Trivy
# =========================================
echo ""
echo "[INFO] Fetching latest Trivy version..."

latest_trivy=$(fetch_latest_version "aquasecurity/trivy")

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

        echo "[INFO] Downloading Trivy from: $url"
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
                run_privileged cp "$tmp_dir/trivy" "$INSTALL_DIR/trivy"
                run_privileged chmod 755 "$INSTALL_DIR/trivy"
                rm -rf "$tmp_dir"
                echo "[OK] Trivy updated to v$latest_trivy"
                trivy_updated=true
            fi
        fi
    fi
fi

# =========================================
# Step 2: Update TrivyScan
# =========================================
echo ""
echo "[INFO] Fetching latest TrivyScan version..."

latest_trivyscan=$(fetch_latest_version "$TRIVYSCAN_REPO")

if [ -z "$latest_trivyscan" ]; then
    echo "[WARN] Cannot fetch TrivyScan version - skipping"
else
    echo "[OK] Latest TrivyScan version: $latest_trivyscan"

    current_trivyscan=""
    if command -v trivyscan &>/dev/null; then
        current_trivyscan=$(trivyscan --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo "[INFO] Installed version: $current_trivyscan"
    fi

    if [ "$current_trivyscan" = "$latest_trivyscan" ]; then
        echo "[OK] TrivyScan is already up to date"
    else
        url="https://github.com/$TRIVYSCAN_REPO/releases/download/v${latest_trivyscan}/trivyscan_${latest_trivyscan}_${OS_GO}_${ARCH_GO}.zip"
        tmp_archive="/tmp/trivyscan.zip"
        tmp_dir="/tmp/trivyscan_extract"

        echo "[INFO] Downloading TrivyScan from: $url"
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
            unzip -q "$tmp_archive" -d "$tmp_dir"
            rm -f "$tmp_archive"

            if [ ! -f "$tmp_dir/trivyscan" ]; then
                echo "[ERROR] trivyscan binary not found after extraction"
            else
                run_privileged cp "$tmp_dir/trivyscan" "$INSTALL_DIR/trivyscan"
                run_privileged chmod 755 "$INSTALL_DIR/trivyscan"
                rm -rf "$tmp_dir"
                echo "[OK] TrivyScan updated to v$latest_trivyscan"
                trivyscan_updated=true
            fi
        fi
    fi
fi

# =========================================
# Step 3: Verify
# =========================================
echo ""
echo "[INFO] Verifying..."

command -v trivy &>/dev/null    && trivy --version
command -v trivyscan &>/dev/null && trivyscan --version

# =========================================
# Summary
# =========================================
echo ""
echo "========================================="
if $trivy_updated;     then echo "[OK] Trivy     -> updated to v$latest_trivy"
else                        echo "[--] Trivy     -> already up to date"
fi
if $trivyscan_updated; then echo "[OK] TrivyScan -> updated to v$latest_trivyscan"
else                        echo "[--] TrivyScan -> already up to date"
fi
echo "========================================="
