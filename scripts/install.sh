#!/bin/bash
#
# Trivy + TrivyScan installer for Linux / macOS
#
# Usage (remote):
#   curl -fsSL https://raw.githubusercontent.com/anhnmt/trivyscan/main/scripts/install.sh | sudo bash
#
# Usage (local, from an extracted release archive):
#   ./install.sh
#
# Every download is verified against the release's SHA-256 checksums file.
# Set TRIVYSCAN_SKIP_CHECKSUM=1 to install without verification (not recommended).

# =========================================
# Config
# =========================================
TRIVY_INSTALL_DIR="/usr/local/bin"
TRIVYSCAN_INSTALL_DIR="/usr/local/bin"
TRIVYSCAN_REPO="anhnmt/trivyscan"

# SCRIPT_DIR is only meaningful when run from a file; under `curl | bash`
# BASH_SOURCE is empty and the binary is downloaded instead.
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

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
# Helpers
# =========================================
run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then "$@"
    else sudo "$@"
    fi
}

# Private temp dir: a fixed /tmp path could be pre-created by another user
# and its contents would then be installed as root.
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trivyscan-install.XXXXXX")" || {
    echo "[ERROR] Cannot create temp directory"
    exit 1
}
trap 'rm -rf "$TMP_DIR"' EXIT

# fetch URL OUTPUT — download following redirects, fail on HTTP errors.
fetch() {
    if command -v curl &>/dev/null; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget &>/dev/null; then
        wget -q "$1" -O "$2"
    else
        echo "[ERROR] curl or wget is required"
        return 1
    fi
}

# latest_tag REPO — print the latest release tag without the leading "v".
# github.com/<repo>/releases/latest redirects to .../releases/tag/<tag>; unlike
# the REST API it has no 60 requests/hour limit, so curl uses it first.
latest_tag() {
    local tag=""
    if command -v curl &>/dev/null; then
        tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$1/releases/latest" 2>/dev/null)"
        tag="${tag##*/releases/tag/}"
    fi
    if ! echo "$tag" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+'; then
        local json="$TMP_DIR/release.json"
        fetch "https://api.github.com/repos/$1/releases/latest" "$json" 2>/dev/null || return 1
        tag="$(grep '"tag_name"' "$json" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
    fi
    echo "${tag#v}"
}

sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        return 1
    fi
}

# verify FILE CHECKSUMS_FILE NAME — compare FILE against the line for NAME.
verify() {
    local file="$1" sums="$2" name="$3" expected actual
    if [ "${TRIVYSCAN_SKIP_CHECKSUM:-}" = "1" ]; then
        echo "[WARN] TRIVYSCAN_SKIP_CHECKSUM=1: NOT verifying $name"
        return 0
    fi
    expected="$(awk -v n="$name" '$2 == n || $2 == "*"n {print $1; exit}' "$sums")"
    if [ -z "$expected" ]; then
        echo "[ERROR] No checksum for $name in checksums file"
        return 1
    fi
    if ! actual="$(sha256_of "$file")"; then
        echo "[ERROR] sha256sum or shasum is required to verify downloads"
        echo "        (set TRIVYSCAN_SKIP_CHECKSUM=1 to install without verification)"
        return 1
    fi
    if [ "$expected" != "$actual" ]; then
        echo "[ERROR] Checksum mismatch for $name"
        echo "        expected $expected"
        echo "        got      $actual"
        return 1
    fi
    echo "[OK] Checksum verified: $name"
}

# =========================================
# Uninstall
# =========================================
if [ "$UNINSTALL" = true ]; then
    echo ""
    echo "[INFO] Uninstalling..."

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
trivyscan_failed=false

# =========================================
# Step 1: Install/Update Trivy
# =========================================
echo ""
echo "[INFO] Checking Trivy..."

current_trivy=""
if command -v trivy &>/dev/null; then
    current_trivy=$(trivy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

latest_trivy="$(latest_tag aquasecurity/trivy)"

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

    base="https://github.com/aquasecurity/trivy/releases/download/v${latest_trivy}"
    asset="trivy_${latest_trivy}_${OS_TRIVY}-${ARCH_TRIVY}.tar.gz"
    sums="trivy_${latest_trivy}_checksums.txt"
    extract_dir="$TMP_DIR/trivy"

    echo "[INFO] Downloading from: $base/$asset"
    if ! fetch "$base/$asset" "$TMP_DIR/$asset" || ! fetch "$base/$sums" "$TMP_DIR/$sums"; then
        echo "[ERROR] Download failed"
    elif ! verify "$TMP_DIR/$asset" "$TMP_DIR/$sums" "$asset"; then
        echo "[ERROR] Trivy not installed"
    else
        echo "[INFO] Extracting..."
        mkdir -p "$extract_dir"
        tar -xzf "$TMP_DIR/$asset" -C "$extract_dir"

        if [ ! -f "$extract_dir/trivy" ]; then
            echo "[ERROR] trivy binary not found after extraction"
        else
            run_privileged install -m 755 "$extract_dir/trivy" "$TRIVY_INSTALL_DIR/trivy"
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

current_trivyscan=""
if [ -x "$TRIVYSCAN_INSTALL_DIR/trivyscan" ]; then
    current_trivyscan=$("$TRIVYSCAN_INSTALL_DIR/trivyscan" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
fi

# Local mode: binary next to this script (extracted archive; older archives used trivyscan_<os>).
source_bin=""
if [ -n "$SCRIPT_DIR" ]; then
    for name in trivyscan "trivyscan_${OS_GO}"; do
        if [ -f "$SCRIPT_DIR/$name" ]; then
            source_bin="$SCRIPT_DIR/$name"
            break
        fi
    done
fi

if [ -n "$source_bin" ]; then
    echo "[INFO] Using local binary: $source_bin"
    if ! $FORCE && [ -n "$current_trivyscan" ]; then
        echo "[OK] TrivyScan already installed (use --force to reinstall)"
        source_bin=""
    fi
else
    # Remote mode: download the release archive for this OS/arch.
    latest_trivyscan="$(latest_tag "$TRIVYSCAN_REPO")"
    if [ -z "$latest_trivyscan" ]; then
        echo "[ERROR] Cannot fetch TrivyScan release info"
        trivyscan_failed=true
    elif ! $FORCE && [ "$current_trivyscan" = "$latest_trivyscan" ]; then
        echo "[OK] TrivyScan already up to date (v$current_trivyscan)"
    else
        base="https://github.com/${TRIVYSCAN_REPO}/releases/download/v${latest_trivyscan}"
        asset="trivyscan_${latest_trivyscan}_${OS_GO}_${ARCH_GO}.tar.gz"
        sums="trivyscan_${latest_trivyscan}_checksums.txt"
        extract_dir="$TMP_DIR/trivyscan"

        echo "[INFO] Downloading from: $base/$asset"
        if ! fetch "$base/$asset" "$TMP_DIR/$asset" || ! fetch "$base/$sums" "$TMP_DIR/$sums"; then
            echo "[ERROR] Download failed"
            trivyscan_failed=true
        elif ! verify "$TMP_DIR/$asset" "$TMP_DIR/$sums" "$asset"; then
            trivyscan_failed=true
        else
            mkdir -p "$extract_dir"
            tar -xzf "$TMP_DIR/$asset" -C "$extract_dir"
            if [ -f "$extract_dir/trivyscan" ]; then
                source_bin="$extract_dir/trivyscan"
            else
                echo "[ERROR] trivyscan binary not found in $asset"
                trivyscan_failed=true
            fi
        fi
    fi
fi

if [ -n "$source_bin" ]; then
    run_privileged install -m 755 "$source_bin" "$TRIVYSCAN_INSTALL_DIR/trivyscan"
    if [ -x "$TRIVYSCAN_INSTALL_DIR/trivyscan" ]; then
        echo "[OK] TrivyScan installed"
        trivyscan_updated=true
    else
        echo "[ERROR] Failed to install TrivyScan"
        trivyscan_failed=true
    fi
fi

# =========================================
# Step 3: Update PATH
# =========================================
echo ""
echo "[INFO] Checking PATH..."

for dir in "$TRIVY_INSTALL_DIR" "$TRIVYSCAN_INSTALL_DIR"; do
    if echo ":$PATH:" | grep -q ":$dir:"; then
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
elif [ -n "$current_trivy" ]; then
    echo "[OK] Trivy     -> already up to date (v$current_trivy)"
else
    echo "[--] Trivy     -> install failed"
fi

if $trivyscan_failed; then
    echo "[--] TrivyScan -> install failed"
elif $trivyscan_updated; then
    echo "[OK] TrivyScan -> installed/updated"
else
    echo "[OK] TrivyScan -> already installed"
fi

echo "========================================="
echo " Install complete! Run: source ~/.bashrc (or ~/.zshrc)"
echo "========================================="

if $trivyscan_failed; then
    exit 1
fi
