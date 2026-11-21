#!/usr/bin/env bash
#
# Trivy + TrivyScan installer for Linux and macOS.
#
# Per-user (default, no sudo):
#   curl -fsSL https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.sh | bash
#
# System-wide:
#   curl -fsSL https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.sh | sudo bash -s -- --system
#
# The installer always checks the latest release. Newer local versions are kept
# unless an explicit version or --force asks for a change. After a successful
# install it runs `trivyscan -u` to refresh the vulnerability databases.
# Every remote download is verified against the release SHA-256 checksums.

set -euo pipefail

REPO="antistudio/trivyscan"
TRIVY_REPO="aquasecurity/trivy"
TRIVY_MIN_VERSION="0.70.0"
MARKER_START="# >>> trivyscan installer >>>"
MARKER_END="# <<< trivyscan installer <<<"

SYSTEM=false
PREFIX="${TRIVYSCAN_PREFIX:-}"
FORCE=false
UNINSTALL=false
PURGE=false
SKIP_DB="${TRIVYSCAN_SKIP_DB_UPDATE:-}"
STRICT="${TRIVYSCAN_STRICT:-}"
NO_PATH="${TRIVYSCAN_NO_PATH:-}"
TRIVYSCAN_VERSION="${TRIVYSCAN_VERSION:-}"
TRIVY_VERSION="${TRIVY_VERSION:-}"

BIN_DIR=""
SHARE_DIR=""
MANIFEST=""
TMP_DIR=""
OS_GO=""
OS_TRIVY=""
ARCH_GO=""
ARCH_TRIVY=""
SUDO_USER_NAME="${SUDO_USER:-}"

TRIVYSCAN_ACTION="not installed"
TRIVY_ACTION="not installed"
TRIVYSCAN_INSTALLED_VERSION=""
TRIVY_INSTALLED_VERSION=""
TRIVY_MANAGED=0
TRIVY_BIN_PATH=""
DB_RESULT="skipped"
DB_FAILED=0
PATH_FILE=""
PATH_MODIFIED=0

log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
die() {
    log_error "$*"
    exit 1
}

usage() {
    cat <<'EOF'
Usage: install.sh [OPTIONS]

Options:
  --system                   Install system-wide (requires root/sudo)
  --prefix DIR               Install prefix (default: $HOME/.local, or /usr/local)
  --trivyscan-version V      Install a specific TrivyScan version
  --trivy-version V          Install a specific Trivy version
  --skip-db-update           Do not run `trivyscan -u` after installing
  --strict                   Exit 1 when the database update fails
  --no-modify-path           Do not modify the shell profile
  --force, -f                Reinstall even when the version is unchanged
  --uninstall, -u            Uninstall managed binaries
  --purge                    With --uninstall, also remove the Trivy DB cache
  --help, -h                 Show this help

Environment:
  TRIVYSCAN_VERSION, TRIVY_VERSION, TRIVYSCAN_PREFIX,
  TRIVYSCAN_SKIP_DB_UPDATE=1, TRIVYSCAN_STRICT=1, TRIVYSCAN_NO_PATH=1
EOF
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --system) SYSTEM=true ;;
            --prefix)
                [ "$#" -ge 2 ] || die "--prefix requires a directory"
                PREFIX="$2"
                shift
                ;;
            --trivyscan-version)
                [ "$#" -ge 2 ] || die "--trivyscan-version requires a version"
                TRIVYSCAN_VERSION="$2"
                shift
                ;;
            --trivy-version)
                [ "$#" -ge 2 ] || die "--trivy-version requires a version"
                TRIVY_VERSION="$2"
                shift
                ;;
            --skip-db-update) SKIP_DB=1 ;;
            --strict) STRICT=1 ;;
            --no-modify-path) NO_PATH=1 ;;
            --force|-f) FORCE=true ;;
            --uninstall|-u) UNINSTALL=true ;;
            --purge) PURGE=true ;;
            --help|-h) usage; exit 0 ;;
            *) die "Unknown option: $1 (use --help)" ;;
        esac
        shift
    done
    if [ "$PURGE" = true ]; then
        UNINSTALL=true
    fi
    return 0
}

run_privileged() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

check_dependencies() {
    for cmd in uname id mktemp tar awk grep sed tr install; do
        command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required"
    done
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || \
        die "curl or wget is required"
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || \
        command -v openssl >/dev/null 2>&1 || die "sha256sum, shasum or openssl is required"
}

setup_paths() {
    if [ "$SYSTEM" = true ]; then
        [ "$(id -u)" -eq 0 ] || die "Re-run with sudo for --system: sudo bash -s -- --system"
        PREFIX="${PREFIX:-/usr/local}"
    else
        if [ "$(id -u)" -eq 0 ] && [ -n "$SUDO_USER_NAME" ] && [ "$SUDO_USER_NAME" != "root" ]; then
            die "Run without sudo for a per-user install, or pass --system for a system-wide install"
        fi
        [ -n "${HOME:-}" ] || die "HOME is not set"
        PREFIX="${PREFIX:-$HOME/.local}"
    fi
    BIN_DIR="$PREFIX/bin"
    SHARE_DIR="$PREFIX/share/trivyscan"
    MANIFEST="$SHARE_DIR/install.env"
    umask 022
    TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/trivyscan-install.XXXXXX")" || die "Cannot create temp directory"
    trap 'rm -rf "$TMP_DIR"' EXIT
    if [ "$SYSTEM" = true ]; then
        run_privileged mkdir -p "$BIN_DIR"
    else
        mkdir -p "$BIN_DIR"
    fi
}

detect_os_arch() {
    case "$(uname -s)" in
        Linux)  OS_GO="linux";  OS_TRIVY="Linux" ;;
        Darwin) OS_GO="darwin"; OS_TRIVY="macOS" ;;
        *) die "Unsupported OS: $(uname -s)" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64)  ARCH_GO="amd64"; ARCH_TRIVY="64bit" ;;
        arm64|aarch64) ARCH_GO="arm64"; ARCH_TRIVY="ARM64" ;;
        *) die "Unsupported architecture: $(uname -m)" ;;
    esac
}

normalize_version() {
    printf '%s' "${1#v}"
}

version_lt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        n = split(a, x, "."); m = split(b, y, ".")
        for (i = 1; i <= n || i <= m; i++) {
            ai = (i <= n ? x[i] : 0) + 0
            bi = (i <= m ? y[i] : 0) + 0
            if (ai < bi) exit 0
            if (ai > bi) exit 1
        }
        exit 1
    }'
}

get_binary_version() {
    local out
    out="$("$1" --version 2>/dev/null || true)"
    printf '%s\n' "$out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true
}

fetch() {
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused \
            --connect-timeout 10 "$url" -o "$out"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --tries=3 --timeout=30 "$url" -O "$out"
    else
        return 1
    fi
}

latest_tag() {
    local repo="$1" tag="" json="$TMP_DIR/release.json"
    if command -v curl >/dev/null 2>&1; then
        tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
            "https://github.com/$repo/releases/latest" 2>/dev/null || true)"
        tag="${tag##*/releases/tag/}"
    fi
    if ! printf '%s' "$tag" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+'; then
        fetch "https://api.github.com/repos/$repo/releases/latest" "$json" >/dev/null 2>&1 || return 1
        tag="$(grep -m1 '"tag_name"' "$json" 2>/dev/null | \
            sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true)"
    fi
    printf '%s' "$tag" | grep -qE '^v?[0-9]+\.[0-9]+\.[0-9]+' || return 1
    normalize_version "$tag"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        return 1
    fi
}

verify_checksum() {
    local file="$1" sums="$2" name="$3" expected actual
    expected="$(tr -d '\r' < "$sums" | awk -v n="$name" '$2 == n || $2 == "*"n {print $1; exit}')"
    if [ -z "$expected" ]; then
        log_error "No checksum for $name in $sums"
        return 1
    fi
    if [ "${#expected}" -ne 64 ]; then
        log_error "Malformed checksum for $name"
        return 1
    fi
    actual="$(sha256_of "$file")" || {
        log_error "Cannot compute SHA-256 for $name"
        return 1
    }
    if [ "$expected" != "$actual" ]; then
        log_error "Checksum mismatch for $name"
        log_error "  expected $expected"
        log_error "  got      $actual"
        return 1
    fi
    log_info "Checksum verified: $name"
    return 0
}

download_verified() {
    local repo="$1" version="$2" asset="$3" sums_name="$4" outdir="$5"
    local base="https://github.com/$repo/releases/download/v${version}"
    mkdir -p "$outdir"
    log_info "Downloading $asset..."
    fetch "$base/$asset" "$outdir/$asset" || die "Download failed: $base/$asset"
    fetch "$base/$sums_name" "$outdir/$sums_name" || die "Download failed: $base/$sums_name"
    verify_checksum "$outdir/$asset" "$outdir/$sums_name" "$asset" || die "Refusing to install unverified $asset"
    DL_ARCHIVE="$outdir/$asset"
}

extract_binary() {
    local archive="$1" dir="$2" name="$3"
    mkdir -p "$dir"
    tar -xzf "$archive" -C "$dir" || return 1
    [ -f "$dir/$name" ] || return 1
    printf '%s' "$dir/$name"
}

install_binary() {
    local src="$1" dest="$2" expected="${3:-}"
    local tmp="$dest.tmp.$$" bak="$dest.bak.$$" had=0 got
    if [ -e "$dest" ]; then
        run_privileged cp -p "$dest" "$bak" || return 1
        had=1
    fi
    if ! run_privileged install -m 0755 "$src" "$tmp"; then
        if [ "$had" -eq 1 ]; then run_privileged rm -f "$bak"; fi
        return 1
    fi
    if ! run_privileged mv -f "$tmp" "$dest"; then
        run_privileged rm -f "$tmp"
        if [ "$had" -eq 1 ]; then run_privileged rm -f "$bak"; fi
        return 1
    fi
    got="$(get_binary_version "$dest")"
    if [ -n "$expected" ] && [ "$got" != "$expected" ]; then
        log_error "$dest reports '$got', expected '$expected'; rolling back"
        if [ "$had" -eq 1 ]; then
            run_privileged mv -f "$bak" "$dest"
        else
            run_privileged rm -f "$dest"
        fi
        return 1
    fi
    if [ "$had" -eq 1 ]; then run_privileged rm -f "$bak"; fi
    return 0
}

write_manifest() {
    local tmp="$TMP_DIR/install.env"
    {
        printf 'installer=trivyscan\n'
        printf 'layout=unix\n'
        printf 'prefix=%s\n' "$PREFIX"
        printf 'bin_dir=%s\n' "$BIN_DIR"
        printf 'trivyscan_path=%s\n' "$BIN_DIR/trivyscan"
        printf 'trivyscan_version=%s\n' "$1"
        printf 'trivy_version=%s\n' "$2"
        printf 'trivy_managed=%s\n' "$TRIVY_MANAGED"
        printf 'trivy_path=%s\n' "$TRIVY_BIN_PATH"
        printf 'path_file=%s\n' "$PATH_FILE"
        printf 'path_modified=%s\n' "$PATH_MODIFIED"
        printf 'installed_at=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    } > "$tmp"
    run_privileged mkdir -p "$SHARE_DIR"
    run_privileged install -m 0644 "$tmp" "$MANIFEST"
}

path_has_bin() {
    case ":$PATH:" in
        *":$BIN_DIR:"*) return 0 ;;
        *) return 1 ;;
    esac
}

add_path_block() {
    local rc="$1"
    [ -f "$rc" ] || : > "$rc" || return 1
    grep -qF "$MARKER_START" "$rc" 2>/dev/null && return 0
    {
        printf '\n%s\n' "$MARKER_START"
        # shellcheck disable=SC2016 # $PATH must be written literally to the profile.
        printf 'case ":$PATH:" in *":%s:"*) ;; *) export PATH="%s:$PATH";; esac\n' "$BIN_DIR" "$BIN_DIR"
        printf '%s\n' "$MARKER_END"
    } >> "$rc"
    PATH_MODIFIED=1
    PATH_FILE="$rc"
}

remove_path_block() {
    local rc="$1" tmp="$TMP_DIR/rc.$$"
    [ -n "$rc" ] && [ -f "$rc" ] || return 0
    awk -v start="$MARKER_START" -v end="$MARKER_END" '
        $0 == start { skip = 1; next }
        $0 == end { skip = 0; next }
        !skip { print }
    ' "$rc" > "$tmp" || return 1
    cat "$tmp" > "$rc"
}

configure_path() {
    if path_has_bin; then
        log_info "PATH already contains $BIN_DIR"
        return 0
    fi
    if [ "$NO_PATH" = "1" ]; then
        log_warn "$BIN_DIR is not in PATH; add it manually"
        return 0
    fi
    if [ "$SYSTEM" = true ]; then
        log_warn "$BIN_DIR is not in PATH; add it manually for system-wide use"
        return 0
    fi
    local rc
    case "${SHELL:-}" in
        *zsh) rc="$HOME/.zshrc" ;;
        *bash)
            if [ "$(uname -s)" = "Darwin" ]; then
                rc="$HOME/.bash_profile"
            else
                rc="$HOME/.bashrc"
            fi
            ;;
        *) rc="$HOME/.profile" ;;
    esac
    if add_path_block "$rc"; then
        log_info "Added $BIN_DIR to PATH in $rc"
    else
        log_warn "Could not update $rc; add $BIN_DIR to PATH manually"
    fi
}

run_db_update() {
    if [ "$SKIP_DB" = "1" ]; then
        DB_RESULT="skipped"
        log_info "Skipping database update"
        return 0
    fi
    [ -x "$BIN_DIR/trivyscan" ] || { DB_RESULT="failed"; DB_FAILED=1; log_warn "trivyscan is not executable"; return 0; }
    [ -n "$TRIVY_BIN_PATH" ] || { DB_RESULT="failed"; DB_FAILED=1; log_warn "Trivy is unavailable; run trivyscan -u later"; return 0; }

    log_info "Updating Trivy databases (trivyscan -u)..."
    local ok=1
    if [ "$SYSTEM" = true ] && [ -n "$SUDO_USER_NAME" ] && [ "$SUDO_USER_NAME" != "root" ]; then
        sudo -u "$SUDO_USER_NAME" -H env PATH="$BIN_DIR:$PATH" TRIVY_BIN="$TRIVY_BIN_PATH" \
            "$BIN_DIR/trivyscan" -u || ok=0
    else
        if [ "$SYSTEM" = true ] && [ -z "$SUDO_USER_NAME" ]; then
            log_warn "Running database update as root; the DB will be cached for root"
        fi
        env PATH="$BIN_DIR:$PATH" TRIVY_BIN="$TRIVY_BIN_PATH" "$BIN_DIR/trivyscan" -u || ok=0
    fi
    if [ "$ok" -eq 1 ]; then
        DB_RESULT="updated"
        log_info "Databases updated"
    else
        DB_RESULT="failed"
        DB_FAILED=1
        log_warn "Database update failed; run 'trivyscan -u' later"
    fi
}

read_manifest_value() {
    [ -f "$MANIFEST" ] || return 1
    grep "^$1=" "$MANIFEST" 2>/dev/null | head -n 1 | cut -d= -f2-
}

do_uninstall() {
    local trivyscan_path="$BIN_DIR/trivyscan"
    local trivy_path=""
    local tv_managed="0" path_file=""

    if [ -f "$MANIFEST" ]; then
        trivyscan_path="$(read_manifest_value trivyscan_path || true)"
        [ -n "$trivyscan_path" ] || trivyscan_path="$BIN_DIR/trivyscan"
        tv_managed="$(read_manifest_value trivy_managed || true)"
        trivy_path="$(read_manifest_value trivy_path || true)"
        path_file="$(read_manifest_value path_file || true)"
    else
        log_warn "No install manifest found; using safe fallback"
        [ "$FORCE" = true ] || log_warn "Pass --force to remove $trivyscan_path without a manifest"
        [ "$FORCE" = true ] || { log_info "Nothing removed"; return 0; }
    fi

    if [ -f "$trivyscan_path" ]; then
        run_privileged rm -f "$trivyscan_path" && log_info "Removed $trivyscan_path"
    fi
    if [ "$tv_managed" = "1" ] && [ -n "$trivy_path" ] && [ -f "$trivy_path" ]; then
        run_privileged rm -f "$trivy_path" && log_info "Removed $trivy_path"
    fi
    if [ -f "$MANIFEST" ]; then
        run_privileged rm -f "$MANIFEST"
        run_privileged rmdir "$SHARE_DIR" 2>/dev/null || true
    fi
    remove_path_block "$path_file" || log_warn "Could not clean PATH block in $path_file"

    if [ "$PURGE" = true ]; then
        if [ "$SYSTEM" = true ] && [ -n "$SUDO_USER_NAME" ] && [ "$SUDO_USER_NAME" != "root" ]; then
            sudo -u "$SUDO_USER_NAME" -H sh -c 'rm -rf "$HOME/.cache/trivy"'
            log_info "Removed Trivy DB cache for $SUDO_USER_NAME"
        elif [ "$SYSTEM" = true ]; then
            log_warn "Skipping DB purge for a system install; remove the user cache manually"
        else
            run_privileged rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/trivy"
            log_info "Removed Trivy DB cache"
        fi
    fi
    echo ""
    log_info "Uninstall complete"
}

resolve_existing_trivyscan() {
    local path=""
    if [ -x "$BIN_DIR/trivyscan" ]; then
        path="$BIN_DIR/trivyscan"
    elif command -v trivyscan >/dev/null 2>&1; then
        path="$(command -v trivyscan)"
    elif [ -x "/usr/local/bin/trivyscan" ]; then
        path="/usr/local/bin/trivyscan"
    fi
    printf '%s' "$path"
}

resolve_existing_trivy() {
    local path=""
    if [ -x "$BIN_DIR/trivy" ]; then
        path="$BIN_DIR/trivy"
    elif command -v trivy >/dev/null 2>&1; then
        path="$(command -v trivy)"
    fi
    printf '%s' "$path"
}

main() {
    parse_args "$@"
    if [ "$TRIVYSCAN_VERSION" = "latest" ]; then TRIVYSCAN_VERSION=""; fi
    if [ "$TRIVY_VERSION" = "latest" ]; then TRIVY_VERSION=""; fi
    check_dependencies
    setup_paths

    if [ "$UNINSTALL" = true ]; then
        do_uninstall
        return 0
    fi

    detect_os_arch
    log_info "OS: $(uname -s) | Arch: $ARCH_GO | Prefix: $PREFIX"

    local current_trivyscan_path current_trivyscan_version
    current_trivyscan_path="$(resolve_existing_trivyscan)"
    current_trivyscan_version=""
    if [ -n "$current_trivyscan_path" ]; then
        current_trivyscan_version="$(get_binary_version "$current_trivyscan_path")"
    fi

    if [ -n "$current_trivyscan_path" ] && [ "$current_trivyscan_path" != "$BIN_DIR/trivyscan" ]; then
        die "Unmanaged TrivyScan found at $current_trivyscan_path; remove it or use --system"
    fi

    local source_bin="" local_version=""
    if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        for name in trivyscan "trivyscan_${OS_GO}"; do
            if [ -f "$script_dir/$name" ]; then
                source_bin="$script_dir/$name"
                break
            fi
        done
    fi
    if [ -n "$source_bin" ]; then
        local_version="$(get_binary_version "$source_bin")"
        [ -n "$local_version" ] || die "Cannot read version from $source_bin"
    fi

    local desired_trivyscan explicit_trivyscan=false
    if [ -n "$TRIVYSCAN_VERSION" ]; then
        desired_trivyscan="$(normalize_version "$TRIVYSCAN_VERSION")"
        explicit_trivyscan=true
        if [ -n "$source_bin" ] && [ "$local_version" != "$desired_trivyscan" ]; then
            die "Local binary is v$local_version but --trivyscan-version is v$desired_trivyscan"
        fi
    elif [ -n "$source_bin" ]; then
        desired_trivyscan="$local_version"
    else
        desired_trivyscan="$(latest_tag "$REPO" || true)"
        if [ -z "$desired_trivyscan" ] && [ -n "$current_trivyscan_version" ]; then
            desired_trivyscan="$current_trivyscan_version"
            log_warn "Cannot resolve latest TrivyScan; keeping v$desired_trivyscan"
        fi
        [ -n "$desired_trivyscan" ] || die "Cannot resolve the latest TrivyScan release"
    fi
    if [ -n "$source_bin" ]; then
        desired_trivyscan="$local_version"
    fi

    local install_trivyscan=true
    if [ "$FORCE" = false ] && [ -n "$current_trivyscan_version" ]; then
        if [ "$current_trivyscan_version" = "$desired_trivyscan" ]; then
            install_trivyscan=false
        elif [ "$explicit_trivyscan" = false ] && version_lt "$desired_trivyscan" "$current_trivyscan_version"; then
            install_trivyscan=false
            log_warn "Installed TrivyScan v$current_trivyscan_version is newer than v$desired_trivyscan; keeping it"
        fi
    fi

    if [ "$install_trivyscan" = true ]; then
        if [ -z "$source_bin" ]; then
            local asset="trivyscan_${desired_trivyscan}_${OS_GO}_${ARCH_GO}.tar.gz"
            local sums="trivyscan_${desired_trivyscan}_checksums.txt"
            download_verified "$REPO" "$desired_trivyscan" "$asset" "$sums" "$TMP_DIR/trivyscan"
            source_bin="$(extract_binary "$DL_ARCHIVE" "$TMP_DIR/trivyscan/extract" trivyscan)" || \
                die "trivyscan binary not found in $asset"
        else
            log_info "Using local binary: $source_bin"
        fi
        install_binary "$source_bin" "$BIN_DIR/trivyscan" "$desired_trivyscan" || \
            die "Failed to install TrivyScan"
        TRIVYSCAN_ACTION="updated to v$desired_trivyscan"
        TRIVYSCAN_INSTALLED_VERSION="$desired_trivyscan"
    else
        TRIVYSCAN_ACTION="kept v$current_trivyscan_version"
        TRIVYSCAN_INSTALLED_VERSION="$current_trivyscan_version"
        log_info "TrivyScan already at v$current_trivyscan_version"
        if [ -n "$current_trivyscan_path" ]; then
            desired_trivyscan="$current_trivyscan_version"
        fi
    fi

    local current_trivy_path current_trivy_version
    current_trivy_path="$(resolve_existing_trivy)"
    current_trivy_version=""
    if [ -n "$current_trivy_path" ]; then
        current_trivy_version="$(get_binary_version "$current_trivy_path")"
    fi

    local desired_trivy explicit_trivy=false
    if [ -n "$TRIVY_VERSION" ]; then
        desired_trivy="$(normalize_version "$TRIVY_VERSION")"
        explicit_trivy=true
    else
        desired_trivy="$(latest_tag "$TRIVY_REPO" || true)"
        if [ -z "$desired_trivy" ] && [ -n "$current_trivy_version" ]; then
            desired_trivy="$current_trivy_version"
            log_warn "Cannot resolve latest Trivy; keeping v$desired_trivy"
        fi
        [ -n "$desired_trivy" ] || die "Cannot resolve the latest Trivy release"
    fi

    local install_trivy=true
    if [ "$FORCE" = false ] && [ -n "$current_trivy_path" ]; then
        if [ -n "$current_trivy_version" ] && [ "$current_trivy_version" = "$desired_trivy" ]; then
            install_trivy=false
        elif [ "$explicit_trivy" = false ] && [ -n "$current_trivy_version" ] && \
             version_lt "$desired_trivy" "$current_trivy_version"; then
            install_trivy=false
            log_warn "Installed Trivy v$current_trivy_version is newer than v$desired_trivy; keeping it"
        fi
    fi

    if [ "$install_trivy" = true ]; then
        local asset="trivy_${desired_trivy}_${OS_TRIVY}-${ARCH_TRIVY}.tar.gz"
        local sums="trivy_${desired_trivy}_checksums.txt"
        download_verified "$TRIVY_REPO" "$desired_trivy" "$asset" "$sums" "$TMP_DIR/trivy"
        local trivy_src
        trivy_src="$(extract_binary "$DL_ARCHIVE" "$TMP_DIR/trivy/extract" trivy)" || \
            die "trivy binary not found in $asset"
        install_binary "$trivy_src" "$BIN_DIR/trivy" "$desired_trivy" || \
            die "Failed to install Trivy"
        TRIVY_ACTION="updated to v$desired_trivy"
        TRIVY_INSTALLED_VERSION="$desired_trivy"
        TRIVY_MANAGED=1
        TRIVY_BIN_PATH="$BIN_DIR/trivy"
    else
        TRIVY_ACTION="kept v$current_trivy_version"
        TRIVY_INSTALLED_VERSION="$current_trivy_version"
        if [ "$current_trivy_path" = "$BIN_DIR/trivy" ]; then
            TRIVY_MANAGED=1
        else
            TRIVY_MANAGED=0
        fi
        TRIVY_BIN_PATH="$current_trivy_path"
        log_info "Using existing Trivy v$current_trivy_version at $current_trivy_path"
    fi

    if [ -z "$TRIVY_BIN_PATH" ] || [ ! -x "$TRIVY_BIN_PATH" ]; then
        die "Trivy is not available after setup"
    fi

    if version_lt "$TRIVY_INSTALLED_VERSION" "$TRIVY_MIN_VERSION"; then
        log_warn "Trivy v$TRIVY_INSTALLED_VERSION is older than the tested minimum v$TRIVY_MIN_VERSION"
    fi

    configure_path
    write_manifest "$TRIVYSCAN_INSTALLED_VERSION" "$TRIVY_INSTALLED_VERSION"
    run_db_update

    echo ""
    echo "========================================="
    echo "      TrivyScan installer summary"
    echo "========================================="
    printf '[OK] TrivyScan  -> %s\n' "$TRIVYSCAN_ACTION"
    printf '[OK] Trivy      -> %s\n' "$TRIVY_ACTION"
    printf '[OK] Binaries   -> %s\n' "$BIN_DIR"
    printf '[%s] Database  -> %s\n' "$([ "$DB_FAILED" -eq 1 ] && printf 'WARN' || printf 'OK')" "$DB_RESULT"
    if [ "$PATH_MODIFIED" = "1" ] && [ -n "$PATH_FILE" ]; then
        printf '[OK] PATH       -> added in %s (open a new terminal)\n' "$PATH_FILE"
    fi
    echo "========================================="

    if [ "$DB_FAILED" -eq 1 ] && [ "$STRICT" = "1" ]; then
        exit 1
    fi
    return 0
}

main "$@"
