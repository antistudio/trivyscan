#!/bin/bash

# TrivyScan Update Script for Linux/macOS
# This script updates both Trivy and TrivyScan to their latest versions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/bin"
TRIVYSCAN_BINARY="trivyscan"
TRIVY_BINARY="trivy"

# GitHub repositories
TRIVY_REPO="aquasecurity/trivy"
TRIVYSCAN_REPO="anhnmt/trivyscan"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)
        ARCH_TRIVY="64bit"
        ARCH_GO="amd64"
        ;;
    aarch64|arm64)
        ARCH_TRIVY="ARM64"
        ARCH_GO="arm64"
        ;;
    *)
        echo -e "${RED}✗ Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

case "$OS" in
    linux)
        OS_NAME="Linux"
        ;;
    darwin)
        OS_NAME="macOS"
        ;;
    *)
        echo -e "${RED}✗ Unsupported operating system: $OS${NC}"
        exit 1
        ;;
esac

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get latest version from GitHub
get_latest_version() {
    local repo=$1
    local version
    
    if command_exists curl; then
        version=$(curl -s "https://api.github.com/repos/$repo/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    elif command_exists wget; then
        version=$(wget -qO- "https://api.github.com/repos/$repo/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
    else
        echo ""
        return 1
    fi
    
    echo "$version"
}

# Function to get current installed version
get_installed_version() {
    local binary=$1
    local version
    
    if command_exists "$binary"; then
        version=$("$binary" --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
        echo "$version"
    else
        echo ""
    fi
}

# Function to compare versions
version_gt() {
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}

# Function to check write permission
check_write_permission() {
    if [ -w "$1" ]; then
        return 0
    else
        return 1
    fi
}

# Function to update with sudo if needed
update_binary() {
    local source=$1
    local target=$2
    
    if check_write_permission "$(dirname "$target")"; then
        echo -e "${BLUE}Updating $target...${NC}"
        cp "$source" "$target"
        chmod 755 "$target"
    else
        echo -e "${YELLOW}⚠ Requires sudo to update $target${NC}"
        sudo cp "$source" "$target"
        sudo chmod 755 "$target"
    fi
}

# Function to update Trivy
update_trivy() {
    echo -e "${BLUE}Fetching latest Trivy version...${NC}"
    local latest_version=$(get_latest_version "$TRIVY_REPO")
    
    if [ -z "$latest_version" ]; then
        echo -e "${RED}✗ Failed to fetch latest Trivy version${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ Latest Trivy version: v$latest_version${NC}"
    
    local current_version=$(get_installed_version "trivy")
    if [ -n "$current_version" ]; then
        echo -e "${BLUE}  Current installed: v$current_version${NC}"
        
        if [ "$current_version" = "$latest_version" ]; then
            echo -e "${GREEN}✓ Trivy is already up to date!${NC}"
            return 0
        elif version_gt "$current_version" "$latest_version"; then
            echo -e "${YELLOW}⚠ Installed version is newer than latest release${NC}"
            read -p "Do you want to downgrade to v$latest_version? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo -e "${BLUE}Skipping Trivy update${NC}"
                return 0
            fi
        fi
    else
        echo -e "${YELLOW}⚠ Trivy is not installed${NC}"
    fi
    
    echo ""
    
    # Check for package managers first
    if [ "$OS" = "darwin" ] && command_exists brew; then
        echo -e "${BLUE}Using Homebrew to update Trivy...${NC}"
        brew upgrade aquasecurity/trivy/trivy || brew install aquasecurity/trivy/trivy
        echo -e "${GREEN}✓ Trivy updated successfully via Homebrew!${NC}"
        return 0
    elif [ "$OS" = "linux" ] && command_exists apt-get; then
        echo -e "${BLUE}Using APT to update Trivy...${NC}"
        sudo apt-get update
        sudo apt-get install --only-upgrade trivy -y || sudo apt-get install trivy -y
        echo -e "${GREEN}✓ Trivy updated successfully via APT!${NC}"
        return 0
    elif [ "$OS" = "linux" ] && command_exists yum; then
        echo -e "${BLUE}Using YUM to update Trivy...${NC}"
        sudo yum update trivy -y || sudo yum install trivy -y
        echo -e "${GREEN}✓ Trivy updated successfully via YUM!${NC}"
        return 0
    fi
    
    # Manual update
    echo -e "${BLUE}Updating Trivy manually...${NC}"
    
    TRIVY_URL="https://github.com/$TRIVY_REPO/releases/download/v${latest_version}/trivy_${latest_version}_${OS_NAME}-${ARCH_TRIVY}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    
    echo "Downloading from: $TRIVY_URL"
    if command_exists curl; then
        curl -sL "$TRIVY_URL" -o "$TEMP_DIR/trivy.tar.gz"
    elif command_exists wget; then
        wget -q "$TRIVY_URL" -O "$TEMP_DIR/trivy.tar.gz"
    else
        echo -e "${RED}✗ Neither curl nor wget is available${NC}"
        rm -rf "$TEMP_DIR"
        return 1
    fi
    
    echo "Extracting..."
    tar -xzf "$TEMP_DIR/trivy.tar.gz" -C "$TEMP_DIR"
    
    echo "Installing Trivy..."
    update_binary "$TEMP_DIR/trivy" "$INSTALL_DIR/trivy"
    
    # Cleanup
    rm -rf "$TEMP_DIR"
    
    echo -e "${GREEN}✓ Trivy updated successfully!${NC}"
    return 0
}

# Function to update TrivyScan
update_trivyscan() {
    echo -e "${BLUE}Fetching latest TrivyScan version...${NC}"
    local latest_version=$(get_latest_version "$TRIVYSCAN_REPO")
    
    if [ -z "$latest_version" ]; then
        echo -e "${RED}✗ Failed to fetch latest TrivyScan version${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✓ Latest TrivyScan version: v$latest_version${NC}"
    
    local current_version=$(get_installed_version "trivyscan")
    if [ -n "$current_version" ]; then
        echo -e "${BLUE}  Current installed: v$current_version${NC}"
        
        if [ "$current_version" = "$latest_version" ]; then
            echo -e "${GREEN}✓ TrivyScan is already up to date!${NC}"
            return 0
        elif version_gt "$current_version" "$latest_version"; then
            echo -e "${YELLOW}⚠ Installed version is newer than latest release${NC}"
            read -p "Do you want to downgrade to v$latest_version? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo -e "${BLUE}Skipping TrivyScan update${NC}"
                return 0
            fi
        fi
    else
        echo -e "${YELLOW}⚠ TrivyScan is not installed${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Updating TrivyScan manually...${NC}"
    
    TRIVYSCAN_URL="https://github.com/$TRIVYSCAN_REPO/releases/download/v${latest_version}/trivyscan_${latest_version}_${OS}_${ARCH_GO}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    
    echo "Downloading from: $TRIVYSCAN_URL"
    if command_exists curl; then
        curl -sL "$TRIVYSCAN_URL" -o "$TEMP_DIR/trivyscan.tar.gz"
    elif command_exists wget; then
        wget -q "$TRIVYSCAN_URL" -O "$TEMP_DIR/trivyscan.tar.gz"
    else
        echo -e "${RED}✗ Neither curl nor wget is available${NC}"
        rm -rf "$TEMP_DIR"
        return 1
    fi
    
    echo "Extracting..."
    tar -xzf "$TEMP_DIR/trivyscan.tar.gz" -C "$TEMP_DIR"
    
    echo "Installing TrivyScan..."
    update_binary "$TEMP_DIR/trivyscan" "$INSTALL_DIR/trivyscan"
    
    # Cleanup
    rm -rf "$TEMP_DIR"
    
    echo -e "${GREEN}✓ TrivyScan updated successfully!${NC}"
    return 0
}

echo "═══════════════════════════════════════════════════════════"
echo "           TrivyScan Update Script"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "OS: $OS_NAME"
echo "Architecture: $ARCH ($ARCH_GO)"
echo "Install Directory: $INSTALL_DIR"
echo ""

# Step 1: Update Trivy (priority)
echo "───────────────────────────────────────────────────────────"
echo "Step 1: Updating Trivy..."
echo "───────────────────────────────────────────────────────────"
echo ""

if update_trivy; then
    TRIVY_UPDATED=true
else
    TRIVY_UPDATED=false
    echo -e "${YELLOW}⚠ Trivy update failed, continuing...${NC}"
fi

echo ""

# Step 2: Update TrivyScan
echo "───────────────────────────────────────────────────────────"
echo "Step 2: Updating TrivyScan..."
echo "───────────────────────────────────────────────────────────"
echo ""

if update_trivyscan; then
    TRIVYSCAN_UPDATED=true
else
    TRIVYSCAN_UPDATED=false
    echo -e "${YELLOW}⚠ TrivyScan update failed${NC}"
fi

echo ""

# Step 3: Verify updates
echo "───────────────────────────────────────────────────────────"
echo "Step 3: Verifying updates..."
echo "───────────────────────────────────────────────────────────"
echo ""

if command_exists trivy; then
    echo "Trivy version:"
    trivy --version
    echo ""
fi

if command_exists trivyscan; then
    echo "TrivyScan version:"
    trivyscan --version
    echo ""
fi

# Summary
echo "═══════════════════════════════════════════════════════════"
echo "              Update Summary"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ "$TRIVY_UPDATED" = true ]; then
    echo -e "${GREEN}✓ Trivy updated successfully${NC}"
else
    echo -e "${YELLOW}⚠ Trivy update skipped or failed${NC}"
fi

if [ "$TRIVYSCAN_UPDATED" = true ]; then
    echo -e "${GREEN}✓ TrivyScan updated successfully${NC}"
else
    echo -e "${YELLOW}⚠ TrivyScan update skipped or failed${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ "$TRIVY_UPDATED" = true ] || [ "$TRIVYSCAN_UPDATED" = true ]; then
    echo "Update completed! 🚀"
    exit 0
else
    echo "No updates were performed."
    exit 1
fi
