#!/bin/bash

# TrivyScan Installation Script for Linux/macOS
# This script installs both TrivyScan and Trivy (if not present)

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

# Function to get latest Trivy version from GitHub
get_latest_trivy_version() {
    echo -e "${BLUE}Fetching latest Trivy version...${NC}"

    if command_exists curl; then
        TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    elif command_exists wget; then
        TRIVY_VERSION=$(wget -qO- https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    else
        # Fallback to a known stable version
        TRIVY_VERSION="0.58.1"
        echo -e "${YELLOW}⚠ Cannot detect curl/wget, using fallback version: v$TRIVY_VERSION${NC}"
        return
    fi

    if [ -z "$TRIVY_VERSION" ]; then
        TRIVY_VERSION="0.58.1"
        echo -e "${YELLOW}⚠ Failed to fetch latest version, using fallback: v$TRIVY_VERSION${NC}"
    else
        echo -e "${GREEN}✓ Latest Trivy version: v$TRIVY_VERSION${NC}"
    fi
}

# Function to check write permission
check_write_permission() {
    if [ -w "$1" ]; then
        return 0
    else
        return 1
    fi
}

# Function to install with sudo if needed
install_binary() {
    local source=$1
    local target=$2

    if check_write_permission "$(dirname "$target")"; then
        echo -e "${BLUE}Installing to $target...${NC}"
        cp "$source" "$target"
        chmod 755 "$target"
    else
        echo -e "${YELLOW}⚠ Requires sudo to install to $target${NC}"
        sudo cp "$source" "$target"
        sudo chmod 755 "$target"
    fi
}

echo "═══════════════════════════════════════════════════════════"
echo "           TrivyScan Installation Script"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "OS: $OS_NAME"
echo "Architecture: $ARCH ($ARCH_GO)"
echo "Install Directory: $INSTALL_DIR"
echo ""

# Step 1: Check and install Trivy
echo "───────────────────────────────────────────────────────────"
echo "Step 1: Checking Trivy installation..."
echo "───────────────────────────────────────────────────────────"
echo ""

if command_exists trivy; then
    echo -e "${GREEN}✓ Trivy is already installed${NC}"
    trivy --version
else
    echo -e "${YELLOW}✗ Trivy not found. Installing Trivy...${NC}"
    echo ""

    # Get latest version
    get_latest_trivy_version
    echo ""

    # Check for package managers first
    if [ "$OS" = "darwin" ] && command_exists brew; then
        echo -e "${BLUE}Using Homebrew to install Trivy...${NC}"
        brew install aquasecurity/trivy/trivy
        echo -e "${GREEN}✓ Trivy installed successfully via Homebrew!${NC}"
    elif [ "$OS" = "linux" ] && command_exists apt-get; then
        echo -e "${BLUE}Using APT to install Trivy...${NC}"
        sudo apt-get install wget apt-transport-https gnupg lsb-release -y
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
        sudo apt-get update
        sudo apt-get install trivy -y
        echo -e "${GREEN}✓ Trivy installed successfully via APT!${NC}"
    elif [ "$OS" = "linux" ] && command_exists yum; then
        echo -e "${BLUE}Using YUM to install Trivy...${NC}"
        cat << EOF | sudo tee /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/\$basearch/
gpgcheck=0
enabled=1
EOF
        sudo yum -y update
        sudo yum -y install trivy
        echo -e "${GREEN}✓ Trivy installed successfully via YUM!${NC}"
    else
        # Manual installation
        echo -e "${BLUE}Installing Trivy manually...${NC}"

        TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${OS_NAME}-${ARCH_TRIVY}.tar.gz"
        TEMP_DIR=$(mktemp -d)

        echo "Downloading from: $TRIVY_URL"
        if command_exists curl; then
            curl -sL "$TRIVY_URL" -o "$TEMP_DIR/trivy.tar.gz"
        elif command_exists wget; then
            wget -q "$TRIVY_URL" -O "$TEMP_DIR/trivy.tar.gz"
        else
            echo -e "${RED}✗ Neither curl nor wget is available. Please install one of them.${NC}"
            exit 1
        fi

        echo "Extracting..."
        tar -xzf "$TEMP_DIR/trivy.tar.gz" -C "$TEMP_DIR"

        echo "Installing Trivy..."
        install_binary "$TEMP_DIR/trivy" "$INSTALL_DIR/trivy"

        # Cleanup
        rm -rf "$TEMP_DIR"

        echo -e "${GREEN}✓ Trivy installed successfully!${NC}"
    fi
fi

echo ""

# Step 2: Install TrivyScan
echo "───────────────────────────────────────────────────────────"
echo "Step 2: Installing TrivyScan..."
echo "───────────────────────────────────────────────────────────"
echo ""

# Find TrivyScan binary in current directory
if [ -f "./$TRIVYSCAN_BINARY" ]; then
    TRIVYSCAN_SOURCE="./$TRIVYSCAN_BINARY"
elif [ -f "./trivyscan_${OS}_${ARCH_GO}" ]; then
    TRIVYSCAN_SOURCE="./trivyscan_${OS}_${ARCH_GO}"
elif [ -f "./trivyscan" ]; then
    TRIVYSCAN_SOURCE="./trivyscan"
else
    echo -e "${RED}✗ TrivyScan binary not found in current directory${NC}"
    echo "Expected: ./$TRIVYSCAN_BINARY or ./trivyscan_${OS}_${ARCH_GO}"
    exit 1
fi

echo "Source: $TRIVYSCAN_SOURCE"
echo "Target: $INSTALL_DIR/$TRIVYSCAN_BINARY"
echo ""

install_binary "$TRIVYSCAN_SOURCE" "$INSTALL_DIR/$TRIVYSCAN_BINARY"

echo -e "${GREEN}✓ TrivyScan installed successfully!${NC}"
echo ""

# Step 3: Verify installation
echo "───────────────────────────────────────────────────────────"
echo "Step 3: Verifying installation..."
echo "───────────────────────────────────────────────────────────"
echo ""

if command_exists trivy && command_exists trivyscan; then
    echo -e "${GREEN}✓ Verification successful!${NC}"
    echo ""
    echo "Trivy version:"
    trivy --version
    echo ""
    echo "TrivyScan version:"
    trivyscan --version
else
    echo -e "${RED}✗ Verification failed. Please check your PATH.${NC}"
    exit 1
fi

# Step 4: Check PATH
echo ""
echo "───────────────────────────────────────────────────────────"
echo "Step 4: Checking PATH configuration..."
echo "───────────────────────────────────────────────────────────"
echo ""

if echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo -e "${GREEN}✓ $INSTALL_DIR is already in PATH${NC}"
else
    echo -e "${YELLOW}⚠ Warning: $INSTALL_DIR is not in your PATH${NC}"
    echo ""
    echo "To add it permanently, add this line to your shell configuration:"

    # Detect shell
    if [ -n "$ZSH_VERSION" ]; then
        echo ""
        echo -e "${BLUE}  echo 'export PATH=\"\$PATH:$INSTALL_DIR\"' >> ~/.zshrc${NC}"
        echo -e "${BLUE}  source ~/.zshrc${NC}"
    elif [ -n "$BASH_VERSION" ]; then
        echo ""
        echo -e "${BLUE}  echo 'export PATH=\"\$PATH:$INSTALL_DIR\"' >> ~/.bashrc${NC}"
        echo -e "${BLUE}  source ~/.bashrc${NC}"
    else
        echo ""
        echo -e "${BLUE}  export PATH=\"\$PATH:$INSTALL_DIR\"${NC}"
    fi

    echo ""
    echo "Or run this command temporarily:"
    echo -e "${BLUE}  export PATH=\"\$PATH:$INSTALL_DIR\"${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "              Installation Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "You can now use:"
echo "  trivyscan --help"
echo "  trivyscan -i image.tar -o reports/"
echo ""
echo "Happy scanning! 🚀"
echo ""