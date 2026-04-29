# TrivyScan Installation Script for Windows
# This script installs both TrivyScan and Trivy (if not present)

#Requires -RunAsAdministrator

# Configuration
$ErrorActionPreference = "Stop"
$TRIVYSCAN_BINARY = "trivyscan.exe"
$TRIVY_BINARY = "trivy.exe"

# Detect architecture
$ARCH = $env:PROCESSOR_ARCHITECTURE
switch ($ARCH) {
    "AMD64" { $ARCH_TRIVY = "64bit"; $ARCH_GO = "amd64" }
    "ARM64" { $ARCH_TRIVY = "ARM64"; $ARCH_GO = "arm64" }
    default {
        Write-Host "✗ Unsupported architecture: $ARCH" -ForegroundColor Red
        exit 1
    }
}

# Determine install directory
$ProgramFiles = [Environment]::GetFolderPath("ProgramFiles")
$INSTALL_DIR = Join-Path $ProgramFiles "TrivyScan"
$TRIVY_DIR = Join-Path $ProgramFiles "Trivy"

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "           TrivyScan Installation Script" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "OS: Windows"
Write-Host "Architecture: $ARCH ($ARCH_GO)"
Write-Host "TrivyScan Install Directory: $INSTALL_DIR"
Write-Host "Trivy Install Directory: $TRIVY_DIR"
Write-Host ""

# Function to check if command exists
function Test-CommandExists {
    param($command)
    $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
}

# Function to get latest Trivy version
function Get-LatestTrivyVersion {
    Write-Host "Fetching latest Trivy version..." -ForegroundColor Blue

    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
        $version = $response.tag_name -replace '^v', ''
        Write-Host "✓ Latest Trivy version: v$version" -ForegroundColor Green
        return $version
    } catch {
        Write-Host "⚠ Failed to fetch latest version, using fallback: v0.58.1" -ForegroundColor Yellow
        return "0.58.1"
    }
}

# Function to add to PATH
function Add-ToPath {
    param($PathToAdd)

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")

    if ($currentPath -notlike "*$PathToAdd*") {
        Write-Host "Adding $PathToAdd to system PATH..." -ForegroundColor Yellow
        $newPath = "$currentPath;$PathToAdd"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")

        # Update current session PATH
        $env:Path = "$env:Path;$PathToAdd"

        Write-Host "✓ Added to PATH successfully" -ForegroundColor Green
        return $true
    } else {
        Write-Host "✓ Already in PATH" -ForegroundColor Green
        return $false
    }
}

# Function to download file
function Download-File {
    param($Url, $Output)

    Write-Host "Downloading from: $Url" -ForegroundColor Blue

    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $Output -UseBasicParsing
        Write-Host "✓ Download completed" -ForegroundColor Green
    } catch {
        Write-Host "✗ Download failed: $_" -ForegroundColor Red
        throw
    }
}

# Step 1: Check and install Trivy
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Step 1: Checking Trivy installation..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

if (Test-CommandExists trivy) {
    Write-Host "✓ Trivy is already installed" -ForegroundColor Green
    trivy --version
} else {
    Write-Host "✗ Trivy not found. Installing Trivy..." -ForegroundColor Yellow
    Write-Host ""

    # Get latest version
    $TRIVY_VERSION = Get-LatestTrivyVersion
    Write-Host ""

    # Check for Chocolatey
    if (Test-CommandExists choco) {
        Write-Host "Using Chocolatey to install Trivy..." -ForegroundColor Blue
        try {
            choco install trivy -y
            Write-Host "✓ Trivy installed successfully via Chocolatey!" -ForegroundColor Green
        } catch {
            Write-Host "⚠ Chocolatey installation failed, trying manual installation..." -ForegroundColor Yellow
        }
    }

    # Manual installation if Chocolatey failed or not available
    if (-not (Test-CommandExists trivy)) {
        Write-Host "Installing Trivy manually..." -ForegroundColor Blue

        $TRIVY_URL = "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_Windows-${ARCH_TRIVY}.zip"
        $TEMP_DIR = [System.IO.Path]::GetTempPath()
        $TEMP_ZIP = Join-Path $TEMP_DIR "trivy.zip"
        $TEMP_EXTRACT = Join-Path $TEMP_DIR "trivy_extract"

        try {
            # Download
            Download-File -Url $TRIVY_URL -Output $TEMP_ZIP

            # Extract
            Write-Host "Extracting..." -ForegroundColor Blue
            Expand-Archive -Path $TEMP_ZIP -DestinationPath $TEMP_EXTRACT -Force

            # Create install directory
            if (-not (Test-Path $TRIVY_DIR)) {
                New-Item -ItemType Directory -Path $TRIVY_DIR -Force | Out-Null
            }

            # Copy binary
            Write-Host "Installing Trivy to $TRIVY_DIR..." -ForegroundColor Blue
            Copy-Item -Path (Join-Path $TEMP_EXTRACT "trivy.exe") -Destination $TRIVY_DIR -Force

            # Add to PATH
            Add-ToPath -PathToAdd $TRIVY_DIR

            # Cleanup
            Remove-Item -Path $TEMP_ZIP -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $TEMP_EXTRACT -Recurse -Force -ErrorAction SilentlyContinue

            Write-Host "✓ Trivy installed successfully!" -ForegroundColor Green
        } catch {
            Write-Host "✗ Failed to install Trivy: $_" -ForegroundColor Red
            exit 1
        }
    }
}

Write-Host ""

# Step 2: Install TrivyScan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Step 2: Installing TrivyScan..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

# Find TrivyScan binary in current directory
$possiblePaths = @(
    ".\$TRIVYSCAN_BINARY",
    ".\trivyscan_windows_$ARCH_GO.exe",
    ".\trivyscan.exe"
)

$TRIVYSCAN_SOURCE = $null
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $TRIVYSCAN_SOURCE = $path
        break
    }
}

if (-not $TRIVYSCAN_SOURCE) {
    Write-Host "✗ TrivyScan binary not found in current directory" -ForegroundColor Red
    Write-Host "Expected: $TRIVYSCAN_BINARY or trivyscan_windows_$ARCH_GO.exe" -ForegroundColor Red
    exit 1
}

Write-Host "Source: $TRIVYSCAN_SOURCE"
Write-Host "Target: $INSTALL_DIR\$TRIVYSCAN_BINARY"
Write-Host ""

try {
    # Create install directory
    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    }

    # Copy binary
    Write-Host "Installing TrivyScan to $INSTALL_DIR..." -ForegroundColor Blue
    Copy-Item -Path $TRIVYSCAN_SOURCE -Destination (Join-Path $INSTALL_DIR $TRIVYSCAN_BINARY) -Force

    # Add to PATH
    Add-ToPath -PathToAdd $INSTALL_DIR

    Write-Host "✓ TrivyScan installed successfully!" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to install TrivyScan: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Step 3: Verify installation
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Step 3: Verifying installation..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

# Refresh environment variables for current session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

if ((Test-CommandExists trivy) -and (Test-CommandExists trivyscan)) {
    Write-Host "✓ Verification successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Trivy version:"
    & trivy --version
    Write-Host ""
    Write-Host "TrivyScan version:"
    & trivyscan --version
} else {
    Write-Host "✗ Verification failed." -ForegroundColor Red
    Write-Host ""
    Write-Host "Please restart your terminal/PowerShell to update PATH, then verify:" -ForegroundColor Yellow
    Write-Host "  trivy --version"
    Write-Host "  trivyscan --version"
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "              Installation Complete!" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: Please restart your terminal/PowerShell for PATH changes to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "After restart, you can use:" -ForegroundColor Green
Write-Host "  trivyscan --help"
Write-Host "  trivyscan -i image.tar -o reports\"
Write-Host ""
Write-Host "Happy scanning! 🚀"
Write-Host ""