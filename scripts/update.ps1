# TrivyScan Update Script for Windows
# This script updates both Trivy and TrivyScan to their latest versions

#Requires -RunAsAdministrator

# Configuration
$ErrorActionPreference = "Stop"
$TRIVYSCAN_BINARY = "trivyscan.exe"
$TRIVY_BINARY = "trivy.exe"

# GitHub repositories
$TRIVY_REPO = "aquasecurity/trivy"
$TRIVYSCAN_REPO = "anhnmt/trivyscan"

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

# Determine install directories
$ProgramFiles = [Environment]::GetFolderPath("ProgramFiles")
$INSTALL_DIR = Join-Path $ProgramFiles "TrivyScan"
$TRIVY_DIR = Join-Path $ProgramFiles "Trivy"

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "           TrivyScan Update Script" -ForegroundColor Cyan
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

# Function to get latest version from GitHub
function Get-LatestVersion {
    param($Repo)
    
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
        $version = $response.tag_name -replace '^v', ''
        return $version
    } catch {
        return $null
    }
}

# Function to get current installed version
function Get-InstalledVersion {
    param($Binary)
    
    try {
        $versionOutput = & $Binary --version 2>&1 | Select-Object -First 1
        if ($versionOutput -match '(\d+\.\d+\.\d+)') {
            return $matches[1]
        }
    } catch {
        return $null
    }
    
    return $null
}

# Function to compare versions
function Compare-Version {
    param(
        [string]$Version1,
        [string]$Version2
    )
    
    $v1 = [version]$Version1
    $v2 = [version]$Version2
    
    return $v1.CompareTo($v2)
}

# Function to download file with progress
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

# Function to update Trivy
function Update-Trivy {
    Write-Host "Fetching latest Trivy version..." -ForegroundColor Blue
    $latestVersion = Get-LatestVersion -Repo $TRIVY_REPO
    
    if (-not $latestVersion) {
        Write-Host "✗ Failed to fetch latest Trivy version" -ForegroundColor Red
        return $false
    }
    
    Write-Host "✓ Latest Trivy version: v$latestVersion" -ForegroundColor Green
    
    $currentVersion = Get-InstalledVersion -Binary "trivy"
    if ($currentVersion) {
        Write-Host "  Current installed: v$currentVersion" -ForegroundColor Blue
        
        $comparison = Compare-Version -Version1 $currentVersion -Version2 $latestVersion
        
        if ($comparison -eq 0) {
            Write-Host "✓ Trivy is already up to date!" -ForegroundColor Green
            return $true
        } elseif ($comparison -gt 0) {
            Write-Host "⚠ Installed version is newer than latest release" -ForegroundColor Yellow
            $response = Read-Host "Do you want to downgrade to v$latestVersion? (y/N)"
            if ($response -notmatch '^[Yy]$') {
                Write-Host "Skipping Trivy update" -ForegroundColor Blue
                return $true
            }
        }
    } else {
        Write-Host "⚠ Trivy is not installed" -ForegroundColor Yellow
    }
    
    Write-Host ""
    
    # Check for Chocolatey
    if (Test-CommandExists choco) {
        Write-Host "Using Chocolatey to update Trivy..." -ForegroundColor Blue
        try {
            choco upgrade trivy -y
            Write-Host "✓ Trivy updated successfully via Chocolatey!" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "⚠ Chocolatey update failed, trying manual update..." -ForegroundColor Yellow
        }
    }
    
    # Manual update
    Write-Host "Updating Trivy manually..." -ForegroundColor Blue
    
    $TRIVY_URL = "https://github.com/$TRIVY_REPO/releases/download/v$latestVersion/trivy_${latestVersion}_Windows-${ARCH_TRIVY}.zip"
    $TEMP_DIR = [System.IO.Path]::GetTempPath()
    $TEMP_ZIP = Join-Path $TEMP_DIR "trivy_update.zip"
    $TEMP_EXTRACT = Join-Path $TEMP_DIR "trivy_update_extract"
    
    try {
        # Download
        Download-File -Url $TRIVY_URL -Output $TEMP_ZIP
        
        # Extract
        Write-Host "Extracting..." -ForegroundColor Blue
        if (Test-Path $TEMP_EXTRACT) {
            Remove-Item -Path $TEMP_EXTRACT -Recurse -Force
        }
        Expand-Archive -Path $TEMP_ZIP -DestinationPath $TEMP_EXTRACT -Force
        
        # Create install directory if needed
        if (-not (Test-Path $TRIVY_DIR)) {
            New-Item -ItemType Directory -Path $TRIVY_DIR -Force | Out-Null
        }
        
        # Copy binary
        Write-Host "Installing Trivy to $TRIVY_DIR..." -ForegroundColor Blue
        Copy-Item -Path (Join-Path $TEMP_EXTRACT "trivy.exe") -Destination $TRIVY_DIR -Force
        
        # Cleanup
        Remove-Item -Path $TEMP_ZIP -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $TEMP_EXTRACT -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Host "✓ Trivy updated successfully!" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "✗ Failed to update Trivy: $_" -ForegroundColor Red
        
        # Cleanup on error
        Remove-Item -Path $TEMP_ZIP -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $TEMP_EXTRACT -Recurse -Force -ErrorAction SilentlyContinue
        
        return $false
    }
}

# Function to update TrivyScan
function Update-TrivyScan {
    Write-Host "Fetching latest TrivyScan version..." -ForegroundColor Blue
    $latestVersion = Get-LatestVersion -Repo $TRIVYSCAN_REPO
    
    if (-not $latestVersion) {
        Write-Host "✗ Failed to fetch latest TrivyScan version" -ForegroundColor Red
        return $false
    }
    
    Write-Host "✓ Latest TrivyScan version: v$latestVersion" -ForegroundColor Green
    
    $currentVersion = Get-InstalledVersion -Binary "trivyscan"
    if ($currentVersion) {
        Write-Host "  Current installed: v$currentVersion" -ForegroundColor Blue
        
        $comparison = Compare-Version -Version1 $currentVersion -Version2 $latestVersion
        
        if ($comparison -eq 0) {
            Write-Host "✓ TrivyScan is already up to date!" -ForegroundColor Green
            return $true
        } elseif ($comparison -gt 0) {
            Write-Host "⚠ Installed version is newer than latest release" -ForegroundColor Yellow
            $response = Read-Host "Do you want to downgrade to v$latestVersion? (y/N)"
            if ($response -notmatch '^[Yy]$') {
                Write-Host "Skipping TrivyScan update" -ForegroundColor Blue
                return $true
            }
        }
    } else {
        Write-Host "⚠ TrivyScan is not installed" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Updating TrivyScan manually..." -ForegroundColor Blue
    
    $TRIVYSCAN_URL = "https://github.com/$TRIVYSCAN_REPO/releases/download/v$latestVersion/trivyscan_${latestVersion}_windows_${ARCH_GO}.zip"
    $TEMP_DIR = [System.IO.Path]::GetTempPath()
    $TEMP_ZIP = Join-Path $TEMP_DIR "trivyscan_update.zip"
    $TEMP_EXTRACT = Join-Path $TEMP_DIR "trivyscan_update_extract"
    
    try {
        # Download
        Download-File -Url $TRIVYSCAN_URL -Output $TEMP_ZIP
        
        # Extract
        Write-Host "Extracting..." -ForegroundColor Blue
        if (Test-Path $TEMP_EXTRACT) {
            Remove-Item -Path $TEMP_EXTRACT -Recurse -Force
        }
        Expand-Archive -Path $TEMP_ZIP -DestinationPath $TEMP_EXTRACT -Force
        
        # Create install directory if needed
        if (-not (Test-Path $INSTALL_DIR)) {
            New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
        }
        
        # Copy binary
        Write-Host "Installing TrivyScan to $INSTALL_DIR..." -ForegroundColor Blue
        Copy-Item -Path (Join-Path $TEMP_EXTRACT "trivyscan.exe") -Destination $INSTALL_DIR -Force
        
        # Cleanup
        Remove-Item -Path $TEMP_ZIP -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $TEMP_EXTRACT -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Host "✓ TrivyScan updated successfully!" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "✗ Failed to update TrivyScan: $_" -ForegroundColor Red
        
        # Cleanup on error
        Remove-Item -Path $TEMP_ZIP -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $TEMP_EXTRACT -Recurse -Force -ErrorAction SilentlyContinue
        
        return $false
    }
}

# Step 1: Update Trivy (priority)
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Step 1: Updating Trivy..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

$trivyUpdated = Update-Trivy
if (-not $trivyUpdated) {
    Write-Host "⚠ Trivy update failed, continuing..." -ForegroundColor Yellow
}

Write-Host ""

# Step 2: Update TrivyScan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Step 2: Updating TrivyScan..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

$trivyscanUpdated = Update-TrivyScan
if (-not $trivyscanUpdated) {
    Write-Host "⚠ TrivyScan update failed" -ForegroundColor Yellow
}

Write-Host ""

# Step 3: Verify updates
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "Step 3: Verifying updates..." -ForegroundColor Cyan
Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""

# Refresh environment variables for current session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

if (Test-CommandExists trivy) {
    Write-Host "Trivy version:"
    & trivy --version
    Write-Host ""
}

if (Test-CommandExists trivyscan) {
    Write-Host "TrivyScan version:"
    & trivyscan --version
    Write-Host ""
}

# Summary
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "              Update Summary" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($trivyUpdated) {
    Write-Host "✓ Trivy updated successfully" -ForegroundColor Green
} else {
    Write-Host "⚠ Trivy update skipped or failed" -ForegroundColor Yellow
}

if ($trivyscanUpdated) {
    Write-Host "✓ TrivyScan updated successfully" -ForegroundColor Green
} else {
    Write-Host "⚠ TrivyScan update skipped or failed" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($trivyUpdated -or $trivyscanUpdated) {
    Write-Host "Update completed! 🚀"
    exit 0
} else {
    Write-Host "No updates were performed."
    exit 1
}
