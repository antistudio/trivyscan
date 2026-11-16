# =========================================
# TrivyScan Installer
#
# Usage (remote):
#   irm https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.ps1 | iex
#
# Usage (local, from extracted zip):
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Every download is verified against the release's SHA-256 checksums file.
# Set $env:TRIVYSCAN_SKIP_CHECKSUM = "1" to install without verification (not recommended).
#
# Options:
#   --force, -f      Force reinstall
#   --uninstall, -u  Uninstall both Trivy and TrivyScan
#   --help, -h       Show help
# =========================================

# =========================================
# Ensure: Run as Admin + ExecutionPolicy Bypass
# =========================================

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

$policy = Get-ExecutionPolicy -Scope Process

if (-not $isAdmin -or $policy -ne 'Bypass') {
    Write-Host "[INFO] Restarting script with Admin + Bypass..."

    # When run via "irm | iex", $PSCommandPath is empty.
    # Save current script to a temp file so re-elevation works.
    if ($PSCommandPath) {
        $scriptFile = $PSCommandPath
    } else {
        $scriptFile = Join-Path $env:TEMP "trivyscan_install.ps1"
        $MyInvocation.MyCommand.Definition | Out-File $scriptFile -Encoding UTF8
    }

    $passArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptFile`""

    Start-Process powershell -ArgumentList $passArgs -Verb RunAs
    exit
}

# =========================================
# Config
# =========================================
$RepoOwner    = "antistudio"
$RepoName     = "trivyscan"
$ApiUrl       = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
$TrivyDir     = "C:\Program Files\Trivy"
$TrivyScanDir = "C:\Program Files\TrivyScan"
$TempDir      = "$env:TEMP\trivyscan_install"

# ScriptDir: directory where install.ps1 lives (for local mode)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# =========================================
# Colors
# =========================================
function Write-Green  { param($msg) Write-Host $msg -ForegroundColor Green }
function Write-Yellow { param($msg) Write-Host $msg -ForegroundColor Yellow }
function Write-Red    { param($msg) Write-Host $msg -ForegroundColor Red }

# =========================================
# Args
# =========================================
$Force = $false
$Uninstall = $false

foreach ($arg in $args) {
    switch -Regex ($arg) {
        "^(--force|-f)$"   { $Force = $true }
        "^(--uninstall|-u)$" { $Uninstall = $true }
        "^(--help|-h)$"     { 
            Write-Host "Usage: install.ps1 [OPTIONS]"
            Write-Host "  --force, -f      Force reinstall"
            Write-Host "  --uninstall, -u  Uninstall both"
            Write-Host "  --help, -h       Show this help"
            exit 0
        }
    }
}

# =========================================
# Uninstall
# =========================================
if ($Uninstall) {
    Write-Host ""
    Write-Host "[INFO] Uninstalling..."

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = ($currentPath -split ';' | Where-Object { $_ -notin @($TrivyDir, $TrivyScanDir) }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")

    if (Test-Path $TrivyDir) {
        Remove-Item $TrivyDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed $TrivyDir"
    }

    if (Test-Path $TrivyScanDir) {
        Remove-Item $TrivyScanDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed $TrivyScanDir"
    }

    if (Test-Path $TempDir) {
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "[SUCCESS] Uninstall complete! Restart your terminal."
    exit 0
}

# =========================================
# Detect Arch
# =========================================
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$ArchTrivy = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "ARM64" } else { "64bit" }

Write-Host "========================================="
Write-Host "      Trivy + TrivyScan Installer"
Write-Host "========================================="
Write-Host "[INFO] OS: Windows | Arch: $Arch"

$trivyUpdated     = $false
$trivyscanUpdated = $false

# =========================================
# Helper Functions
# =========================================

# New-TempDir returns an empty directory under $TempDir for one download.
function New-TempDir($name) {
    $dir = Join-Path $TempDir $name
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

# Test-Checksum compares $File with the line for $Name in a goreleaser-style checksums file.
function Test-Checksum($File, $SumsFile, $Name) {
    if ($env:TRIVYSCAN_SKIP_CHECKSUM -eq "1") {
        Write-Yellow "[WARN] TRIVYSCAN_SKIP_CHECKSUM=1: NOT verifying $Name"
        return $true
    }
    $expected = $null
    foreach ($line in Get-Content $SumsFile) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $Name) {
            $expected = $parts[0].ToLower()
            break
        }
    }
    if (-not $expected) {
        Write-Red "[ERROR] No checksum for $Name in checksums file"
        return $false
    }
    $actual = (Get-FileHash -Algorithm SHA256 -Path $File).Hash.ToLower()
    if ($expected -ne $actual) {
        Write-Red "[ERROR] Checksum mismatch for $Name"
        Write-Red "        expected $expected"
        Write-Red "        got      $actual"
        return $false
    }
    Write-Green "[OK] Checksum verified: $Name"
    return $true
}

function Install-Trivy($latestVersion) {
    # Asset names in trivy's checksums file are lowercase ("windows-64bit").
    $base    = "https://github.com/aquasecurity/trivy/releases/download/v$latestVersion"
    $asset   = "trivy_${latestVersion}_windows-${ArchTrivy}.zip"
    $sums    = "trivy_${latestVersion}_checksums.txt"
    $workDir = New-TempDir "trivy"
    $zipPath = Join-Path $workDir $asset
    $sumPath = Join-Path $workDir $sums

    Write-Host "[INFO] Downloading Trivy from: $base/$asset"
    try {
        Invoke-WebRequest -Uri "$base/$asset" -OutFile $zipPath
        Invoke-WebRequest -Uri "$base/$sums" -OutFile $sumPath
    } catch {
        Write-Red "[ERROR] Trivy download failed: $_"
        return $false
    }

    if (-not (Test-Checksum $zipPath $sumPath $asset)) {
        return $false
    }

    Write-Host "[INFO] Extracting Trivy..."
    $extractDir = Join-Path $workDir "extract"
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $exe = Get-ChildItem $extractDir -Recurse -Filter "trivy.exe" | Select-Object -First 1
    if (-not $exe) {
        Write-Red "[ERROR] trivy.exe not found after extraction"
        return $false
    }

    if (-not (Test-Path $TrivyDir)) {
        New-Item -ItemType Directory -Path $TrivyDir | Out-Null
    }
    Copy-Item $exe.FullName "$TrivyDir\trivy.exe" -Force

    return (Test-Path "$TrivyDir\trivy.exe")
}

function Install-TrivyScan {
    param(
        [string]$SourceExe,
        [string]$TargetExe
    )

    if (-not (Test-Path $SourceExe)) {
        Write-Red "[ERROR] Binary not found: $SourceExe"
        return $false
    }

    if (-not (Test-Path $TrivyScanDir)) {
        New-Item -ItemType Directory -Path $TrivyScanDir | Out-Null
    }

    Copy-Item $SourceExe $TargetExe -Force

    if (-not (Test-Path $TargetExe)) {
        Write-Red "[ERROR] Failed to install trivyscan"
        return $false
    }

    return $true
}

function Get-TrivyScanBinary {
    # Try local mode first: check if binary exists alongside install.ps1
    # (trivyscan_windows.exe is the name used by older release archives)
    $candidates = @(
        "trivyscan.exe",
        "trivyscan_windows.exe"
    )
    foreach ($name in $candidates) {
        $localBinary = Join-Path $ScriptDir $name
        if (Test-Path $localBinary) {
            Write-Host "[INFO] Found local binary: $localBinary"
            return $localBinary
        }
    }

    # Remote mode: download from GitHub release
    Write-Yellow "[INFO] No local binary found. Downloading from GitHub releases..."

    $workDir = New-TempDir "trivyscan"

    # Get latest release
    $release = $null
    try {
        $release = Invoke-RestMethod -Uri $ApiUrl
    } catch {
        Write-Red "[ERROR] Cannot fetch release info: $_"
        return $null
    }

    $tagName = $release.tag_name
    $version = $tagName -replace "^v", ""
    Write-Host "[INFO] Latest version: v$version"

    # Find matching asset + checksums (names come from .goreleaser.yaml)
    $assetName = "trivyscan_${version}_windows_${Arch}.zip"
    $sumsName  = "trivyscan_${version}_checksums.txt"
    $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
    $sums  = $release.assets | Where-Object { $_.name -eq $sumsName } | Select-Object -First 1

    if (-not $asset -or -not $sums) {
        Write-Red "[ERROR] Asset not found: $assetName / $sumsName"
        Write-Host "        Available assets:"
        $release.assets | ForEach-Object { Write-Host "          $($_.name)" }
        return $null
    }

    $zipPath = Join-Path $workDir $assetName
    $sumPath = Join-Path $workDir $sumsName
    Write-Host "[INFO] Downloading $assetName..."
    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
        Invoke-WebRequest -Uri $sums.browser_download_url -OutFile $sumPath
    } catch {
        Write-Red "[ERROR] Download failed: $_"
        return $null
    }

    if (-not (Test-Checksum $zipPath $sumPath $assetName)) {
        return $null
    }

    # Extract
    Write-Host "[INFO] Extracting..."
    $extractDir = Join-Path $workDir "extract"
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $binary = Get-ChildItem $extractDir -Recurse -Filter "trivyscan.exe" | Select-Object -First 1
    if ($binary) {
        return $binary.FullName
    }

    Write-Red "[ERROR] trivyscan.exe not found in archive"
    return $null
}

# =========================================
# Step 1: Install/Update Trivy
# =========================================
Write-Host ""
Write-Host "[INFO] Checking Trivy..."

$currentTrivy = $null

if (Test-Path "$TrivyDir\trivy.exe") {
    $currentTrivy = ((& "$TrivyDir\trivy.exe" --version 2>$null) -replace ".*?([0-9]+\.[0-9]+\.[0-9]+).*", '$1' | Select-Object -First 1)
}

$latestTrivy = $null
try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
    $latestTrivy = $release.tag_name -replace "^v", ""
} catch {
    Write-Yellow "[WARN] Cannot fetch Trivy version: $_"
}

if (-not $latestTrivy) {
    Write-Yellow "[WARN] Skipping Trivy installation"
} elseif (-not $Force -and $currentTrivy -and $currentTrivy -eq $latestTrivy) {
    Write-Green "[OK] Trivy already up to date (v$currentTrivy)"
} else {
    if ($currentTrivy) {
        Write-Host "[INFO] Current version: $currentTrivy, updating to v$latestTrivy..."
    } else {
        Write-Host "[INFO] Trivy not found, installing v$latestTrivy..."
    }

    if (Install-Trivy $latestTrivy) {
        Write-Green "[OK] Trivy installed/updated to v$latestTrivy"
        $trivyUpdated = $true
    }
}

# =========================================
# Step 2: Install/Update TrivyScan
# =========================================
Write-Host ""
Write-Host "[INFO] Checking TrivyScan..."

$SourceExe = Get-TrivyScanBinary
$TargetExe = Join-Path $TrivyScanDir "trivyscan.exe"

$currentTrivyscan = $null

if (Test-Path $TargetExe) {
    $currentTrivyscan = (& $TargetExe --version 2>$null) | Select-Object -First 1
}

# Check if downloaded binary is newer than installed
$shouldInstall = $false
if (-not $SourceExe) {
    Write-Red "[ERROR] Cannot locate trivyscan binary"
} elseif ($Force) {
    $shouldInstall = $true
} elseif (-not $currentTrivyscan) {
    # Not installed yet
    $shouldInstall = $true
} elseif ($SourceExe -ne $TargetExe -and (Test-Path $SourceExe)) {
    # Remote mode: always overwrite with latest download
    $shouldInstall = $true
    Write-Yellow "[INFO] New version available, updating..."
} else {
    Write-Green "[OK] TrivyScan already installed"
}

if ($shouldInstall) {
    if (Install-TrivyScan -SourceExe $SourceExe -TargetExe $TargetExe) {
        Write-Green "[OK] TrivyScan installed/updated"
        $trivyscanUpdated = $true
    }
}

# =========================================
# Step 3: Update PATH
# =========================================
Write-Host ""
Write-Host "[INFO] Updating PATH..."

$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")

foreach ($dir in @($TrivyDir, $TrivyScanDir)) {
    if ($currentPath -notlike "*$dir*") {
        $currentPath += ";$dir"
        Write-Green "[OK] Added to PATH: $dir"
    } else {
        Write-Host "[OK] Already in PATH: $dir"
    }
}

[Environment]::SetEnvironmentVariable("Path", $currentPath, "Machine")

# =========================================
# Step 4: Verify
# =========================================
Write-Host ""
Write-Host "[INFO] Verifying..."

if (Test-Path "$TrivyDir\trivy.exe") {
    & "$TrivyDir\trivy.exe" --version
}

if (Test-Path $TargetExe) {
    & $TargetExe --version
}

# =========================================
# Cleanup temp files
# =========================================
if (Test-Path $TempDir) {
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# =========================================
# Summary
# =========================================
Write-Host ""
Write-Host "========================================="
if (-not $latestTrivy)         { Write-Host "[--] Trivy     -> skipped (cannot fetch version)" }
elseif ($trivyUpdated)         { Write-Green "[OK] Trivy     -> installed/updated to v$latestTrivy" }
else                          { Write-Green "[OK] Trivy     -> already up to date (v$currentTrivy)" }

if (-not $SourceExe)          { Write-Host "[--] TrivyScan -> skipped (binary not found)" }
elseif ($trivyscanUpdated)     { Write-Green "[OK] TrivyScan -> installed/updated" }
elseif ($currentTrivyscan)    { Write-Green "[OK] TrivyScan -> already installed" }
else                          { Write-Host "[--] TrivyScan -> install failed" }

Write-Host "========================================="
Write-Host " Install complete! Open a new terminal to use."
Write-Host "========================================="
