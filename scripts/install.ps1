# =========================================
# Ensure: Run as Admin + ExecutionPolicy Bypass
# =========================================

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

$policy = Get-ExecutionPolicy -Scope Process

if (-not $isAdmin -or $policy -ne 'Bypass') {
    Write-Host "[INFO] Restarting script with Admin + Bypass..."

    $passArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""

    Start-Process powershell -ArgumentList $passArgs -Verb RunAs
    exit
}

# =========================================
# Config
# =========================================
$TrivyDir     = "C:\Program Files\Trivy"
$TrivyScanDir = "C:\Program Files\TrivyScan"
$TrivyZip     = "$env:TEMP\trivy.zip"
$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path

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
            Write-Host "Usage: .\install.ps1 [OPTIONS]"
            Write-Host "  --force, -f     Force reinstall"
            Write-Host "  --uninstall, -u Uninstall both"
            Write-Host "  --help, -h      Show this help"
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

    # Remove from PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = ($currentPath -split ';' | Where-Object { $_ -notin @($TrivyDir, $TrivyScanDir) }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")

    # Remove Trivy
    if (Test-Path $TrivyDir) {
        Remove-Item $TrivyDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed $TrivyDir"
    }

    # Remove TrivyScan
    if (Test-Path $TrivyScanDir) {
        Remove-Item $TrivyScanDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed $TrivyScanDir"
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

function Install-Trivy($latestVersion) {
    $url = "https://github.com/aquasecurity/trivy/releases/download/v$latestVersion/trivy_${latestVersion}_Windows-${ArchTrivy}.zip"

    Write-Host "[INFO] Downloading from: $url"
    try {
        Invoke-WebRequest -Uri $url -OutFile $TrivyZip
    } catch {
        Write-Host "[ERROR] Download failed: $_"
        return $false
    }

    Write-Host "[INFO] Extracting..."
    if (-not (Test-Path $TrivyDir)) {
        New-Item -ItemType Directory -Path $TrivyDir | Out-Null
    }

    Expand-Archive -Path $TrivyZip -DestinationPath $TrivyDir -Force
    Remove-Item $TrivyZip -Force -ErrorAction SilentlyContinue

    # Fix nested folder if needed
    if (Test-Path "$TrivyDir\trivy\trivy.exe") {
        Move-Item "$TrivyDir\trivy\trivy.exe" "$TrivyDir\trivy.exe" -Force
        Remove-Item "$TrivyDir\trivy" -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path "$TrivyDir\trivy.exe")) {
        Write-Host "[ERROR] trivy.exe not found after extraction"
        return $false
    }

    return $true
}

function Install-TrivyScan {
    param(
        [string]$SourceExe,
        [string]$TargetExe
    )

    if (-not (Test-Path $SourceExe)) {
        Write-Host "[ERROR] Binary not found: $SourceExe"
        return $false
    }

    if (-not (Test-Path $TrivyScanDir)) {
        New-Item -ItemType Directory -Path $TrivyScanDir | Out-Null
    }

    Copy-Item $SourceExe $TargetExe -Force

    if (-not (Test-Path $TargetExe)) {
        Write-Host "[ERROR] Failed to install trivyscan"
        return $false
    }

    return $true
}

# =========================================
# Step 1: Install/Update Trivy
# =========================================
Write-Host ""
Write-Host "[INFO] Checking Trivy..."

$currentTrivy = $null

# Check if Trivy is already installed
if (Test-Path "$TrivyDir\trivy.exe") {
    $currentTrivy = ((& "$TrivyDir\trivy.exe" --version 2>$null) -replace ".*?([0-9]+\.[0-9]+\.[0-9]+).*", '$1' | Select-Object -First 1)
}

# Get latest version from GitHub
$latestTrivy = $null
try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
    $latestTrivy = $release.tag_name -replace "^v", ""
} catch {
    Write-Host "[WARN] Cannot fetch Trivy version: $_"
}

if (-not $latestTrivy) {
    Write-Host "[WARN] Skipping Trivy installation"
} elseif (-not $Force -and $currentTrivy -and $currentTrivy -eq $latestTrivy) {
    Write-Host "[OK] Trivy already up to date (v$currentTrivy)"
} else {
    if ($currentTrivy) {
        Write-Host "[INFO] Current version: $currentTrivy, updating to v$latestTrivy..."
    } else {
        Write-Host "[INFO] Trivy not found, installing v$latestTrivy..."
    }

    if (Install-Trivy $latestTrivy) {
        Write-Host "[OK] Trivy installed/updated to v$latestTrivy"
        $trivyUpdated = $true
    }
}

# =========================================
# Step 2: Install/Update TrivyScan
# =========================================
Write-Host ""
Write-Host "[INFO] Checking TrivyScan..."

$SourceExe = Join-Path $ScriptDir "trivyscan_windows.exe"
$TargetExe = Join-Path $TrivyScanDir "trivyscan.exe"

$currentTrivyscan = $null

# Check if TrivyScan is already installed
if (Test-Path $TargetExe) {
    $currentTrivyscan = (& $TargetExe --version 2>$null) | Select-Object -First 1
}

if (-not (Test-Path $SourceExe)) {
    Write-Host "[ERROR] Binary not found: trivyscan_windows.exe"
    Write-Host "        Available files:"
    Get-ChildItem "$ScriptDir\trivyscan_*" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "        $_" }
} elseif (-not $Force -and $currentTrivyscan) {
    Write-Host "[OK] TrivyScan already installed"
} else {
    if ($currentTrivyscan) {
        Write-Host "[INFO] Reinstalling TrivyScan..."
    } else {
        Write-Host "[INFO] TrivyScan not found, installing..."
    }

    if (Install-TrivyScan -SourceExe $SourceExe -TargetExe $TargetExe) {
        Write-Host "[OK] TrivyScan installed/updated"
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
        Write-Host "[OK] Added to PATH: $dir"
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
# Summary
# =========================================
Write-Host ""
Write-Host "========================================="
if (-not $latestTrivy)         { Write-Host "[--] Trivy     -> skipped (cannot fetch version)" }
elseif ($trivyUpdated)         { Write-Host "[OK] Trivy     -> installed/updated to v$latestTrivy" }
else                          { Write-Host "[OK] Trivy     -> already up to date (v$currentTrivy)" }

if (-not (Test-Path $SourceExe)) { Write-Host "[--] TrivyScan -> skipped (binary not found)" }
elseif ($trivyscanUpdated)     { Write-Host "[OK] TrivyScan -> installed/updated" }
elseif ($currentTrivyscan)    { Write-Host "[OK] TrivyScan -> already installed" }
else                          { Write-Host "[--] TrivyScan -> install failed" }

Write-Host "========================================="
Write-Host " Install complete! Open a new terminal to use."
Write-Host "========================================="
