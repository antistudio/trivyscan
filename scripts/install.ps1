# =========================================
# Ensure: Run as Admin + ExecutionPolicy Bypass
# =========================================

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

$policy = Get-ExecutionPolicy -Scope Process

if (-not $isAdmin -or $policy -ne 'Bypass') {
    Write-Host "[INFO] Restarting script with Admin + Bypass..."

    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""

    Start-Process powershell -ArgumentList $args -Verb RunAs
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
# Detect Arch
# =========================================
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$ArchTrivy = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "ARM64" } else { "64bit" }

Write-Host "========================================="
Write-Host "      Trivy + TrivyScan Installer"
Write-Host "========================================="
Write-Host "[INFO] OS: Windows | Arch: $Arch"

# =========================================
# Step 1: Install Trivy
# =========================================
Write-Host ""
Write-Host "[INFO] Checking Trivy..."

if (Get-Command trivy -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Trivy already installed - skipping"
} else {
    Write-Host "[INFO] Fetching latest Trivy version..."
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
        $version = $release.tag_name -replace "^v", ""
    } catch {
        Write-Host "[ERROR] Cannot fetch Trivy version: $_"
        exit 1
    }

    if (-not $version) {
        Write-Host "[ERROR] Version is empty"
        exit 1
    }

    Write-Host "[OK] Latest Trivy version: $version"

    $url = "https://github.com/aquasecurity/trivy/releases/download/v$version/trivy_${version}_Windows-${ArchTrivy}.zip"

    Write-Host "[INFO] Downloading from: $url"
    try {
        Invoke-WebRequest -Uri $url -OutFile $TrivyZip
    } catch {
        Write-Host "[ERROR] Download failed: $_"
        exit 1
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
        exit 1
    }

    Write-Host "[OK] Trivy installed"
}

# =========================================
# Step 2: Install TrivyScan (detect binary)
# =========================================
Write-Host ""
Write-Host "[INFO] Installing TrivyScan..."

$SourceExe = Join-Path $ScriptDir "trivyscan_windows_${Arch}.exe"
$TargetExe = Join-Path $TrivyScanDir "trivyscan.exe"

if (-not (Test-Path $SourceExe)) {
    Write-Host "[ERROR] Binary not found: trivyscan_windows_${Arch}.exe"
    Write-Host "        Available files:"
    Get-ChildItem "$ScriptDir\trivyscan_*" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "        $_" }
    exit 1
}

if (-not (Test-Path $TrivyScanDir)) {
    New-Item -ItemType Directory -Path $TrivyScanDir | Out-Null
}

Copy-Item $SourceExe $TargetExe -Force

if (-not (Test-Path $TargetExe)) {
    Write-Host "[ERROR] Failed to install trivyscan"
    exit 1
}

Write-Host "[OK] TrivyScan installed"

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

& "$TrivyDir\trivy.exe" --version
& "$TrivyScanDir\trivyscan.exe" --version

Write-Host ""
Write-Host "========================================="
Write-Host "[SUCCESS] Installation complete!"
Write-Host "         Open a new terminal to use."
Write-Host "========================================="
