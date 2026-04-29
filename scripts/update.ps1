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
Write-Host "      Trivy + TrivyScan Updater"
Write-Host "========================================="
Write-Host "[INFO] OS: Windows | Arch: $Arch"

$trivyUpdated     = $false
$trivyscanUpdated = $false

# =========================================
# Step 1: Update Trivy
# =========================================
Write-Host ""
Write-Host "[INFO] Fetching latest Trivy version..."

try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
    $latestTrivy = $release.tag_name -replace "^v", ""
} catch {
    Write-Host "[WARN] Cannot fetch Trivy version - skipping: $_"
    $latestTrivy = $null
}

if (-not $latestTrivy) {
    Write-Host "[WARN] Skipping Trivy update"
} else {
    Write-Host "[OK] Latest Trivy version: $latestTrivy"

    $currentTrivy = $null
    if (Get-Command trivy -ErrorAction SilentlyContinue) {
        $currentTrivy = (trivy --version 2>$null) -replace ".*?([0-9]+\.[0-9]+\.[0-9]+).*", '$1' | Select-Object -First 1
        Write-Host "[INFO] Installed version: $currentTrivy"
    }

    if ($currentTrivy -eq $latestTrivy) {
        Write-Host "[OK] Trivy is already up to date"
    } else {
        $url = "https://github.com/aquasecurity/trivy/releases/download/v$latestTrivy/trivy_${latestTrivy}_Windows-${ArchTrivy}.zip"

        Write-Host "[INFO] Downloading from: $url"
        try {
            Invoke-WebRequest -Uri $url -OutFile $TrivyZip
        } catch {
            Write-Host "[ERROR] Download failed: $_"
            $latestTrivy = $null
        }

        if ($latestTrivy -and (Test-Path $TrivyZip)) {
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
            } else {
                Write-Host "[OK] Trivy updated to v$latestTrivy"
                $trivyUpdated = $true
            }
        }
    }
}

# =========================================
# Step 2: Update TrivyScan (from local binary)
# =========================================
Write-Host ""
Write-Host "[INFO] Updating TrivyScan..."

$SourceExe = Join-Path $ScriptDir "trivyscan_windows_${Arch}.exe"
$TargetExe = Join-Path $TrivyScanDir "trivyscan.exe"

if (-not (Test-Path $SourceExe)) {
    Write-Host "[ERROR] Binary not found: trivyscan_windows_${Arch}.exe"
} else {
    if (-not (Test-Path $TrivyScanDir)) {
        New-Item -ItemType Directory -Path $TrivyScanDir | Out-Null
    }

    Copy-Item $SourceExe $TargetExe -Force

    if (-not (Test-Path $TargetExe)) {
        Write-Host "[ERROR] Failed to update TrivyScan"
    } else {
        Write-Host "[OK] TrivyScan updated"
        $trivyscanUpdated = $true
    }
}

# =========================================
# Step 3: Update PATH
# =========================================
Write-Host ""
Write-Host "[INFO] Checking PATH..."

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

# =========================================
# Summary
# =========================================
Write-Host ""
Write-Host "========================================="
if ($trivyUpdated)     { Write-Host "[OK] Trivy     -> updated to v$latestTrivy" }
else                   { Write-Host "[--] Trivy     -> already up to date" }
if ($trivyscanUpdated) { Write-Host "[OK] TrivyScan -> updated" }
else                   { Write-Host "[--] TrivyScan -> update failed or skipped" }
Write-Host "========================================="
