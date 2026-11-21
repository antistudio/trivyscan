#Requires -Version 5.1
#
# Trivy + TrivyScan installer for Windows.
#
# Per-user (default, no admin):
#   irm https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.ps1 | iex
#
# System-wide (run from a file):
#   irm https://raw.githubusercontent.com/antistudio/trivyscan/main/scripts/install.ps1 -OutFile "$env:TEMP\install.ps1"
#   powershell -ExecutionPolicy Bypass -File "$env:TEMP\install.ps1" -System
#
# The installer checks the latest release on every run, updates older versions,
# keeps newer versions unless -Force/-TrivyScanVersion/-TrivyVersion is used,
# and runs `trivyscan -u` after a successful install.
# Windows Application Control diagnosis/allow is built in; use -DiagnoseOnly.

param(
    [switch]$System,
    [string]$InstallDir = "",
    [string]$TrivyScanVersion = $env:TRIVYSCAN_VERSION,
    [string]$TrivyVersion = $env:TRIVY_VERSION,
    [switch]$SkipDbUpdate,
    [switch]$Strict,
    [switch]$NoPath,
    [switch]$Force,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$NoPause,
    [switch]$NonInteractive,
    [switch]$Help,
    [switch]$DiagnoseOnly,
    [switch]$AppLockerHash,
    [switch]$AppLockerPath,
    [switch]$WdacDraft,
    [switch]$Deploy,
    [switch]$Unblock,
    [string]$User = "Everyone",
    [string]$BasePolicyPath = "",
    [string]$BasePolicyId = "",
    [string]$SigningCertPath = "",
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($env:TRIVYSCAN_SKIP_DB_UPDATE -eq "1") { $SkipDbUpdate = $true }
if ($env:TRIVYSCAN_STRICT -eq "1") { $Strict = $true }
if ($env:TRIVYSCAN_NO_PATH -eq "1") { $NoPath = $true }
if ($Purge) { $Uninstall = $true }

$Repo = "antistudio/trivyscan"
$TrivyRepo = "aquasecurity/trivy"
$TrivyMinVersion = "0.70.0"

$script:TempDir = ""
$script:DbFailed = $false
$script:DbSkipped = $false
$script:ExitCode = 0
$script:AppControlBlocked = $false
$script:AppControlStatus = ""
$script:Applied = @()
$script:BackupPath = ""
$script:Mechanism = "unknown"

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Show-Usage {
    @'
Usage: install.ps1 [OPTIONS]

Options:
  -System                  Install system-wide (requires admin; use from a file)
  -InstallDir DIR          Install directory override
  -TrivyScanVersion V      Install a specific TrivyScan version
  -TrivyVersion V          Install a specific Trivy version
  -SkipDbUpdate            Do not run `trivyscan -u`
  -Strict                  Exit 1 when the database update fails
  -NoPath                  Do not update PATH
  -Force                   Reinstall even when unchanged
  -Uninstall               Uninstall managed binaries
  -Purge                   With -Uninstall, also remove the Trivy DB cache
  -NoPause                 Do not wait for Enter at the end
  -NonInteractive          No pause; return an exit code for automation
  -Help                    Show this help

Application Control:
  -DiagnoseOnly            Only diagnose SAC/AppLocker/WDAC; no install
  -AppLockerHash           Apply local AppLocker hash allow rules
  -AppLockerPath           Apply local AppLocker path allow rules
  -WdacDraft               Generate a WDAC supplemental policy draft
  -Deploy                  With -WdacDraft, deploy via CiTool
  -Unblock                 Remove Mark-of-the-Web from installed binaries
  -User USER               AppLocker rule target (default: Everyone)
  -BasePolicyPath PATH     Base WDAC policy XML for supplemental draft
  -BasePolicyId GUID       Base WDAC policy ID for supplemental draft
  -SigningCertPath PATH    Certificate used to sign the WDAC draft
  -WhatIf                  Preview Application Control changes
'@ | Write-Host
}

function Complete-Script {
    param([int]$Code = 0)
    if ($NonInteractive) { exit $Code }
    if (-not $NoPause -and [Environment]::UserInteractive) {
        Write-Host ""
        try { [void](Read-Host "Press Enter to close") } catch { }
    }
}

function Test-Admin {
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Architecture {
    $name = ""
    try {
        $name = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    } catch {
        $raw = $env:PROCESSOR_ARCHITEW6432
        if (-not $raw) { $raw = $env:PROCESSOR_ARCHITECTURE }
        $name = [string]$raw
    }
    switch ($name.ToLowerInvariant()) {
        "x64"   { return [pscustomobject]@{ Go = "amd64"; Trivy = "64bit"; Arm64 = $false } }
        "amd64" { return [pscustomobject]@{ Go = "amd64"; Trivy = "64bit"; Arm64 = $false } }
        "arm64" { return [pscustomobject]@{ Go = "arm64"; Trivy = "64bit"; Arm64 = $true } }
        default { throw "Unsupported architecture: $name" }
    }
}

function Get-Paths {
    $programFiles = [Environment]::GetFolderPath("ProgramFiles")
    $localAppData = [Environment]::GetFolderPath("LocalApplicationData")
    $appDir = ""
    $trivyDir = ""

    if ($InstallDir) {
        $appDir = $InstallDir
        $trivyDir = $InstallDir
    } elseif ($System) {
        $appDir = Join-Path $programFiles "TrivyScan"
        $trivyDir = Join-Path $programFiles "Trivy"
    } else {
        $appDir = Join-Path $localAppData "Programs\TrivyScan"
        $trivyDir = $appDir
    }

    return [pscustomobject]@{
        AppDir      = $appDir
        TrivyDir    = $trivyDir
        TrivyScan   = Join-Path $appDir "trivyscan.exe"
        Trivy       = Join-Path $trivyDir "trivy.exe"
        Manifest    = Join-Path $appDir "install.json"
        PathScope   = $(if ($System) { "Machine" } else { "User" })
    }
}

function New-TempDir {
    $dir = Join-Path ([IO.Path]::GetTempPath()) ("trivyscan-install-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return $dir
}

function Invoke-Download {
    param([string]$Uri, [string]$OutFile)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing `
                -Headers @{ "User-Agent" = "trivyscan-installer" } -TimeoutSec 300
            return
        } catch {
            if ($attempt -eq 3) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

function Get-LatestTag {
    param([string]$Repository)
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/$Repository/releases/latest" `
            -Method Head -MaximumRedirection 10 -UseBasicParsing `
            -Headers @{ "User-Agent" = "trivyscan-installer" }
        $uri = ""
        if ($response.BaseResponse -and $response.BaseResponse.ResponseUri) {
            $uri = $response.BaseResponse.ResponseUri.AbsoluteUri
        } elseif ($response.BaseResponse -and $response.BaseResponse.RequestMessage -and
                  $response.BaseResponse.RequestMessage.RequestUri) {
            $uri = $response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
        }
        if ($uri -match "/tag/(v?[0-9]+\.[0-9]+\.[0-9]+)") { return $Matches[1].TrimStart("v") }
    } catch { }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest" `
        -Headers @{ "User-Agent" = "trivyscan-installer" }
    $tag = ([string]$release.tag_name).TrimStart("v")
    if (-not $tag) { throw "Cannot resolve the latest release for $Repository" }
    return $tag
}

function Get-BinaryVersion {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    try {
        $text = (& $Path --version 2>$null | Out-String)
        if ($text -match "([0-9]+\.[0-9]+\.[0-9]+)") { return $Matches[1] }
    } catch {
        if ($_.Exception.Message -match "Application Control|blocked") { return "BLOCKED" }
    }
    return ""
}

function Compare-Version {
    param([string]$Left, [string]$Right)
    try {
        $a = [version]$Left
        $b = [version]$Right
        return $a.CompareTo($b)
    } catch {
        return -1
    }
}

function Get-ActionLabel {
    param([bool]$Installed, [string]$From, [string]$To)
    if (-not $Installed) { return "v$To" }
    if (-not $From) { return "INSTALL v$To" }
    if ($From -eq $To) { return "REINSTALL v$To" }
    return "UPDATE v$From -> v$To"
}

function Test-Checksum {
    param([string]$File, [string]$SumsFile, [string]$Name)
    $expected = ""
    foreach ($line in Get-Content -LiteralPath $SumsFile) {
        $parts = $line.Trim() -split "\s+", 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart("*") -eq $Name) {
            $expected = $parts[0].ToLowerInvariant()
            break
        }
    }
    if (-not $expected -or $expected.Length -ne 64) {
        throw "No valid checksum for $Name"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $File).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "Checksum mismatch for $Name (expected $expected, got $actual)"
    }
    Write-Info "Checksum verified: $Name"
}

function Download-ReleaseAsset {
    param(
        [string]$Repository,
        [string]$Version,
        [string]$Asset,
        [string]$SumsName,
        [string]$OutDir
    )
    $base = "https://github.com/$Repository/releases/download/v$Version"
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    $archive = Join-Path $OutDir $Asset
    $sums = Join-Path $OutDir $SumsName
    Write-Info "Downloading $Asset..."
    Invoke-Download -Uri "$base/$Asset" -OutFile $archive
    Invoke-Download -Uri "$base/$SumsName" -OutFile $sums
    Test-Checksum -File $archive -SumsFile $sums -Name $Asset
    return $archive
}

function Expand-Binary {
    param([string]$Archive, [string]$Destination, [string]$Name)
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Expand-Archive -Path $Archive -DestinationPath $Destination -Force
    $file = Get-ChildItem -LiteralPath $Destination -Recurse -Filter $Name -File |
        Select-Object -First 1
    if (-not $file) { throw "$Name not found in $Archive" }
    return $file.FullName
}

function Install-Binary {
    param([string]$Source, [string]$Target, [string]$ExpectedVersion)

    $processName = [IO.Path]::GetFileNameWithoutExtension($Target)
    if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
        throw "$processName is running; close it and retry"
    }

    $dir = Split-Path -Parent $Target
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $tmp = "$Target.tmp"
    $bak = "$Target.bak"
    $hadOld = Test-Path -LiteralPath $Target

    Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $Source -Destination $tmp -Force
    if ($hadOld) { Move-Item -LiteralPath $Target -Destination $bak -Force }
    try {
        Move-Item -LiteralPath $tmp -Destination $Target -Force
        $got = Get-BinaryVersion -Path $Target
        if ($ExpectedVersion -and $got -ne $ExpectedVersion) {
            if ($got -eq "BLOCKED") {
                $script:AppControlBlocked = $true
                Write-Warn "$Target is installed but blocked by Application Control"
            } else {
                throw "$Target reports '$got', expected '$ExpectedVersion'"
            }
        }
        if ($hadOld) { Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue }
    } catch {
        Remove-Item -LiteralPath $Target -Force -ErrorAction SilentlyContinue
        if ($hadOld -and (Test-Path -LiteralPath $bak)) {
            Move-Item -LiteralPath $bak -Destination $Target -Force
        }
        throw
    }
}

function Get-RegistryKey {
    param([string]$Scope)
    if ($Scope -eq "Machine") {
        return "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    }
    return "HKCU:\Environment"
}

function Get-RawPath {
    param([string]$Scope)
    $key = Get-Item -LiteralPath (Get-RegistryKey $Scope)
    $value = $key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    return [string]$value
}

function Send-EnvironmentChange {
    try {
        if (-not ("EnvBroadcast" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class EnvBroadcast {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
        uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
"@
        }
        $result = [UIntPtr]::Zero
        [void][EnvBroadcast]::SendMessageTimeout(
            [IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result)
    } catch { }
}

function Set-RawPath {
    param([string]$Scope, [string]$Value)
    $key = Get-Item -LiteralPath (Get-RegistryKey $Scope)
    $key.SetValue("Path", $Value, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    Send-EnvironmentChange
}

function Add-PathEntry {
    param([string]$Directory, [string]$Scope)
    $dir = $Directory.TrimEnd("\")
    $raw = Get-RawPath -Scope $Scope
    $parts = @()
    if ($raw) {
        $parts = @($raw -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    $found = $false
    foreach ($part in $parts) {
        if ($part.TrimEnd("\") -ieq $dir) { $found = $true; break }
    }
    if (-not $found) {
        $parts += $dir
        Set-RawPath -Scope $Scope -Value ($parts -join ";")
        $env:Path = "$dir;$env:Path"
        return $true
    }
    $env:Path = "$dir;$env:Path"
    return $false
}

function Remove-PathEntry {
    param([string]$Directory, [string]$Scope)
    $dir = $Directory.TrimEnd("\")
    $raw = Get-RawPath -Scope $Scope
    if (-not $raw) { return }
    $parts = @($raw -split ";" | ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and ($_.TrimEnd("\") -ine $dir) })
    Set-RawPath -Scope $Scope -Value ($parts -join ";")
}

function Get-ExistingTrivyScan {
    param($Paths)
    if (Test-Path -LiteralPath $Paths.TrivyScan) {
        return [pscustomobject]@{ Path = $Paths.TrivyScan; Version = (Get-BinaryVersion $Paths.TrivyScan) }
    }
    $cmd = Get-Command trivyscan -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return [pscustomobject]@{ Path = $cmd.Source; Version = (Get-BinaryVersion $cmd.Source) }
    }
    return $null
}

function Get-ExistingTrivy {
    param($Paths)
    if (Test-Path -LiteralPath $Paths.Trivy) {
        return [pscustomobject]@{ Path = $Paths.Trivy; Version = (Get-BinaryVersion $Paths.Trivy) }
    }
    $cmd = Get-Command trivy -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return [pscustomobject]@{ Path = $cmd.Source; Version = (Get-BinaryVersion $cmd.Source) }
    }
    return $null
}

function Get-LocalTrivyScan {
    $dir = ""
    if ($PSScriptRoot) {
        $dir = $PSScriptRoot
    } elseif ($PSCommandPath) {
        $dir = Split-Path -Parent $PSCommandPath
    }
    if (-not $dir) { return "" }
    foreach ($name in @("trivyscan.exe", "trivyscan_windows.exe")) {
        $candidate = Join-Path $dir $name
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return ""
}

function Get-ElevatedArguments {
    $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-System")
    if ($InstallDir) { $arguments += @("-InstallDir", "`"$InstallDir`"") }
    if ($TrivyScanVersion) { $arguments += @("-TrivyScanVersion", $TrivyScanVersion) }
    if ($TrivyVersion) { $arguments += @("-TrivyVersion", $TrivyVersion) }
    if ($SkipDbUpdate) { $arguments += "-SkipDbUpdate" }
    if ($Strict) { $arguments += "-Strict" }
    if ($NoPath) { $arguments += "-NoPath" }
    if ($Force) { $arguments += "-Force" }
    if ($Uninstall) { $arguments += "-Uninstall" }
    if ($Purge) { $arguments += "-Purge" }
    if ($NoPause) { $arguments += "-NoPause" }
    if ($NonInteractive) { $arguments += "-NonInteractive" }
    return $arguments
}

function Get-BinaryPaths {
    param([string]$InstallDir)
    $result = [pscustomobject]@{ TrivyScan = ""; Trivy = "" }
    if ($InstallDir) {
        $candidate = Join-Path $InstallDir "trivyscan.exe"
        if (Test-Path -LiteralPath $candidate) { $result.TrivyScan = $candidate }
        $candidate = Join-Path $InstallDir "trivy.exe"
        if (Test-Path -LiteralPath $candidate) { $result.Trivy = $candidate }
        return $result
    }
    $local = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "Programs\TrivyScan"
    $machine = Join-Path ([Environment]::GetFolderPath("ProgramFiles")) "TrivyScan"
    $machineTrivy = Join-Path ([Environment]::GetFolderPath("ProgramFiles")) "Trivy"

    $cmd = Get-Command trivyscan -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { $result.TrivyScan = $cmd.Source }
    if (-not $result.TrivyScan) {
        foreach ($p in @((Join-Path $local "trivyscan.exe"), (Join-Path $machine "trivyscan.exe"))) {
            if (Test-Path -LiteralPath $p) { $result.TrivyScan = $p; break }
        }
    }

    $cmd = Get-Command trivy -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { $result.Trivy = $cmd.Source }
    if (-not $result.Trivy) {
        foreach ($p in @(
            (Join-Path $local "trivy.exe"),
            (Join-Path $machine "trivy.exe"),
            (Join-Path $machineTrivy "trivy.exe")
        )) {
            if (Test-Path -LiteralPath $p) { $result.Trivy = $p; break }
        }
    }
    if (-not $result.Trivy -and $result.TrivyScan) {
        $sibling = Join-Path (Split-Path -Parent $result.TrivyScan) "trivy.exe"
        if (Test-Path -LiteralPath $sibling) { $result.Trivy = $sibling }
    }
    return $result
}

function Get-SignatureState {
    param([string[]]$Paths)
    $out = @()
    foreach ($path in $Paths) {
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            $out += [pscustomobject]@{
                Path   = $path
                Status = $sig.Status.ToString()
                Signer = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" })
            }
        } catch {
            $out += [pscustomobject]@{ Path = $path; Status = "Unknown"; Signer = "" }
        }
    }
    return $out
}

function Get-CiPolicies {
    if (-not $env:SystemRoot) { return @() }
    $tool = Join-Path $env:SystemRoot "System32\CiTool.exe"
    if (-not (Test-Path -LiteralPath $tool)) { return @() }
    try {
        $json = (& $tool -lp -json 2>$null | Out-String)
        if (-not $json) { return @() }
        $data = $json | ConvertFrom-Json
        if ($data.Policies) { return @($data.Policies) }
    } catch { }
    return @()
}

function Get-CodeIntegrityEvents {
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-CodeIntegrity/Operational"; Id = @(3076, 3077)
        } -MaxEvents 20 -ErrorAction Stop)
    } catch { }
    return $events
}

function Get-AppLockerEvents {
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-AppLocker/EXE and DLL"; Id = 8004
        } -MaxEvents 20 -ErrorAction Stop)
    } catch { }
    return $events
}

function Get-SacState {
    $state = $null
    try {
        $state = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" `
            -Name "VerifiedAndReputablePolicyState" -ErrorAction Stop).VerifiedAndReputablePolicyState
    } catch { }
    return $state
}

function Get-AppLockerState {
    $local = ""
    $effective = ""
    try { $local = Get-AppLockerPolicy -Local -Xml } catch { }
    try { $effective = Get-AppLockerPolicy -Effective -Xml } catch { }
    $domain = $false
    if ($local -and $effective -and ($local -ne $effective)) { $domain = $true }
    return [pscustomobject]@{ Local = $local; Effective = $effective; Domain = $domain }
}

function Test-AppLockerDenied {
    param([string[]]$Paths, [string]$User)
    if (-not $Paths -or -not $Paths.Count) { return $false }
    try {
        $policy = Get-AppLockerPolicy -Effective
        $decisions = @(Test-AppLockerPolicy -PolicyObject $policy -Path $Paths -User $User -ErrorAction Stop)
        foreach ($decision in $decisions) {
            $text = ($decision | Format-List * | Out-String)
            if ($text -match "Denied") { return $true }
        }
    } catch { }
    return $false
}

function Start-AppIdService {
    try {
        $svc = Get-Service -Name AppIDSvc -ErrorAction Stop
        if ($svc.Status -ne "Running") {
            Start-Service -Name AppIDSvc -ErrorAction Stop
            Write-Info "Started AppIDSvc"
        }
    } catch {
        Write-Warn "AppIDSvc is not running; AppLocker rules may not take effect"
    }
}

function New-AppLockerAllow {
    param([string[]]$Paths, [string]$RuleType, [string]$User, [bool]$Preview)
    if (-not (Test-Admin)) {
        throw "AppLocker changes require an elevated PowerShell window"
    }
    $existing = @($Paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if (-not $existing.Count) { throw "No installed TrivyScan/Trivy binaries found" }

    $state = Get-AppLockerState
    if ($state.Domain) {
        throw "An AppLocker domain policy is active; ask IT to add a $RuleType rule for: $($existing -join ', ')"
    }
    if (-not $Preview) { Start-AppIdService }

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $newPolicy = Join-Path $env:TEMP "applocker-trivyscan-$stamp.xml"
    if (-not $Preview) {
        $script:BackupPath = Join-Path $env:TEMP "applocker-backup-$stamp.xml"
        Write-Info "Backing up local AppLocker policy to $script:BackupPath"
        Get-AppLockerPolicy -Local -Xml | Set-Content -LiteralPath $script:BackupPath -Encoding UTF8
    }

    $info = Get-AppLockerFileInformation -Path $existing
    $xml = $info | New-AppLockerPolicy -RuleType $RuleType -User $User -Xml
    if ($Preview) {
        Write-Info "Would add AppLocker $RuleType allow rules for: $($existing -join ', ')"
        return
    }

    $xml | Set-Content -LiteralPath $newPolicy -Encoding UTF8
    Write-Info "Merging AppLocker $RuleType allow rules"
    try {
        Set-AppLockerPolicy -XmlPolicy $newPolicy -Merge
    } catch {
        Write-Warn "Merge failed; restoring AppLocker backup"
        Set-AppLockerPolicy -XmlPolicy $script:BackupPath
        throw
    }

    if (Test-AppLockerDenied -Paths $existing -User $User) {
        Write-Warn "Verification still reports Denied; restoring AppLocker backup"
        Set-AppLockerPolicy -XmlPolicy $script:BackupPath
        throw "AppLocker rule did not take effect"
    }

    $script:Applied += "AppLocker $RuleType allow rules"
    $script:AppControlStatus = "AppLocker $RuleType rules applied"
    Write-Ok "AppLocker $RuleType allow rules applied"
    Write-Info "Re-run this install after each TrivyScan/Trivy update for hash rules"
}

function New-WdacDraft {
    param(
        [string[]]$Paths,
        [string]$BasePolicyPath,
        [string]$BasePolicyId,
        [string]$SigningCertPath,
        [bool]$Deploy,
        [bool]$Preview
    )
    foreach ($cmd in @("New-CIPolicyRule", "New-CIPolicy", "Set-CIPolicyIdInfo", "ConvertFrom-CIPolicy")) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            throw "ConfigCI cmdlet $cmd is unavailable; install the Windows ADK/ConfigCI module"
        }
    }
    if (-not $BasePolicyPath -and -not $BasePolicyId) {
        throw "Provide -BasePolicyPath or -BasePolicyId for the supplemental policy"
    }

    $existing = @($Paths | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    if (-not $existing.Count) { throw "No installed TrivyScan/Trivy binaries found" }
    if ($Preview) {
        Write-Info "Would create a WDAC supplemental draft for: $($existing -join ', ')"
        return
    }

    $rules = @()
    foreach ($path in $existing) {
        $sig = Get-AuthenticodeSignature -FilePath $path
        if ($sig.Status -eq "Valid") {
            $rules += New-CIPolicyRule -DriverFilePath $path -Level FilePublisher -Fallback Hash
        } else {
            $rules += New-CIPolicyRule -DriverFilePath $path -Level Hash
        }
    }

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $xmlPath = Join-Path $env:TEMP "trivyscan-wdac-$stamp.xml"
    $cipPath = Join-Path $env:TEMP "trivyscan-wdac-$stamp.cip"
    New-CIPolicy -MultiplePolicyFormat -FilePath $xmlPath -Rules $rules
    if ($BasePolicyPath) {
        Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName "TrivyScan Allow" `
            -BasePolicyToSupplementPath $BasePolicyPath
    } else {
        $guid = [guid]$BasePolicyId
        Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName "TrivyScan Allow" `
            -SupplementsBasePolicyID $guid
    }
    if ($SigningCertPath) {
        Add-SignerRule -FilePath $xmlPath -CertificatePath $SigningCertPath -Update -Supplemental
    }
    ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath
    Write-Info "WDAC draft: $xmlPath"
    Write-Info "WDAC binary: $cipPath"

    if ($Deploy) {
        if (-not (Test-Admin)) { throw "WDAC deployment requires an elevated PowerShell window" }
        $tool = Join-Path $env:SystemRoot "System32\CiTool.exe"
        if (-not (Test-Path -LiteralPath $tool)) { throw "CiTool.exe is unavailable" }
        & $tool -up $cipPath
        if ($LASTEXITCODE -ne 0) { throw "CiTool failed with exit code $LASTEXITCODE" }
        $script:Applied += "WDAC supplemental policy"
        $script:AppControlStatus = "WDAC supplemental policy deployed"
        Write-Ok "WDAC supplemental policy deployed"
    } else {
        $script:AppControlStatus = "WDAC draft created"
        Write-Warn "Draft only. Sign it per your WDAC process, then deploy with -Deploy or CiTool"
    }
}

function Invoke-Unblock {
    param([string[]]$Paths, [bool]$Preview)
    foreach ($path in $Paths) {
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
        if ($Preview) {
            Write-Info "Would unblock $path"
            continue
        }
        try {
            Unblock-File -LiteralPath $path
            Write-Ok "Unblocked $path"
        } catch {
            Write-Warn "Could not unblock $path"
        }
    }
}

function Show-Diagnosis {
    param($Paths, $Signatures, $CiPolicies, $SacState, $AppLocker, $AppLockerDenied, $AppLockerEvents, $CodeIntegrityEvents)
    Write-Host ""
    Write-Host "========================================="
    Write-Host "  Windows Application Control diagnosis"
    Write-Host "========================================="
    Write-Host "Binaries:"
    if ($Paths.TrivyScan) { Write-Host "  TrivyScan: $($Paths.TrivyScan)" } else { Write-Host "  TrivyScan: not found" }
    if ($Paths.Trivy)     { Write-Host "  Trivy:     $($Paths.Trivy)" } else { Write-Host "  Trivy:     not found" }

    Write-Host "Authenticode:"
    if (-not $Signatures.Count) { Write-Host "  no binaries to inspect" }
    foreach ($sig in $Signatures) {
        Write-Host "  $($sig.Status): $($sig.Path)"
        if ($sig.Signer) { Write-Host "    $($sig.Signer)" }
    }

    Write-Host "Smart App Control:"
    if ($null -ne $SacState) { Write-Host "  VerifiedAndReputablePolicyState = $SacState" } else { Write-Host "  state unavailable" }
    $sacPolicy = @($CiPolicies | Where-Object { $_.FriendlyName -like "VerifiedAndReputableDesktop*" })
    if ($sacPolicy.Count) {
        foreach ($p in $sacPolicy) { Write-Host "  $($p.FriendlyName) enforced=$($p.IsEnforced)" }
    } else {
        Write-Host "  no Smart App Control policy listed"
    }

    Write-Host "AppLocker:"
    Write-Host "  local policy: $(if ($AppLocker.Local) { 'present' } else { 'none' })"
    Write-Host "  effective policy: $(if ($AppLocker.Effective) { 'present' } else { 'none' })"
    Write-Host "  domain override: $($AppLocker.Domain)"
    Write-Host "  denied by effective policy: $AppLockerDenied"
    Write-Host "  recent block events: $($AppLockerEvents.Count)"

    Write-Host "WDAC / App Control:"
    $wdac = @($CiPolicies | Where-Object {
        $_.FriendlyName -notlike "VerifiedAndReputableDesktop*" -and $_.IsSystemPolicy -eq $false
    })
    if ($wdac.Count) {
        foreach ($p in $wdac) {
            Write-Host "  $($p.FriendlyName) enforced=$($p.IsEnforced) system=$($p.IsSystemPolicy)"
        }
    } else {
        Write-Host "  no organization WDAC policy listed"
    }
    Write-Host "  recent CodeIntegrity block/audit events: $($CodeIntegrityEvents.Count)"
    Write-Host "========================================="
}

function Invoke-ApplicationControlAllow {
    param($Paths, [bool]$DiagnoseOnlyMode, [bool]$ForceRun, [bool]$Blocked)
    $exes = @($Paths.TrivyScan, $Paths.Trivy) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $shouldRun = $DiagnoseOnlyMode -or $ForceRun -or $Blocked -or $AppLockerHash -or $AppLockerPath -or $WdacDraft -or $Unblock -or $WhatIf
    if (-not $shouldRun) { return }

    $signatures = @(Get-SignatureState -Paths $exes)
    $ciPolicies = @(Get-CiPolicies)
    $sacState = Get-SacState
    $appLocker = Get-AppLockerState
    $appLockerDenied = Test-AppLockerDenied -Paths $exes -User $User
    $appLockerEvents = @(Get-AppLockerEvents | Where-Object { $_.Message -match "(?i)trivyscan|trivy" })
    $codeIntegrityEvents = @(Get-CodeIntegrityEvents | Where-Object { $_.Message -match "(?i)trivyscan|trivy" })
    $sacPolicy = @($ciPolicies | Where-Object { $_.FriendlyName -like "VerifiedAndReputableDesktop*" })
    $orgWdac = @($ciPolicies | Where-Object {
        $_.FriendlyName -notlike "VerifiedAndReputableDesktop*" -and $_.IsSystemPolicy -eq $false
    })

    if ($sacPolicy.Count) {
        $script:Mechanism = "Smart App Control"
    } elseif ($appLockerDenied -or $appLockerEvents.Count) {
        $script:Mechanism = "AppLocker"
    } elseif ($orgWdac.Count) {
        $script:Mechanism = "WDAC"
    } else {
        $script:Mechanism = "none detected"
    }

    Show-Diagnosis -Paths $Paths -Signatures $signatures -CiPolicies $ciPolicies `
        -SacState $sacState -AppLocker $appLocker -AppLockerDenied $appLockerDenied `
        -AppLockerEvents $appLockerEvents -CodeIntegrityEvents $codeIntegrityEvents

    if ($Unblock) {
        Invoke-Unblock -Paths $exes -Preview $WhatIf
        if (-not $AppLockerHash -and -not $AppLockerPath -and -not $WdacDraft) {
            $script:AppControlStatus = "Mark-of-the-Web handled"
            return
        }
    }

    if ($DiagnoseOnlyMode) {
        $script:AppControlStatus = "diagnosed: $script:Mechanism"
        return
    }

    if ($WdacDraft) {
        if ($sacPolicy.Count) { throw "Refusing to create a supplemental policy for Smart App Control" }
        New-WdacDraft -Paths $exes -BasePolicyPath $BasePolicyPath -BasePolicyId $BasePolicyId `
            -SigningCertPath $SigningCertPath -Deploy $Deploy -Preview $WhatIf
        return
    }

    if ($AppLockerPath) {
        New-AppLockerAllow -Paths $exes -RuleType Path -User $User -Preview $WhatIf
        return
    }
    if ($AppLockerHash) {
        New-AppLockerAllow -Paths $exes -RuleType Hash -User $User -Preview $WhatIf
        return
    }

    if ($sacPolicy.Count) {
        $script:AppControlStatus = "blocked by Smart App Control; signing required"
        Write-Warn "Smart App Control has no per-app allow list"
        Write-Warn "Fix: Authenticode-sign both binaries, or turn off Smart App Control manually (one-way)"
        return
    }

    if ($appLockerDenied -or $appLockerEvents.Count) {
        if ($appLocker.Domain) {
            $script:AppControlStatus = "blocked by AppLocker domain policy"
            Write-Warn "AppLocker domain policy is blocking; ask IT for a Publisher/Hash rule"
        } elseif (-not (Test-Admin)) {
            $script:AppControlStatus = "AppLocker block needs elevation"
            Write-Warn "AppLocker allow rule needs elevation; re-run this script as Administrator"
        } else {
            try {
                New-AppLockerAllow -Paths $exes -RuleType Hash -User $User -Preview $WhatIf
            } catch {
                $script:AppControlStatus = "AppLocker allow failed"
                Write-Warn "AppLocker allow failed: $($_.Exception.Message)"
            }
        }
        return
    }

    if ($orgWdac.Count) {
        $script:AppControlStatus = "blocked by WDAC; draft required"
        Write-Warn "Organization WDAC is active; use -WdacDraft and have IT sign/deploy the policy"
        return
    }

    if ($ForceRun -and (Test-Admin)) {
        New-AppLockerAllow -Paths $exes -RuleType Hash -User $User -Preview $WhatIf
    } elseif ($ForceRun) {
        $script:AppControlStatus = "allow changes need elevation"
        Write-Warn "AppLocker changes require an elevated PowerShell window"
    } else {
        $script:AppControlStatus = "no active block detected"
        Write-Info "No active Application Control block detected for these binaries"
    }
}

function Invoke-DatabaseUpdate {
    param($Paths, [string]$TrivyPath)
    if ($SkipDbUpdate) {
        $script:DbSkipped = $true
        Write-Info "Skipping database update"
        return
    }
    if (-not (Test-Path -LiteralPath $Paths.TrivyScan)) {
        $script:DbSkipped = $true
        Write-Warn "trivyscan is not installed; skipping database update"
        return
    }
    if (-not $TrivyPath -or -not (Test-Path -LiteralPath $TrivyPath)) {
        $script:DbSkipped = $true
        Write-Warn "Trivy is unavailable; run trivyscan -u later"
        return
    }

    Write-Info "Updating Trivy databases (trivyscan -u)..."
    $oldPath = $env:Path
    $oldTrivy = $env:TRIVY_BIN
    try {
        $env:Path = "$($Paths.TrivyDir);$($Paths.AppDir);$env:Path"
        $env:TRIVY_BIN = $TrivyPath
        & $Paths.TrivyScan -u
        if ($LASTEXITCODE -ne 0) { throw "trivyscan -u exited with $LASTEXITCODE" }
        Write-Info "Databases updated"
    } catch {
        $script:DbFailed = $true
        $message = $_.Exception.Message
        if ($message -match "Application Control|blocked") {
            Write-Warn "Windows Application Control blocked trivyscan.exe. Run install.ps1 -DiagnoseOnly."
        } else {
            Write-Warn "Database update failed: $message"
        }
        Write-Warn "Run 'trivyscan -u' later"
    } finally {
        $env:Path = $oldPath
        $env:TRIVY_BIN = $oldTrivy
    }
}

function Write-Manifest {
    param($Paths, [string]$TrivyScanVersion, [string]$TrivyVersionValue, [bool]$TrivyManaged, [string]$TrivyPath, [bool]$PathModified)
    New-Item -ItemType Directory -Path $Paths.AppDir -Force | Out-Null
    $manifest = [ordered]@{
        installer          = "trivyscan"
        layout             = "windows"
        app_dir            = $Paths.AppDir
        trivyscan_path     = $Paths.TrivyScan
        trivyscan_version  = $TrivyScanVersion
        trivy_path         = $TrivyPath
        trivy_version      = $TrivyVersionValue
        trivy_managed      = [bool]$TrivyManaged
        path_scope         = $Paths.PathScope
        path_modified      = [bool]$PathModified
        installed_at       = (Get-Date).ToUniversalTime().ToString("o")
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $Paths.Manifest -Encoding UTF8
}

function Invoke-Uninstall {
    param($Paths)
    if (-not (Test-Path -LiteralPath $Paths.Manifest)) {
        if (-not $Force) {
            Write-Warn "No install manifest found; pass -Force to remove $($Paths.TrivyScan)"
            return
        }
        Remove-Item -LiteralPath $Paths.TrivyScan -Force -ErrorAction SilentlyContinue
        Write-Info "Removed $($Paths.TrivyScan)"
        if (-not $NoPath) {
            Remove-PathEntry -Directory $Paths.AppDir -Scope $Paths.PathScope
            if ($Paths.TrivyDir -ne $Paths.AppDir) {
                Remove-PathEntry -Directory $Paths.TrivyDir -Scope $Paths.PathScope
            }
        }
        return
    }

    $manifest = Get-Content -LiteralPath $Paths.Manifest -Raw | ConvertFrom-Json
    $trivyscanPath = [string]$manifest.trivyscan_path
    if (-not $trivyscanPath) { $trivyscanPath = $Paths.TrivyScan }
    Remove-Item -LiteralPath $trivyscanPath -Force -ErrorAction SilentlyContinue
    Write-Info "Removed $trivyscanPath"

    if ([bool]$manifest.trivy_managed) {
        $trivyPath = [string]$manifest.trivy_path
        if ($trivyPath) {
            Remove-Item -LiteralPath $trivyPath -Force -ErrorAction SilentlyContinue
            Write-Info "Removed $trivyPath"
        }
    }

    $pathWasModified = $true
    if ($manifest.PSObject.Properties["path_modified"]) {
        $pathWasModified = [bool]$manifest.path_modified
    }
    if ($pathWasModified) {
        Remove-PathEntry -Directory $Paths.AppDir -Scope $Paths.PathScope
        if ($Paths.TrivyDir -ne $Paths.AppDir) {
            Remove-PathEntry -Directory $Paths.TrivyDir -Scope $Paths.PathScope
        }
    }
    Remove-Item -LiteralPath $Paths.Manifest -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $Paths.AppDir) -and
        -not (Get-ChildItem -LiteralPath $Paths.AppDir -Force -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $Paths.AppDir -Force -ErrorAction SilentlyContinue
    }

    if ($Purge) {
        if ($System) {
            Write-Warn "Skipping DB purge for a system install; remove the user cache manually"
        } else {
            Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "trivy") `
                -Recurse -Force -ErrorAction SilentlyContinue
            Write-Info "Removed Trivy DB cache"
        }
    }
}

function Invoke-Main {
    if ($Help) { Show-Usage; return }

    if ($env:OS -ne "Windows_NT") { throw "This installer is for Windows" }

    if ($DiagnoseOnly) {
        $diagPaths = Get-BinaryPaths -InstallDir $InstallDir
        Invoke-ApplicationControlAllow -Paths $diagPaths -DiagnoseOnlyMode $true -ForceRun $false -Blocked $false
        Write-Host "Mechanism: $script:Mechanism"
        return
    }

    if ($System -and -not (Test-Admin)) {
        if (-not $PSCommandPath) {
            throw "For -System, download install.ps1 to a file and run it with powershell -File ... -System"
        }
        $arguments = Get-ElevatedArguments
        if ($NonInteractive) {
            $process = Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs -Wait -PassThru
            $script:ExitCode = $process.ExitCode
            return
        }
        $elevated = @("-NoExit") + $arguments
        Start-Process -FilePath "powershell.exe" -ArgumentList $elevated -Verb RunAs | Out-Null
        Write-Info "Elevated install started in a new window"
        $script:NoPause = $true
        return
    }

    $paths = Get-Paths
    $arch = Get-Architecture
    Write-Info "Windows | Arch: $($arch.Go) | Prefix: $($paths.AppDir)"

    $script:TempDir = New-TempDir
    New-Item -ItemType Directory -Path $paths.AppDir -Force | Out-Null
    if ($paths.TrivyDir -ne $paths.AppDir) {
        New-Item -ItemType Directory -Path $paths.TrivyDir -Force | Out-Null
    }

    if ($Uninstall) {
        Invoke-Uninstall -Paths $paths
        return
    }

    if ($arch.Arm64) {
        Write-Warn "Trivy has no native Windows ARM64 build; installing the x64 build under emulation"
    }

    $existingTrivyScan = Get-ExistingTrivyScan -Paths $paths
    if ($existingTrivyScan -and $existingTrivyScan.Path -ne $paths.TrivyScan) {
        throw "Unmanaged TrivyScan found at $($existingTrivyScan.Path); remove it or use -System"
    }
    if ($existingTrivyScan -and $existingTrivyScan.Version -eq "BLOCKED") {
        $script:AppControlBlocked = $true
    }

    $localBinary = Get-LocalTrivyScan
    $localVersion = ""
    if ($localBinary) {
        $localVersion = Get-BinaryVersion -Path $localBinary
        if (-not $localVersion) { throw "Cannot read version from $localBinary" }
    }

    $explicitTrivyScan = $false
    $desiredTrivyScan = ""
    if ($TrivyScanVersion -and $TrivyScanVersion -ne "latest") {
        $desiredTrivyScan = $TrivyScanVersion.TrimStart("v")
        $explicitTrivyScan = $true
    } elseif ($localBinary) {
        $desiredTrivyScan = $localVersion
    } else {
        try {
            $desiredTrivyScan = Get-LatestTag -Repository $Repo
        } catch {
            if ($existingTrivyScan -and $existingTrivyScan.Version) {
                $desiredTrivyScan = $existingTrivyScan.Version
                Write-Warn "Cannot resolve latest TrivyScan; keeping v$desiredTrivyScan"
            } else {
                throw "Cannot resolve the latest TrivyScan release"
            }
        }
    }
    if ($localBinary) {
        if ($explicitTrivyScan -and $localVersion -ne $desiredTrivyScan) {
            throw "Local binary is v$localVersion but -TrivyScanVersion is v$desiredTrivyScan"
        }
        $desiredTrivyScan = $localVersion
        Write-Info "Using local binary: $localBinary"
    }

    $installTrivyScan = $true
    if (-not $Force -and $existingTrivyScan -and $existingTrivyScan.Version) {
        $cmp = Compare-Version $existingTrivyScan.Version $desiredTrivyScan
        if ($cmp -eq 0) {
            $installTrivyScan = $false
        } elseif (-not $explicitTrivyScan -and $cmp -gt 0) {
            $installTrivyScan = $false
            Write-Warn "Installed TrivyScan v$($existingTrivyScan.Version) is newer than v$desiredTrivyScan; keeping it"
        }
    }

    $trivyScanInstalled = $existingTrivyScan
    if ($installTrivyScan) {
        if ($localBinary) {
            $source = $localBinary
        } else {
            $asset = "trivyscan_${desiredTrivyScan}_windows_$($arch.Go).zip"
            $sums = "trivyscan_${desiredTrivyScan}_checksums.txt"
            $archive = Download-ReleaseAsset -Repository $Repo -Version $desiredTrivyScan `
                -Asset $asset -SumsName $sums -OutDir (Join-Path $script:TempDir "trivyscan")
            $source = Expand-Binary -Archive $archive -Destination (Join-Path $script:TempDir "trivyscan\extract") -Name "trivyscan.exe"
        }
        Install-Binary -Source $source -Target $paths.TrivyScan -ExpectedVersion $desiredTrivyScan
        $trivyScanInstalled = [pscustomobject]@{ Path = $paths.TrivyScan; Version = $desiredTrivyScan }
        Write-Info "TrivyScan installed/updated to v$desiredTrivyScan"
    } else {
        Write-Info "TrivyScan already at v$($trivyScanInstalled.Version)"
    }

    $existingTrivy = Get-ExistingTrivy -Paths $paths
    if ($existingTrivy -and $existingTrivy.Version -eq "BLOCKED") {
        $script:AppControlBlocked = $true
    }
    $explicitTrivy = $false
    $desiredTrivy = ""
    if ($TrivyVersion -and $TrivyVersion -ne "latest") {
        $desiredTrivy = $TrivyVersion.TrimStart("v")
        $explicitTrivy = $true
    } else {
        try {
            $desiredTrivy = Get-LatestTag -Repository $TrivyRepo
        } catch {
            if ($existingTrivy -and $existingTrivy.Version) {
                $desiredTrivy = $existingTrivy.Version
                Write-Warn "Cannot resolve latest Trivy; keeping v$desiredTrivy"
            } else {
                throw "Cannot resolve the latest Trivy release"
            }
        }
    }

    $installTrivy = $true
    if (-not $Force -and $existingTrivy -and $existingTrivy.Version) {
        $cmp = Compare-Version $existingTrivy.Version $desiredTrivy
        if ($cmp -eq 0) {
            $installTrivy = $false
        } elseif (-not $explicitTrivy -and $cmp -gt 0) {
            $installTrivy = $false
            Write-Warn "Installed Trivy v$($existingTrivy.Version) is newer than v$desiredTrivy; keeping it"
        }
    }

    $trivyManaged = $false
    $trivyPath = ""
    $trivyVersionInstalled = ""
    if ($installTrivy) {
        $asset = "trivy_${desiredTrivy}_windows-64bit.zip"
        $sums = "trivy_${desiredTrivy}_checksums.txt"
        $archive = Download-ReleaseAsset -Repository $TrivyRepo -Version $desiredTrivy `
            -Asset $asset -SumsName $sums -OutDir (Join-Path $script:TempDir "trivy")
        $source = Expand-Binary -Archive $archive -Destination (Join-Path $script:TempDir "trivy\extract") -Name "trivy.exe"
        Install-Binary -Source $source -Target $paths.Trivy -ExpectedVersion $desiredTrivy
        $trivyManaged = $true
        $trivyPath = $paths.Trivy
        $trivyVersionInstalled = $desiredTrivy
        Write-Info "Trivy installed/updated to v$desiredTrivy"
    } else {
        $trivyPath = $existingTrivy.Path
        $trivyVersionInstalled = $existingTrivy.Version
        $trivyManaged = ($existingTrivy.Path -eq $paths.Trivy)
        Write-Info "Using existing Trivy v$($existingTrivy.Version) at $($existingTrivy.Path)"
    }

    if (-not $trivyPath -or -not (Test-Path -LiteralPath $trivyPath)) {
        throw "Trivy is not available after setup"
    }
    if ((Compare-Version $trivyVersionInstalled $TrivyMinVersion) -lt 0) {
        Write-Warn "Trivy v$trivyVersionInstalled is older than the tested minimum v$TrivyMinVersion"
    }

    $pathModified = $false
    if (-not $NoPath) {
        $pathModified = Add-PathEntry -Directory $paths.AppDir -Scope $paths.PathScope
        if ($paths.TrivyDir -ne $paths.AppDir) {
            if (Add-PathEntry -Directory $paths.TrivyDir -Scope $paths.PathScope) { $pathModified = $true }
        }
    } else {
        Write-Warn "PATH was not modified; add $($paths.AppDir) manually if needed"
    }

    Write-Manifest -Paths $paths -TrivyScanVersion $trivyScanInstalled.Version `
        -TrivyVersionValue $trivyVersionInstalled -TrivyManaged $trivyManaged `
        -TrivyPath $trivyPath -PathModified $pathModified

    $forceAllow = $AppLockerHash -or $AppLockerPath -or $WdacDraft
    Invoke-ApplicationControlAllow -Paths $paths -DiagnoseOnlyMode $false `
        -ForceRun $forceAllow -Blocked $script:AppControlBlocked

    Invoke-DatabaseUpdate -Paths $paths -TrivyPath $trivyPath

    $trivyScanFrom = if ($existingTrivyScan -and $existingTrivyScan.Version -ne "BLOCKED") { $existingTrivyScan.Version } else { "" }
    $trivyFrom = if ($existingTrivy -and $existingTrivy.Version -ne "BLOCKED") { $existingTrivy.Version } else { "" }
    $trivyScanLabel = Get-ActionLabel -Installed $installTrivyScan -From $trivyScanFrom -To $trivyScanInstalled.Version
    $trivyLabel = Get-ActionLabel -Installed $installTrivy -From $trivyFrom -To $trivyVersionInstalled

    Write-Host ""
    Write-Host "========================================="
    Write-Host "      TrivyScan installer summary"
    Write-Host "========================================="
    Write-Host "[OK] TrivyScan  -> $trivyScanLabel at $($paths.TrivyScan)"
    Write-Host "[OK] Trivy      -> $trivyLabel at $trivyPath"
    if ($script:DbFailed) {
        Write-Warn "Database -> update failed; run trivyscan -u later"
    } elseif ($script:DbSkipped) {
        Write-Host "[OK] Database  -> skipped"
    } else {
        Write-Host "[OK] Database  -> updated"
    }
    if ($pathModified) {
        Write-Host "[OK] PATH      -> updated; open a new terminal"
    }
    if ($script:AppControlStatus) {
        Write-Host "[OK] AppControl -> $($script:AppControlStatus)"
    }
    if ($script:BackupPath) {
        Write-Host "[OK] Backup     -> $($script:BackupPath)"
    }
    Write-Host "========================================="

    if ($script:DbFailed -and $Strict) {
        throw "Database update failed"
    }
}

try {
    Invoke-Main
} catch {
    Write-Err $_.Exception.Message
    $script:ExitCode = 1
} finally {
    if ($script:TempDir -and (Test-Path -LiteralPath $script:TempDir)) {
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Complete-Script -Code $script:ExitCode
}
