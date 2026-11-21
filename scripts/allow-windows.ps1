#Requires -Version 5.1
#
# Diagnose and allow TrivyScan/Trivy through Windows Application Control.
#
# Default: diagnose. If a local AppLocker policy is blocking the binaries and
# the script is running as admin, apply targeted hash allow rules automatically.
# Smart App Control and Windows-managed WDAC policies are never modified.
#
# Examples:
#   .\allow-windows.ps1 -DiagnoseOnly
#   .\allow-windows.ps1 -WhatIf
#   .\allow-windows.ps1 -AppLockerHash
#   .\allow-windows.ps1 -AppLockerPath
#   .\allow-windows.ps1 -WdacDraft -BasePolicyPath .\Base.xml -SigningCertPath .\codesign.cer
#   .\allow-windows.ps1 -Unblock

param(
    [switch]$DiagnoseOnly,
    [switch]$AppLockerHash,
    [switch]$AppLockerPath,
    [switch]$WdacDraft,
    [switch]$Deploy,
    [switch]$Unblock,
    [string]$User = "Everyone",
    [string]$InstallDir = "",
    [string]$BasePolicyPath = "",
    [string]$BasePolicyId = "",
    [string]$SigningCertPath = "",
    [switch]$WhatIf,
    [switch]$Force,
    [switch]$NoPause,
    [switch]$NonInteractive,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:ExitCode = 0
$script:Applied = @()
$script:BackupPath = ""
$script:Mechanism = "unknown"

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err  { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Show-Usage {
    @'
Usage: allow-windows.ps1 [OPTIONS]

Default: diagnose; auto-apply AppLocker hash rules when local AppLocker is
blocking the binaries and the script is elevated. Smart App Control and
Windows-managed WDAC policies are never modified.

Options:
  -DiagnoseOnly            Read-only diagnosis
  -AppLockerHash           Force local AppLocker hash allow rules
  -AppLockerPath           Force local AppLocker path allow rules
  -WdacDraft               Generate a WDAC supplemental policy draft
  -Deploy                  With -WdacDraft, deploy via CiTool
  -Unblock                 Remove Mark-of-the-Web from installed binaries
  -User USER               AppLocker rule target (default: Everyone)
  -InstallDir DIR          Look for binaries in a custom install directory
  -BasePolicyPath PATH     Base WDAC policy XML for supplemental draft
  -BasePolicyId GUID       Base WDAC policy ID for supplemental draft
  -SigningCertPath PATH    Certificate used to sign the WDAC draft
  -WhatIf                  Show actions without changing policy
  -Force                   Reapply even when already allowed
  -NoPause                 Do not wait for Enter
  -NonInteractive          No pause; return an exit code
  -Help                    Show this help
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
        $candidates = @(
            (Join-Path $local "trivy.exe"),
            (Join-Path $machine "trivy.exe"),
            (Join-Path $machineTrivy "trivy.exe")
        )
        foreach ($p in $candidates) {
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
        Write-Info "Preview XML: $newPolicy"
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
    Write-Ok "AppLocker $RuleType allow rules applied"
    Write-Info "Re-run this script after each TrivyScan/Trivy update for hash rules"
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
        if ($Deploy) { Write-Info "Would deploy the signed policy with CiTool" }
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
        if ($Preview) { Write-Info "Would deploy $cipPath with CiTool"; return }
        $tool = Join-Path $env:SystemRoot "System32\CiTool.exe"
        if (-not (Test-Path -LiteralPath $tool)) { throw "CiTool.exe is unavailable" }
        & $tool -up $cipPath
        if ($LASTEXITCODE -ne 0) { throw "CiTool failed with exit code $LASTEXITCODE" }
        $script:Applied += "WDAC supplemental policy"
        Write-Ok "WDAC supplemental policy deployed"
    } else {
        Write-Warn "Draft only. Sign it per your WDAC process, then deploy with -Deploy or CiTool"
    }
}

function Invoke-Unblock {
    param([string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
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
        foreach ($p in $sacPolicy) {
            Write-Host "  $($p.FriendlyName) enforced=$($p.IsEnforced)"
        }
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

function Invoke-Main {
    if ($Help) { Show-Usage; return }

    if ($env:OS -ne "Windows_NT") { throw "This script is for Windows" }

    $paths = Get-BinaryPaths -InstallDir $InstallDir
    $exes = @($paths.TrivyScan, $paths.Trivy) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $signatures = @(Get-SignatureState -Paths $exes)
    $ciPolicies = @(Get-CiPolicies)
    $sacState = Get-SacState
    $appLocker = Get-AppLockerState
    $appLockerDenied = Test-AppLockerDenied -Paths $exes -User $User
    $appLockerEvents = @(Get-AppLockerEvents)
    $codeIntegrityEvents = @(Get-CodeIntegrityEvents)
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

    Show-Diagnosis -Paths $paths -Signatures $signatures -CiPolicies $ciPolicies `
        -SacState $sacState -AppLocker $appLocker -AppLockerDenied $appLockerDenied `
        -AppLockerEvents $appLockerEvents -CodeIntegrityEvents $codeIntegrityEvents

    if ($Unblock) {
        Invoke-Unblock -Paths $exes
    }

    if ($WdacDraft) {
        if ($sacPolicy.Count) { throw "Refusing to create a supplemental policy for Smart App Control" }
        New-WdacDraft -Paths $exes -BasePolicyPath $BasePolicyPath -BasePolicyId $BasePolicyId `
            -SigningCertPath $SigningCertPath -Deploy $Deploy -Preview $WhatIf
    }

    if ($AppLockerPath) {
        New-AppLockerAllow -Paths $exes -RuleType Path -User $User -Preview $WhatIf
    } elseif ($AppLockerHash) {
        New-AppLockerAllow -Paths $exes -RuleType Hash -User $User -Preview $WhatIf
    } elseif (-not $DiagnoseOnly -and -not $WdacDraft) {
        if ($sacPolicy.Count) {
            Write-Warn "Smart App Control has no per-app allow list"
            Write-Warn "Fix: Authenticode-sign both binaries, or turn off Smart App Control manually (one-way)"
        } elseif ($appLockerDenied -or $appLockerEvents.Count) {
            if ($appLocker.Domain) {
                Write-Warn "AppLocker domain policy is blocking; ask IT for a Publisher/Hash rule"
            } elseif (-not (Test-Admin)) {
                Write-Warn "AppLocker allow rule needs elevation; re-run this script as Administrator"
            } else {
                New-AppLockerAllow -Paths $exes -RuleType Hash -User $User -Preview $WhatIf
            }
        } elseif ($orgWdac.Count) {
            Write-Warn "Organization WDAC is active; use -WdacDraft and have IT sign/deploy the policy"
        } elseif ($Force) {
            if (Test-Admin) {
                New-AppLockerAllow -Paths $exes -RuleType Hash -User $User -Preview $WhatIf
            } else {
                Write-Warn "AppLocker changes require an elevated PowerShell window"
            }
        } else {
            Write-Info "No active Application Control block detected for these binaries"
        }
    }

    Write-Host ""
    Write-Host "========================================="
    Write-Host "  Allow script summary"
    Write-Host "========================================="
    Write-Host "Mechanism: $script:Mechanism"
    if ($script:Applied.Count) {
        foreach ($item in $script:Applied) { Write-Host "Applied: $item" }
    } else {
        Write-Host "Applied: no policy changes"
    }
    if ($script:BackupPath) { Write-Host "Backup: $script:BackupPath" }
    Write-Host "Limits: hash rules change after updates; Smart App Control requires signing"
    Write-Host "========================================="
}

try {
    Invoke-Main
} catch {
    Write-Err $_.Exception.Message
    $script:ExitCode = 1
} finally {
    Complete-Script -Code $script:ExitCode
}
