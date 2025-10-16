<#
  Uinst-W11-KB5066835_KB5065789_KB5054156_v2.ps1
  Targets (Windows 11 only):
    - KB5066835  (Oct 14, 2025 LCU)  → UBR .6899 for 26100 / 26200
    - KB5065789  (Sep 29, 2025 Preview LCU) → UBR .6725 for 26100 / 26200
    - KB5054156  (25H2 Enablement package)

  Version: 
    V5.1 pause updates for 5 weeks
    V6 

  Notes:
    * Uses WUSA first, then DISM with strict identity patterns.
    * Logs to C:\Windows\Temp\KB_Rollback.log
    * No auto-restart and no other KBs are touched.

  Additional Info:
  🔹 KB5066835 – October 14, 2025 Cumulative Update for Windows 11

    Applies to: Windows 11 versions 24H2 and 25H2 only.
    OS Builds: 26100.6899 (24H2) and 26200.6899 (25H2).
    Purpose: This cumulative update includes security fixes, performance improvements, and updates to AI components such as Image Search, Semantic Analysis, and Content Extraction.
    Notes: It is not applicable to Windows 10. Microsoft recommends using DISM for rollback due to combined SSU+LCU packaging.
    Reference: https://support.microsoft.com/en-us/topic/october-14-2025-kb5066835-os-builds-26200-6899-and-26100-6899-1db237d8-9f3b-4218-9515-3e0a32729685 


    🔹 KB5065789 – September 29, 2025 Preview Update for Windows 11

    Applies to: Windows 11 versions 21H2, 22H2, 23H2, 24H2, and 25H2.
    OS Builds: 26100.6725 and 26200.6725.
    Purpose: Preview update introducing improvements to Windows servicing stack and AI components. Known issues include playback problems in certain media apps.
    Notes: This update is not applicable to Windows 10, as confirmed by internal email from Enzo Flores Lagos. [RE: Window...ocking RDM]
    Reference: https://support.microsoft.com/en-us/topic/september-29-2025-kb5065789-os-builds-26200-6725-and-26100-6725-preview-fa03ce47-cec5-4d1c-87d0-cac4195b4b4e


    🔹 KB5054156 – October 14, 2025 Enablement Package for Windows 11 25H2

    Applies to: Windows 11 version 24H2 upgrading to 25H2.
    Purpose: Acts as a "master switch" to activate dormant 25H2 features already present in 24H2 builds. Enables a fast upgrade with minimal downtime.
    Notes: This is an enablement package and only applies to Windows 11. Windows 10 is not supported.
    Reference: https://support.microsoft.com/en-us/topic/kb5054156-feature-update-to-windows-11-version-25h2-by-using-an-enablement-package-4d307e2d-3028-4323-bb46-552cff491643
#>
param (
  [string[]]$TargetKBs = @('5066835','5065789'),
  [switch]$RemoveEnablement25H2
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$Log = "C:\Windows\Temp\KB_Rollback_$timestamp.log"

function Write-Log {
  param([string]$Message)
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  "$ts $Message" | Out-File -FilePath $Log -Encoding utf8 -Append
}

"==== Start $(Get-Date) ====" | Out-File -FilePath $Log -Encoding utf8

# --- Guardrails ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Host "Run this from an elevated PowerShell session."
  exit 1
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Log "OS: $($os.Caption) ($($os.Version))"
if ($os.Caption -notmatch 'Windows 11') {
  Write-Log "Non-Windows 11 detected. Exiting."
  Write-Host "This rollback targets Windows 11 only."
  exit 0
}

# --- Helpers ---
function Test-PendingReboot {
  foreach ($p in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
  )) { if (Test-Path $p) { return $true } }
  return $false
}

function Invoke-DismRemove {
  param([string]$PackageName,[int]$Retries=1)
  for ($i=0; $i -le $Retries; $i++) {
    Write-Log "DISM removing: ${PackageName} (attempt $($i+1))"
    $p = Start-Process -FilePath dism.exe -ArgumentList "/Online","/Remove-Package","/PackageName:$PackageName","/Quiet","/NoRestart" -PassThru -Wait
    Write-Log "DISM ExitCode=$($p.ExitCode)"
    if ($p.ExitCode -in 0,3010) { return $p.ExitCode }
    Start-Sleep 3
  }
  return $p.ExitCode
}

function Get-InstalledPackages {
  Write-Log "Querying installed packages via DISM…"
  $tmp = New-TemporaryFile
  try {
    & dism.exe /English /Online /Get-Packages > $tmp 2>&1
    $raw = Get-Content $tmp -Raw
    $blocks = ($raw -split 'Package Identity :').Where({$_ -match '\S'})
    $result = @()
    foreach ($b in $blocks) {
      $name = ($b -split "`r?`n")[0].Trim()
      if ($b -match 'State :\s*(\S+)') {
        if ($matches[1] -eq 'Installed') { $result += $name }
      }
    }
    return $result
  } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

function Invoke-WusaUninstall {
  param([string]$KB)
  Write-Log "WUSA /uninstall /kb:${KB}"
  $p = Start-Process wusa.exe -ArgumentList "/uninstall","/kb:$KB","/quiet","/norestart" -PassThru -Wait
  Write-Log "WUSA KB${KB} ExitCode=$($p.ExitCode)"
  switch ($p.ExitCode) {
    0      { return $true }
    3010   { return $true }
    2359302{ Write-Log "KB${KB} not installed (WUSA reports not applicable)."; return $false }
    87     { Write-Log "KB${KB} not found / invalid param (likely LCU identity needed)."; return $false }
    default{ Write-Log "WUSA unexpected code $($p.ExitCode) for KB${KB}."; return $false }
  }
}

$LcuPatterns = @{
  '5066835' = @('*Package_for_RollupFix*~~26100.6899*','*Package_for_RollupFix*~~26200.6899*')
  '5065789' = @('*Package_for_RollupFix*~~26100.6725*','*Package_for_RollupFix*~~26200.6725*')
}

function Remove-LCUByKB {
  param([string]$KB)
  if (-not $LcuPatterns.ContainsKey($KB)) {
    Write-Log "ERROR: No identity patterns defined for KB${KB}. Skipping."
    return $false
  }

  $changed = $false
  if (Invoke-WusaUninstall -KB $KB) { $changed = $true }

  $pkgs = Get-InstalledPackages
  $cands = @()
  foreach ($pat in $LcuPatterns[$KB]) { $cands += ($pkgs | Where-Object { $_ -like $pat }) }
  $cands = $cands | Select-Object -Unique

  if ($cands.Count -gt 0) {
    $lines = @("LCU candidates for KB${KB}:") + ($cands | ForEach-Object { "  - $_" })
    Write-Log ($lines -join [Environment]::NewLine)
    foreach ($p in $cands) {
      $code = Invoke-DismRemove -PackageName $p
      if ($code -in 0,3010) { $changed = $true; Write-Log "Removed LCU: $p" }
    }
  } else {
    Write-Log "No LCU identity match found for KB${KB}."
  }
  return $changed
}

function Remove-Enablement25H2 {
  Write-Log "Scanning for 25H2 Enablement (KB5054156)…"
  $pkgs = Get-InstalledPackages
  $ekb = $pkgs | Where-Object { ($_ -match 'Package_for_.*Enablement') -and ($_ -match '25H2') }
  if (-not $ekb) { Write-Log "No 25H2 enablement package found."; return $false }

  $lines = @('Enablement candidates (25H2):') + ($ekb | ForEach-Object { "  - $_" })
  Write-Log ($lines -join [Environment]::NewLine)
  $changed = $false
  foreach ($p in $ekb) {
    $code = Invoke-DismRemove -PackageName $p
    if ($code -in 0,3010) { $changed = $true; Write-Log "Removed eKB: $p" }
  }
  return $changed
}

function Pause-Windowsupdates {
  param([int]$Weeks=5)
  if ($Weeks -lt 1 -or $Weeks -gt 5) {
    Write-Log "Invalid weeks value: $Weeks. Must be between 1 and 5."
    return $false
  }
  $pauseUntil = (Get-Date).AddDays($Weeks * 7)

  Write-Log "Windows Updates paused until: $($pauseUntil.ToString('MMMM dd, yyyy')) Starting…"

  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" `
                   -Name "PauseUpdatesExpiryTime" `
                   -Value $pauseUntil.ToString("yyyy-MM-ddTHH:mm:ssZ")
  Write-Log "Windows Updates paused until: $($pauseUntil.ToString('MMMM dd, yyyy')) Finished."
}
# --- Execution ---
$anythingChanged = $false
Write-Log "=== Phase 1: LCUs ==="
foreach ($kb in $TargetKBs) {
  if (Remove-LCUByKB $kb) { $anythingChanged = $true }
}

if ($RemoveEnablement25H2) {
  Write-Log "=== Phase 2: 25H2 Enablement ==="
  if (Remove-Enablement25H2) { $anythingChanged = $true }
}

Pause-Windowsupdates 5

$pending = Test-PendingReboot
Write-Log "Pending reboot: $pending"

if ($anythingChanged) {
  if ($pending) {
    Write-Host "Updates removed. Reboot required to complete rollback."
    Write-Log  "Completed with reboot required."
    exit 3010
  } else {
    Write-Host "Updates removed. Restart recommended."
    Write-Log  "Completed without reboot required."
    exit 0
  }
} else {
  Write-Host "Nothing to remove (targets not found)."
  Write-Log  "No changes performed."
  exit 0
}