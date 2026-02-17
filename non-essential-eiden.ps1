#requires -Version 5.1
<#
kill-nonessential-v5.ps1

- Universal Gaming Laptop Version (ASUS + MSI)
- Whitelists MSI Center, Dragon Center, SteelSeries, etc.
- Whitelists ASUS G-Helper, Armoury Crate, etc.
- Prompts user to SAVE WORK.
#>

param(
  [switch]$WhatIf,
  [switch]$NoForce,
  [switch]$StopThirdPartyServices,

  # Apps/Services containing these names will be SAVED (Case-insensitive)
  [string[]]$Whitelist = @(
    # --- ASUS / Zephyrus ---
    "Armoury",      # ASUS Armoury Crate
    "Asus",         # ASUS Optimization/Link/Framework
    "GHelper",      # Popular lightweight alternative for Zephyrus
    "Aura",         # ASUS Lighting

    # --- MSI ---
    "MSI",          # MSI Center / MSI SDK
    "Dragon",       # Dragon Center
    "SteelSeries",  # MSI Keyboard/RGB Software
    "Killer",       # Killer Intelligence Center (Network for MSI)
    
    # --- Universal / Drivers ---
    "Nvidia",       # GPU Drivers
    "NvContainer",  # NVIDIA Container
    "Amd",          # AMD CPU/GPU Drivers
    "Radeon",       # AMD Graphics
    "Realtek",      # Audio Drivers
    "Dolby",        # Audio Effects
    "Nahimic",      # Audio software (Common on MSI & ASUS)
    "Thx"           # THX Spatial Audio (Common on Razer/MSI)
  ),

  [string[]]$StopServiceNameLike = @(
    "nord", "nordvpn", "urban", "urbanvpn"
  ),

  [switch]$DisableUserRunStartup
)

# ---- Defaults ----
$Force = -not $NoForce
if (-not $PSBoundParameters.ContainsKey('StopThirdPartyServices')) {
  $StopThirdPartyServices = $true
}

# --- Self-elevate to Admin ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
  Write-Host "Requesting administrative privileges..."
  $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
  if ($WhatIf) { $argList += "-WhatIf" }
  if ($NoForce) { $argList += "-NoForce" }
  if ($PSBoundParameters.ContainsKey('StopThirdPartyServices')) { $argList += ("-StopThirdPartyServices:{0}" -f ([bool]$StopThirdPartyServices)) }
  if ($PSBoundParameters.ContainsKey('StopServiceNameLike')) { foreach ($p in $StopServiceNameLike) { $argList += "-StopServiceNameLike"; $argList += $p } }
  if ($PSBoundParameters.ContainsKey('Whitelist')) { foreach ($w in $Whitelist) { $argList += "-Whitelist"; $argList += $w } }
  if ($DisableUserRunStartup) { $argList += "-DisableUserRunStartup" }

  try { Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList | Out-Null } catch { Write-Error "Admin privileges required."; exit }
  exit
}

# --- SAFETY CHECK: Warn User ---
if (-not $WhatIf) {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "                         WARNING                                " -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " This script will forcefully close ALL non-essential applications"
    Write-Host " and services to free up resources."
    Write-Host ""
    Write-Host " PLEASE SAVE YOUR WORK NOW."
    Write-Host " Any unsaved data in open applications may be lost."
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    
    $confirmation = Read-Host " Do you want to continue? (Y/N)"
    if ($confirmation -notmatch "^[Yy]$") {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        exit
    }
}

# Conservative allowlist of Windows essentials
$Allow = @(
  "System","Idle","Registry","smss","csrss","wininit","services","lsass",
  "winlogon","svchost","fontdrvhost","dwm","explorer","taskhostw","sihost",
  "spoolsv","ctfmon","WmiPrvSE","audiodg","RuntimeBroker","SearchIndexer",
  "dllhost","conhost","WUDFHost","SecurityHealthService",
  "ShellExperienceHost","StartMenuExperienceHost","SearchHost","SystemSettings",
  "ApplicationFrameHost","NisSrv","MsMpEng","SmartScreen"
)
$Allow += (Get-Process -Id $PID).ProcessName

function Write-Plan($msg) { if ($WhatIf) { Write-Host "[WhatIf] $msg" -ForegroundColor Cyan } else { Write-Host $msg } }

# Helper to check against Whitelist
function Test-IsWhitelisted($Name, $DisplayName = "") {
    foreach ($term in $Whitelist) {
        if ($Name -like "*$term*" -or $DisplayName -like "*$term*") { return $true }
    }
    return $false
}

# --- Stop third-party services ---
if ($StopThirdPartyServices) {
  $ServiceAllow = @(
    "RpcSs","DcomLaunch","PlugPlay","Power","EventLog","Schedule","SamSs",
    "Winmgmt","WlanSvc","Dhcp","Dnscache","NlaSvc","LanmanWorkstation",
    "LanmanServer","W32Time","CryptSvc","BFE","MpsSvc","WdNisSvc","WinDefend",
    "SecurityHealthService","UserManager","ProfSvc","AudioSrv","Audiosrv",
    "LSM","TermService","SgrmBroker","SysMain","AudioEndpointBuilder"
  )

  try {
    $svc = Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" }

    foreach ($s in $svc) {
      $name = $s.Name
      $disp = $s.DisplayName
      $path = ($s.PathName + "")
      $isWindowsPath = $path -match '(?i)\\Windows\\(System32|SysWOW64)\\'
      $isAllowed = $ServiceAllow -contains $name

      # Check Whitelist
      $isWhitelisted = Test-IsWhitelisted -Name $name -DisplayName $disp

      if (-not $isAllowed -and -not $isWindowsPath -and -not $isWhitelisted) {
        if ($WhatIf) {
          Write-Plan "Would stop service: $name ($disp)"
        } else {
          try { 
            Stop-Service -Name $name -Force -ErrorAction Stop
            Write-Host "Stopped service: $name" 
          }
          catch { 
            Write-Host "Failed stopping service $($name): $($_.Exception.Message)" -ForegroundColor Yellow 
          }
        }
      }
    }
  } catch { Write-Host "Service scan failed." }
}

# --- Kill non-allowlisted processes ---
$procs = Get-Process | Where-Object { $Allow -notcontains $_.ProcessName }

foreach ($p in $procs) {
  # Check Whitelist
  if (Test-IsWhitelisted -Name $p.ProcessName -DisplayName $p.MainWindowTitle) {
      continue
  }

  if ($WhatIf) {
    Write-Plan "Would stop process: $($p.ProcessName) (Id $($p.Id))"
  } else {
    try {
      Stop-Process -Id $p.Id -Force -ErrorAction Stop
      Write-Host "Stopped process: $($p.ProcessName)"
    } catch {
      Write-Host "Failed stopping $($p.ProcessName): $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

Write-Host "`nDone."