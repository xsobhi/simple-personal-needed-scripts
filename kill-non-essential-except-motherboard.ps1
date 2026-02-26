#requires -Version 5.1
<#
kill-nonessential-v7.ps1

- Strict Max-Performance Version
- Whitelists MSI, ASUS, Gigabyte, ASRock, and major peripherals.
- Closes ALL dev, creator, and background tools for maximum RAM/CPU freeing.
- Gracefully attempts to close apps before forcing them.
- Protects core Windows paths dynamically.
- Includes Execution Transcript (Logging).
#>

param(
  [switch]$WhatIf,
  [switch]$NoForce,
  [switch]$StopThirdPartyServices,

  # Apps/Services containing these names will be SAVED (Case-insensitive)
  [string[]]$Whitelist = @(
    # --- ASUS / Zephyrus ---
    "Armoury", "Asus", "GHelper", "Aura",
    
    # --- MSI ---
    "MSI", "Dragon", "SteelSeries", "Killer", "Nahimic",
    
    # --- Gigabyte / AORUS ---
    "Gigabyte", "Aorus", "RGBFusion", "AppCenter",
    
    # --- ASRock ---
    "ASRock", "Polychrome", "A-Tuning",
    
    # --- Other Hardware / Peripherals ---
    "Corsair", "iCUE", "NZXT", "CAM", "EVGA", "Precision", "Logitech", "LGHUB", "Razer", "Synapse",
    
    # --- Universal / Drivers ---
    "Nvidia", "NvContainer", "Amd", "Radeon", "Realtek", "Dolby", "Thx"
  ),

  # Services matching these names will be specifically TARGETED for stopping
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
  Write-Host "Requesting administrative privileges..." -ForegroundColor Cyan
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

# --- Logging ---
$LogPath = "$env:TEMP\GameOptimizerLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $LogPath -Append:$false | Out-Null

# --- SAFETY CHECK: Warn User ---
if (-not $WhatIf) {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "                        WARNING                                 " -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host " This script will aggressively close ALL non-essential apps,"
    Write-Host " including dev environments (Python, Node) and editing software."
    Write-Host " PLEASE SAVE YOUR WORK NOW."
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    
    $confirmation = Read-Host " Do you want to continue? (Y/N)"
    if ($confirmation -notmatch "^[Yy]$") {
        Write-Host "Operation cancelled by user." -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        exit
    }
}

# Core Windows processes and standard terminals so the script doesn't kill itself
$Allow = @(
  "System","Idle","Registry","smss","csrss","wininit","services","lsass",
  "winlogon","svchost","fontdrvhost","dwm","explorer","taskhostw","sihost",
  "spoolsv","ctfmon","WmiPrvSE","audiodg","RuntimeBroker","SearchIndexer",
  "dllhost","conhost","WUDFHost","SecurityHealthService","smartscreen",
  "ShellExperienceHost","StartMenuExperienceHost","SearchHost","SystemSettings",
  "ApplicationFrameHost","NisSrv","MsMpEng","powershell_ise", "WindowsTerminal", "pwsh"
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

# --- 1. Stop Third-Party Services ---
if ($StopThirdPartyServices) {
  Write-Host "`nChecking Services..." -ForegroundColor Green
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
      $isWhitelisted = Test-IsWhitelisted -Name $name -DisplayName $disp
      
      # Check if this service is specifically targeted for death (e.g. VPNs)
      $isLikeTarget = $false
      foreach ($likeName in $StopServiceNameLike) {
          if ($name -match $likeName -or $disp -match $likeName) { $isLikeTarget = $true; break }
      }

      if ($isLikeTarget -or (-not $isAllowed -and -not $isWindowsPath -and -not $isWhitelisted)) {
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

# --- 2. Kill Non-Allowlisted Processes ---
Write-Host "`nChecking Processes..." -ForegroundColor Green
$procs = Get-Process | Where-Object { $Allow -notcontains $_.ProcessName }

foreach ($p in $procs) {
  # Skip if whitelisted
  if (Test-IsWhitelisted -Name $p.ProcessName -DisplayName $p.MainWindowTitle) {
      continue
  }

  # Dynamic Windows Path Safety Check
  $isWindowsProcess = $false
  try {
      if ($p.Path -match '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\') {
          $isWindowsProcess = $true
      }
  } catch { 
      # If we get Access Denied reading the path, it's highly likely a protected system process
      $isWindowsProcess = $true 
  }

  if ($isWindowsProcess) { continue }

  if ($WhatIf) {
    Write-Plan "Would stop process: $($p.ProcessName) (Id $($p.Id))"
  } else {
    try {
      # Graceful Close Attempt First
      if ($p.MainWindowHandle -ne 0) {
          Write-Host "Attempting to gracefully close $($p.ProcessName)..." -ForegroundColor DarkGray
          $p.CloseMainWindow() | Out-Null
          Start-Sleep -Seconds 1
      }
      
      # Force Kill if it's still running
      $p.Refresh()
      if (-not $p.HasExited) {
          Stop-Process -Id $p.Id -Force -ErrorAction Stop
          Write-Host "Forcefully stopped process: $($p.ProcessName)"
      } else {
          Write-Host "Gracefully closed process: $($p.ProcessName)"
      }
    } catch {
      Write-Host "Failed stopping $($p.ProcessName): $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

# --- 3. Disable User Run Startup (Optional) ---
if ($DisableUserRunStartup) {
    Write-Host "`nChecking HKCU Startup Items..." -ForegroundColor Green
    $runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    
    try {
        $startupItems = Get-ItemProperty $runKey -ErrorAction Stop | Get-Member -MemberType NoteProperty
        foreach ($item in $startupItems) {
            # Optionally, you could add whitelist checks here too before removing
            if ($WhatIf) {
                Write-Plan "Would remove startup item: $($item.Name)"
            } else {
                Remove-ItemProperty -Path $runKey -Name $item.Name -ErrorAction SilentlyContinue
                Write-Host "Removed startup item: $($item.Name)"
            }
        }
    } catch {
        Write-Host "Could not read or edit startup registry key." -ForegroundColor Yellow
    }
}

Write-Host "`nOptimization Complete." -ForegroundColor Green
Write-Host "A log of stopped processes and services has been saved to: $LogPath" -ForegroundColor DarkGray

Stop-Transcript | Out-Null