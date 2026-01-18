#requires -Version 5.1
<#
kill-nonessential.ps1

- Elevates to Administrator on start (UAC prompt).
- "Force" behavior is ON by default (use -NoForce to opt out).
- -WhatIf shows what would be stopped, without stopping anything.
#>

param(
  # Dry-run mode
  [switch]$WhatIf,

  # Opt-out of forceful stopping (Force is ON by default)
  [switch]$NoForce,

  # Stops non-Microsoft services (defaults to ON if not specified)
  [switch]$StopThirdPartyServices,

  # Extra aggressive stop for specific vendor/service name patterns (e.g., NordVPN)
  [string[]]$StopServiceNameLike = @(
    "nord",
    "nordvpn",
    "urban",
    "urbanvpn"
  ),

  # Optional: stop per-user startup apps (registry "Run" entries) for THIS user session
  [switch]$DisableUserRunStartup
)

# ---- Defaults ----
# Force ON by default unless -NoForce
$Force = -not $NoForce

# StopThirdPartyServices ON by default unless explicitly set by user
if (-not $PSBoundParameters.ContainsKey('StopThirdPartyServices')) {
  $StopThirdPartyServices = $true
}

# --- Self-elevate to Admin (prompts for UAC at startup) ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
  Write-Host "Requesting administrative privileges..."

  # Rebuild the call using bound parameters (safe, no weird Object[] binding)
  $argList = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $PSCommandPath
  )

  if ($WhatIf) { $argList += "-WhatIf" }
  if ($NoForce) { $argList += "-NoForce" }

  if ($PSBoundParameters.ContainsKey('StopThirdPartyServices')) {
    # Preserve explicit true/false if user set it
    $argList += ("-StopThirdPartyServices:{0}" -f ([bool]$StopThirdPartyServices))
  }

  if ($PSBoundParameters.ContainsKey('StopServiceNameLike')) {
    foreach ($p in $StopServiceNameLike) {
      $argList += "-StopServiceNameLike"
      $argList += $p
    }
  }

  if ($DisableUserRunStartup) { $argList += "-DisableUserRunStartup" }

  try {
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList | Out-Null
  } catch {
    Write-Error "Administrator privileges are required. Aborting."
  }
  exit
}

# --- Guardrail: if Force is disabled, only allow -WhatIf runs ---
if (-not $Force -and -not $WhatIf) {
  Write-Host "Refusing to stop anything because -NoForce was specified. Use -WhatIf to review actions."
  Write-Host "Example: .\kill-nonessential.ps1 -WhatIf"
  Write-Host "Or run with Force default (no flag): .\kill-nonessential.ps1"
  exit 1
}

# Conservative allowlist of Windows essentials (process names without .exe)
$Allow = @(
  "System","Idle","Registry","smss","csrss","wininit","services","lsass",
  "winlogon","svchost","fontdrvhost","dwm","explorer","taskhostw","sihost",
  "spoolsv","ctfmon","WmiPrvSE","audiodg","RuntimeBroker","SearchIndexer",
  "dllhost","conhost","WUDFHost","SecurityHealthService",
  "ShellExperienceHost","StartMenuExperienceHost","SearchHost","SystemSettings",
  "ApplicationFrameHost","NisSrv","MsMpEng"
)

# Always allow this script's host process
$Allow += (Get-Process -Id $PID).ProcessName

function Write-Plan($msg) {
  if ($WhatIf) { Write-Host "[WhatIf] $msg" } else { Write-Host $msg }
}

# --- Optionally disable current-user startup "Run" entries (prevents relaunch next login) ---
if ($DisableUserRunStartup) {
  $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $runKey) {
    $props = (Get-ItemProperty $runKey)
    $names = $props.PSObject.Properties |
      Where-Object { $_.Name -notmatch '^PS' } |
      Select-Object -ExpandProperty Name

    foreach ($n in $names) {
      if ($WhatIf) {
        Write-Plan "Would remove HKCU Run startup entry: $n"
      } else {
        try {
          Remove-ItemProperty -Path $runKey -Name $n -ErrorAction Stop
          Write-Host "Removed HKCU Run startup entry: $n"
        } catch {
          Write-Host "Failed removing HKCU Run entry $n -> $($_.Exception.Message)"
        }
      }
    }
  }
}

# --- Stop third-party services (so things like nordvpn-service don't keep running) ---
if ($StopThirdPartyServices) {
  # A small allowlist for core Windows service hosts / essentials (service names)
  $ServiceAllow = @(
    "RpcSs","DcomLaunch","PlugPlay","Power","EventLog","Schedule","SamSs",
    "Winmgmt","WlanSvc","Dhcp","Dnscache","NlaSvc","LanmanWorkstation",
    "LanmanServer","W32Time","CryptSvc","BFE","MpsSvc","WdNisSvc","WinDefend",
    "SecurityHealthService","UserManager","ProfSvc","AudioSrv","Audiosrv",
    "LSM","TermService","SgrmBroker","SysMain"
  )

  try {
    $svc = Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" }

    foreach ($s in $svc) {
      $name = $s.Name
      $path = ($s.PathName + "")
      $isWindowsPath = $path -match '(?i)\\Windows\\(System32|SysWOW64)\\'
      $isAllowed = $ServiceAllow -contains $name

      # Stop if it's not in allowlist and doesn't look like a Windows binary path
      if (-not $isAllowed -and -not $isWindowsPath) {
        if ($WhatIf) {
          Write-Plan "Would stop service: $name  ($($s.DisplayName))  Path=$path"
        } else {
          try {
            Stop-Service -Name $name -Force -ErrorAction Stop
            Write-Host "Stopped service: $name ($($s.DisplayName))"
          } catch {
            Write-Host "Failed stopping service $name -> $($_.Exception.Message)"
          }
        }
      }
    }
  } catch {
    Write-Host "Service scan failed (try running PowerShell as Admin): $($_.Exception.Message)"
  }

  # Extra pass: stop services matching patterns (e.g., NordVPN)
  foreach ($pat in $StopServiceNameLike) {
    if ([string]::IsNullOrWhiteSpace($pat)) { continue }

    $matches = Get-Service | Where-Object {
      $_.Status -eq "Running" -and (
        $_.Name -match [regex]::Escape($pat) -or $_.DisplayName -match [regex]::Escape($pat)
      )
    }

    foreach ($m in $matches) {
      if ($WhatIf) {
        Write-Plan "Would stop (pattern '$pat') service: $($m.Name) ($($m.DisplayName))"
      } else {
        try {
          Stop-Service -Name $m.Name -Force -ErrorAction Stop
          Write-Host "Stopped (pattern '$pat') service: $($m.Name) ($($m.DisplayName))"
        } catch {
          Write-Host "Failed stopping (pattern '$pat') service $($m.Name) -> $($_.Exception.Message)"
        }
      }
    }
  }
}

# --- Kill non-allowlisted processes ---
$procs = Get-Process | Where-Object { $Allow -notcontains $_.ProcessName }

foreach ($p in $procs) {
  if ($WhatIf) {
    Write-Plan "Would stop process: $($p.ProcessName) (Id $($p.Id))"
  } else {
    try {
      Stop-Process -Id $p.Id -Force -ErrorAction Stop
      Write-Host "Stopped process: $($p.ProcessName) (Id $($p.Id))"
    } catch {
      Write-Host "Failed stopping process $($p.ProcessName) (Id $($p.Id)) -> $($_.Exception.Message)"
    }
  }
}



if ($Host.Name -ne 'ServerHost') {
  Write-Host ""
  Write-Host "Done. Press Enter to exit..."
  [void](Read-Host)
}