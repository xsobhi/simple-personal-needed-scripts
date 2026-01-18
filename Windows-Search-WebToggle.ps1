#requires -Version 5.1
<#
Windows Search Web Results Toggle
- Uses policy key: DisableSearchBoxSuggestions
- Machine-wide (HKLM)
- Auto-elevates to Administrator
#>

# ------------------ Self-elevate to Admin ------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "Requesting administrative privileges..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath
    )
    exit
}

# ------------------ Config ------------------
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
$ValueName = "DisableSearchBoxSuggestions"

# Ensure key exists
New-Item -Path $RegPath -Force | Out-Null

function Get-WebSearchStatus {
    try {
        $v = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop
        return ($v.$ValueName -eq 1)
    } catch {
        return $false
    }
}

function Disable-WebSearch {
    New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "✔ Internet search DISABLED in Windows Search"
}

function Enable-WebSearch {
    Remove-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    Write-Host "✔ Internet search ENABLED in Windows Search"
}

function Restart-Explorer {
    Write-Host "Restarting Explorer..."
    Stop-Process -Name explorer -Force
}

# ------------------ Menu ------------------
Clear-Host
$status = Get-WebSearchStatus

Write-Host "============================================"
Write-Host " Windows Search – Internet Results Control"
Write-Host "============================================"
Write-Host ""
Write-Host ("Current status: " + $(if ($status) { "DISABLED" } else { "ENABLED" }))
Write-Host ""
Write-Host "1) Disable internet search"
Write-Host "2) Enable internet search"
Write-Host "3) Exit"
Write-Host ""

$choice = Read-Host "Select an option (1-3)"

switch ($choice) {
    "1" {
        if ($status) {
            Write-Host "Internet search is already disabled."
        } else {
            Disable-WebSearch
            Restart-Explorer
        }
    }
    "2" {
        if (-not $status) {
            Write-Host "Internet search is already enabled."
        } else {
            Enable-WebSearch
            Restart-Explorer
        }
    }
    default {
        Write-Host "No changes made."
    }
}

Write-Host ""
Write-Host "Done. Press Enter to exit..."
[void](Read-Host)
