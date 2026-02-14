# --- AUTO-ADMIN ELEVATION BLOCK ---
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Exit
}
# ----------------------------------

$basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}"

Write-Host "Scanning ALL audio drivers for power settings..." -ForegroundColor Cyan
Write-Host "Targeting: Realtek, Intel Smart Sound (SST), NVIDIA, and others.`n" -ForegroundColor Gray

# 1. Get all 4-digit subkeys (0000, 0001, etc.)
try {
    $subKeys = Get-ChildItem -Path $basePath -Name | Where-Object { $_ -match "^\d{4}$" }
}
catch {
    Write-Host "Critical Error: Cannot read registry path." -ForegroundColor Red
    Pause
    Exit
}

foreach ($keyName in $subKeys) {
    $fullPath = Join-Path -Path $basePath -ChildPath $keyName

    # 2. Read the Description
    $desc = (Get-ItemProperty -Path $fullPath -Name "DriverDesc" -ErrorAction SilentlyContinue).DriverDesc

    if ([string]::IsNullOrWhiteSpace($desc)) { continue }

    # 3. FILTER: We apply this to ANYTHING that looks like an audio device
    # This covers Realtek, Intel Smart Sound, NVIDIA, USB Audio, etc.
    if ($desc -match "Audio" -or $desc -match "Sound" -or $desc -match "Realtek" -or $desc -match "Intel" -or $desc -match "SST" -or $desc -match "NVIDIA") {
        
        Write-Host "Processing [$keyName]: $desc" -ForegroundColor White
        
        # 4. Check priority: PowerSettings sub-folder vs Root
        $powerKeyPath = Join-Path -Path $fullPath -ChildPath "PowerSettings"
        
        if (Test-Path $powerKeyPath) {
            $targetPath = $powerKeyPath
            Write-Host "   -> Target: 'PowerSettings' sub-folder" -ForegroundColor Yellow
        } else {
            $targetPath = $fullPath
            Write-Host "   -> Target: Root driver folder" -ForegroundColor Gray
        }

        # 5. Apply the FF FF FF FF fix
        try {
            # Force create/update the keys
            Set-ItemProperty -Path $targetPath -Name "ConservationIdleTime" -Value 0xffffffff -Type DWORD -ErrorAction Stop
            Set-ItemProperty -Path $targetPath -Name "PerformanceIdleTime" -Value 0xffffffff -Type DWORD -ErrorAction Stop
            
            Write-Host "   [OK] Power Saving Disabled (Max Performance)" -ForegroundColor Green
        }
        catch {
            Write-Host "   [X] Error: Could not write keys. Access Denied?" -ForegroundColor Red
        }
    } else {
        # Skip non-audio things (like proxy services) to be safe
        Write-Host "Skipping [$keyName]: $desc (Not an audio device)" -ForegroundColor DarkGray
    }
}

Write-Host "`n------------------------------------------------------------"
Write-Host "DONE. All audio devices have been set to High Performance." -ForegroundColor Cyan
Write-Host "Please RESTART your laptop now." -ForegroundColor White
Write-Host "Press Enter to exit..."
Read-Host