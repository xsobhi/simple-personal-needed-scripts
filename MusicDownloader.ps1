$Host.UI.RawUI.WindowTitle = "YouTube Downloader"

try {
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = $utf8
    [Console]::InputEncoding  = $utf8
    $global:OutputEncoding    = $utf8
} catch { }

$Theme = [ordered]@{
    Title   = "Cyan"
    Accent  = "White"
    Muted   = "DarkGray"
    Divider = "DarkCyan"
    Good    = "Green"
    Warn    = "Yellow"
    Bad     = "Red"
}

$ScriptDir  = $PSScriptRoot
$OutDir     = "$env:USERPROFILE\Desktop\MusicDownloads"
$ConfigFile = Join-Path $ScriptDir "music_downloader_settings.json"
$VenvDir    = Join-Path $ScriptDir ".venv"

if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

function Write-Divider {
    param([string]$Char = "=", [int]$Width = 48)
    Write-Host ($Char * $Width) -ForegroundColor $Theme.Divider
}

function Write-Header {
    param([string]$Title)
    Clear-Host
    Write-Divider "=" 48
    Write-Host ("  {0}" -f $Title) -ForegroundColor $Theme.Title
    Write-Divider "=" 48
}

function Test-IsAdmin {
    $Identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]$Identity
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-AsAdmin {
    Write-Host "`n[!] Administrator privileges are required to install missing components." -ForegroundColor $Theme.Warn
    Write-Host "[!] The script will now restart to install them." -ForegroundColor $Theme.Warn
    Start-Sleep -Seconds 2
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Refresh-EnvVariables {
    $MachinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $UserPath    = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path    = "$MachinePath;$UserPath"
}

function Check-And-Install-Deps {
    $HasPython = (Get-Command "python" -ErrorAction SilentlyContinue)
    $HasFFmpeg = (Get-Command "ffmpeg" -ErrorAction SilentlyContinue)
    $HasDeno   = (Get-Command "deno"   -ErrorAction SilentlyContinue)

    if ($HasPython -and $HasFFmpeg -and $HasDeno) { return }

    Write-Header "Dependency Check"
    Write-Host "Dependencies missing!" -ForegroundColor $Theme.Warn
    if (!$HasPython) { Write-Host " - Python is missing." -ForegroundColor $Theme.Accent }
    if (!$HasFFmpeg) { Write-Host " - FFmpeg is missing." -ForegroundColor $Theme.Accent }
    if (!$HasDeno)   { Write-Host " - Deno (JS Runtime) is missing." -ForegroundColor $Theme.Accent }

    if (-not (Test-IsAdmin)) { Restart-AsAdmin }

    Write-Host "`nStarting Auto-Install..." -ForegroundColor $Theme.Title

    if (!$HasPython) {
        Write-Host "Installing Python..." -ForegroundColor $Theme.Title
        winget install --id Python.Python.3 --scope machine --accept-source-agreements --accept-package-agreements --disable-interactivity
        Refresh-EnvVariables
    }
    if (!$HasFFmpeg) {
        Write-Host "Installing FFmpeg..." -ForegroundColor $Theme.Title
        winget install --id Gyan.FFmpeg --accept-source-agreements --accept-package-agreements --disable-interactivity
        Refresh-EnvVariables
    }
    if (!$HasDeno) {
        Write-Host "Installing Deno..." -ForegroundColor $Theme.Title
        winget install --id DenoLand.Deno --accept-source-agreements --accept-package-agreements --disable-interactivity
        Refresh-EnvVariables
    }

    Write-Host "`n[OK] Installation complete." -ForegroundColor $Theme.Good
    Start-Sleep -Seconds 1
}

function Get-Settings {
    $Defaults = @{ Browser = "NONE"; Format = "mp3" }
    if (Test-Path $ConfigFile) {
        try {
            $Json = Get-Content $ConfigFile -Raw | ConvertFrom-Json
            if ($Json.Browser) { $Defaults.Browser = $Json.Browser }
            if ($Json.Format)  { $Defaults.Format  = $Json.Format }
        } catch { }
    }
    return $Defaults
}

function Save-Settings ($Obj) { $Obj | ConvertTo-Json | Set-Content -Path $ConfigFile }

function Invoke-InteractiveMenu {
    param ([string]$Title, [string[]]$Options)
    $Selection = 0
    try { [Console]::CursorVisible = $false } catch {}

    while ($true) {
        Write-Header $Title
        Write-Host " Use UP/DOWN arrows and ENTER" -ForegroundColor $Theme.Muted
        Write-Divider "-" 48

        for ($i = 0; $i -lt $Options.Count; $i++) {
            if ($i -eq $Selection) {
                Write-Host ("  > {0}" -f $Options[$i]) -ForegroundColor "Black" -BackgroundColor "White"
            } else {
                Write-Host ("    {0}" -f $Options[$i]) -ForegroundColor $Theme.Accent
            }
        }

        Write-Divider "-" 48
        $Key = [Console]::ReadKey($true)
        switch ($Key.Key) {
            "UpArrow"   { if ($Selection -gt 0) { $Selection-- } else { $Selection = $Options.Count - 1 } }
            "DownArrow" { if ($Selection -lt ($Options.Count - 1)) { $Selection++ } else { $Selection = 0 } }
            "Enter"     { try { [Console]::CursorVisible = $true } catch {}; return $Selection }
        }
    }
}

function Get-YtDlpPath {
    $VenvExe = Join-Path $VenvDir "Scripts\yt-dlp.exe"
    if (Test-Path $VenvExe) { return $VenvExe }
    if (Get-Command "yt-dlp" -ErrorAction SilentlyContinue) { return "yt-dlp" }
    return $null
}

$script:UseUnicodeBar   = $true
$script:BarWithBrackets = $false

function Test-UnicodeBarSupport {
    try {
        $chars = "█░"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($chars)
        $round = [System.Text.Encoding]::UTF8.GetString($bytes)
        if ($round -ne $chars) { return $false }
        $cp = [Console]::OutputEncoding.CodePage
        if ($cp -ne 65001) { return $false }
        return $true
    } catch { return $false }
}

$script:UseUnicodeBar = Test-UnicodeBarSupport

function Make-Bar([double]$pct, [int]$width = 28) {
    if ($pct -lt 0) { $pct = 0 }
    if ($pct -gt 100) { $pct = 100 }

    $filled = [int][Math]::Floor(($pct / 100.0) * $width)
    if ($filled -lt 0) { $filled = 0 }
    if ($filled -gt $width) { $filled = $width }
    $empty = $width - $filled

    if ($script:UseUnicodeBar) { $core = ("█" * $filled) + ("░" * $empty) }
    else { $core = ("#" * $filled) + ("-" * $empty) }

    if ($script:BarWithBrackets) { return "[" + $core + "]" }
    return $core
}

function Start-Download ($Url, $Settings, $ForceAnonymous) {
    $Exe = Get-YtDlpPath
    if (-not $Exe) { throw "yt-dlp not found. Run 'Setup Virtual Env (First Run)' first." }

    $AuthArgs = @()
    if ($ForceAnonymous) {
        Write-Host "[Info] Attempting download without login..." -ForegroundColor $Theme.Warn
    } elseif (Test-Path (Join-Path $ScriptDir "cookies.txt")) {
        $AuthArgs = @("--cookies", (Join-Path $ScriptDir "cookies.txt"))
    } elseif ($Settings.Browser -ne "NONE") {
        $AuthArgs = @("--cookies-from-browser", $Settings.Browser)
    }

    $PlaylistOpts = "--no-playlist"
    $Template = "$OutDir\%(title)s.%(ext)s"

    if ($Url -match "list=" -and $Url -match "v=") {
        $PL_Choice = Invoke-InteractiveMenu -Title "Context Detected" -Options @(
            "Download Single Video (Current)",
            "Download Entire Playlist"
        )
        if ($PL_Choice -eq 1) {
            $PlaylistOpts = "--yes-playlist"
            $Template = "$OutDir\%(playlist_index)02d - %(title)s.%(ext)s"
        }
    }
    elseif ($Url -match "list=") {
        $PlaylistOpts = "--yes-playlist"
        $Template = "$OutDir\%(playlist_index)02d - %(title)s.%(ext)s"
        Write-Host "Playlist detected." -ForegroundColor $Theme.Muted
    }

    $currentTitle = ""
    $currentVid = ""
    $lastLineLen = 0
    $sawAnyOutput = $false

    function Clear-And-Header([string]$title) {
        Clear-Host
        Write-Host "[Downloading]" -ForegroundColor $Theme.Title
        Write-Host (" Output: {0}" -f $OutDir) -ForegroundColor $Theme.Muted
        if ($title) { Write-Host (" Now: {0}" -f $title) -ForegroundColor $Theme.Accent }
        Write-Host (" " + ("-" * 48)) -ForegroundColor $Theme.Divider
        $script:lastLineLen = 0
    }

    function Write-LiveLine([string]$text) {
        $pad = ""
        if ($script:lastLineLen -gt $text.Length) { $pad = " " * ($script:lastLineLen - $text.Length) }
        [Console]::Write("`r$text$pad")
        $script:lastLineLen = $text.Length
    }

    function End-LiveLine() {
        if ($script:lastLineLen -gt 0) {
            [Console]::WriteLine("")
            $script:lastLineLen = 0
        }
    }

    $YtArgs = @()
    $YtArgs += $PlaylistOpts
    $YtArgs += $AuthArgs
    $YtArgs += @(
        "-x",
        "--audio-format", $Settings.Format,
        "--audio-quality", "0",
        "--no-mtime",
        "--windows-filenames",
        "--ignore-errors",
        "--no-warnings",
        "--no-write-thumbnail",
        "--newline",
        "--progress",
        "--print", "before_dl:START:ID=%(id)s|T=%(title)s",
        "-o", $Template,
        $Url
    )

    Clear-And-Header ""

    $tail   = New-Object System.Collections.Generic.List[string]
    $errors = New-Object System.Collections.Generic.List[string]

    $reProg = '^\[download\]\s+(\d+(?:\.\d+)?)%\s+of\s+(?:~\s*)?(.+?)(?:\s+at\s+(.+?)\s+ETA\s+([0-9:]+))?(?:\s+\(frag.*\))?\s*$'
    $reIn   = '^\[download\]\s+(\d+(?:\.\d+)?)%\s+of\s+(.+?)\s+in\s+([0-9:]+)\s*$'

    & $Exe @YtArgs 2>&1 | ForEach-Object {
        $sawAnyOutput = $true
        $lineStr = $_.ToString()
        if ($lineStr) {
            $tail.Add($lineStr.Trim())
            if ($tail.Count -gt 80) { $tail.RemoveAt(0) }
        }

        $trim = $lineStr.Trim()

        if ($trim -match '^START:ID=([^|]+)\|T=(.*)$') {
            $currentVid = $Matches[1]
            $currentTitle = $Matches[2]
            Clear-And-Header $currentTitle
            $bar = Make-Bar 0 28
            $pctTxt = ("{0,5:0.0}%" -f 0.0)
            Write-LiveLine ("{0}  {1}  {2}" -f $bar, $pctTxt, "Starting...")
            return
        }

        if ($trim -match $reProg) {
            $pctNum = [double]$Matches[1]
            $pctTxt = ("{0,5:0.0}%" -f $pctNum)
            $tot    = $Matches[2].Trim()

            $spd = ""
            $eta = ""
            if ($Matches.Count -ge 4) { $spd = $Matches[3] }
            if ($Matches.Count -ge 5) { $eta = $Matches[4] }

            $bar = Make-Bar $pctNum 28

            $right = if ([string]::IsNullOrWhiteSpace($spd) -and [string]::IsNullOrWhiteSpace($eta)) {
                ("of {0}" -f $tot)
            } elseif ([string]::IsNullOrWhiteSpace($eta)) {
                ("of {0}  {1}" -f $tot, $spd.Trim())
            } else {
                ("of {0}  {1}  ETA {2}" -f $tot, $spd.Trim(), $eta.Trim())
            }

            Write-LiveLine ("{0}  {1}  {2}" -f $bar, $pctTxt, $right)
            return
        }

        if ($trim -match $reIn) {
            $pctNum = [double]$Matches[1]
            $tot    = $Matches[2].Trim()
            $timeIn = $Matches[3].Trim()
            $bar = Make-Bar $pctNum 28
            $pctTxt = ("{0,5:0.0}%" -f $pctNum)
            Write-LiveLine ("{0}  {1}  of {2}  done in {3}" -f $bar, $pctTxt, $tot, $timeIn)
            return
        }

        if ($trim -match '^ERROR:\s*(.+)$') {
            $errors.Add($trim)
            End-LiveLine
            Write-Host $trim -ForegroundColor $Theme.Bad
            return
        }

        if ($trim -match '^WARNING:\s*(.+)$') {
            End-LiveLine
            Write-Host $trim -ForegroundColor $Theme.Warn
            return
        }

        if ($trim -match '^\[(ExtractAudio|download|ffmpeg)\]') { return }
        if ($trim -match '^\[.*\] Destination:') { return }
        if ($trim -match '^\[.*\] Writing video thumbnail') { return }
    }

    $exit = $LASTEXITCODE
    End-LiveLine

    if (-not $sawAnyOutput) {
        Write-Host "[ERROR] yt-dlp produced no output." -ForegroundColor $Theme.Bad
        return $false
    }

    if ($exit -eq 0) {
        Write-Host ""
        Write-Host (" " + ("-" * 48)) -ForegroundColor $Theme.Divider
        Write-Host "[DONE] Process Finished." -ForegroundColor $Theme.Good
        return $true
    }

    if ($exit -eq 1) {
        Write-Host ""
        Write-Host (" " + ("-" * 48)) -ForegroundColor $Theme.Divider
        if ($errors.Count -gt 0) {
            Write-Host "[DONE] Finished with some skipped/unavailable videos." -ForegroundColor $Theme.Warn
            Write-Host "Errors (first 10):" -ForegroundColor $Theme.Muted
            $errors | Select-Object -First 10 | ForEach-Object { Write-Host $_ -ForegroundColor $Theme.Muted }
            if ($errors.Count -gt 10) { Write-Host ("... and {0} more" -f ($errors.Count - 10)) -ForegroundColor $Theme.Muted }
        } else {
            Write-Host "[DONE] Finished (exit code 1). Some items may have been skipped." -ForegroundColor $Theme.Warn
        }
        return $true
    }

    Write-Host (" " + ("-" * 48)) -ForegroundColor $Theme.Divider
    Write-Host "[FAILED] yt-dlp exited with code $exit" -ForegroundColor $Theme.Bad
    Write-Host "Last output:" -ForegroundColor $Theme.Muted
    $tail | ForEach-Object { Write-Host $_ -ForegroundColor $Theme.Muted }
    return $false
}

Check-And-Install-Deps

while ($true) {
    $Settings = Get-Settings
    $AuthTxt = if ($Settings.Browser -eq "NONE") { "Anonymous" } else { $Settings.Browser }
    if (Test-Path (Join-Path $ScriptDir "cookies.txt")) { $AuthTxt = "cookies.txt" }
    $FmtTxt  = $Settings.Format.ToUpper()

    $MenuOptions = @(
        "Download Music",
        "Settings: Audio Format  [Current: $FmtTxt]",
        "Settings: Login Source  [Current: $AuthTxt]",
        "Update Tool (yt-dlp)",
        "Setup Virtual Env (First Run)",
        "Exit"
    )

    $Choice = Invoke-InteractiveMenu -Title "YouTube Downloader" -Options $MenuOptions

    switch ($Choice) {
        0 {
            $Exe = Get-YtDlpPath
            if (!$Exe) { Write-Host "Please run Setup (Virtual Env) first!" -ForegroundColor $Theme.Bad; Pause; continue }

            Write-Host ""
            $Url = Read-Host "Enter YouTube URL"
            if ([string]::IsNullOrWhiteSpace($Url)) { continue }

            $null = Start-Download $Url $Settings $false
            Pause
        }
        1 {
            $Sel = Invoke-InteractiveMenu "Select Format" @("mp3", "m4a", "flac", "wav")
            $Settings.Format = ("mp3","m4a","flac","wav")[$Sel]
            Save-Settings $Settings
        }
        2 {
            $Browsers = @("Chrome", "Edge", "Firefox", "Brave", "Opera", "None (Anonymous)")
            $Sel = Invoke-InteractiveMenu "Select Browser" $Browsers
            $Settings.Browser = (("chrome","edge","firefox","brave","opera","NONE")[$Sel])
            Save-Settings $Settings
        }
        3 {
            Write-Header "Updating yt-dlp"
            Write-Host "[Updating...]" -ForegroundColor $Theme.Title
            if (Test-Path "$VenvDir\Scripts\pip.exe") { & "$VenvDir\Scripts\pip.exe" install --upgrade yt-dlp }
            else { pip install --upgrade yt-dlp }
            Write-Host "[OK] Update finished." -ForegroundColor $Theme.Good
            Pause
        }
        4 {
            Write-Header "Setup"
            Write-Host "[Creating Virtual Environment...]" -ForegroundColor $Theme.Title
            if (!(Test-Path $VenvDir)) { python -m venv $VenvDir }
            & "$VenvDir\Scripts\pip.exe" install --upgrade pip
            & "$VenvDir\Scripts\pip.exe" install --upgrade yt-dlp
            Write-Host "[OK] Setup Complete." -ForegroundColor $Theme.Good
            Pause
        }
        5 { exit }
    }
}
