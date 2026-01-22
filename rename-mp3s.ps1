# Rename-Mp3.ps1
# Right-click → Run with PowerShell
# Renames MP3s to: "- Title (Artist).mp3"

Set-StrictMode -Version Latest

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

function Normalize-Spaces($s) {
    if ($null -eq $s) { return "" }
    ($s -replace '\s+', ' ').Trim()
}

function Sanitize-FileName($s) {
    Normalize-Spaces ($s -replace '[<>:"/\\|?*]', ' ')
}

function Remove-TrackNumber($s) {
    ($s -replace '^\s*\d+\s*[-._]\s*', '').Trim()
}

function Remove-Feat($artist) {
    Normalize-Spaces ($artist -replace '\s+(?i)(feat\.?|ft\.?)\s+.*$', '')
}

function Remove-JunkTags($title) {
    $junk = @(
        'lyric','lyrics','audio','official','video','visualizer',
        'premiere','mv','music video','hd','4k','karaoke','instrumental'
    )

    $pattern = '(\(([^)]*)\))|(\[([^\]]*)\])'
    $result = $title

    $matches = [regex]::Matches($result, $pattern)
    foreach ($m in ($matches | Sort-Object Index -Descending)) {
        $inside = ($m.Groups[2].Value + $m.Groups[4].Value).ToLower()
        foreach ($j in $junk) {
            if ($inside -like "*$j*") {
                $result = $result.Remove($m.Index, $m.Length)
                break
            }
        }
    }

    Normalize-Spaces ($result -replace '\(\s*\)|\[\s*\]', '')
}

function Get-UniqueName($dir, $name) {
    if (-not (Test-Path (Join-Path $dir $name))) { return $name }

    $base = [IO.Path]::GetFileNameWithoutExtension($name)
    $ext  = [IO.Path]::GetExtension($name)
    $i = 2

    while ($true) {
        $try = "$base ($i)$ext"
        if (-not (Test-Path (Join-Path $dir $try))) { return $try }
        $i++
    }
}

Get-ChildItem -Filter *.mp3 -File | ForEach-Object {
    $file = $_
    $base = Remove-TrackNumber ([IO.Path]::GetFileNameWithoutExtension($file.Name))

    if ($base -match '\s-\s') {
        $artist, $title = $base -split '\s-\s', 2
        $artist = Remove-Feat $artist
    } else {
        $artist = ""
        $title = $base
    }

    $title = Remove-JunkTags $title
    $title = Sanitize-FileName $title
    $artist = Sanitize-FileName $artist

    if ([string]::IsNullOrWhiteSpace($title)) { return }

    if ($artist) {
        $newName = "- $title ($artist).mp3"
    } else {
        $newName = "- $title.mp3"
    }

    $newName = Normalize-Spaces $newName
    if ($file.Name -eq $newName) { return }

    $finalName = Get-UniqueName $file.DirectoryName $newName
    Rename-Item $file.FullName $finalName
}
