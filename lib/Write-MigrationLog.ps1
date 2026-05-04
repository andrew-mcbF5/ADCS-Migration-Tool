function Write-MigrationLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'WHATIF', 'STEP', 'CHECK')]
        [string]$Level = 'INFO',
        [string]$LogPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix    = switch ($Level) {
        'INFO'    { '[INFO   ]' }
        'WARN'    { '[WARN   ]' }
        'ERROR'   { '[ERROR  ]' }
        'SUCCESS' { '[SUCCESS]' }
        'WHATIF'  { '[WHATIF ]' }
        'STEP'    { '[STEP   ]' }
        'CHECK'   { '[CHECK  ]' }
    }
    $entry = "[$timestamp] $prefix $Message"

    $color = switch ($Level) {
        'INFO'    { 'Cyan' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
        'WHATIF'  { 'Magenta' }
        'STEP'    { 'White' }
        'CHECK'   { 'DarkCyan' }
    }
    Write-Host $entry -ForegroundColor $color

    if ($LogPath) {
        try {
            Add-Content -Path $LogPath -Value $entry -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Warning "Could not write to log file '$LogPath': $_"
        }
    }
}

function Write-MigrationBanner {
    param([string]$Title, [string]$LogPath)
    $line = '=' * 70
    $entry = "`n$line`n  $Title`n$line"
    Write-Host $entry -ForegroundColor White
    if ($LogPath) { Add-Content -Path $LogPath -Value $entry -Encoding UTF8 }
}
