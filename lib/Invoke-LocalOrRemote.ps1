function Invoke-LocalOrRemote {
    <#
    .SYNOPSIS
        Runs a ScriptBlock locally or via Invoke-Command transparently.
    .PARAMETER Server
        Target hostname. If it matches the local machine name or 'localhost', runs locally.
    .PARAMETER Credential
        Optional PSCredential for remote sessions. Omit if running as a privileged account.
    .PARAMETER ScriptBlock
        The code to execute on the target.
    .PARAMETER ArgumentList
        Arguments to pass to the ScriptBlock (as positional parameters).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [PSCredential]$Credential,
        [Parameter(Mandatory)][ScriptBlock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    $isLocal = ($Server -eq $env:COMPUTERNAME) -or
               ($Server -match '^(localhost|127\.0\.0\.1|\.)$')

    try {
        if ($isLocal) {
            if ($ArgumentList.Count -gt 0) {
                & $ScriptBlock @ArgumentList
            } else {
                & $ScriptBlock
            }
        } else {
            $params = @{
                ComputerName = $Server
                ScriptBlock  = $ScriptBlock
                ErrorAction  = 'Stop'
            }
            if ($ArgumentList.Count -gt 0) { $params.ArgumentList = $ArgumentList }
            if ($Credential)               { $params.Credential   = $Credential }
            Invoke-Command @params
        }
    } catch {
        # Unwrap RemoteException so callers see a consistent exception type regardless
        # of whether the ScriptBlock ran locally or via Invoke-Command.
        $ex = $_.Exception
        if ($ex -is [System.Management.Automation.RemoteException] -and $null -ne $ex.InnerException) {
            throw $ex.InnerException
        }
        throw
    }
}

function Test-ServerReachable {
    <#
    .SYNOPSIS
        Tests whether a server is reachable via WinRM (port 5985/5986).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [PSCredential]$Credential
    )
    try {
        $params = @{ ComputerName = $Server; ScriptBlock = { $env:COMPUTERNAME }; ErrorAction = 'Stop' }
        if ($Credential) { $params.Credential = $Credential }
        $result = Invoke-Command @params
        return ($null -ne $result)
    } catch {
        return $false
    }
}

function Read-SignOffFile {
    <#
    .SYNOPSIS
        Reads a phase sign-off JSON file and returns the parsed object.
        Returns $null if file does not exist.
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        $content = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        return $content
    } catch {
        throw "Sign-off file at '$Path' is not valid JSON: $_"
    }
}

function Assert-SignOffApproved {
    <#
    .SYNOPSIS
        Hard-stops execution if the required phase sign-off is missing or not approved.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PhaseName
    )
    $signOff = Read-SignOffFile -Path $Path
    if ($null -eq $signOff) {
        throw "HARD STOP: $PhaseName sign-off file not found at '$Path'. Complete the previous phase and approve the sign-off before proceeding."
    }
    if ($signOff.Status -ne 'Approved') {
        throw "HARD STOP: $PhaseName sign-off status is '$($signOff.Status)' — must be 'Approved'. Edit '$Path', set Status to 'Approved', and fill ApprovedBy before running this script."
    }
    if ([string]::IsNullOrWhiteSpace($signOff.ApprovedBy)) {
        throw "HARD STOP: $PhaseName sign-off has no ApprovedBy value. Edit '$Path' and fill in ApprovedBy before proceeding."
    }
    return $signOff
}

function Get-JsonFileHash {
    <#
    .SYNOPSIS
        Returns the SHA256 hash of a file. Used to detect tampering with JSON files between phases.
    #>
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}
