<#
.SYNOPSIS
    Phase 2 Rollback — Revert ADCS migration and re-enable CA on DC01-VM.

.DESCRIPTION
    Reverses the Phase 2 migration by re-enabling CertSvc on DC01-VM and stopping it
    on DC03-VM. DC01-VM's CA configuration (CDP/AIA) was never modified during Phase 2,
    so no CA config changes are needed — only service state changes.

    This script is only valid when:
      - DC01-VM is still a domain controller (Phase 3 has NOT been run)
      - CertSvc on DC01-VM is stopped/disabled (Phase 2 Step 9 completed)
      - CertSvc on DC03-VM is either running or stopped

    If Phase 3 has already run (DC01-VM demoted), rollback requires manual AD DS restore
    procedures and is beyond the scope of this script.

    Run with -WhatIf first to confirm intended changes.

.PARAMETER DC01Server
    Hostname of the original CA server to re-enable. Defaults to Config.psd1 value.

.PARAMETER DC03Server
    Hostname of the new CA server to stop. Defaults to Config.psd1 value.

.PARAMETER Credential
    Optional PSCredential. Omit when running as Domain Admin.

.PARAMETER Reason
    Mandatory free-text reason for the rollback (written to the rollback report for audit purposes).
    Example: "CA health check failures 48h post-migration — clients reporting CRL errors"

.PARAMETER OutputPath
    Directory for rollback reports (default: .\reports).

.EXAMPLE
    .\2_Rollback-ADCSMigration.ps1 -Reason "CRL unavailable after migration — reverting" -WhatIf

.EXAMPLE
    $cred = Get-Credential
    .\2_Rollback-ADCSMigration.ps1 -Reason "CRL unavailable after migration — reverting" -Credential $cred
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$DC01Server     = 'DC01-VM',
    [string]$DC03Server     = 'DC03-VM',
    [PSCredential]$Credential,
    [Parameter(Mandatory)][string]$Reason,
    [string]$OutputPath     = '.\reports'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Initialise ---
$scriptDir  = $PSScriptRoot

$configFile = Join-Path $scriptDir 'Config.psd1'
if (Test-Path $configFile) {
    $Cfg = Import-PowerShellDataFile $configFile
    if (-not $PSBoundParameters.ContainsKey('DC01Server')) { $DC01Server = $Cfg.DC01Server }
    if (-not $PSBoundParameters.ContainsKey('DC03Server')) { $DC03Server = $Cfg.DC03Server }
}

$datestamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportsDir     = [System.IO.Path]::GetFullPath($OutputPath)
$signOffDir     = Join-Path $reportsDir 'SignOff'
$logFile        = Join-Path $reportsDir "ADCS-Rollback-$datestamp.log"
$rollbackReport = Join-Path $reportsDir "ADCS-Rollback-$datestamp.json"
$signOffIn      = Join-Path $signOffDir 'Phase2-SignOff.json'

foreach ($dir in @($reportsDir, $signOffDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Start-Transcript -Path $logFile -Append | Out-Null

. (Join-Path $scriptDir 'lib\Write-MigrationLog.ps1')
. (Join-Path $scriptDir 'lib\Invoke-LocalOrRemote.ps1')

Write-MigrationBanner -Title '*** ADCS ROLLBACK — Reversing Phase 2 Migration ***' -LogPath $logFile
if ($WhatIfPreference) {
    Write-MigrationLog 'WHATIF MODE — No changes will be made.' -Level WHATIF -LogPath $logFile
}
Write-MigrationLog "Rollback reason: $Reason" -Level WARN -LogPath $logFile
Write-MigrationLog "Initiated by: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Level INFO -LogPath $logFile
#endregion

#region --- Pre-rollback checks ---
Write-MigrationBanner -Title 'Pre-Rollback Checks' -LogPath $logFile

# 1. Warn if Phase 2 was already Approved (rolling back after approval is unusual)
$phase2SignOff = Read-SignOffFile -Path $signOffIn
if ($null -eq $phase2SignOff) {
    Write-MigrationLog "Phase 2 sign-off file not found at '$signOffIn'. Rollback may be premature — Phase 2 may not have completed. Proceeding anyway." -Level WARN -LogPath $logFile
} elseif ($phase2SignOff.Status -eq 'Approved') {
    Write-MigrationLog "WARNING: Phase 2 sign-off is 'Approved'. You are rolling back a signed-off migration. Ensure this is intentional." -Level WARN -LogPath $logFile
} else {
    Write-MigrationLog "Phase 2 sign-off status: $($phase2SignOff.Status). Proceeding with rollback." -Level INFO -LogPath $logFile
}

# 2. Confirm DC01-VM is still a domain controller (Phase 3 not run)
Write-MigrationLog "Confirming DC01-VM ($DC01Server) is still a domain controller..." -Level CHECK -LogPath $logFile
try {
    $dc01IsStillDC = $null -ne (Get-ADDomainController -Identity $DC01Server -ErrorAction Stop)
    Write-MigrationLog "$DC01Server is confirmed as a domain controller — rollback is feasible." -Level SUCCESS -LogPath $logFile
} catch {
    throw "HARD STOP: $DC01Server is not (or is no longer) a domain controller. If Phase 3 has already run, this rollback script cannot restore the environment — manual AD DS procedures are required."
}

# 3. Check CertSvc state on DC01-VM
Write-MigrationLog "Checking CertSvc on $DC01Server..." -Level CHECK -LogPath $logFile
$dc01SvcStatus = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
    $svc = Get-Service CertSvc -ErrorAction SilentlyContinue
    return if ($svc) { @{ Exists = $true; Status = $svc.Status.ToString(); StartType = $svc.StartType.ToString() } } else { @{ Exists = $false; Status = 'NotFound'; StartType = 'N/A' } }
}
if (-not $dc01SvcStatus.Exists) {
    throw "HARD STOP: CertSvc does not exist on $DC01Server. The ADCS role may have been uninstalled (Phase 3 partial run?). Cannot roll back automatically."
}
if ($dc01SvcStatus.Status -eq 'Running') {
    Write-MigrationLog "CertSvc is already Running on $DC01Server — no restart needed." -Level INFO -LogPath $logFile
} else {
    Write-MigrationLog "CertSvc on $DC01Server: $($dc01SvcStatus.Status) / $($dc01SvcStatus.StartType) — will re-enable." -Level INFO -LogPath $logFile
}

# 4. Check CertSvc state on DC03-VM
Write-MigrationLog "Checking CertSvc on $DC03Server..." -Level CHECK -LogPath $logFile
try {
    $dc03SvcStatus = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
        $svc = Get-Service CertSvc -ErrorAction SilentlyContinue
        return if ($svc) { @{ Exists = $true; Status = $svc.Status.ToString() } } else { @{ Exists = $false; Status = 'NotFound' } }
    }
    Write-MigrationLog "CertSvc on $DC03Server: $($dc03SvcStatus.Status)" -Level INFO -LogPath $logFile
} catch {
    $dc03SvcStatus = @{ Exists = $false; Status = 'Unreachable' }
    Write-MigrationLog "Could not reach $DC03Server — will skip DC03-VM steps: $_" -Level WARN -LogPath $logFile
}

Write-MigrationLog 'Pre-rollback checks complete.' -Level SUCCESS -LogPath $logFile
#endregion

# Result tracking
$RollbackResult = [ordered]@{
    StartedAt  = (Get-Date -Format 'o')
    DC01Server = $DC01Server
    DC03Server = $DC03Server
    Reason     = $Reason
    WhatIf     = [bool]$WhatIfPreference
    Steps      = [ordered]@{}
    Errors     = @()
    CompletedAt= ''
}

function Set-StepResult {
    param([string]$Step, [string]$Status, [string]$Detail)
    $RollbackResult.Steps[$Step] = [ordered]@{ Status = $Status; Detail = $Detail; At = (Get-Date -Format 'o') }
    $level = if ($Status -eq 'Success') { 'SUCCESS' } elseif ($Status -eq 'Skipped') { 'WHATIF' } else { 'ERROR' }
    Write-MigrationLog "[$Status] $Step — $Detail" -Level $level -LogPath $logFile
}

#region --- STEP 1: Re-enable CertSvc on DC01-VM ---
Write-MigrationBanner -Title 'Step 1: Re-enable CA Service on DC01-VM' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC01Server, 'Set CertSvc to Automatic start and start the service')) {
        if ($dc01SvcStatus.Status -eq 'Running') {
            Set-StepResult -Step 'Re-enable CA (DC01)' -Status 'Success' -Detail "CertSvc was already Running on $DC01Server — no action needed."
        } else {
            Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
                Set-Service -Name CertSvc -StartupType Automatic -ErrorAction Stop
                Start-Service -Name CertSvc -ErrorAction Stop
            }
            Set-StepResult -Step 'Re-enable CA (DC01)' -Status 'Success' -Detail "CertSvc set to Automatic and started on $DC01Server."
        }
    } else {
        Set-StepResult -Step 'Re-enable CA (DC01)' -Status 'Skipped' -Detail "WhatIf: Would set CertSvc to Automatic and start it on $DC01Server"
    }
} catch {
    $RollbackResult.Errors += "Step 1 (Re-enable CA): $_"
    Set-StepResult -Step 'Re-enable CA (DC01)' -Status 'Failed' -Detail "$_"
    throw "Step 1 failed — cannot continue rollback: $_"
}
#endregion

#region --- STEP 2: Verify CA Health on DC01-VM ---
Write-MigrationBanner -Title 'Step 2: Verify CA Health on DC01-VM' -LogPath $logFile
try {
    Start-Sleep -Seconds 5  # Allow service to fully initialise
    $health = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $svcStatus = (Get-Service CertSvc).Status.ToString()
        $pingOut   = & certutil -ping 2>&1
        $pingOK    = ($pingOut | Select-String 'connect').Count -gt 0 -or $LASTEXITCODE -eq 0
        return @{ SvcStatus = $svcStatus; PingOK = $pingOK; PingOutput = $pingOut -join "`n" }
    }

    if ($health.SvcStatus -eq 'Running' -and $health.PingOK) {
        Set-StepResult -Step 'CA Health (DC01)' -Status 'Success' -Detail "CertSvc Running and ping successful on $DC01Server — CA is operational."
    } else {
        Set-StepResult -Step 'CA Health (DC01)' -Status 'Failed' -Detail "CertSvc: $($health.SvcStatus) | Ping: $($health.PingOK). Investigate DC01-VM CA before relying on it."
        Write-MigrationLog "CA health check failed on $DC01Server — do NOT stop DC03-VM CA until DC01-VM is confirmed healthy." -Level ERROR -LogPath $logFile
    }
} catch {
    $RollbackResult.Errors += "Step 2 (Health DC01): $_"
    Set-StepResult -Step 'CA Health (DC01)' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Health check error on $DC01Server: $_" -Level ERROR -LogPath $logFile
}
#endregion

#region --- STEP 3: Publish CRL from DC01-VM ---
Write-MigrationBanner -Title 'Step 3: Publish New CRL from DC01-VM' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC01Server, 'Publish new CRL (certutil -CRL)')) {
        $crlOut = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
            $out = & certutil -CRL 2>&1
            if ($LASTEXITCODE -ne 0) { throw "certutil -CRL failed (exit $LASTEXITCODE): $($out -join '; ')" }
            return $out -join "`n"
        }
        Set-StepResult -Step 'CRL Publication (DC01)' -Status 'Success' -Detail "New CRL published from $DC01Server."
    } else {
        Set-StepResult -Step 'CRL Publication (DC01)' -Status 'Skipped' -Detail "WhatIf: Would publish new CRL from $DC01Server"
    }
} catch {
    $RollbackResult.Errors += "Step 3 (CRL DC01): $_"
    Set-StepResult -Step 'CRL Publication (DC01)' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "CRL publication failed on $DC01Server: $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 4: Stop and Disable CertSvc on DC03-VM ---
Write-MigrationBanner -Title 'Step 4: Stop CA Service on DC03-VM' -LogPath $logFile
try {
    if ($dc03SvcStatus.Status -eq 'Unreachable') {
        Set-StepResult -Step 'Stop CA (DC03)' -Status 'Skipped' -Detail "$DC03Server was unreachable — verify CertSvc is stopped manually."
    } elseif (-not $dc03SvcStatus.Exists -or $dc03SvcStatus.Status -eq 'Stopped') {
        Set-StepResult -Step 'Stop CA (DC03)' -Status 'Success' -Detail "CertSvc already stopped or not present on $DC03Server — no action needed."
    } elseif ($PSCmdlet.ShouldProcess($DC03Server, 'Stop and disable CertSvc')) {
        Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
            Stop-Service  -Name CertSvc -Force -ErrorAction Stop
            Set-Service   -Name CertSvc -StartupType Disabled -ErrorAction Stop
        }
        Set-StepResult -Step 'Stop CA (DC03)' -Status 'Success' -Detail "CertSvc stopped and disabled on $DC03Server."
    } else {
        Set-StepResult -Step 'Stop CA (DC03)' -Status 'Skipped' -Detail "WhatIf: Would stop and disable CertSvc on $DC03Server"
    }
} catch {
    $RollbackResult.Errors += "Step 4 (Stop DC03 CA): $_"
    Set-StepResult -Step 'Stop CA (DC03)' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Could not stop CertSvc on $DC03Server: $_ — stop it manually to avoid dual-CA conflicts." -Level ERROR -LogPath $logFile
}
#endregion

#region --- Save rollback report ---
$RollbackResult.CompletedAt = Get-Date -Format 'o'
$RollbackResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $rollbackReport -Encoding UTF8
Write-MigrationLog "Rollback report saved: $rollbackReport" -Level INFO -LogPath $logFile
#endregion

#region --- Console summary ---
Write-MigrationBanner -Title 'Rollback Complete' -LogPath $logFile
Write-Host "`nRollback Step Results:" -ForegroundColor White
$RollbackResult.Steps.GetEnumerator() | ForEach-Object {
    $col = switch ($_.Value.Status) { 'Success' { 'Green' } 'Skipped' { 'Magenta' } default { 'Red' } }
    Write-Host "  [$($_.Value.Status)] $($_.Key)" -ForegroundColor $col
}

if ($RollbackResult.Errors.Count -gt 0) {
    Write-Host "`nErrors during rollback:" -ForegroundColor Red
    $RollbackResult.Errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

if ($WhatIfPreference) {
    Write-Host "`nWHATIF run complete — no changes were made. Remove -WhatIf to execute." -ForegroundColor Magenta
} else {
    Write-Host "`nPost-rollback verification checklist:" -ForegroundColor White
    Write-Host "  [ ] certutil -ping $DC01Server confirms CA is responding" -ForegroundColor Cyan
    Write-Host "  [ ] Web enrollment accessible at http://$DC01Server/certsrv (ESC8 will be present again — remediate after investigation)" -ForegroundColor Yellow
    Write-Host "  [ ] CertSvc is NOT running on $DC03Server" -ForegroundColor Cyan
    Write-Host "  [ ] Test certificate issuance from a client machine" -ForegroundColor Cyan
    Write-Host "  [ ] Update Phase 2 sign-off notes to document rollback reason" -ForegroundColor Yellow
    Write-Host "`n  Report: $rollbackReport" -ForegroundColor Green
    Write-Host "  NOTE: ADCS role may still be installed on $DC03Server. Uninstall it manually if DC03-VM will be repurposed." -ForegroundColor Yellow
}
#endregion

Stop-Transcript | Out-Null
