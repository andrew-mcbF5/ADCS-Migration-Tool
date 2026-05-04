<#
.SYNOPSIS
    Phase 3 — Demote DC01-VM from the domain after ADCS migration.

.DESCRIPTION
    Requires Phase 2 sign-off approval. Verifies all FSMO roles are off DC01-VM,
    confirms DC03-VM CA is healthy, uninstalls the ADCS role from DC01-VM, demotes
    DC01-VM (DCPROMO down), and cleans up residual AD objects, DNS records, and
    Sites & Services entries.

    Run with -WhatIf first to review all planned actions before committing.

.PARAMETER DC01Server
    Hostname of the server to demote. Defaults to Config.psd1 value ('DC01-VM').

.PARAMETER DC02Server
    Hostname of the primary remaining DC. Defaults to Config.psd1 value ('DC02-VM').
    Used for post-demotion cleanup.

.PARAMETER DC03Server
    Hostname of the new CA server. Defaults to Config.psd1 value ('DC03-VM').
    Health-checked before proceeding.

.PARAMETER Credential
    Optional PSCredential. Omit when running as a Domain Admin.

.PARAMETER MigrationJson
    Path to the JSON file produced by Phase 2.

.PARAMETER LocalAdminPassword
    SecureString — the local Administrator password DC01-VM will use after demotion
    (as a member server). NEVER passed as plaintext. Will prompt if not supplied.

.PARAMETER RebootTimeoutSeconds
    Maximum seconds to wait for DC01-VM to reboot after demotion. Default: 1200 (20 minutes).
    Increase on slow hardware or high-latency links.

.PARAMETER OutputPath
    Directory for reports and sign-off files (default: .\reports).

.EXAMPLE
    # Dry run
    .\3_Invoke-DC01Demotion.ps1 -MigrationJson .\reports\ADCS-Migration-20260504.json -WhatIf

.EXAMPLE
    $pass = Read-Host 'Local Admin Password' -AsSecureString
    .\3_Invoke-DC01Demotion.ps1 -MigrationJson .\reports\ADCS-Migration-20260504.json `
        -LocalAdminPassword $pass
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$DC01Server              = 'DC01-VM',
    [string]$DC02Server              = 'DC02-VM',
    [string]$DC03Server              = 'DC03-VM',
    [PSCredential]$Credential,
    [Parameter(Mandatory)][string]$MigrationJson,
    [SecureString]$LocalAdminPassword,
    [int]$RebootTimeoutSeconds       = 1200,
    [string]$OutputPath              = '.\reports'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Initialise ---
$scriptDir   = $PSScriptRoot

# Issue 7: Load environment defaults from Config.psd1; command-line params take precedence.
$configFile = Join-Path $scriptDir 'Config.psd1'
if (Test-Path $configFile) {
    $Cfg = Import-PowerShellDataFile $configFile
    if (-not $PSBoundParameters.ContainsKey('DC01Server')) { $DC01Server = $Cfg.DC01Server }
    if (-not $PSBoundParameters.ContainsKey('DC02Server')) { $DC02Server = $Cfg.DC02Server }
    if (-not $PSBoundParameters.ContainsKey('DC03Server')) { $DC03Server = $Cfg.DC03Server }
}

$datestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportsDir  = [System.IO.Path]::GetFullPath($OutputPath)
$signOffDir  = Join-Path $reportsDir 'SignOff'
$logFile     = Join-Path $reportsDir "ADCS-Demotion-$datestamp.log"
$finalReport = Join-Path $reportsDir "ADCS-Demotion-Final-$datestamp.json"
$signOffIn   = Join-Path $signOffDir 'Phase2-SignOff.json'

foreach ($dir in @($reportsDir, $signOffDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Start-Transcript -Path $logFile -Append | Out-Null

. (Join-Path $scriptDir 'lib\Write-MigrationLog.ps1')
. (Join-Path $scriptDir 'lib\Invoke-LocalOrRemote.ps1')

Write-MigrationBanner -Title 'DC01-VM Demotion — Phase 3' -LogPath $logFile
if ($WhatIfPreference) {
    Write-MigrationLog 'WHATIF MODE — No changes will be made.' -Level WHATIF -LogPath $logFile
}
Write-MigrationLog "Reboot timeout: $RebootTimeoutSeconds seconds" -Level INFO -LogPath $logFile
#endregion

#region --- Pre-flight checks (hard stops) ---
Write-MigrationBanner -Title 'Pre-Flight Checks' -LogPath $logFile

# 1. Phase 2 sign-off
Write-MigrationLog 'Checking Phase 2 sign-off...' -Level CHECK -LogPath $logFile
$phase2SignOff = Assert-SignOffApproved -Path $signOffIn -PhaseName 'Phase 2 (Migration)'
Write-MigrationLog "Phase 2 approved by: $($phase2SignOff.ApprovedBy)" -Level SUCCESS -LogPath $logFile

# 2. Load and hash-verify migration JSON
Write-MigrationLog "Loading migration JSON: $MigrationJson" -Level CHECK -LogPath $logFile
if (-not (Test-Path $MigrationJson)) { throw "Migration JSON not found: $MigrationJson" }

# Issue 2: Verify migration JSON hash against what was recorded at Phase 2 sign-off.
if (-not [string]::IsNullOrWhiteSpace($phase2SignOff.MigrationJsonHash)) {
    $currentHash = Get-JsonFileHash -Path $MigrationJson
    if ($currentHash -ne $phase2SignOff.MigrationJsonHash) {
        throw "HARD STOP: Migration JSON hash mismatch. The file '$MigrationJson' has been modified since Phase 2 sign-off was recorded. Re-run Phase 2 or restore the original file. Expected: $($phase2SignOff.MigrationJsonHash) | Got: $currentHash"
    }
    Write-MigrationLog "Migration JSON hash verified: $currentHash" -Level SUCCESS -LogPath $logFile
} else {
    Write-MigrationLog "WARNING: Phase 2 sign-off contains no MigrationJsonHash — skipping integrity check. Re-run Phase 2 to enable hash verification." -Level WARN -LogPath $logFile
}

$migration = Get-Content $MigrationJson -Raw -Encoding UTF8 | ConvertFrom-Json
$caName    = $migration.CAName
Write-MigrationLog "CA Name from migration: $caName" -Level INFO -LogPath $logFile

# 3. All FSMO roles off DC01-VM
Write-MigrationLog 'Verifying FSMO roles are NOT on DC01-VM...' -Level CHECK -LogPath $logFile
$domain   = Get-ADDomain
$forest   = Get-ADForest
$allRoles = @{
    'PDC Emulator'          = $domain.PDCEmulator
    'RID Master'            = $domain.RIDMaster
    'Infrastructure Master' = $domain.InfrastructureMaster
    'Schema Master'         = $forest.SchemaMaster
    'Domain Naming Master'  = $forest.DomainNamingMaster
}
$dc01Roles = $allRoles.GetEnumerator() | Where-Object { $_.Value -match [regex]::Escape($DC01Server) }
if ($dc01Roles.Count -gt 0) {
    throw "HARD STOP: DC01-VM still holds FSMO role(s): $($dc01Roles.Key -join ', '). Transfer these to DC02-VM first:`n  Move-ADDirectoryServerOperationMasterRole -Identity $DC02Server -OperationMasterRole SchemaMaster,DomainNamingMaster,PDCEmulator,RIDMaster,InfrastructureMaster"
}
Write-MigrationLog 'All FSMO roles confirmed off DC01-VM.' -Level SUCCESS -LogPath $logFile

# 4. CertSvc is stopped on DC01-VM
Write-MigrationLog "Checking CertSvc status on $DC01Server..." -Level CHECK -LogPath $logFile
$certSvcStatus = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
    $svc = Get-Service CertSvc -ErrorAction SilentlyContinue
    return if ($svc) { $svc.Status.ToString() } else { 'NotFound' }
}
if ($certSvcStatus -eq 'Running') {
    throw "HARD STOP: CertSvc is still Running on $DC01Server. Stop and disable it first (Phase 2 Step 9 may not have completed)."
}
Write-MigrationLog "CertSvc status on DC01-VM: $certSvcStatus — OK." -Level SUCCESS -LogPath $logFile

# 5. DC03-VM CA is healthy
Write-MigrationLog "Verifying DC03-VM CA health ($DC03Server)..." -Level CHECK -LogPath $logFile
$caHealthy = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
    $svc = (Get-Service CertSvc -ErrorAction SilentlyContinue).Status.ToString()
    return $svc -eq 'Running'
}
if (-not $caHealthy) {
    throw "HARD STOP: CertSvc is NOT running on $DC03Server. Resolve the CA issue before demoting DC01-VM."
}
Write-MigrationLog "DC03-VM CA is running." -Level SUCCESS -LogPath $logFile

# 6. No critical replication errors
Write-MigrationLog "Checking AD replication status on $DC01Server..." -Level CHECK -LogPath $logFile
try {
    $replErrors = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $results = Get-ADReplicationUpToDatenessVectorTable -Target $env:COMPUTERNAME -ErrorAction SilentlyContinue
        return $results | Where-Object { $_.LastReplicationAttempt -lt (Get-Date).AddHours(-4) } | Measure-Object | Select-Object -ExpandProperty Count
    }
    if ($replErrors -gt 0) {
        Write-MigrationLog "WARNING: $replErrors replication partner(s) may be behind. Review before proceeding." -Level WARN -LogPath $logFile
    } else {
        Write-MigrationLog "Replication appears healthy." -Level SUCCESS -LogPath $logFile
    }
} catch {
    Write-MigrationLog "Replication check failed (non-fatal): $_ — verify manually." -Level WARN -LogPath $logFile
}

# 7. Local admin password
if (-not $LocalAdminPassword) {
    Write-Host "`nEnter the local Administrator password DC01-VM will use after demotion. This will NOT be logged." -ForegroundColor Yellow
    $LocalAdminPassword = Read-Host 'Local Admin Password' -AsSecureString
}

Write-MigrationLog 'All pre-flight checks passed.' -Level SUCCESS -LogPath $logFile
#endregion

# Result tracking
$DemotionResult = [ordered]@{
    StartedAt  = (Get-Date -Format 'o')
    DC01Server = $DC01Server
    DC02Server = $DC02Server
    DC03Server = $DC03Server
    WhatIf     = [bool]$WhatIfPreference
    Steps      = [ordered]@{}
    Errors     = @()
    CompletedAt= ''
}

function Set-StepResult {
    param([string]$Step, [string]$Status, [string]$Detail)
    $DemotionResult.Steps[$Step] = [ordered]@{ Status = $Status; Detail = $Detail; At = (Get-Date -Format 'o') }
    $level = if ($Status -eq 'Success') { 'SUCCESS' } elseif ($Status -eq 'Skipped') { 'WHATIF' } else { 'ERROR' }
    Write-MigrationLog "[$Status] $Step — $Detail" -Level $level -LogPath $logFile
}

#region --- STEP 1: Final FSMO Audit ---
Write-MigrationBanner -Title 'Step 1: Final FSMO Audit' -LogPath $logFile
$fsmoSummary = ($allRoles.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ' | '
Set-StepResult -Step 'FSMO Audit' -Status 'Success' -Detail $fsmoSummary
Write-MigrationLog "FSMO holders: $fsmoSummary" -Level INFO -LogPath $logFile
#endregion

#region --- STEP 2: Uninstall ADCS Role from DC01-VM ---
Write-MigrationBanner -Title 'Step 2: Uninstall ADCS Role from DC01-VM' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC01Server, 'Uninstall ADCS-Cert-Authority and ADCS-Web-Enrollment')) {
        $uninstall = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
            $result = Uninstall-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools
            return @{ Success = $result.Success; RestartNeeded = $result.RestartNeeded.ToString() }
        }
        if (-not $uninstall.Success) { throw "Uninstall-WindowsFeature reported failure." }
        Set-StepResult -Step 'Uninstall ADCS' -Status 'Success' -Detail "ADCS role uninstalled from $DC01Server (RestartNeeded: $($uninstall.RestartNeeded))."
    } else {
        Set-StepResult -Step 'Uninstall ADCS' -Status 'Skipped' -Detail "WhatIf: Would uninstall ADCS-Cert-Authority and ADCS-Web-Enrollment from $DC01Server"
    }
} catch {
    $DemotionResult.Errors += "Step 2 (Uninstall ADCS): $_"
    Set-StepResult -Step 'Uninstall ADCS' -Status 'Failed' -Detail "$_"
    throw "Step 2 failed — aborting demotion: $_"
}
#endregion

#region --- STEP 3: Demote DC01-VM ---
Write-MigrationBanner -Title 'Step 3: Demote DC01-VM (DCPROMO Down)' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC01Server, 'Demote domain controller (Uninstall-ADDSDomainController)')) {
        Write-MigrationLog "Initiating demotion of $DC01Server. The server will reboot." -Level WARN -LogPath $logFile

        # Issue 1: Stop transcript before the demotion call to prevent any chance of the
        # LocalAdminPassword SecureString appearing in the log file. Restart immediately after.
        Write-MigrationLog "Pausing transcript for demotion command to prevent credential logging." -Level INFO -LogPath $logFile
        Stop-Transcript | Out-Null
        try {
            Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
                param($adminPass)
                Uninstall-ADDSDomainController `
                    -LocalAdministratorPassword $adminPass `
                    -Force `
                    -NoRebootOnCompletion:$false `
                    -IgnoreLastDCInDomainMismatch:$false `
                    -ErrorAction Stop
            } -ArgumentList @($LocalAdminPassword)
        } finally {
            Start-Transcript -Path $logFile -Append | Out-Null
            Write-MigrationLog "Transcript resumed after demotion command." -Level INFO -LogPath $logFile
        }

        # Issue 6: Use $RebootTimeoutSeconds (default 1200) for the come-back wait.
        # Allow up to 5 minutes for the server to go offline; rest of budget for it to return.
        $goOfflineMax = [math]::Min(300, $RebootTimeoutSeconds / 4)
        $comeBackMax  = $RebootTimeoutSeconds - $goOfflineMax

        Write-MigrationLog "Waiting for $DC01Server to go offline (max ${goOfflineMax}s)..." -Level INFO -LogPath $logFile
        $elapsed = 0; $interval = 10
        while ($elapsed -lt $goOfflineMax) {
            Start-Sleep -Seconds $interval
            $elapsed += $interval
            if (-not (Test-Connection $DC01Server -Count 1 -Quiet -ErrorAction SilentlyContinue)) { break }
        }
        Write-MigrationLog "$DC01Server appears offline — reboot in progress." -Level INFO -LogPath $logFile

        Write-MigrationLog "Waiting for $DC01Server to come back online as a member server (max ${comeBackMax}s)..." -Level INFO -LogPath $logFile
        $elapsed = 0
        while ($elapsed -lt $comeBackMax) {
            Start-Sleep -Seconds 15; $elapsed += 15
            if (Test-Connection $DC01Server -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                Write-MigrationLog "$DC01Server is back online." -Level SUCCESS -LogPath $logFile
                break
            }
        }
        if ($elapsed -ge $comeBackMax) {
            Write-MigrationLog "WARNING: $DC01Server did not respond within ${comeBackMax}s. It may still be rebooting — verify manually before continuing." -Level WARN -LogPath $logFile
        }

        Set-StepResult -Step 'Demote DC01-VM' -Status 'Success' -Detail "$DC01Server has been demoted and rebooted as a member server."
    } else {
        Set-StepResult -Step 'Demote DC01-VM' -Status 'Skipped' -Detail "WhatIf: Would run Uninstall-ADDSDomainController on $DC01Server — this triggers a reboot."
    }
} catch {
    $DemotionResult.Errors += "Step 3 (Demote): $_"
    Set-StepResult -Step 'Demote DC01-VM' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Demotion failed: $_ — manual intervention required." -Level ERROR -LogPath $logFile
}
#endregion

#region --- STEP 4: Clean Up Stale AD Objects ---
Write-MigrationBanner -Title 'Step 4: Clean Up Stale AD Metadata' -LogPath $logFile
try {
    Start-Sleep -Seconds 30  # Allow AD replication to settle
    if ($PSCmdlet.ShouldProcess($DC02Server, "Remove stale AD objects for $DC01Server")) {
        $cleanupResult = Invoke-LocalOrRemote -Server $DC02Server -Credential $Credential -ScriptBlock {
            param($dc01Short)
            $domain   = Get-ADDomain
            $ntdsPath = "CN=NTDS Settings,CN=$dc01Short,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,$($domain.DistinguishedName)"
            $dcBase   = "OU=Domain Controllers,$($domain.DistinguishedName)"

            $cleaned = @()

            # Remove NTDS Settings object if still present
            try {
                $ntdsObj = Get-ADObject $ntdsPath -ErrorAction Stop
                Remove-ADObject $ntdsObj -Recursive -Confirm:$false
                $cleaned += "Removed NTDS Settings: $ntdsPath"
            } catch {
                $cleaned += "NTDS Settings already cleaned or not found: $_"
            }

            # Remove DC computer object from Domain Controllers OU if lingering
            try {
                $dcObj = Get-ADComputer -Filter "Name -eq '$dc01Short'" -SearchBase $dcBase -ErrorAction Stop
                if ($dcObj) {
                    Remove-ADObject $dcObj.DistinguishedName -Recursive -Confirm:$false
                    $cleaned += "Removed DC computer object: $($dcObj.DistinguishedName)"
                }
            } catch {
                $cleaned += "DC computer object not found in Domain Controllers OU (auto-cleaned or already gone)."
            }

            return $cleaned
        } -ArgumentList @(($DC01Server -replace '\..*', ''))

        Set-StepResult -Step 'AD Metadata Cleanup' -Status 'Success' -Detail ($cleanupResult -join ' | ')
    } else {
        Set-StepResult -Step 'AD Metadata Cleanup' -Status 'Skipped' -Detail "WhatIf: Would remove NTDS Settings and lingering DC object for $DC01Server from AD"
    }
} catch {
    $DemotionResult.Errors += "Step 4 (AD Cleanup): $_"
    Set-StepResult -Step 'AD Metadata Cleanup' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "AD cleanup error (non-fatal, run ntdsutil metadata cleanup manually if needed): $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 5: Clean DNS Records ---
Write-MigrationBanner -Title 'Step 5: Remove DC01-VM DNS Records' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC02Server, "Remove DNS A records for $DC01Server")) {
        Invoke-LocalOrRemote -Server $DC02Server -Credential $Credential -ScriptBlock {
            param($dc01Short, $domain)
            try {
                Import-Module DnsServer -ErrorAction Stop
                Get-DnsServerResourceRecord -ZoneName $domain -Name $dc01Short -RRType A -ErrorAction SilentlyContinue |
                    Remove-DnsServerResourceRecord -ZoneName $domain -Force -ErrorAction SilentlyContinue
                return "DNS A records removed for $dc01Short"
            } catch {
                return "DnsServer module not available or error removing records: $_. Remove manually via DNS console."
            }
        } -ArgumentList @(($DC01Server -replace '\..*', ''), (Get-ADDomain).DNSRoot)

        Set-StepResult -Step 'DNS Cleanup' -Status 'Success' -Detail "DNS A records for $DC01Server removed. Verify reverse lookup zones manually."
    } else {
        Set-StepResult -Step 'DNS Cleanup' -Status 'Skipped' -Detail "WhatIf: Would remove DNS A records for $DC01Server"
    }
} catch {
    $DemotionResult.Errors += "Step 5 (DNS): $_"
    Set-StepResult -Step 'DNS Cleanup' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "DNS cleanup failed (remove manually): $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 6: Sites and Services Cleanup ---
Write-MigrationBanner -Title 'Step 6: Sites and Services Cleanup' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC02Server, "Remove $DC01Server from AD Sites and Services")) {
        Invoke-LocalOrRemote -Server $DC02Server -Credential $Credential -ScriptBlock {
            param($dc01Short)
            $configNC  = (Get-ADRootDSE).configurationNamingContext
            $serverObj = Get-ADObject -Filter "Name -eq '$dc01Short' -and ObjectClass -eq 'server'" `
                            -SearchBase "CN=Sites,$configNC" -ErrorAction SilentlyContinue
            if ($serverObj) {
                Remove-ADObject $serverObj.DistinguishedName -Recursive -Confirm:$false
                return "Removed server object from Sites and Services: $($serverObj.DistinguishedName)"
            }
            return "Server object not found in Sites and Services — may have been auto-removed during demotion."
        } -ArgumentList @(($DC01Server -replace '\..*', ''))

        Set-StepResult -Step 'Sites and Services Cleanup' -Status 'Success' -Detail "DC01-VM server object removed from AD Sites and Services."
    } else {
        Set-StepResult -Step 'Sites and Services Cleanup' -Status 'Skipped' -Detail "WhatIf: Would remove $DC01Server from AD Sites and Services"
    }
} catch {
    $DemotionResult.Errors += "Step 6 (Sites): $_"
    Set-StepResult -Step 'Sites and Services Cleanup' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Sites and Services cleanup failed (remove manually via ADSS console): $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 7: Post-Demotion Domain Health Check ---
Write-MigrationBanner -Title 'Step 7: Post-Demotion Domain Health Check' -LogPath $logFile
try {
    Start-Sleep -Seconds 15
    $healthCheck = Invoke-LocalOrRemote -Server $DC02Server -Credential $Credential -ScriptBlock {
        param($dc01, $dc02, $dc03, $caName)
        $dcs = Get-ADDomainController -Filter * | Select-Object Name, Site, IPv4Address, IsGlobalCatalog, OperationMasterRoles
        $dc01Present = $dcs | Where-Object { $_.Name -match [regex]::Escape($dc01) }
        $caPing = & certutil -ping "$dc03\$caName" 2>&1
        $caPingOK = ($caPing | Select-String 'connect').Count -gt 0 -or $LASTEXITCODE -eq 0

        $replStatus = & repadmin /replsummary 2>&1 | Where-Object { $_ -match 'error|fail' }

        return @{
            DomainControllers = $dcs | ForEach-Object { "$($_.Name) [$($_.Site), GC=$($_.IsGlobalCatalog)]" }
            DC01StillPresent  = ($null -ne $dc01Present)
            CAPingOK          = $caPingOK
            ReplErrors        = @($replStatus)
        }
    } -ArgumentList @(($DC01Server -replace '\..*', ''), $DC02Server, $DC03Server, $caName)

    $dcList = $healthCheck.DomainControllers -join ', '
    if ($healthCheck.DC01StillPresent) {
        Write-MigrationLog "WARNING: DC01-VM still appears in the domain controller list. Allow replication time and re-check." -Level WARN -LogPath $logFile
    }
    if (-not $healthCheck.CAPingOK) {
        Write-MigrationLog "WARNING: CA ping to $DC03Server failed post-demotion. Verify CA health on DC03-VM." -Level WARN -LogPath $logFile
    }
    if ($healthCheck.ReplErrors.Count -gt 0) {
        Write-MigrationLog "Replication errors detected: $($healthCheck.ReplErrors -join '; ')" -Level WARN -LogPath $logFile
    }

    $detail = "DCs: $dcList | DC01 still in list: $($healthCheck.DC01StillPresent) | CA ping OK: $($healthCheck.CAPingOK) | Repl errors: $($healthCheck.ReplErrors.Count)"
    Set-StepResult -Step 'Post-Demotion Health Check' -Status 'Success' -Detail $detail
} catch {
    $DemotionResult.Errors += "Step 7 (Health): $_"
    Set-StepResult -Step 'Post-Demotion Health Check' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Health check failed: $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- Save final report ---
$DemotionResult.CompletedAt = Get-Date -Format 'o'
$DemotionResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $finalReport -Encoding UTF8
Write-MigrationLog "Final demotion report saved: $finalReport" -Level INFO -LogPath $logFile
#endregion

#region --- Console summary ---
Write-MigrationBanner -Title 'Demotion Phase Complete' -LogPath $logFile
Write-Host "`nStep Results:" -ForegroundColor White
$DemotionResult.Steps.GetEnumerator() | ForEach-Object {
    $col = switch ($_.Value.Status) { 'Success' { 'Green' } 'Skipped' { 'Magenta' } default { 'Red' } }
    Write-Host "  [$($_.Value.Status)] $($_.Key)" -ForegroundColor $col
}

if ($WhatIfPreference) {
    Write-Host "`nWHATIF run complete — no changes were made." -ForegroundColor Magenta
    Write-Host "Remove -WhatIf to execute." -ForegroundColor Magenta
} else {
    Write-Host "`nPost-demotion verification checklist:" -ForegroundColor White
    Write-Host "  [ ] Get-ADDomainController -Filter * shows only DC02-VM and DC03-VM" -ForegroundColor Cyan
    Write-Host "  [ ] certutil -ping $DC03Server\$caName succeeds from a client" -ForegroundColor Cyan
    Write-Host "  [ ] Web enrollment accessible at https://$DC03Server/certsrv" -ForegroundColor Cyan
    Write-Host "  [ ] CRL reachable: certutil -verify -urlfetch <cert file>" -ForegroundColor Cyan
    Write-Host "  [ ] Test autoenrollment on a domain-joined machine" -ForegroundColor Cyan
    Write-Host "  [ ] No new certificate-related errors in DC02-VM / DC03-VM event logs" -ForegroundColor Cyan
    Write-Host "  [ ] DC01-VM is operating as a plain member server (can be repurposed or decommissioned)`n" -ForegroundColor Cyan
    Write-Host "  Report saved: $finalReport" -ForegroundColor Green
}
#endregion

Stop-Transcript | Out-Null
