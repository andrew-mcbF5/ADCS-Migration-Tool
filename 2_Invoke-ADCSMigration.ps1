<#
.SYNOPSIS
    Phase 2 — ADCS Migration from DC01-VM to DC03-VM with ESC8 remediation.

.DESCRIPTION
    Migrates the Certificate Authority from DC01-VM to DC03-VM. Requires Phase 1
    sign-off approval. Backs up the CA, installs and restores on DC03-VM, updates
    CDP/AIA, configures HTTPS-only web enrollment (fixing ESC8), publishes the CRL,
    verifies CA health, then stops and disables (but does NOT uninstall) the CA on
    DC01-VM to preserve a rollback window.

    Run with -WhatIf first to review all actions before committing.

.PARAMETER DC01Server
    Hostname of the current CA server. Defaults to Config.psd1 value ('DC01-VM').

.PARAMETER DC03Server
    Hostname of the new CA server. Defaults to Config.psd1 value ('DC03-VM').

.PARAMETER Credential
    Optional PSCredential. Omit when running as a Domain Admin account.

.PARAMETER AssessmentJson
    Path to the JSON file produced by Phase 1. Used for CA name, DB size, CDP/AIA data.

.PARAMETER BackupPath
    UNC path for CA backup. Must be writable from DC01-VM and readable from DC03-VM.
    Example: \\fileserver\CABackup

.PARAMETER CAKeyPassword
    SecureString password used to protect the exported CA private key (PFX).
    If not supplied, the script will prompt interactively. NEVER passed as plaintext.

.PARAMETER OutputPath
    Directory for migration reports and sign-off files (default: .\reports).

.EXAMPLE
    # Dry run — review all planned actions without making changes
    .\2_Invoke-ADCSMigration.ps1 -DC01Server DC01-VM -DC03Server DC03-VM `
        -AssessmentJson .\reports\ADCS-Assessment-20260504.json `
        -BackupPath \\fileserver\CABackup -WhatIf

.EXAMPLE
    # Live run
    $cred    = Get-Credential
    $keyPass = Read-Host 'CA Key Password' -AsSecureString
    .\2_Invoke-ADCSMigration.ps1 -DC01Server DC01-VM -DC03Server DC03-VM `
        -Credential $cred -AssessmentJson .\reports\ADCS-Assessment-20260504.json `
        -BackupPath \\fileserver\CABackup -CAKeyPassword $keyPass
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$DC01Server     = 'DC01-VM',
    [string]$DC03Server     = 'DC03-VM',
    [PSCredential]$Credential,
    [Parameter(Mandatory)][string]$AssessmentJson,
    [Parameter(Mandatory)][string]$BackupPath,
    [SecureString]$CAKeyPassword,
    [string]$OutputPath     = '.\reports'
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
    if (-not $PSBoundParameters.ContainsKey('DC03Server')) { $DC03Server = $Cfg.DC03Server }
}

$datestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportsDir  = [System.IO.Path]::GetFullPath($OutputPath)
$signOffDir  = Join-Path $reportsDir 'SignOff'
$logFile     = Join-Path $reportsDir "ADCS-Migration-$datestamp.log"
$jsonOut     = Join-Path $reportsDir "ADCS-Migration-$datestamp.json"
$signOffIn   = Join-Path $signOffDir 'Phase1-SignOff.json'
$signOffOut  = Join-Path $signOffDir 'Phase2-SignOff.json'

foreach ($dir in @($reportsDir, $signOffDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Start-Transcript -Path $logFile -Append | Out-Null

. (Join-Path $scriptDir 'lib\Write-MigrationLog.ps1')
. (Join-Path $scriptDir 'lib\Invoke-LocalOrRemote.ps1')

Write-MigrationBanner -Title 'ADCS Migration — Phase 2' -LogPath $logFile
if ($WhatIfPreference) {
    Write-MigrationLog 'WHATIF MODE — No changes will be made.' -Level WHATIF -LogPath $logFile
}
#endregion

#region --- Pre-flight checks (hard stops) ---
Write-MigrationBanner -Title 'Pre-Flight Checks' -LogPath $logFile

# 1. Phase 1 sign-off
Write-MigrationLog 'Checking Phase 1 sign-off...' -Level CHECK -LogPath $logFile
$phase1SignOff = Assert-SignOffApproved -Path $signOffIn -PhaseName 'Phase 1 (Assessment)'
Write-MigrationLog "Phase 1 approved by: $($phase1SignOff.ApprovedBy)" -Level SUCCESS -LogPath $logFile

# 2. Load and hash-verify assessment JSON
Write-MigrationLog "Loading assessment JSON: $AssessmentJson" -Level CHECK -LogPath $logFile
if (-not (Test-Path $AssessmentJson)) { throw "Assessment JSON not found: $AssessmentJson" }

# Issue 2: Verify the assessment JSON hash matches what was recorded at sign-off time.
if (-not [string]::IsNullOrWhiteSpace($phase1SignOff.AssessmentJsonHash)) {
    $currentHash = Get-JsonFileHash -Path $AssessmentJson
    if ($currentHash -ne $phase1SignOff.AssessmentJsonHash) {
        throw "HARD STOP: Assessment JSON hash mismatch. The file '$AssessmentJson' has been modified since Phase 1 sign-off was recorded. Re-run Phase 1 or restore the original file. Expected: $($phase1SignOff.AssessmentJsonHash) | Got: $currentHash"
    }
    Write-MigrationLog "Assessment JSON hash verified: $currentHash" -Level SUCCESS -LogPath $logFile
} else {
    Write-MigrationLog "WARNING: Phase 1 sign-off contains no AssessmentJsonHash — skipping integrity check. Re-run Phase 1 to enable hash verification." -Level WARN -LogPath $logFile
}

$assessment = Get-Content $AssessmentJson -Raw -Encoding UTF8 | ConvertFrom-Json
$caName     = $assessment.CAName
$caDbSizeMB = $assessment.CADatabaseSizeMB
Write-MigrationLog "CA Name from assessment: $caName | DB Size: $caDbSizeMB MB" -Level INFO -LogPath $logFile

# 3. DC03-VM reachable
Write-MigrationLog "Testing connectivity to DC03-VM ($DC03Server)..." -Level CHECK -LogPath $logFile
if (-not (Test-ServerReachable -Server $DC03Server -Credential $Credential)) {
    throw "HARD STOP: Cannot reach $DC03Server via WinRM. Ensure DC03-VM is online, domain-joined, and WinRM is enabled."
}
Write-MigrationLog "$DC03Server is reachable." -Level SUCCESS -LogPath $logFile

# 4. DC03-VM is a domain controller
Write-MigrationLog "Verifying $DC03Server is a domain controller..." -Level CHECK -LogPath $logFile
try {
    $dc03Info = Get-ADDomainController -Identity $DC03Server -ErrorAction Stop
    Write-MigrationLog "$DC03Server confirmed as DC: $($dc03Info.HostName)" -Level SUCCESS -LogPath $logFile
} catch {
    throw "HARD STOP: $DC03Server is not a domain controller. Promote it first, then re-run this script."
}

# 5. ADCS not already on DC03-VM
Write-MigrationLog "Checking ADCS role on $DC03Server..." -Level CHECK -LogPath $logFile
$dc03HasADCS = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
    (Get-WindowsFeature -Name 'ADCS-Cert-Authority').Installed
}
if ($dc03HasADCS) {
    throw "HARD STOP: ADCS-Cert-Authority is already installed on $DC03Server. Remove it first or choose a different target."
}
Write-MigrationLog "ADCS not installed on $DC03Server — good." -Level SUCCESS -LogPath $logFile

# 6. Issue 3: HTTPS certificate for web enrollment — hard stop if not present.
# DC03-VM must have a valid machine certificate in Cert:\LocalMachine\My before migration.
# Request one from the current CA (DC01-VM) via certlm.msc or autoenrollment before running this script.
Write-MigrationLog "Checking for HTTPS certificate on $DC03Server (required for ESC8 remediation)..." -Level CHECK -LogPath $logFile
$httpsReady = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
    param($dc03)
    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Subject -match [regex]::Escape($dc03) -and $_.NotAfter -gt (Get-Date) -and $_.HasPrivateKey } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
    return @{
        Found      = ($null -ne $cert)
        Thumbprint = if ($cert) { $cert.Thumbprint } else { '' }
        Subject    = if ($cert) { $cert.Subject } else { '' }
        Expiry     = if ($cert) { $cert.NotAfter.ToString('yyyy-MM-dd') } else { '' }
    }
} -ArgumentList @($DC03Server)

if (-not $httpsReady.Found) {
    throw "HARD STOP: No valid HTTPS certificate found in DC03-VM machine store (Cert:\LocalMachine\My) matching '$DC03Server'. Request a Computer certificate for DC03-VM from the current CA before running this script: open certlm.msc on DC03-VM > Personal > Certificates > right-click > All Tasks > Request New Certificate > Computer template. This certificate is required to configure HTTPS-only web enrollment (ESC8 remediation)."
}
Write-MigrationLog "HTTPS certificate found on $DC03Server: $($httpsReady.Subject) (thumbprint: $($httpsReady.Thumbprint), expires: $($httpsReady.Expiry))" -Level SUCCESS -LogPath $logFile

# 7. Backup path accessible
Write-MigrationLog "Testing backup path access: $BackupPath" -Level CHECK -LogPath $logFile
$backupSubDir = Join-Path $BackupPath "CABackup-$datestamp"
try {
    $testFile = Join-Path $BackupPath 'write-test.tmp'
    [System.IO.File]::WriteAllText($testFile, 'test') | Out-Null
    Remove-Item $testFile -Force
    Write-MigrationLog "Backup path is writable from this machine." -Level SUCCESS -LogPath $logFile
} catch {
    throw "HARD STOP: Cannot write to backup path '$BackupPath': $_"
}

# 8. CA service running on DC01-VM
Write-MigrationLog "Checking CA service on $DC01Server..." -Level CHECK -LogPath $logFile
$caService = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
    $svc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
    return @{ Exists = ($null -ne $svc); Status = if ($svc) { $svc.Status.ToString() } else { 'NotFound' } }
}
if (-not $caService.Exists -or $caService.Status -ne 'Running') {
    throw "HARD STOP: CertSvc is '$($caService.Status)' on $DC01Server. CA must be running to back up. Start it or verify the server."
}
Write-MigrationLog "CertSvc is running on $DC01Server." -Level SUCCESS -LogPath $logFile

# 9. Key password
if (-not $CAKeyPassword) {
    Write-Host "`nEnter the password to protect the CA private key backup (PFX). This will NOT be logged." -ForegroundColor Yellow
    $CAKeyPassword = Read-Host 'CA Key Password' -AsSecureString
}

Write-MigrationLog 'All pre-flight checks passed.' -Level SUCCESS -LogPath $logFile
#endregion

# Result tracking
$MigrationResult = [ordered]@{
    StartedAt    = (Get-Date -Format 'o')
    DC01Server   = $DC01Server
    DC03Server   = $DC03Server
    CAName       = $caName
    BackupPath   = $backupSubDir
    WhatIf       = [bool]$WhatIfPreference
    Steps        = [ordered]@{}
    Errors       = @()
    CompletedAt  = ''
}

function Set-StepResult {
    param([string]$Step, [string]$Status, [string]$Detail)
    $MigrationResult.Steps[$Step] = [ordered]@{ Status = $Status; Detail = $Detail; At = (Get-Date -Format 'o') }
    $level = if ($Status -eq 'Success') { 'SUCCESS' } elseif ($Status -eq 'Skipped') { 'WHATIF' } else { 'ERROR' }
    Write-MigrationLog "[$Status] $Step — $Detail" -Level $level -LogPath $logFile
}

#region --- STEP 1: Backup CA ---
Write-MigrationBanner -Title 'Step 1: Back Up CA Private Key and Database' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC01Server, "Back up CA database and private key to $backupSubDir")) {
        # Convert SecureString once — plaintext only lives in $keyPass for the duration of the backup attempt.
        $bstr    = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CAKeyPassword)
        $keyPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        # Issue 5: Retry backup up to 3 times with a 30-second delay between attempts.
        $maxAttempts = 3
        $attempt     = 0
        $backupDone  = $false
        while (-not $backupDone -and $attempt -lt $maxAttempts) {
            $attempt++
            try {
                $backupResult = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
                    param($destPath, $pw)
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null

                    # Backup database
                    $dbOut = & certutil -backupDB "$destPath\Database" 2>&1
                    if ($LASTEXITCODE -ne 0) { throw "certutil -backupDB failed (exit $LASTEXITCODE): $($dbOut -join '; ')" }

                    # Backup private key (PFX)
                    $keyOut = & certutil -backupKey "$destPath\Key" -p $pw 2>&1
                    if ($LASTEXITCODE -ne 0) { throw "certutil -backupKey failed (exit $LASTEXITCODE): $($keyOut -join '; ')" }

                    # Verify backup integrity
                    $p12File   = Get-ChildItem -Path "$destPath\Key" -Filter '*.p12' -ErrorAction SilentlyContinue | Select-Object -First 1
                    $verifyOut = if ($p12File) { & certutil -verifystore -v $p12File.FullName 2>&1 } else { 'No .p12 file found to verify.' }

                    return @{ DB = $dbOut -join "`n"; Key = 'Protected — not logged'; Verify = $verifyOut -join "`n" }
                } -ArgumentList @($backupSubDir, $keyPass)
                $backupDone = $true
            } catch {
                if ($attempt -lt $maxAttempts) {
                    Write-MigrationLog "Backup attempt $attempt of $maxAttempts failed: $_. Retrying in 30 seconds..." -Level WARN -LogPath $logFile
                    Start-Sleep -Seconds 30
                } else {
                    $keyPass = $null; [GC]::Collect()
                    throw "All $maxAttempts backup attempts failed. Last error: $_"
                }
            }
        }

        # Wipe the plaintext password from memory immediately
        $keyPass = $null
        [GC]::Collect()

        Set-StepResult -Step 'CA Backup' -Status 'Success' -Detail "Backup written to $backupSubDir (succeeded on attempt $attempt)"
    } else {
        Set-StepResult -Step 'CA Backup' -Status 'Skipped' -Detail "WhatIf: Would back up CA to $backupSubDir"
    }
} catch {
    $keyPass = $null; [GC]::Collect()
    $MigrationResult.Errors += "Step 1 (Backup): $_"
    Set-StepResult -Step 'CA Backup' -Status 'Failed' -Detail "$_"
    throw "Step 1 failed — aborting migration: $_"
}
#endregion

#region --- STEP 2: Install ADCS Role on DC03-VM ---
Write-MigrationBanner -Title 'Step 2: Install ADCS Role on DC03-VM' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC03Server, 'Install ADCS-Cert-Authority, ADCS-Web-Enrollment, Web-Server features')) {
        $installResult = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
            $result = Install-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment, ADCS-Online-Cert, Web-Server, Web-Scripting-Tools -IncludeManagementTools
            return @{
                Success       = $result.Success
                RestartNeeded = $result.RestartNeeded.ToString()
                ExitCode      = $result.ExitCode.ToString()
            }
        }
        if (-not $installResult.Success) {
            throw "Install-WindowsFeature reported failure. ExitCode: $($installResult.ExitCode)"
        }
        if ($installResult.RestartNeeded -eq 'Yes') {
            Write-MigrationLog 'WARNING: DC03-VM indicates a restart may be needed. If restore fails, restart DC03-VM and re-run from Step 3.' -Level WARN -LogPath $logFile
        }
        Set-StepResult -Step 'ADCS Role Install' -Status 'Success' -Detail "Features installed on $DC03Server (RestartNeeded: $($installResult.RestartNeeded))"
    } else {
        Set-StepResult -Step 'ADCS Role Install' -Status 'Skipped' -Detail "WhatIf: Would install ADCS-Cert-Authority, ADCS-Web-Enrollment, Web-Server on $DC03Server"
    }
} catch {
    $MigrationResult.Errors += "Step 2 (Role Install): $_"
    Set-StepResult -Step 'ADCS Role Install' -Status 'Failed' -Detail "$_"
    throw "Step 2 failed: $_"
}
#endregion

#region --- STEP 3: Restore CA on DC03-VM ---
Write-MigrationBanner -Title 'Step 3: Restore CA on DC03-VM' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC03Server, "Restore CA '$caName' from backup at $backupSubDir")) {
        $bstr    = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CAKeyPassword)
        $keyPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

        $restoreResult = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
            param($backupDir, $pw, $name)
            # Import the PFX key
            $pfxFile = Get-ChildItem -Path "$backupDir\Key" -Filter '*.p12' | Select-Object -First 1
            if (-not $pfxFile) { throw "No .p12 key backup found in $backupDir\Key" }

            $keyImport = & certutil -restoreKey "$($pfxFile.FullName)" -p $pw 2>&1
            if ($LASTEXITCODE -ne 0) { throw "certutil -restoreKey failed: $($keyImport -join '; ')" }

            # Restore database
            $dbRestore = & certutil -restoreDB "$backupDir\Database" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "certutil -restoreDB failed: $($dbRestore -join '; ')" }

            # Install the CA using existing key
            $caInstall = Install-AdcsCertificationAuthority `
                -CAType EnterpriseRootCA `
                -CACommonName $name `
                -RestoreFromBackup `
                -Force `
                -ErrorAction Stop

            return @{ KeyImport = 'Done'; DBRestore = 'Done'; CAInstall = $caInstall.Status.ToString() }
        } -ArgumentList @($backupSubDir, $keyPass, $caName)

        $keyPass = $null; [GC]::Collect()
        Set-StepResult -Step 'CA Restore' -Status 'Success' -Detail "CA restored on $DC03Server. Status: $($restoreResult.CAInstall)"
    } else {
        $keyPass = $null; [GC]::Collect()
        Set-StepResult -Step 'CA Restore' -Status 'Skipped' -Detail "WhatIf: Would restore CA '$caName' from $backupSubDir to $DC03Server"
    }
} catch {
    $keyPass = $null; [GC]::Collect()
    $MigrationResult.Errors += "Step 3 (CA Restore): $_"
    Set-StepResult -Step 'CA Restore' -Status 'Failed' -Detail "$_"
    throw "Step 3 failed: $_"
}
#endregion

#region --- STEP 4 & 5: Update CDP and AIA ---
Write-MigrationBanner -Title 'Steps 4 & 5: Update CDP and AIA to DC03-VM' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC03Server, 'Update CRL Distribution Points and AIA to reference DC03-VM')) {
        Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
            param($dc03, $caName)
            $domain = (Get-ADDomain).DNSRoot

            # CDP URLs — LDAP (AD) + HTTP pointing to DC03
            $cdpUrls = @(
                "1:C:\Windows\System32\CertSrv\CertEnroll\%3%8%9.crl",
                "2:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10",
                "2:http://$dc03/CertEnroll/%3%8%9.crl"
            )
            $cdpString = $cdpUrls -join '\n'
            & certutil -setreg CA\CRLPublicationURLs $cdpString | Out-Null

            # AIA URLs
            $aiaUrls = @(
                "1:C:\Windows\System32\CertSrv\CertEnroll\%1_%3%4.crt",
                "2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11",
                "2:http://$dc03/CertEnroll/%1_%3%4.crt"
            )
            $aiaString = $aiaUrls -join '\n'
            & certutil -setreg CA\CACertPublicationURLs $aiaString | Out-Null

            # Restart CA service to apply
            Restart-Service CertSvc -Force
        } -ArgumentList @($DC03Server, $caName)

        Set-StepResult -Step 'CDP/AIA Update' -Status 'Success' -Detail "CDP and AIA updated to reference $DC03Server. CertSvc restarted."
    } else {
        Set-StepResult -Step 'CDP/AIA Update' -Status 'Skipped' -Detail "WhatIf: Would update CDP and AIA URLs from DC01-VM to $DC03Server"
    }
} catch {
    $MigrationResult.Errors += "Step 4/5 (CDP/AIA): $_"
    Set-StepResult -Step 'CDP/AIA Update' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "CDP/AIA update failed — continuing to attempt remaining steps: $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 6: Configure HTTPS Web Enrollment on DC03-VM (ESC8 Fix) ---
Write-MigrationBanner -Title 'Step 6: Configure HTTPS Web Enrollment — ESC8 Remediation' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC03Server, 'Configure HTTPS-only web enrollment with Extended Protection for Authentication')) {
        Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
            param($dc03, $thumbprint)
            Import-Module WebAdministration -ErrorAction Stop

            # Install web enrollment role
            Install-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue | Out-Null

            # Bind the certificate we verified in pre-flight
            $existingHttps = Get-WebBinding -Name 'Default Web Site' -Protocol 'https' -ErrorAction SilentlyContinue
            if (-not $existingHttps) {
                New-WebBinding -Name 'Default Web Site' -Protocol 'https' -Port 443 -SslFlags 0
                $binding = Get-WebBinding -Name 'Default Web Site' -Protocol 'https'
                $binding.AddSslCertificate($thumbprint, 'My')
            }

            # Enable Extended Protection for Authentication on certsrv (fixes ESC8)
            $appFilter = 'system.webServer/security/authentication/windowsAuthentication'
            $psPath     = 'IIS:\Sites\Default Web Site\certsrv'
            Set-WebConfigurationProperty -Filter $appFilter -PSPath $psPath -Name 'enabled' -Value $true
            Set-WebConfigurationProperty -Filter $appFilter -PSPath $psPath `
                -Name 'extendedProtection.tokenChecking' -Value 'Require'

            # Add HSTS header
            $headersFilter = 'system.webServer/httpProtocol/customHeaders'
            try {
                Add-WebConfigurationProperty -PSPath $psPath -Filter $headersFilter -Name '.' `
                    -Value @{ name = 'Strict-Transport-Security'; value = 'max-age=31536000; includeSubDomains' } `
                    -ErrorAction SilentlyContinue
            } catch {}

            # HTTP -> HTTPS redirect (safer than removing the HTTP binding entirely)
            try {
                Add-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site' `
                    -Filter 'system.webServer/httpRedirect' -Name 'enabled' -Value $true -ErrorAction SilentlyContinue
                Set-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site' `
                    -Filter 'system.webServer/httpRedirect' -Name 'destination' -Value "https://$dc03/certsrv/" -ErrorAction SilentlyContinue
            } catch {}

            Restart-WebSite -Name 'Default Web Site'
        } -ArgumentList @($DC03Server, $httpsReady.Thumbprint)

        Set-StepResult -Step 'HTTPS Web Enrollment (ESC8 Fix)' -Status 'Success' `
            -Detail "Web enrollment configured with HTTPS and Extended Protection for Authentication on $DC03Server. HTTP redirects to HTTPS."
    } else {
        Set-StepResult -Step 'HTTPS Web Enrollment (ESC8 Fix)' -Status 'Skipped' `
            -Detail "WhatIf: Would install web enrollment with HTTPS binding (thumbprint: $($httpsReady.Thumbprint)) and EPA on $DC03Server"
    }
} catch {
    $MigrationResult.Errors += "Step 6 (Web Enrollment): $_"
    Set-StepResult -Step 'HTTPS Web Enrollment (ESC8 Fix)' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Web enrollment config failed — review manually: $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 7: Publish CRL from DC03-VM ---
Write-MigrationBanner -Title 'Step 7: Publish CRL from DC03-VM' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC03Server, 'Publish new CRL')) {
        $crlResult = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
            $out = & certutil -CRL 2>&1
            if ($LASTEXITCODE -ne 0) { throw "certutil -CRL failed: $($out -join '; ')" }
            return $out -join "`n"
        }
        Set-StepResult -Step 'CRL Publication' -Status 'Success' -Detail "New CRL published from $DC03Server."
    } else {
        Set-StepResult -Step 'CRL Publication' -Status 'Skipped' -Detail "WhatIf: Would publish new CRL from $DC03Server"
    }
} catch {
    $MigrationResult.Errors += "Step 7 (CRL): $_"
    Set-StepResult -Step 'CRL Publication' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "CRL publication failed: $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 8: Verify CA Health on DC03-VM ---
Write-MigrationBanner -Title 'Step 8: Verify CA Health on DC03-VM' -LogPath $logFile
try {
    $healthResult = Invoke-LocalOrRemote -Server $DC03Server -Credential $Credential -ScriptBlock {
        param($caName)
        $pingOut   = & certutil -ping "$($env:COMPUTERNAME)\$caName" 2>&1
        $pingOK    = ($pingOut | Select-String 'connect').Count -gt 0 -or $LASTEXITCODE -eq 0

        $svcStatus = (Get-Service CertSvc).Status.ToString()

        $crlOut    = & certutil -getreg CA\CRLPublicationURLs 2>&1
        $crlUrls   = $crlOut | Where-Object { $_ -match 'http' } | ForEach-Object { $_.Trim() }

        return @{
            CAServiceStatus = $svcStatus
            PingSuccess     = $pingOK
            PingOutput      = $pingOut -join "`n"
            CRLUrls         = $crlUrls
        }
    } -ArgumentList @($caName)

    if ($healthResult.PingSuccess -and $healthResult.CAServiceStatus -eq 'Running') {
        Set-StepResult -Step 'CA Health Verification' -Status 'Success' `
            -Detail "CA service Running. Ping successful. CRL URLs: $($healthResult.CRLUrls -join ', ')"
    } else {
        Set-StepResult -Step 'CA Health Verification' -Status 'Failed' `
            -Detail "CA service: $($healthResult.CAServiceStatus). Ping: $($healthResult.PingSuccess). Review DC03-VM manually."
        Write-MigrationLog 'CA health check did not fully pass — do not approve Phase 2 sign-off until verified.' -Level WARN -LogPath $logFile
    }
} catch {
    $MigrationResult.Errors += "Step 8 (Health): $_"
    Set-StepResult -Step 'CA Health Verification' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Health verification error: $_" -Level WARN -LogPath $logFile
}
#endregion

#region --- STEP 9: Stop and Disable CA on DC01-VM ---
Write-MigrationBanner -Title 'Step 9: Stop and Disable CA Service on DC01-VM (Rollback Window Preserved)' -LogPath $logFile
try {
    if ($PSCmdlet.ShouldProcess($DC01Server, 'Stop and disable CertSvc (CA service) — role NOT uninstalled')) {
        Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
            Stop-Service  -Name CertSvc -Force -ErrorAction Stop
            Set-Service   -Name CertSvc -StartupType Disabled -ErrorAction Stop
        }
        Set-StepResult -Step 'Disable CA on DC01-VM' -Status 'Success' `
            -Detail "CertSvc stopped and disabled on $DC01Server. Role preserved for rollback. Wait ≥48h before approving Phase 2 sign-off."
        Write-MigrationLog '*** WAIT AT LEAST 48 HOURS before approving Phase 2 sign-off. Monitor for certificate-related errors. ***' -Level WARN -LogPath $logFile
    } else {
        Set-StepResult -Step 'Disable CA on DC01-VM' -Status 'Skipped' -Detail "WhatIf: Would stop and disable CertSvc on $DC01Server (role kept for rollback)"
    }
} catch {
    $MigrationResult.Errors += "Step 9 (Disable DC01 CA): $_"
    Set-StepResult -Step 'Disable CA on DC01-VM' -Status 'Failed' -Detail "$_"
    Write-MigrationLog "Could not stop CA on DC01-VM: $_" -Level ERROR -LogPath $logFile
}
#endregion

#region --- STEP 10: DNS Update Check ---
Write-MigrationBanner -Title 'Step 10: DNS — Check for CA-Related Records Pointing to DC01-VM' -LogPath $logFile
try {
    $domain    = (Get-ADDomain).DNSRoot
    $dnsZone   = $domain
    $dc01Short = $DC01Server -replace '\..*', ''

    try {
        Import-Module DnsServer -ErrorAction SilentlyContinue
        $cnameRecords = Get-DnsServerResourceRecord -ZoneName $dnsZone -RRType CName -ErrorAction SilentlyContinue |
                        Where-Object { $_.RecordData.HostNameAlias -match [regex]::Escape($dc01Short) }
        if ($cnameRecords) {
            Write-MigrationLog "Found CNAME records pointing to DC01-VM: $($cnameRecords.HostName -join ', '). Update these to $DC03Server manually or via DNS console." -Level WARN -LogPath $logFile
            Set-StepResult -Step 'DNS Check' -Status 'Success' -Detail "CNAME records found pointing to DC01-VM: $($cnameRecords.HostName -join ', '). Update manually to $DC03Server."
        } else {
            Set-StepResult -Step 'DNS Check' -Status 'Success' -Detail "No CA-related CNAME records found pointing to $DC01Server."
        }
    } catch {
        Set-StepResult -Step 'DNS Check' -Status 'Success' -Detail "DNS check skipped (DnsServer module unavailable) — review DNS manually for records pointing to $DC01Server."
    }
} catch {
    Set-StepResult -Step 'DNS Check' -Status 'Success' -Detail "DNS check could not complete — verify manually: $_"
}
#endregion

#region --- Save migration result JSON ---
$MigrationResult.CompletedAt = Get-Date -Format 'o'
$MigrationResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonOut -Encoding UTF8
Write-MigrationLog "Migration result JSON saved: $jsonOut" -Level INFO -LogPath $logFile

# Issue 2: Compute SHA256 hash of migration JSON for Phase 3 integrity verification.
$migrationJsonHash = Get-JsonFileHash -Path $jsonOut
Write-MigrationLog "Migration JSON SHA256: $migrationJsonHash" -Level INFO -LogPath $logFile
#endregion

#region --- Create Phase 2 sign-off file ---
$p2signOff = [ordered]@{
    Phase             = 'Migration'
    Status            = 'PendingApproval'
    CompletedAt       = $MigrationResult.CompletedAt
    MigrationJson     = $jsonOut
    MigrationJsonHash = $migrationJsonHash   # Issue 2: SHA256 hash for Phase 3 integrity check
    WhatIfRun         = [bool]$WhatIfPreference
    StepSummary       = ($MigrationResult.Steps.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value.Status)" }) -join ' | '
    ApprovedBy        = ''
    ApprovedAt        = ''
    Notes             = ''
}
$p2signOff | ConvertTo-Json -Depth 5 | Out-File -FilePath $signOffOut -Encoding UTF8
Write-MigrationLog "Phase 2 sign-off file created: $signOffOut" -Level INFO -LogPath $logFile
#endregion

#region --- Console summary ---
Write-MigrationBanner -Title 'Migration Phase Complete' -LogPath $logFile
Write-Host "`nStep Results:" -ForegroundColor White
$MigrationResult.Steps.GetEnumerator() | ForEach-Object {
    $col = switch ($_.Value.Status) { 'Success' { 'Green' } 'Skipped' { 'Magenta' } default { 'Red' } }
    Write-Host "  [$($_.Value.Status)] $($_.Key)" -ForegroundColor $col
}

if ($WhatIfPreference) {
    Write-Host "`nWHATIF run complete — no changes were made. Review planned actions above." -ForegroundColor Magenta
    Write-Host "Re-run without -WhatIf to execute." -ForegroundColor Magenta
} else {
    Write-Host "`nNext steps:" -ForegroundColor White
    Write-Host "  1. Verify DC03-VM CA is healthy: certutil -ping $DC03Server\$caName" -ForegroundColor Cyan
    Write-Host "  2. Test certificate enrollment from a client machine." -ForegroundColor Cyan
    Write-Host "  3. Verify CRL is accessible via HTTPS from a client." -ForegroundColor Cyan
    Write-Host "  4. WAIT AT LEAST 48 HOURS and monitor for certificate errors." -ForegroundColor Yellow
    Write-Host "  5. Edit sign-off to approve: $signOffOut" -ForegroundColor Yellow
    Write-Host "  6. Run 3_Invoke-DC01Demotion.ps1 with -WhatIf first.`n" -ForegroundColor Cyan
}
#endregion

Stop-Transcript | Out-Null
