<#
.SYNOPSIS
    Phase 1 — ADCS Assessment (Read-Only).
    Assesses whether Certificate Services on DC01-VM is still required and
    documents the current CA configuration before any migration work begins.

.DESCRIPTION
    All operations in this script are READ-ONLY. No changes are made to any system.
    Produces a JSON assessment file (input to Phase 2), an HTML report, and a
    sign-off file that an administrator must approve before Phase 2 can run.

    Tested on: Windows Server 2019 (build 17763) and Windows Server 2022 (build 20348).
    Requires certutil.exe 10.0.17763+ and the ActiveDirectory RSAT module.

.PARAMETER DC01Server
    Hostname of the current CA server. Defaults to Config.psd1 value ('DC01-VM').

.PARAMETER DC02Server
    Hostname of the secondary DC where machine cert stores will be checked.
    Defaults to Config.psd1 value ('DC02-VM').

.PARAMETER Credential
    Optional PSCredential. Omit when running as a Domain Admin account with rights to both servers.

.PARAMETER OutputPath
    Directory for reports and sign-off files. Created if it does not exist. Default: .\reports

.EXAMPLE
    .\1_Invoke-ADCSAssessment.ps1

.EXAMPLE
    $cred = Get-Credential
    .\1_Invoke-ADCSAssessment.ps1 -DC01Server DC01-VM -DC02Server DC02-VM -Credential $cred -OutputPath C:\ADCS-Reports
#>
[CmdletBinding()]
param(
    [string]$DC01Server  = 'DC01-VM',
    [string]$DC02Server  = 'DC02-VM',
    [PSCredential]$Credential,
    [string]$OutputPath  = '.\reports'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Initialise paths and logging ---
$scriptDir    = $PSScriptRoot

# Issue 7: Load environment defaults from Config.psd1; command-line params take precedence.
$configFile = Join-Path $scriptDir 'Config.psd1'
if (Test-Path $configFile) {
    $Cfg = Import-PowerShellDataFile $configFile
    if (-not $PSBoundParameters.ContainsKey('DC01Server')) { $DC01Server = $Cfg.DC01Server }
    if (-not $PSBoundParameters.ContainsKey('DC02Server')) { $DC02Server = $Cfg.DC02Server }
}

$datestamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportsDir   = [System.IO.Path]::GetFullPath($OutputPath)
$signOffDir   = Join-Path $reportsDir 'SignOff'
$logFile      = Join-Path $reportsDir "ADCS-Assessment-$datestamp.log"
$jsonFile     = Join-Path $reportsDir "ADCS-Assessment-$datestamp.json"
$htmlFile     = Join-Path $reportsDir "ADCS-Assessment-$datestamp.html"
$signOffFile  = Join-Path $signOffDir 'Phase1-SignOff.json'

foreach ($dir in @($reportsDir, $signOffDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

Start-Transcript -Path $logFile -Append | Out-Null

. (Join-Path $scriptDir 'lib\Write-MigrationLog.ps1')
. (Join-Path $scriptDir 'lib\Invoke-LocalOrRemote.ps1')

Write-MigrationBanner -Title 'ADCS Assessment — Phase 1 (Read-Only)' -LogPath $logFile
Write-MigrationLog "DC01 (CA Server) : $DC01Server" -Level INFO -LogPath $logFile
Write-MigrationLog "DC02 (Secondary DC): $DC02Server" -Level INFO -LogPath $logFile
Write-MigrationLog "Output path      : $reportsDir"   -Level INFO -LogPath $logFile

# Issue 4: OS/certutil version guard — document tested platform and warn on unsupported versions.
$osBuild = [System.Environment]::OSVersion.Version
if ($osBuild.Major -lt 10) {
    Write-MigrationLog "WARNING: Unsupported OS version $osBuild — this script was tested on Windows Server 2019/2022 (build 17763+). Proceed with caution." -Level WARN -LogPath $logFile
}
$certutilVer = (& certutil -? 2>&1 | Select-String 'CertUtil' | Select-Object -First 1).ToString().Trim()
Write-MigrationLog "Platform: $osBuild | certutil: $certutilVer" -Level INFO -LogPath $logFile
#endregion

#region --- Result object ---
$Results = [ordered]@{
    AssessmentDate    = (Get-Date -Format 'o')
    DC01Server        = $DC01Server
    DC02Server        = $DC02Server
    Checks            = [ordered]@{}
    Recommendation    = ''
    CAIsRequired      = $null
    CADatabaseSizeMB  = 0
    CAName            = ''
    CAType            = ''
    CACertExpiry      = ''
    CDPUrls           = @()
    AIAUrls           = @()
    IssuedCertCount   = 0
    ActiveCertCount   = 0
    PublishedTemplates= @()
    FSMORolesOnDC01   = @()
    Errors            = @()
}
#endregion

function Add-CheckResult {
    param([string]$Name, [string]$Status, [string]$Detail, $Data = $null)
    $Results.Checks[$Name] = [ordered]@{
        Status = $Status   # PASS | WARN | FAIL | INFO
        Detail = $Detail
        Data   = $Data
    }
    $level = switch ($Status) { 'PASS' { 'SUCCESS' } 'WARN' { 'WARN' } 'FAIL' { 'ERROR' } default { 'INFO' } }
    Write-MigrationLog "[$Status] $Name — $Detail" -Level $level -LogPath $logFile
}

#region --- CHECK 1: ADCS Role Presence ---
Write-MigrationBanner -Title 'Check 1: ADCS Role Presence' -LogPath $logFile
try {
    $roleInfo = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $feat = Get-WindowsFeature -Name 'ADCS-Cert-Authority'
        return @{
            Installed    = $feat.Installed
            InstallState = $feat.InstallState.ToString()
            DisplayName  = $feat.DisplayName
        }
    }
    if ($roleInfo.Installed) {
        Add-CheckResult -Name 'ADCS Role' -Status 'INFO' -Detail "Installed ($($roleInfo.InstallState))" -Data $roleInfo
    } else {
        Add-CheckResult -Name 'ADCS Role' -Status 'WARN' -Detail "ADCS-Cert-Authority is NOT installed on $DC01Server — nothing to migrate." -Data $roleInfo
        Write-MigrationLog "ADCS role not found. Verify target server is correct. Exiting assessment." -Level WARN -LogPath $logFile
        $Results.Recommendation = 'ADCS role not found on DC01-VM. Verify the correct server was specified.'
        $Results.CAIsRequired   = $false
    }
} catch {
    $Results.Errors += "Check 1 (ADCS Role): $_"
    Add-CheckResult -Name 'ADCS Role' -Status 'FAIL' -Detail "Could not query role: $_"
}
#endregion

#region --- CHECK 2: CA Configuration ---
Write-MigrationBanner -Title 'Check 2: CA Configuration' -LogPath $logFile
try {
    $caConfig = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $dump       = & certutil -dump 2>&1
        $configStr  = ($dump | Where-Object { $_ -match 'Config:' } | Select-Object -First 1) -replace '.*Config:\s+', ''
        $caName     = ($dump | Where-Object { $_ -match '^\s*Name:' } | Select-Object -First 1) -replace '^\s*Name:\s+', ''
        $caType     = ($dump | Where-Object { $_ -match 'CA type:' } | Select-Object -First 1) -replace '.*CA type:\s+', ''

        # CA certificate expiry
        $certExpiry = ''
        try {
            $caCert = Get-ChildItem Cert:\LocalMachine\CA | Where-Object {
                $_.Subject -match [regex]::Escape($caName.Trim())
            } | Sort-Object NotAfter -Descending | Select-Object -First 1
            if ($caCert) { $certExpiry = $caCert.NotAfter.ToString('yyyy-MM-dd') }
        } catch {}

        # CA database path
        $dbPath = ''
        try {
            $dbPath = (& certutil -getreg CA\DBDirectory 2>&1 | Where-Object { $_ -match '\\' } | Select-Object -First 1).Trim()
        } catch {}

        return @{
            ConfigString = $configStr.Trim()
            CAName       = $caName.Trim()
            CAType       = $caType.Trim()
            CACertExpiry = $certExpiry
            DBPath       = $dbPath
        }
    }

    $Results.CAName      = $caConfig.CAName
    $Results.CAType      = $caConfig.CAType
    $Results.CACertExpiry= $caConfig.CACertExpiry

    $expiryDetail = if ($caConfig.CACertExpiry) { " | CA cert expires: $($caConfig.CACertExpiry)" } else { '' }
    Add-CheckResult -Name 'CA Configuration' -Status 'INFO' `
        -Detail "Name: $($caConfig.CAName) | Type: $($caConfig.CAType)$expiryDetail" -Data $caConfig

    # Check if CA cert is close to expiry
    if ($caConfig.CACertExpiry) {
        $expDate = [datetime]$caConfig.CACertExpiry
        $daysLeft = ($expDate - (Get-Date)).Days
        if ($daysLeft -lt 90) {
            Add-CheckResult -Name 'CA Cert Expiry' -Status 'WARN' `
                -Detail "CA certificate expires in $daysLeft days ($($caConfig.CACertExpiry)). Plan renewal as part of migration."
        } else {
            Add-CheckResult -Name 'CA Cert Expiry' -Status 'PASS' `
                -Detail "CA certificate valid for $daysLeft more days (expires $($caConfig.CACertExpiry))."
        }
    }

    # CA DB size
    if ($caConfig.DBPath) {
        try {
            $dbSize = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
                param($path)
                if (Test-Path $path) {
                    $bytes = (Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                    return [math]::Round($bytes / 1MB, 1)
                }
                return 0
            } -ArgumentList @($caConfig.DBPath)
            $Results.CADatabaseSizeMB = $dbSize
            Add-CheckResult -Name 'CA Database Size' -Status 'INFO' -Detail "$dbSize MB at $($caConfig.DBPath) — ensure backup destination has at least $([math]::Round($dbSize * 2, 0)) MB free."
        } catch {
            Add-CheckResult -Name 'CA Database Size' -Status 'WARN' -Detail "Could not measure DB size: $_"
        }
    }
} catch {
    $Results.Errors += "Check 2 (CA Config): $_"
    Add-CheckResult -Name 'CA Configuration' -Status 'FAIL' -Detail "Could not retrieve CA config: $_"
}
#endregion

#region --- CHECK 3: Issued Certificates ---
Write-MigrationBanner -Title 'Check 3: Issued Certificates' -LogPath $logFile
try {
    $certCounts = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        # Total issued (Disposition=20 = issued/valid)
        $allOutput  = & certutil -view -restrict 'Disposition=20' -out 'RequestID' 2>&1
        $totalCount = ($allOutput | Select-String '^Row \d+:').Count

        # Active (not yet expired) — check NotAfter column
        $now         = Get-Date
        $expiryOut   = & certutil -view -restrict 'Disposition=20' -out 'RequestID,NotAfter' 2>&1
        $notAfterLines = $expiryOut | Select-String 'NotAfter:\s+(.+)'
        $activeCount = 0
        foreach ($line in $notAfterLines) {
            $dateStr = $line.Matches[0].Groups[1].Value.Trim()
            try {
                if ([datetime]::Parse($dateStr) -gt $now) { $activeCount++ }
            } catch {}
        }

        # Template breakdown
        $templateOut   = & certutil -view -restrict 'Disposition=20' -out 'RequestID,CertificateTemplate' 2>&1
        $templateLines = $templateOut | Select-String 'CertificateTemplate:\s+(.+)'
        $templateCounts= @{}
        foreach ($line in $templateLines) {
            $t = $line.Matches[0].Groups[1].Value.Trim()
            if ($t -and $t -ne '(null)') {
                if ($templateCounts.ContainsKey($t)) { $templateCounts[$t]++ }
                else { $templateCounts[$t] = 1 }
            }
        }

        return @{
            TotalIssued      = $totalCount
            ActiveCount      = $activeCount
            TemplateCounts   = $templateCounts
        }
    }

    $Results.IssuedCertCount  = $certCounts.TotalIssued
    $Results.ActiveCertCount  = $certCounts.ActiveCount

    $templateSummary = ($certCounts.TemplateCounts.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join '; '
    $templateSummary = if ($templateSummary) { $templateSummary } else { 'None identified' }

    if ($certCounts.ActiveCount -gt 0) {
        Add-CheckResult -Name 'Issued Certificates' -Status 'WARN' `
            -Detail "Total issued: $($certCounts.TotalIssued) | Active (non-expired): $($certCounts.ActiveCount) | Templates: $templateSummary" `
            -Data $certCounts
    } elseif ($certCounts.TotalIssued -gt 0) {
        Add-CheckResult -Name 'Issued Certificates' -Status 'PASS' `
            -Detail "Total issued: $($certCounts.TotalIssued) — all are expired. Templates: $templateSummary" `
            -Data $certCounts
    } else {
        Add-CheckResult -Name 'Issued Certificates' -Status 'PASS' `
            -Detail 'No certificates have been issued by this CA.' -Data $certCounts
    }
} catch {
    $Results.Errors += "Check 3 (Issued Certs): $_"
    Add-CheckResult -Name 'Issued Certificates' -Status 'FAIL' -Detail "Could not enumerate certificates: $_"
}
#endregion

#region --- CHECK 4: Published Certificate Templates ---
Write-MigrationBanner -Title 'Check 4: Published Certificate Templates' -LogPath $logFile
try {
    $templates = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $output = & certutil -catemplates 2>&1
        $list   = $output | Where-Object { $_ -match '^\s+\S' -and $_ -notmatch '^-' }
        return $list | ForEach-Object { $_.Trim() }
    }

    $Results.PublishedTemplates = @($templates)
    if ($templates.Count -gt 0) {
        Add-CheckResult -Name 'Certificate Templates' -Status 'WARN' `
            -Detail "$($templates.Count) template(s) published: $($templates -join ', ')" -Data @($templates)
    } else {
        Add-CheckResult -Name 'Certificate Templates' -Status 'PASS' `
            -Detail 'No certificate templates are published on this CA.'
    }
} catch {
    $Results.Errors += "Check 4 (Templates): $_"
    Add-CheckResult -Name 'Certificate Templates' -Status 'FAIL' -Detail "Could not retrieve templates: $_"
}
#endregion

#region --- CHECK 5: CRL Distribution Points ---
Write-MigrationBanner -Title 'Check 5: CRL Distribution Points' -LogPath $logFile
try {
    $cdp = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $output = & certutil -getreg CA\CRLPublicationURLs 2>&1
        return $output | Where-Object { $_ -match '(ldap://|http://|https://|file://)' } |
                         ForEach-Object { $_.Trim() }
    }
    $Results.CDPUrls = @($cdp)
    $dc01Refs = @($cdp | Where-Object { $_ -match [regex]::Escape($DC01Server) })
    $status   = if ($dc01Refs.Count -gt 0) { 'WARN' } else { 'INFO' }
    $detail   = "$($cdp.Count) CDP URL(s) configured. DC01-VM references: $($dc01Refs.Count) (must be updated during migration)."
    Add-CheckResult -Name 'CRL Distribution Points' -Status $status -Detail $detail -Data @($cdp)
} catch {
    $Results.Errors += "Check 5 (CDP): $_"
    Add-CheckResult -Name 'CRL Distribution Points' -Status 'FAIL' -Detail "Could not retrieve CDP config: $_"
}
#endregion

#region --- CHECK 6: Authority Information Access ---
Write-MigrationBanner -Title 'Check 6: Authority Information Access (AIA)' -LogPath $logFile
try {
    $aia = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $output = & certutil -getreg CA\CACertPublicationURLs 2>&1
        return $output | Where-Object { $_ -match '(ldap://|http://|https://|file://)' } |
                         ForEach-Object { $_.Trim() }
    }
    $Results.AIAUrls  = @($aia)
    $dc01RefsAIA      = @($aia | Where-Object { $_ -match [regex]::Escape($DC01Server) })
    $statusAIA        = if ($dc01RefsAIA.Count -gt 0) { 'WARN' } else { 'INFO' }
    Add-CheckResult -Name 'AIA Locations' -Status $statusAIA `
        -Detail "$($aia.Count) AIA URL(s) configured. DC01-VM references: $($dc01RefsAIA.Count) (must be updated during migration)." -Data @($aia)
} catch {
    $Results.Errors += "Check 6 (AIA): $_"
    Add-CheckResult -Name 'AIA Locations' -Status 'FAIL' -Detail "Could not retrieve AIA config: $_"
}
#endregion

#region --- CHECK 7: Web Enrollment (ESC8) ---
Write-MigrationBanner -Title 'Check 7: Web Enrollment Service (ESC8)' -LogPath $logFile
try {
    $webEnroll = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $feat    = Get-WindowsFeature -Name 'ADCS-Web-Enrollment'
        $httpBnd = $false
        $httpsB  = $false
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $site    = Get-WebSite -Name 'Default Web Site' -ErrorAction SilentlyContinue
            if ($site) {
                $bindings = Get-WebBinding -Name 'Default Web Site'
                $httpBnd  = ($bindings | Where-Object { $_.protocol -eq 'http' }) -ne $null
                $httpsB   = ($bindings | Where-Object { $_.protocol -eq 'https' }) -ne $null
            }
        } catch {}

        $extProtection = $false
        try {
            $config        = Get-WebConfiguration 'system.webServer/security/authentication/windowsAuthentication' -PSPath 'IIS:\Sites\Default Web Site\certsrv'
            $extProtection = $config.extendedProtection.tokenChecking -eq 'Require'
        } catch {}

        return @{
            WebEnrollInstalled = $feat.Installed
            HTTPEnabled        = $httpBnd
            HTTPSEnabled       = $httpsB
            ExtProtectionReq   = $extProtection
        }
    }

    $esc8Active = $webEnroll.WebEnrollInstalled -and $webEnroll.HTTPEnabled -and (-not $webEnroll.ExtProtectionReq)
    if ($esc8Active) {
        Add-CheckResult -Name 'Web Enrollment (ESC8)' -Status 'FAIL' `
            -Detail 'Web Enrollment is installed and accessible over HTTP without Extended Protection for Authentication — ESC8 vulnerability confirmed. Will be remediated during migration.' `
            -Data $webEnroll
    } elseif ($webEnroll.WebEnrollInstalled) {
        Add-CheckResult -Name 'Web Enrollment (ESC8)' -Status 'WARN' `
            -Detail 'Web Enrollment is installed. HTTP/HTTPS/EPA status noted — verify ESC8 status manually.' -Data $webEnroll
    } else {
        Add-CheckResult -Name 'Web Enrollment (ESC8)' -Status 'INFO' `
            -Detail 'Web Enrollment (ADCS-Web-Enrollment) is not installed on this server.' -Data $webEnroll
    }
} catch {
    $Results.Errors += "Check 7 (Web Enrollment): $_"
    Add-CheckResult -Name 'Web Enrollment (ESC8)' -Status 'FAIL' -Detail "Could not check web enrollment: $_"
}
#endregion

#region --- CHECK 8: OCSP Responder ---
Write-MigrationBanner -Title 'Check 8: OCSP Responder' -LogPath $logFile
try {
    $ocsp = Invoke-LocalOrRemote -Server $DC01Server -Credential $Credential -ScriptBlock {
        $feat = Get-WindowsFeature -Name 'ADCS-Online-Cert'
        return @{ Installed = $feat.Installed; InstallState = $feat.InstallState.ToString() }
    }
    if ($ocsp.Installed) {
        Add-CheckResult -Name 'OCSP Responder' -Status 'WARN' `
            -Detail 'Online Responder (OCSP) is installed on DC01-VM — this role must also be migrated or decommissioned.' -Data $ocsp
    } else {
        Add-CheckResult -Name 'OCSP Responder' -Status 'PASS' `
            -Detail 'OCSP Responder is not installed. No additional role migration required.' -Data $ocsp
    }
} catch {
    $Results.Errors += "Check 8 (OCSP): $_"
    Add-CheckResult -Name 'OCSP Responder' -Status 'FAIL' -Detail "Could not check OCSP role: $_"
}
#endregion

#region --- CHECK 9: Autoenrollment GPOs ---
Write-MigrationBanner -Title 'Check 9: Autoenrollment GPOs' -LogPath $logFile
try {
    $gpoResults = @()

    # Try GroupPolicy module first
    $gpModuleAvailable = Get-Module -ListAvailable -Name GroupPolicy -ErrorAction SilentlyContinue
    if ($gpModuleAvailable) {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue
        foreach ($gpo in $allGPOs) {
            try {
                # Machine autoenrollment: HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment
                $val = Get-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName 'AEPolicy' -ErrorAction SilentlyContinue
                if ($val) {
                    $gpoResults += "$($gpo.DisplayName) [Machine — AEPolicy=$($val.Value)]"
                }
            } catch {}
            try {
                # User autoenrollment
                $val = Get-GPRegistryValue -Guid $gpo.Id -Key 'HKCU\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -ValueName 'AEPolicy' -ErrorAction SilentlyContinue
                if ($val) {
                    $gpoResults += "$($gpo.DisplayName) [User — AEPolicy=$($val.Value)]"
                }
            } catch {}
        }
    } else {
        # Fallback: search SYSVOL for autoenrollment policy references
        $domain  = (Get-ADDomain).DNSRoot
        $sysvol  = "\\$domain\SYSVOL\$domain\Policies"
        if (Test-Path $sysvol) {
            $hits = Select-String -Path "$sysvol\*\Machine\registry.pol" -Pattern 'AutoEnrollment' -ErrorAction SilentlyContinue
            if ($hits) { $gpoResults += $hits | ForEach-Object { "SYSVOL match: $($_.Filename)" } }
        }
        if ($gpoResults.Count -eq 0) {
            $gpoResults += 'GroupPolicy module not available — SYSVOL scan performed. Review manually if uncertain.'
        }
    }

    if ($gpoResults.Count -gt 0 -and $gpoResults[0] -notmatch 'not available') {
        Add-CheckResult -Name 'Autoenrollment GPOs' -Status 'WARN' `
            -Detail "$($gpoResults.Count) autoenrollment GPO(s) found — clients are likely auto-enrolling certificates." `
            -Data $gpoResults
    } else {
        Add-CheckResult -Name 'Autoenrollment GPOs' -Status 'PASS' `
            -Detail 'No autoenrollment GPOs detected.' -Data $gpoResults
    }
} catch {
    $Results.Errors += "Check 9 (GPOs): $_"
    Add-CheckResult -Name 'Autoenrollment GPOs' -Status 'WARN' -Detail "Could not fully check autoenrollment GPOs: $_"
}
#endregion

#region --- CHECK 10: Machine Cert Store Scan on DC02-VM ---
Write-MigrationBanner -Title 'Check 10: Machine Certificate Store Scan (DC02-VM)' -LogPath $logFile
try {
    $caNameForScan = $Results.CAName
    $storeCerts = Invoke-LocalOrRemote -Server $DC02Server -Credential $Credential -ScriptBlock {
        param($caName)
        $stores = @('My', 'CA', 'Root', 'WebHosting')
        $found  = @()
        foreach ($store in $stores) {
            try {
                $certs = Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
                         Where-Object { $_.Issuer -match [regex]::Escape($caName) -or $_.IssuerName.Name -match [regex]::Escape($caName) }
                foreach ($c in $certs) {
                    $found += @{
                        Store    = $store
                        Subject  = $c.Subject
                        Issuer   = $c.Issuer
                        NotAfter = $c.NotAfter.ToString('yyyy-MM-dd')
                        Expired  = ($c.NotAfter -lt (Get-Date))
                        Thumbprint = $c.Thumbprint
                    }
                }
            } catch {}
        }
        return $found
    } -ArgumentList @($caNameForScan)

    $activeMachineCerts = @($storeCerts | Where-Object { -not $_.Expired })
    if ($activeMachineCerts.Count -gt 0) {
        Add-CheckResult -Name 'DC02 Machine Cert Store' -Status 'WARN' `
            -Detail "$($activeMachineCerts.Count) active certificate(s) from this CA found in DC02-VM machine stores — CA is in use for machine authentication." `
            -Data @($storeCerts)
    } elseif ($storeCerts.Count -gt 0) {
        Add-CheckResult -Name 'DC02 Machine Cert Store' -Status 'PASS' `
            -Detail "$($storeCerts.Count) expired certificate(s) from this CA found. No active machine certs." -Data @($storeCerts)
    } else {
        Add-CheckResult -Name 'DC02 Machine Cert Store' -Status 'PASS' `
            -Detail 'No certificates from this CA found in DC02-VM machine stores.'
    }
} catch {
    $Results.Errors += "Check 10 (DC02 Cert Store): $_"
    Add-CheckResult -Name 'DC02 Machine Cert Store' -Status 'WARN' -Detail "Could not scan DC02 cert store: $_"
}
#endregion

#region --- CHECK 11: FSMO Roles ---
Write-MigrationBanner -Title 'Check 11: FSMO Role Verification' -LogPath $logFile
try {
    $domain   = Get-ADDomain
    $forest   = Get-ADForest

    $allRoles = @{
        'PDC Emulator'          = $domain.PDCEmulator
        'RID Master'            = $domain.RIDMaster
        'Infrastructure Master' = $domain.InfrastructureMaster
        'Schema Master'         = $forest.SchemaMaster
        'Domain Naming Master'  = $forest.DomainNamingMaster
    }

    $dc01Roles = $allRoles.GetEnumerator() | Where-Object {
        $_.Value -match [regex]::Escape($DC01Server)
    } | ForEach-Object { $_.Key }

    $Results.FSMORolesOnDC01 = @($dc01Roles)

    if ($dc01Roles.Count -gt 0) {
        Add-CheckResult -Name 'FSMO Roles' -Status 'FAIL' `
            -Detail "DC01-VM still holds $($dc01Roles.Count) FSMO role(s): $($dc01Roles -join ', '). These MUST be transferred to DC02-VM before demotion." `
            -Data $allRoles
    } else {
        Add-CheckResult -Name 'FSMO Roles' -Status 'PASS' `
            -Detail "All FSMO roles confirmed on DC02-VM or other servers — not on DC01-VM." -Data $allRoles
    }
} catch {
    $Results.Errors += "Check 11 (FSMO): $_"
    Add-CheckResult -Name 'FSMO Roles' -Status 'FAIL' -Detail "Could not verify FSMO roles: $_"
}
#endregion

#region --- RECOMMENDATION ---
Write-MigrationBanner -Title 'Generating Recommendation' -LogPath $logFile

$requiredIndicators = @()
if ($Results.ActiveCertCount -gt 0)                                                            { $requiredIndicators += "Active issued certificates: $($Results.ActiveCertCount)" }
if ($Results.PublishedTemplates.Count -gt 0)                                                   { $requiredIndicators += "Published templates: $($Results.PublishedTemplates.Count)" }
if ($Results.Checks.ContainsKey('Autoenrollment GPOs') -and $Results.Checks['Autoenrollment GPOs'].Status -eq 'WARN') { $requiredIndicators += 'Autoenrollment GPOs detected' }
if ($Results.Checks.ContainsKey('DC02 Machine Cert Store') -and $Results.Checks['DC02 Machine Cert Store'].Status -eq 'WARN') { $requiredIndicators += 'Active machine certs from this CA on DC02-VM' }
if ($Results.Checks.ContainsKey('OCSP Responder') -and $Results.Checks['OCSP Responder'].Status -eq 'WARN')                   { $requiredIndicators += 'OCSP Responder installed' }

if ($requiredIndicators.Count -gt 0) {
    $Results.Recommendation = "CA IS REQUIRED — Migrate to DC03-VM. Indicators: $($requiredIndicators -join '; ')"
    $Results.CAIsRequired   = $true
    Write-MigrationLog "RECOMMENDATION: CA IS REQUIRED — $($requiredIndicators -join '; ')" -Level WARN -LogPath $logFile
} else {
    $Results.Recommendation = "CA MAY NOT BE REQUIRED — No active certificates, templates, GPOs, or dependencies detected. Human review still recommended before decommissioning."
    $Results.CAIsRequired   = $false
    Write-MigrationLog "RECOMMENDATION: CA MAY NOT BE REQUIRED — review manually before decommissioning." -Level SUCCESS -LogPath $logFile
}
#endregion

#region --- OUTPUT: JSON Assessment ---
$Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8
Write-MigrationLog "JSON assessment saved: $jsonFile" -Level INFO -LogPath $logFile

# Issue 2: Compute SHA256 hash of assessment JSON for sign-off integrity verification in Phase 2.
$assessmentJsonHash = Get-JsonFileHash -Path $jsonFile
Write-MigrationLog "Assessment JSON SHA256: $assessmentJsonHash" -Level INFO -LogPath $logFile
#endregion

#region --- OUTPUT: HTML Report ---
$statusBadge = {
    param($s)
    $class = switch ($s) { 'PASS' { 'pass' } 'WARN' { 'warn' } 'FAIL' { 'fail' } default { 'info' } }
    "<span class='badge badge-$class'>$s</span>"
}

$checkRows = ($Results.Checks.GetEnumerator() | ForEach-Object {
    $badge = & $statusBadge $_.Value.Status
    "<tr><td><strong>$($_.Key)</strong></td><td>$badge</td><td>$($_.Value.Detail)</td></tr>"
}) -join "`n"

$recClass  = if ($Results.CAIsRequired) { 'required' } else { 'not-required' }
$recIcon   = if ($Results.CAIsRequired) { '&#9888;' } else { '&#10003;' }
$fsmoWarn  = if ($Results.FSMORolesOnDC01.Count -gt 0) { "<p style='color:#721c24'><strong>&#9888; WARNING:</strong> DC01-VM still holds FSMO roles: $($Results.FSMORolesOnDC01 -join ', '). Transfer these before proceeding.</p>" } else { '' }

# Issue 9: Per-signal breakdown table for the recommendation section.
$autoenrollRequired = $Results.Checks.ContainsKey('Autoenrollment GPOs') -and $Results.Checks['Autoenrollment GPOs'].Status -eq 'WARN'
$dc02CertsRequired  = $Results.Checks.ContainsKey('DC02 Machine Cert Store') -and $Results.Checks['DC02 Machine Cert Store'].Status -eq 'WARN'
$ocspRequired       = $Results.Checks.ContainsKey('OCSP Responder') -and $Results.Checks['OCSP Responder'].Status -eq 'WARN'

$signalRows = @(
    @{ Signal = 'Active (non-expired) issued certificates'; Value = $Results.ActiveCertCount; Required = $Results.ActiveCertCount -gt 0 }
    @{ Signal = 'Published certificate templates';          Value = $Results.PublishedTemplates.Count; Required = $Results.PublishedTemplates.Count -gt 0 }
    @{ Signal = 'Autoenrollment GPOs';                      Value = if ($autoenrollRequired) { 'Detected' } else { 'None found' }; Required = $autoenrollRequired }
    @{ Signal = 'Active machine certs from CA on DC02-VM';  Value = if ($dc02CertsRequired) { 'Found' } else { 'None found' }; Required = $dc02CertsRequired }
    @{ Signal = 'OCSP Responder installed on DC01-VM';      Value = if ($ocspRequired) { 'Yes' } else { 'No' }; Required = $ocspRequired }
) | ForEach-Object {
    $badge = if ($_.Required) { "<span class='badge badge-fail'>CA REQUIRED</span>" } else { "<span class='badge badge-pass'>Not contributing</span>" }
    "<tr><td>$($_.Signal)</td><td>$($_.Value)</td><td>$badge</td></tr>"
}
$signalRowsHtml = $signalRows -join "`n"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ADCS Assessment Report — $($Results.DC01Server)</title>
<style>
  body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;margin:0;padding:20px}
  .container{max-width:1100px;margin:0 auto;background:#fff;padding:30px 40px;border-radius:10px;box-shadow:0 2px 12px rgba(0,0,0,.12)}
  h1{color:#1a1a2e;border-bottom:3px solid #c0392b;padding-bottom:10px;margin-top:0}
  h2{color:#16213e;margin-top:30px;font-size:1.1em;text-transform:uppercase;letter-spacing:.05em}
  .meta{color:#6c757d;font-size:.9em;margin-bottom:20px}
  .badge{display:inline-block;padding:3px 10px;border-radius:12px;font-weight:700;font-size:.8em}
  .badge-pass{background:#d4edda;color:#155724}.badge-warn{background:#fff3cd;color:#856404}
  .badge-fail{background:#f8d7da;color:#721c24}.badge-info{background:#d1ecf1;color:#0c5460}
  table{width:100%;border-collapse:collapse;margin-top:8px;font-size:.95em}
  th{background:#16213e;color:#fff;padding:10px 12px;text-align:left;font-weight:600}
  td{padding:9px 12px;border-bottom:1px solid #e9ecef;vertical-align:top}
  tr:hover td{background:#f8f9fa}
  .rec{padding:18px 22px;border-radius:8px;margin:20px 0;font-size:1.05em}
  .required{background:#f8d7da;border-left:5px solid #dc3545;color:#721c24}
  .not-required{background:#d4edda;border-left:5px solid #28a745;color:#155724}
  .checklist{background:#eaf4fb;padding:15px 25px;border-radius:8px;margin-top:10px}
  .checklist li{margin:7px 0}
  .limitation-note{background:#fff8e1;border:2px solid #f0ad4e;padding:15px 20px;border-radius:8px;margin-top:20px}
  .limitation-note p{margin:8px 0 0 0}
  .signoff{background:#fff3cd;border:2px solid #ffc107;padding:15px 20px;border-radius:8px;margin-top:25px}
  .errors{background:#f8d7da;padding:15px 20px;border-radius:8px;margin-top:15px}
</style>
</head>
<body>
<div class="container">
  <h1>ADCS Assessment Report</h1>
  <p class="meta">
    Generated: $($Results.AssessmentDate) &nbsp;|&nbsp;
    CA Server: <strong>$($Results.DC01Server)</strong> &nbsp;|&nbsp;
    CA Name: <strong>$($Results.CAName)</strong> &nbsp;|&nbsp;
    CA Type: <strong>$($Results.CAType)</strong> &nbsp;|&nbsp;
    CA Cert Expiry: <strong>$($Results.CACertExpiry)</strong>
  </p>

  <div class="rec $recClass">$recIcon $($Results.Recommendation)</div>
  $fsmoWarn

  <h2>Recommendation Signal Breakdown</h2>
  <table>
    <tr><th>Signal</th><th>Observed Value</th><th>Contribution to Recommendation</th></tr>
    $signalRowsHtml
  </table>

  <h2>Assessment Checks</h2>
  <table>
    <tr><th>Check</th><th>Status</th><th>Detail</th></tr>
    $checkRows
  </table>

  <h2>Summary Metrics</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Issued Certificates</td><td>$($Results.IssuedCertCount)</td></tr>
    <tr><td>Active (Non-Expired) Certificates</td><td>$($Results.ActiveCertCount)</td></tr>
    <tr><td>Published Templates</td><td>$($Results.PublishedTemplates.Count)</td></tr>
    <tr><td>CA Database Size</td><td>$($Results.CADatabaseSizeMB) MB</td></tr>
    <tr><td>CDP URLs</td><td>$($Results.CDPUrls -join '<br>')</td></tr>
    <tr><td>AIA URLs</td><td>$($Results.AIAUrls -join '<br>')</td></tr>
  </table>

  <h2>DC03-VM Prerequisites Checklist</h2>
  <div class="checklist">
    <p>Before running Phase 2 (Migration), ensure DC03-VM meets ALL of the following:</p>
    <ul>
      <li>&#9744; Windows Server 2019 or 2022 installed and activated</li>
      <li>&#9744; Joined to the <strong>eyeinstitute.local</strong> domain</li>
      <li>&#9744; Promoted as an additional Domain Controller (DCPROMO complete)</li>
      <li>&#9744; ADCS-Cert-Authority role is <strong>NOT</strong> installed</li>
      <li>&#9744; WinRM is enabled and reachable from the workstation running this tool</li>
      <li>&#9744; At least <strong>$([math]::Max([math]::Round($Results.CADatabaseSizeMB * 2, 0), 500)) MB</strong> free disk space for CA database restore</li>
      <li>&#9744; A UNC backup share (e.g., <code>\\fileserver\CABackup</code>) is accessible from both DC01-VM and DC03-VM with write access</li>
      <li>&#9744; IIS (Web-Server) feature is installed or will be installed by the migration script</li>
      <li>&#9744; DNS A record for DC03-VM exists and resolves correctly</li>
      <li>&#9744; A machine certificate for DC03-VM has been requested from the current CA and is present in <code>Cert:\LocalMachine\My</code> — required for HTTPS web enrollment binding</li>
    </ul>
  </div>

  <div class="limitation-note">
    <strong>&#9888; Permanent Limitation: CDP and AIA URLs in Already-Issued Certificates</strong>
    <p>CDP (CRL Distribution Point) and AIA (Authority Information Access) URLs are embedded in certificates <strong>at the time of issuance and cannot be changed retroactively</strong>. Certificates issued before this migration will continue to reference DC01-VM's hostname for the remainder of their validity period.</p>
    <p><strong>Recommended mitigation:</strong> Before decommissioning DC01-VM, create a DNS CNAME or HTTP redirect so that CDP/AIA requests directed at <code>$DC01Server</code> are transparently served by DC03-VM. For example, add a DNS CNAME <code>pki.eyeinstitute.local</code> pointing to DC03-VM, and configure Phase 2 to use that alias in the new CDP/AIA URLs — so both old and new certificates can resolve their CRL and CA certificate locations from a single stable hostname.</p>
  </div>

  <div class="signoff">
    <strong>&#9888; Sign-Off Required Before Phase 2</strong><br>
    Review the assessment above and the JSON file at:<br>
    <code>$jsonFile</code><br><br>
    Then edit the sign-off file: <code>$signOffFile</code><br>
    Set <code>"Status"</code> to <code>"Approved"</code> and fill in <code>"ApprovedBy"</code> with your name.
  </div>

  $(if ($Results.Errors.Count -gt 0) {
    "<div class='errors'><strong>Errors during assessment (non-fatal):</strong><ul>$(($Results.Errors | ForEach-Object { "<li>$_</li>" }) -join '')</ul></div>"
  })
</div>
</body>
</html>
"@

$html | Out-File -FilePath $htmlFile -Encoding UTF8
Write-MigrationLog "HTML report saved: $htmlFile" -Level INFO -LogPath $logFile
#endregion

#region --- OUTPUT: Sign-Off File ---
$signOff = [ordered]@{
    Phase              = 'Assessment'
    Status             = 'PendingApproval'
    CompletedAt        = (Get-Date -Format 'o')
    AssessmentJson     = $jsonFile
    AssessmentJsonHash = $assessmentJsonHash   # Issue 2: SHA256 hash for Phase 2 integrity check
    AssessmentHtml     = $htmlFile
    CAIsRequired       = $Results.CAIsRequired
    Recommendation     = $Results.Recommendation
    ApprovedBy         = ''
    ApprovedAt         = ''
    Notes              = ''
}
$signOff | ConvertTo-Json -Depth 5 | Out-File -FilePath $signOffFile -Encoding UTF8
Write-MigrationLog "Sign-off file created: $signOffFile" -Level INFO -LogPath $logFile
#endregion

#region --- Console Summary ---
Write-MigrationBanner -Title 'Assessment Complete' -LogPath $logFile
Write-Host "`nRECOMMENDATION: " -NoNewline -ForegroundColor White
Write-Host $Results.Recommendation -ForegroundColor $(if ($Results.CAIsRequired) { 'Yellow' } else { 'Green' })

Write-Host "`nNext steps:" -ForegroundColor White
Write-Host "  1. Review the HTML report: $htmlFile" -ForegroundColor Cyan
Write-Host "  2. Review the JSON data:   $jsonFile" -ForegroundColor Cyan
Write-Host "  3. Build DC03-VM per the prerequisites checklist above." -ForegroundColor Cyan
Write-Host "  4. Request a machine certificate for DC03-VM from the current CA (for HTTPS binding)." -ForegroundColor Cyan
Write-Host "  5. Edit sign-off file to approve: $signOffFile" -ForegroundColor Yellow
Write-Host "     Set Status to 'Approved' and fill in ApprovedBy." -ForegroundColor Yellow
Write-Host "  6. Run 2_Invoke-ADCSMigration.ps1 with -WhatIf first.`n" -ForegroundColor Cyan
#endregion

Stop-Transcript | Out-Null
