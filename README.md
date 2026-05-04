# ADCS Migration Tool

A three-phase PowerShell tool to safely assess, migrate, and decommission an Active Directory Certificate Services (ADCS) Certificate Authority from one Windows Server domain controller to another — with built-in ESC8 remediation, sign-off gating, and full rollback capability.

---

## Background

This tool was built to address the following scenario:

- **DC01-VM** hosts the domain CA (`eyeinstitute-DC01-VM-CA`) and is running an end-of-life Windows OS
- All FSMO roles have already been migrated to **DC02-VM**
- The CA has an active ESC8 vulnerability (HTTP web enrollment without Extended Protection for Authentication)
- A new domain controller (**DC03-VM**) will be built to host the migrated CA
- DC01-VM must be safely demoted (DCPROMO) once the CA is confirmed migrated and healthy

---

## Tool Structure

```
ADCS-Migration-Tool/
├── 1_Invoke-ADCSAssessment.ps1       # Phase 1 — Read-only assessment
├── 2_Invoke-ADCSMigration.ps1        # Phase 2 — CA migration with ESC8 fix
├── 2_Rollback-ADCSMigration.ps1      # Phase 2 rollback companion
├── 3_Invoke-DC01Demotion.ps1         # Phase 3 — DC demotion and cleanup
├── Config.psd1                       # Environment defaults (servers, domain, CA name)
├── DEPENDENCIES.psd1                 # Dependency manifest (no PSGallery packages)
└── lib/
    ├── Invoke-LocalOrRemote.ps1      # Transparent local/remote execution wrapper
    └── Write-MigrationLog.ps1        # Structured logging with console colour output
```

---

## Phases

### Phase 1 — Assessment (`1_Invoke-ADCSAssessment.ps1`)

**Read-only. Makes no changes.**

Connects to DC01-VM and DC02-VM to gather:

| Check | What it looks for |
|---|---|
| ADCS role presence | Is the CA role installed? |
| CA configuration | Name, type, certificate expiry, DB path/size |
| Issued certificates | Total issued, active (non-expired), template breakdown |
| Published templates | Templates actively published on the CA |
| CRL Distribution Points | Current CDP URLs, DC01-VM reference count |
| AIA Locations | Current AIA URLs, DC01-VM reference count |
| Web Enrollment (ESC8) | HTTP-accessible certsrv without EPA — confirms ESC8 |
| OCSP Responder | Whether Online Responder is installed |
| Autoenrollment GPOs | GPOs configuring certificate autoenrollment |
| DC02 machine cert store | Active certs issued by this CA on DC02-VM |
| FSMO roles | Confirms all 5 roles are off DC01-VM |

**Outputs:**
- `reports/ADCS-Assessment-<date>.json` — machine-readable (input to Phase 2)
- `reports/ADCS-Assessment-<date>.html` — colour-coded HTML report with signal breakdown
- `reports/SignOff/Phase1-SignOff.json` — admin must set `Status: Approved` before Phase 2 runs

**Recommendation logic:**  
`CA IS REQUIRED` if any of: active certs > 0, templates published, autoenrollment GPOs found, active machine certs on DC02-VM, OCSP installed.  
`CA MAY NOT BE REQUIRED` if none of the above. Human review always required.

---

### Phase 2 — Migration (`2_Invoke-ADCSMigration.ps1`)

Migrates the CA from DC01-VM to DC03-VM. Supports `-WhatIf` for dry runs.

**Pre-flight hard stops:**
- Phase 1 sign-off is `Approved` (SHA256 hash of assessment JSON verified)
- DC03-VM is reachable via WinRM
- DC03-VM is a domain controller
- ADCS role is **not** already installed on DC03-VM
- DC03-VM has a valid HTTPS certificate in `Cert:\LocalMachine\My` (required for ESC8 fix)
- Backup UNC path is writable
- CertSvc is running on DC01-VM

**Migration steps:**
1. Back up CA private key and database to UNC share (3-attempt retry, 30s delay)
2. Install ADCS role on DC03-VM
3. Restore CA from backup on DC03-VM
4. Update CRL Distribution Points to reference DC03-VM
5. Update AIA locations to reference DC03-VM
6. Configure HTTPS-only web enrollment with Extended Protection for Authentication (**ESC8 remediated**)
7. Publish new CRL from DC03-VM
8. Verify CA health (certutil ping, service status, CRL URLs)
9. Stop and disable CertSvc on DC01-VM (role **not** uninstalled — preserves rollback window)
10. Check DNS for CNAME records still pointing to DC01-VM

> **Wait at least 48 hours** after Phase 2 before approving the sign-off. Monitor clients for certificate errors.

---

### Phase 2 Rollback (`2_Rollback-ADCSMigration.ps1`)

Reverses Phase 2 if issues are found during the observation window.

- Re-enables CertSvc on DC01-VM (original CDP/AIA config was never modified)
- Verifies CA health on DC01-VM
- Publishes a new CRL from DC01-VM
- Stops and disables CertSvc on DC03-VM
- Requires a mandatory `-Reason` parameter for audit trail

> Only valid while DC01-VM is still a domain controller (before Phase 3 runs).

---

### Phase 3 — Demotion (`3_Invoke-DC01Demotion.ps1`)

Demotes DC01-VM from the domain. Supports `-WhatIf` for dry runs.

**Pre-flight hard stops:**
- Phase 2 sign-off is `Approved` (SHA256 hash of migration JSON verified)
- All 5 FSMO roles confirmed off DC01-VM
- CertSvc is stopped/disabled on DC01-VM
- CertSvc is running on DC03-VM
- No critical replication errors

**Demotion steps:**
1. Final FSMO audit (logged)
2. Uninstall ADCS role from DC01-VM
3. Demote DC01-VM (`Uninstall-ADDSDomainController`) — waits for reboot with configurable timeout
4. Clean up stale AD metadata (NTDS Settings object)
5. Remove DC01-VM DNS A records
6. Remove DC01-VM from AD Sites and Services
7. Post-demotion domain health check (DC list, CA ping, replication)

---

## Configuration

Edit `Config.psd1` to set your environment defaults. All values can be overridden at runtime via script parameters.

```powershell
@{
    DC01Server = 'DC01-VM'               # Current CA server (to be decommissioned)
    DC02Server = 'DC02-VM'               # Primary DC holding all FSMO roles
    DC03Server = 'DC03-VM'               # New CA target
    Domain     = 'eyeinstitute.local'
    CAName     = 'eyeinstitute-DC01-VM-CA'
}
```

---

## DC03-VM Prerequisites (before Phase 2)

- [ ] Windows Server 2019 or 2022 installed and activated
- [ ] Joined to the domain and promoted as an additional DC
- [ ] ADCS role **not** installed
- [ ] WinRM enabled and reachable from the machine running this tool
- [ ] Adequate free disk space (≥ 2× CA database size)
- [ ] UNC backup share accessible from both DC01-VM and DC03-VM
- [ ] A machine certificate for DC03-VM requested from the current CA and present in `Cert:\LocalMachine\My`

---

## Safety Features

| Feature | Detail |
|---|---|
| `-WhatIf` support | All destructive operations respect `SupportsShouldProcess` — dry-run before committing |
| Sign-off gating | JSON files require human approval between phases; never auto-approved |
| SHA256 integrity | Phase 2 verifies the assessment JSON hash; Phase 3 verifies the migration JSON hash |
| Backup retry | CA backup retried up to 3 times with 30-second delays |
| Transcript protection | Transcript paused around `Uninstall-ADDSDomainController` to prevent credential logging |
| SecureString | CA key password and local admin password never written to disk or logs |
| Rollback window | Phase 2 stops (not uninstalls) the CA on DC01-VM; the role is preserved until Phase 3 |
| No PSGallery packages | All operations use Windows built-ins (`certutil`, RSAT, ServerManager, WebAdministration) |

---

## CDP/AIA Limitation

CDP and AIA URLs are baked into certificates **at issuance time** and cannot be changed retroactively. Certificates issued before migration will continue to reference DC01-VM's hostname for the remainder of their validity period.

**Recommended mitigation:** Create a DNS CNAME (e.g. `pki.eyeinstitute.local`) pointing to DC03-VM and use that alias in the Phase 2 CDP/AIA configuration. This ensures both old and new certificates can resolve CRL and CA certificate locations from a single stable hostname after DC01-VM is decommissioned.

---

## Dependencies

No third-party packages. All dependencies are Windows platform features:

| Dependency | Source |
|---|---|
| `certutil.exe` | Windows built-in |
| `ActiveDirectory` module | Windows RSAT feature |
| `ServerManager` module | Windows Server built-in |
| `ADCSAdministration` / `ADCSDeployment` | Windows Server role cmdlets |
| `WebAdministration` module | IIS Windows feature |
| `GroupPolicy` module | Windows RSAT feature (optional, falls back to SYSVOL scan) |
| `DnsServer` module | Windows RSAT feature (optional) |

---

## Usage

```powershell
# Phase 1 — assess (read-only, safe to run anytime)
.\1_Invoke-ADCSAssessment.ps1

# Phase 2 — dry run first
.\2_Invoke-ADCSMigration.ps1 -AssessmentJson .\reports\ADCS-Assessment-20260504.json `
    -BackupPath \\fileserver\CABackup -WhatIf

# Phase 2 — live run
$keyPass = Read-Host 'CA Key Password' -AsSecureString
.\2_Invoke-ADCSMigration.ps1 -AssessmentJson .\reports\ADCS-Assessment-20260504.json `
    -BackupPath \\fileserver\CABackup -CAKeyPassword $keyPass

# Phase 2 rollback (if needed)
.\2_Rollback-ADCSMigration.ps1 -Reason "CRL errors observed post-migration" -WhatIf

# Phase 3 — dry run first
.\3_Invoke-DC01Demotion.ps1 -MigrationJson .\reports\ADCS-Migration-20260504.json -WhatIf

# Phase 3 — live run
$adminPass = Read-Host 'DC01 Local Admin Password' -AsSecureString
.\3_Invoke-DC01Demotion.ps1 -MigrationJson .\reports\ADCS-Migration-20260504.json `
    -LocalAdminPassword $adminPass
```
