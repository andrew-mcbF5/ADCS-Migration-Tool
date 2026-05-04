@{
    # No third-party packages from PSGallery, NuGet, or any public registry are used.
    # All dependencies are Windows built-in tools or Microsoft RSAT/Server features.
    ThirdPartyPackages = @()

    PlatformDependencies = @(
        @{
            Name        = 'certutil.exe'
            Source      = 'Windows built-in (C:\Windows\System32\certutil.exe)'
            Type        = 'WindowsBuiltIn'
            Purpose     = 'CA backup, restore, verification, CRL publication, CDP/AIA configuration, cert enumeration'
        },
        @{
            Name        = 'ActiveDirectory'
            Source      = 'Windows RSAT Feature — install with: Install-WindowsFeature RSAT-AD-PowerShell'
            Type        = 'WindowsRSATFeature'
            Purpose     = 'Get-ADDomain, Get-ADForest, Get-ADDomainController, Get-ADObject, Remove-ADObject, Uninstall-ADDSDomainController'
        },
        @{
            Name        = 'ServerManager'
            Source      = 'Built-in Windows Server module'
            Type        = 'WindowsBuiltIn'
            Purpose     = 'Get-WindowsFeature, Install-WindowsFeature, Uninstall-WindowsFeature'
        },
        @{
            Name        = 'ADCSAdministration'
            Source      = 'Built-in Windows Server ADCS role module (available after ADCS-Cert-Authority feature install)'
            Type        = 'WindowsBuiltIn'
            Purpose     = 'Install-AdcsCertificationAuthority, Uninstall-AdcsCertificationAuthority'
        },
        @{
            Name        = 'ADCSDeployment'
            Source      = 'Built-in Windows Server ADCS role module'
            Type        = 'WindowsBuiltIn'
            Purpose     = 'Install-AdcsWebEnrollment, Uninstall-AdcsWebEnrollment'
        },
        @{
            Name        = 'WebAdministration'
            Source      = 'Windows Server IIS feature — install with: Install-WindowsFeature Web-Scripting-Tools'
            Type        = 'WindowsServerFeature'
            Purpose     = 'IIS HTTPS binding configuration and Extended Protection for Authentication (ESC8 remediation)'
        },
        @{
            Name        = 'GroupPolicy'
            Source      = 'Windows RSAT Feature — install with: Install-WindowsFeature GPMC'
            Type        = 'WindowsRSATFeature'
            Purpose     = 'Get-GPO, Get-GPRegistryValue — autoenrollment GPO detection (Phase 1 only; falls back gracefully if unavailable)'
        }
    )
}
