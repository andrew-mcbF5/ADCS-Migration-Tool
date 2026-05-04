@{
    # Default target servers — override at runtime by passing script parameters explicitly.
    DC01Server = 'DC01-VM'     # Current CA server (to be decommissioned)
    DC02Server = 'DC02-VM'     # Primary DC holding all FSMO roles
    DC03Server = 'DC03-VM'     # New CA target (must be built and promoted before Phase 2)

    Domain     = 'eyeinstitute.local'
    CAName     = 'eyeinstitute-DC01-VM-CA'
}
