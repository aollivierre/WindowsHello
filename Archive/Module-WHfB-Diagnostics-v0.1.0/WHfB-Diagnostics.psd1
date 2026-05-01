@{
    RootModule = 'WHfB-Diagnostics.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'f8b633d9-ccd4-4e77-b9e9-e1c0c9c73f4f'
    Author = 'WHfB Diagnostics Team'
    Description = 'Windows Hello for Business Diagnostics and Management Module'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-WhfbAuthStatus')
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Windows', 'HelloForBusiness', 'Security', 'Authentication')
            ProjectUri = ''
            LicenseUri = ''
        }
    }
}
