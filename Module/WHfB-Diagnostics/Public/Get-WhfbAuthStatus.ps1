#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Retrieves the status of Windows Hello for Business authentication methods (PIN or Biometric).

.DESCRIPTION
    The Get-WhfbAuthStatus function checks the current status of Windows Hello for Business
    authentication methods on the local system. It can retrieve status information for either
    PIN or Biometric authentication, including whether the method is enabled and when it was
    last used (for PIN only).

    The function requires administrative privileges to access the necessary registry keys
    and system services.

.PARAMETER AuthType
    Specifies the type of Windows Hello for Business authentication to check.
    Valid values are:
    - PIN: Checks the status of PIN authentication
    - Biometric: Checks the status of Biometric authentication (fingerprint, facial recognition)

.EXAMPLE
    Get-WhfbAuthStatus -AuthType PIN
    
    Retrieves the status of PIN authentication. Example output:
    AuthType IsEnabled LastUsed             Status
    -------- --------- --------             ------
    PIN      True      2/20/2025 9:30:15 AM Enabled

.EXAMPLE
    Get-WhfbAuthStatus -AuthType Biometric
    
    Retrieves the status of Biometric authentication. Example output:
    AuthType  IsEnabled LastUsed Status
    --------  --------- -------- ------
    Biometric True               Enrolled

.EXAMPLE
    Get-WhfbAuthStatus -AuthType PIN | Where-Object IsEnabled -eq $true
    
    Retrieves PIN status and filters to show only if enabled.

.NOTES
    File Name      : Get-WhfbAuthStatus.ps1
    Required Rights: Administrative privileges
    Requirements   : Windows PowerShell 5.1 or later
    
    The function checks the following locations:
    - PIN: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers
    - Biometric: Windows Biometric Service (WBioSrvc) and related registry keys
    
    For Biometric status, the function first attempts to use the WinBio API. If not available,
    it falls back to registry checks.

.OUTPUTS
    PSCustomObject with the following properties:
    - AuthType: The type of authentication checked (PIN or Biometric)
    - IsEnabled: Boolean indicating if the authentication method is enabled
    - LastUsed: DateTime when the authentication was last used (PIN only)
    - Status: String indicating the current status (Enabled, Disabled, Enrolled, NotEnrolled)

.LINK
    https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-overview
#>

function Get-WhfbAuthStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PIN', 'Biometric')]
        [string]$AuthType
    )

    begin {
        $ErrorActionPreference = 'Stop'
        
        # Helper function to convert FileTime to DateTime (PS 5.1 compatible)
        function ConvertFrom-FileTime {
            param([Int64]$FileTime)
            if ($FileTime) {
                try {
                    [DateTime]::FromFileTime($FileTime)
                }
                catch {
                    $null
                }
            }
            else {
                $null
            }
        }
    }

    process {
        try {
            # Check if Windows Hello for Business is available
            $ngcPrereq = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" -ErrorAction SilentlyContinue
            
            if (-not $ngcPrereq) {
                Write-Warning "Windows Hello for Business is not configured on this device."
                return $null
            }

            # Get authentication status based on type
            switch ($AuthType) {
                'PIN' {
                    $pinInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}" -ErrorAction SilentlyContinue
                    
                    $result = [PSCustomObject]@{
                        AuthType = $AuthType
                        IsEnabled = [bool]$pinInfo.IsEnabled
                        LastUsed = ConvertFrom-FileTime -FileTime $pinInfo.LastUsed
                        Status = if ($pinInfo.IsEnabled) { 'Enabled' } else { 'Disabled' }
                    }
                    
                    Write-Output $result
                }
                'Biometric' {
                    # Check if the biometric service is available
                    $bioService = Get-Service -Name "WBioSrvc" -ErrorAction SilentlyContinue
                    
                    if (-not $bioService) {
                        Write-Warning "Windows Biometric Service is not available on this system."
                        return $null
                    }
                    
                    # Use WinBio API if available, otherwise fall back to registry check
                    $bioStatus = if (Get-Command -Name Get-WinBioConfiguration -ErrorAction SilentlyContinue) {
                        $bioConfig = Get-WinBioConfiguration
                        @{
                            IsEnabled = $bioConfig.EnrollmentStatus -eq 'Enrolled'
                            Status = $bioConfig.EnrollmentStatus
                        }
                    }
                    else {
                        # Fallback to registry check
                        $bioRegistry = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Biometrics" -ErrorAction SilentlyContinue
                        @{
                            IsEnabled = [bool]$bioRegistry.Enabled
                            Status = if ($bioRegistry.Enabled) { 'Enrolled' } else { 'NotEnrolled' }
                        }
                    }
                    
                    $result = [PSCustomObject]@{
                        AuthType = $AuthType
                        IsEnabled = $bioStatus.IsEnabled
                        LastUsed = $null  # Biometric last used time not readily available
                        Status = $bioStatus.Status
                    }
                    
                    Write-Output $result
                }
            }
        }
        catch {
            Write-Error "Failed to retrieve $AuthType status: $_"
            return $null
        }
    }
}

# Export the function
Export-ModuleMember -Function Get-WhfbAuthStatus
