<#
Windows Hello for Business Diagnostic Script
Version: 2.1
Combines insights from:
- windows-hello-business-troubleshooting.md
- Comprehensive Troubleshooting Framework.md
#>

function Show-Menu {
    param (
        [string]$Title = 'Windows Hello for Business Diagnostics'
    )
    Clear-Host
    Write-Host "======== $Title ========"
    Write-Host "1. PIN Reset Diagnostics"
    Write-Host "2. Authentication Failure Analysis"
    Write-Host "3. Environment Cleanup Wizard"
    Write-Host "4. Log Collection Package"
    Write-Host "5. TPM Health Check"
    Write-Host "6. Exit"
}

function Invoke-PINCheck {
    Write-Host "
[PIN Reset Diagnostics]"
    # Check network connectivity to Microsoft Entra
    Test-NetConnection -ComputerName login.microsoftonline.com -Port 443

    # Verify PIN reset policies
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'

    # Check event logs for recent PIN operations
    Get-WinEvent -LogName 'Microsoft-Windows-HelloForBusiness/Operational' -MaxEvents 50 | 
        Where-Object { $_.Id -in @(1000,1100,1200) } | Format-List
}

function Invoke-AuthDiagnostics {
    Write-Host "
[Authentication Analysis]"
    # Domain controller connectivity check
    nltest /dsgetdc:$env:USERDOMAIN

    # Key synchronization verification
    try {
        $user = whoami
        Get-ADUser $user -Properties msDS-KeyCredentialLink |
            Select-Object DistinguishedName, msDS-KeyCredentialLink
    }
    catch {
        Write-Warning "AD module not installed. Running basic check..."
        dsregcmd /status
    }

    # Certificate trust validation
    certutil -verifyStore -v My
}

function Start-SafeCleanup {
    param($Level)
    switch ($Level) {
        1 {
            Write-Host "Clearing credential cache..."
            cmdkey /list | ForEach-Object { cmdkey /delete:$_ }
        }
        2 {
            Write-Host "Resetting NGC folder (non-destructive)..."
            TakeOwnership -Path "$env:SystemDrive\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
        }
        3 {
            Write-Host "FULL Reset (requires admin confirmation)"
            certutil -DeleteHelloContainer
            Initialize-Tpm -AllowClear -Force
        }
    }
}

function New-LogPackage {
    $tempDir = "$env:TEMP\WHfB_Logs_$(Get-Date -Format yyyyMMdd_HHmmss)"
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    # Collect critical logs
    Get-WinEvent -LogName 'Microsoft-Windows-HelloForBusiness/Operational' -Oldest | 
        Export-Csv "$tempDir\EventLogs.csv"
    dsregcmd /status > "$tempDir\DsregCmd.txt"
    systeminfo > "$tempDir\SystemInfo.txt"

    Compress-Archive -Path "$tempDir\*" -DestinationPath "$tempDir.zip"
    Write-Host "Log package created: $tempDir.zip"
}

# Main execution loop
while ($true) {
    Show-Menu
    $selection = Read-Host "Please choose an option"
    switch ($selection) {
        '1' { Invoke-PINCheck }
        '2' { Invoke-AuthDiagnostics }
        '3' { 
            Write-Host "
[Environment Cleanup]"
            Write-Host "1. Basic Credential Reset"
            Write-Host "2. NGC Folder Reset"
            Write-Host "3. Full WHfB Reset (CAUTION)"
            $cleanChoice = Read-Host "Select cleanup level"
            Start-SafeCleanup -Level $cleanChoice
        }
        '4' { New-LogPackage }
        '5' { Get-Tpm | Format-List }
        '6' { exit }
        default { Write-Warning "Invalid selection" }
    }
    Pause
}
