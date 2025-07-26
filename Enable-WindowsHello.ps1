# Requires -RunAsAdministrator

function Write-StatusMessage {
    param(
        [string]$Message,
        [string]$Status = "Info"
    )
    
    $color = switch ($Status) {
        "Success" { "Green" }
        "Error" { "Red" }
        "Warning" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Message" -ForegroundColor $color
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    
    try {
        Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

try {
    Write-StatusMessage "Starting Windows Hello for Business configuration..."
    
    # Create and configure PassportForWork policy
    Write-StatusMessage "Configuring PassportForWork policy..."
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Force | Out-Null
        Write-StatusMessage "Created PassportForWork registry key" "Success"
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -Value 1 -Type DWord
    Write-StatusMessage "Enabled PassportForWork" "Success"

    # Enable PIN logon
    Write-StatusMessage "Configuring PIN logon..."
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
        Write-StatusMessage "Created System registry key" "Success"
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value 1 -Type DWord
    Write-StatusMessage "Enabled Domain PIN logon" "Success"

    # Configure and start services using sc.exe
    Write-StatusMessage "Configuring Windows Hello services..."
    
    # Configure NgcSvc
    $result = Start-Process -FilePath "sc.exe" -ArgumentList "config NgcSvc start= auto" -Wait -NoNewWindow -PassThru
    if ($result.ExitCode -eq 0) {
        Write-StatusMessage "Set NgcSvc to Automatic startup" "Success"
    } else {
        Write-StatusMessage "Failed to set NgcSvc startup type" "Error"
    }

    # Configure NgcCtnrSvc
    $result = Start-Process -FilePath "sc.exe" -ArgumentList "config NgcCtnrSvc start= auto" -Wait -NoNewWindow -PassThru
    if ($result.ExitCode -eq 0) {
        Write-StatusMessage "Set NgcCtnrSvc to Automatic startup" "Success"
    } else {
        Write-StatusMessage "Failed to set NgcCtnrSvc startup type" "Error"
    }

    # Start services
    Write-StatusMessage "Starting services..."
    
    # Start NgcSvc
    $result = Start-Process -FilePath "sc.exe" -ArgumentList "start NgcSvc" -Wait -NoNewWindow -PassThru
    if ($result.ExitCode -eq 0) {
        Write-StatusMessage "Started NgcSvc" "Success"
    } else {
        Write-StatusMessage "Failed to start NgcSvc" "Warning"
    }

    # Start NgcCtnrSvc
    $result = Start-Process -FilePath "sc.exe" -ArgumentList "start NgcCtnrSvc" -Wait -NoNewWindow -PassThru
    if ($result.ExitCode -eq 0) {
        Write-StatusMessage "Started NgcCtnrSvc" "Success"
    } else {
        Write-StatusMessage "Failed to start NgcCtnrSvc" "Warning"
    }

    # Verify the configuration
    Write-StatusMessage "Verifying configuration..."
    
    # Check registry settings
    $passportEnabled = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled"
    $pinEnabled = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon"
    
    if ($passportEnabled -and $pinEnabled) {
        Write-StatusMessage "Registry configuration verified" "Success"
    } else {
        Write-StatusMessage "Registry configuration incomplete" "Warning"
    }

    # Check service status
    $ngcService = Get-Service NgcSvc -ErrorAction SilentlyContinue
    $ngcCtnrService = Get-Service NgcCtnrSvc -ErrorAction SilentlyContinue
    
    if ($ngcService.Status -eq 'Running' -and $ngcCtnrService.Status -eq 'Running') {
        Write-StatusMessage "Services are running correctly" "Success"
    } else {
        Write-StatusMessage "Warning: One or more services not running. Current status:" "Warning"
        Write-StatusMessage "NgcSvc: $($ngcService.Status)" "Info"
        Write-StatusMessage "NgcCtnrSvc: $($ngcCtnrService.Status)" "Info"
    }

    Write-StatusMessage "Configuration complete! Please sign out and sign back in to see the changes." "Success"
    Write-StatusMessage "After signing back in, check Settings > Accounts > Sign-in options for Windows Hello setup" "Info"
    Write-StatusMessage "If you don't see the options, you may need to restart your computer" "Info"

} catch {
    Write-StatusMessage "Error occurred: $_" "Error"
    Write-StatusMessage "Please ensure you're running this script as Administrator" "Error"
    exit 1
}
