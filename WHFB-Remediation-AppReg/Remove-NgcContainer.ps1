<#
.SYNOPSIS
    WHFB remediation Step 2: clear the corrupt NGC / Microsoft Passport
    container for the signed-in user (`certutil -deleteHelloContainer`).

.DESCRIPTION
    Deployed via Intune as a user-context PowerShell script. Each affected
    user (affected-user-a@example.com, affected-user-b@example.com, any other front-desk profile that
    has ever used Hello on the device) gets their corrupt NGC container
    cleared on next sign-in / check-in.

    Sequencing - IMPORTANT:
      Assign the WHFB-disable Account Protection policy FIRST and confirm it
      has applied to the device. THEN assign this script. If WHFB is still
      enabled by policy when this runs, Windows re-provisions Hello
      immediately and the loop resumes (per Microsoft's WHFB FAQ).

    Win 11 caveat: on current Windows 11, certutil -deleteHelloContainer also
    wipes device-bound passkeys stored on the machine, not just the Hello
    PIN. Each affected user must have an alternative sign-in available
    (password remains as designed; a registered YubiKey is the
    passwordless option) before this is assigned.

    The script intentionally does NOT sign the user out. The handover says
    "sign out to complete the action" - the user should do that at their
    next opportunity. Forcing a sign-out from Intune would be disruptive.

.NOTES
    Runs in user context (Intune deviceManagementScripts runAsAccount = user).
    ASCII only. PowerShell 5.1 compatible.
#>

$ErrorActionPreference = 'Continue'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath   = Join-Path $env:TEMP "Remove-NgcContainer-$env:USERNAME-$timestamp.log"

Start-Transcript -Path $logPath -Force | Out-Null

try {
    Write-Host "WHFB remediation Step 2 - clear NGC / Microsoft Passport container"
    Write-Host "==================================================================="
    Write-Host "User:       $env:USERDOMAIN\$env:USERNAME"
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($env:USERDOMAIN, $env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-Host "User SID:   $sid"
    } catch {
        Write-Host "User SID:   (could not resolve)"
    }
    Write-Host "Timestamp:  $timestamp"
    Write-Host "Host:       $env:COMPUTERNAME"
    Write-Host ""

    # Quick PRE-state for the log (so we can confirm the container existed
    # before the wipe). Errors here are non-fatal.
    Write-Host "--- Pre-state: certutil -key (Microsoft Passport KSP) ---"
    & certutil.exe -key -csp "Microsoft Passport Key Storage Provider" 2>&1 |
        Out-String | ForEach-Object { Write-Host $_ }

    Write-Host "--- Running certutil -deleteHelloContainer ---"
    $out = & certutil.exe -deleteHelloContainer 2>&1
    $exit = $LASTEXITCODE
    $out | Out-String | ForEach-Object { Write-Host $_ }
    Write-Host "certutil exit code: $exit"
    Write-Host ""

    if ($exit -eq 0) {
        Write-Host "[OK] NGC container cleared for $env:USERNAME."
        Write-Host "     User should sign out at their next opportunity to"
        Write-Host "     finalise the change."
    } else {
        Write-Host "[WARN] certutil returned $exit. Review the log above."
    }
} catch {
    Write-Host "[ERROR] Unexpected exception: $($_.Exception.Message)"
    $exit = 1
} finally {
    Write-Host ""
    Write-Host "Log file: $logPath"
    Stop-Transcript | Out-Null
}

exit $exit
