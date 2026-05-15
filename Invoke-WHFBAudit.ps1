<#
.SYNOPSIS
    WHFB (Windows Hello for Business) diagnostic and audit script.
    Captures all 12 data points from the BW Neepawa field guide and produces
    a self-contained HTML report. DIAGNOSIS ONLY — no remediation actions.

.DESCRIPTION
    Run on the affected workstation in the user context that experiences PIN
    failures (so AzureAdPrt and NGC key state are visible). Most steps work
    without elevation; TPM, AD, and DC-side checks gracefully degrade or skip.

    The report flags fingerprints of the nine documented root-cause classes:
      1. Hybrid Key Trust drift in msDS-KeyCredentialLink
      2. PRT renewal failure (14-day sliding window)
      3. Conditional Access Sign-in Frequency cadence
      4. KB5060842/KB5062553 UsePassportForWork user-scope bug (Event 7055/7703 + 0x80090010)
      5. CVE-2025-26647 Kerberos NTAuth chain enforcement (KDC Event 45/21)
      6. 24H2 strict UPN binding drift
      7. TPM lockout / firmware reset
      8. NGC container corruption
      9. Defender ASR / AV interference

.PARAMETER OutputPath
    Folder to write the HTML report. Defaults to C:\code\WHFB\Reports.

.PARAMETER EventLookbackDays
    How many days of event-log history to scan. Default 60 (covers two cycles).

.PARAMETER SkipADQueries
    Skip msDS-KeyCredentialLink lookups (only meaningful on a DC with AD module).

.PARAMETER SkipDCEvents
    Skip KDC operational log scan (only meaningful on a DC).

.PARAMETER TargetUser
    sAMAccountName for AD-side msDS-KeyCredentialLink lookup. Defaults to current user.

.EXAMPLE
    .\Invoke-WHFBAudit.ps1
    Run as the affected user on the affected workstation.

.EXAMPLE
    .\Invoke-WHFBAudit.ps1 -OutputPath C:\Temp -EventLookbackDays 90
#>
[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\code\WHFB\Reports',
    [int]$EventLookbackDays = 60,
    [switch]$SkipADQueries,
    [switch]$SkipDCEvents,
    [string]$TargetUser
)

$ErrorActionPreference = 'Continue'
$script:StartTime = Get-Date
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Sections = New-Object System.Collections.Generic.List[object]

# ---------- helpers ----------

function HtmlEncode {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $Text = $Text -replace '&', '&amp;'
    $Text = $Text -replace '<', '&lt;'
    $Text = $Text -replace '>', '&gt;'
    $Text = $Text -replace '"', '&quot;'
    return $Text
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('CRITICAL','WARN','OK','INFO')] [string]$Status,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = '',
        [string]$Hypothesis = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Status     = $Status
        Section    = $Section
        Title      = $Title
        Detail     = $Detail
        Hypothesis = $Hypothesis
        Time       = Get-Date
    })
}

function Add-Section {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [string]$Description = '',
        [string]$BodyHtml = '',
        [string]$RawText = ''
    )
    $script:Sections.Add([pscustomobject]@{
        Id          = $Id
        Title       = $Title
        Description = $Description
        BodyHtml    = $BodyHtml
        RawText     = $RawText
    })
}

function Convert-ObjectToHtmlTable {
    param([object[]]$Objects, [string[]]$Properties)
    if ($null -eq $Objects -or $Objects.Count -eq 0) {
        return '<p class="muted">(no data)</p>'
    }
    if (-not $Properties) {
        $Properties = $Objects[0].PSObject.Properties.Name
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="data"><thead><tr>')
    foreach ($p in $Properties) {
        [void]$sb.Append('<th>' + (HtmlEncode $p) + '</th>')
    }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($obj in $Objects) {
        [void]$sb.Append('<tr>')
        foreach ($p in $Properties) {
            $val = $obj.$p
            if ($null -eq $val) { $val = '' }
            [void]$sb.Append('<td>' + (HtmlEncode ([string]$val)) + '</td>')
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function Convert-PreToHtml {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return '<p class="muted">(no output)</p>'
    }
    return '<pre class="raw">' + (HtmlEncode $Text) + '</pre>'
}

function Get-EventsSafe {
    param(
        [Parameter(Mandatory)][string]$LogName,
        [int[]]$Ids,
        [int]$Days = $EventLookbackDays,
        [int]$MaxEvents = 200
    )
    $filter = @{ LogName = $LogName; StartTime = (Get-Date).AddDays(-$Days) }
    if ($Ids -and $Ids.Count -gt 0) { $filter.Id = $Ids }
    try {
        Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop |
            Sort-Object TimeCreated -Descending
    } catch [System.Exception] {
        $msg = $_.Exception.Message
        if ($msg -like '*No events were found*' -or $msg -like '*does not exist*') {
            return @()
        }
        Add-Finding -Status 'INFO' -Section $LogName -Title "Event log read failed" -Detail $msg
        return @()
    }
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IsDomainController {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        return ($os.ProductType -eq 2)
    } catch {
        return $false
    }
}

# ---------- environment ----------

$IsElevated = Test-IsElevated
$IsDC       = Test-IsDomainController

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$hostName    = $env:COMPUTERNAME
$userName    = $env:USERNAME
$userDomain  = $env:USERDOMAIN
$timestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportPath  = Join-Path $OutputPath ("WHFB-Audit-{0}-{1}-{2}.html" -f $hostName, $userName, $timestamp)
$rawDumpDir  = Join-Path $OutputPath ("WHFB-Audit-Raw-{0}-{1}-{2}" -f $hostName, $userName, $timestamp)
New-Item -ItemType Directory -Path $rawDumpDir -Force | Out-Null

Write-Host "[*] WHFB Audit starting on $hostName as $userDomain\$userName"
Write-Host "[*] Elevated: $IsElevated   IsDomainController: $IsDC"
Write-Host "[*] Report: $reportPath"
Write-Host "[*] Raw dumps: $rawDumpDir"

# ---------- 0. environment & OS / build / patch level ----------

Write-Host "[*] Step 0: Environment and patch level"
$envInfo = [ordered]@{}
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $envInfo['Hostname']        = $hostName
    $envInfo['User']            = "$userDomain\$userName"
    $envInfo['Manufacturer']    = $cs.Manufacturer
    $envInfo['Model']           = $cs.Model
    $envInfo['BIOSVersion']     = $bios.SMBIOSBIOSVersion
    $envInfo['BIOSReleaseDate'] = $bios.ReleaseDate
    $envInfo['OSCaption']       = $os.Caption
    $envInfo['OSVersion']       = $os.Version
    $envInfo['OSBuild']         = $os.BuildNumber
    $envInfo['LastBootTime']    = $os.LastBootUpTime
    $envInfo['ProductType']     = switch ($os.ProductType) { 1 {'Workstation'}; 2 {'Domain Controller'}; 3 {'Member Server'}; default {'Unknown'} }
} catch {
    Add-Finding -Status 'WARN' -Section 'Environment' -Title 'Could not read OS/CS WMI' -Detail $_.Exception.Message
}

# DisplayVersion (24H2, 23H2, etc.) and UBR
try {
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $envInfo['DisplayVersion'] = $reg.DisplayVersion
    $envInfo['UBR']            = $reg.UBR
    $envInfo['BuildDotUBR']    = "$($reg.CurrentBuildNumber).$($reg.UBR)"
    $envInfo['ReleaseId']      = $reg.ReleaseId
} catch { }

$envBody = Convert-ObjectToHtmlTable -Objects @([pscustomobject]$envInfo)

# Hotfix scan: KB5060842, KB5062553, KB5063060, KB5065789 (the WHFB-relevant cluster)
$relevantKbs = 'KB5060842','KB5062553','KB5063060','KB5065789','KB5074105','KB4593226','KB4592440'
$hotfixes = @()
try {
    $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
} catch {
    Add-Finding -Status 'INFO' -Section 'Environment' -Title 'Get-HotFix failed' -Detail $_.Exception.Message
}
$relevantInstalled = $hotfixes | Where-Object { $relevantKbs -contains $_.HotFixID }
$hotfixHtml = '<h4>WHFB-relevant hotfixes installed</h4>'
if ($relevantInstalled) {
    $hotfixHtml += Convert-ObjectToHtmlTable -Objects $relevantInstalled -Properties HotFixID,Description,InstalledOn,InstalledBy
} else {
    $hotfixHtml += '<p class="muted">None of the tracked WHFB-relevant KBs are installed.</p>'
}
$hotfixHtml += '<h4>All installed hotfixes (newest 25)</h4>'
$hotfixHtml += Convert-ObjectToHtmlTable -Objects ($hotfixes | Select-Object -First 25) -Properties HotFixID,Description,InstalledOn

# 24H2 = build 26100. Flag if 24H2 + missing KB5065789 (the UsePassportForWork fix)
if ($envInfo['BuildDotUBR']) {
    $build = $envInfo['BuildDotUBR']
    if ($build -like '26100.*' -and -not ($relevantInstalled | Where-Object HotFixID -eq 'KB5065789')) {
        Add-Finding -Status 'WARN' -Section 'Environment' `
            -Title '24H2 build without KB5065789 (UsePassportForWork bug fix)' `
            -Detail "Build $build is Windows 11 24H2. KB5065789 (Sept 29 2025 preview) fixes the UsePassportForWork user-scope regression that produces Event 7055/7703 and 0x80090010 PIN failures. Confirm Intune profile assignment scope (User vs Device) below." `
            -Hypothesis 'Class 4: KB5060842/KB5062553 UsePassportForWork user-scope bug'
    }
}

Add-Section -Id 'env' -Title '0. Environment, OS build, and patch level' `
    -Description 'OS build, Windows release, BIOS, and WHFB-relevant hotfix inventory. Flags 24H2 systems missing KB5065789 (the UsePassportForWork user-scope bug fix).' `
    -BodyHtml ($envBody + $hotfixHtml)

# ---------- 0a. Multi-profile coverage on this device ----------
# This audit runs in ONE user context. Several sections below (NGC keys via
# certutil, whoami /upn, HKCU PassportForWork registry tree) capture DATA FOR
# THE CURRENT USER ONLY. On shared PCs with multiple affected Entra accounts,
# the audit must be re-run as each affected user to get complete per-user
# evidence. Device-wide signals (event logs, dsregcmd, TPM, network) cover
# all users regardless. This step warns when other Entra profiles are
# present on the device but not covered by the current run.

Write-Host "[*] Step 0a: User-profile coverage scan"
$currentSid = ''
try {
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
} catch { }

$profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$profileRows = @()
try {
    Get-ChildItem -LiteralPath $profileListKey -ErrorAction Stop | ForEach-Object {
        $sid = $_.PSChildName
        # Skip built-in / service accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
        if ($sid -eq 'S-1-5-18' -or $sid -eq 'S-1-5-19' -or $sid -eq 'S-1-5-20') { return }
        try {
            $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
            $path  = $props.ProfileImagePath
            if ([string]::IsNullOrWhiteSpace($path)) { return }
            # Restrict to real interactive profiles under C:\Users\
            if ($path -notlike 'C:\Users\*') { return }
            $kind = if ($sid -like 'S-1-12-1-*')  { 'EntraID' }
                    elseif ($sid -like 'S-1-5-21-*') { 'Local/AD' }
                    else { 'Other' }
            $profileRows += [pscustomobject]@{
                SID         = $sid
                Kind        = $kind
                ProfilePath = $path
                Current     = ($sid -eq $currentSid)
            }
        } catch { }
    }
} catch {
    Add-Finding -Status 'INFO' -Section 'Coverage' -Title 'ProfileList enumeration failed' `
        -Detail $_.Exception.Message
}

$entraProfiles = @($profileRows | Where-Object { $_.Kind -eq 'EntraID' })
$otherEntra    = @($entraProfiles | Where-Object { -not $_.Current })

$coverageBody = '<p>Captured-as user: <code>' + (HtmlEncode "$userDomain\$userName") + '</code>' +
                ' &nbsp; SID: <code>' + (HtmlEncode $currentSid) + '</code></p>'
if ($profileRows.Count -gt 0) {
    $coverageBody += Convert-ObjectToHtmlTable -Objects $profileRows -Properties SID,Kind,ProfilePath,Current
} else {
    $coverageBody += '<p class="muted">No interactive user profiles found under HKLM ProfileList.</p>'
}
$coverageBody += '<p class="muted">Per-user data in this report (NGC keys via certutil, whoami /upn, HKCU PassportForWork policy) is captured for the running user only. Device-wide sections (event logs, dsregcmd, TPM, network) cover all users.</p>'

if ($entraProfiles.Count -gt 1 -and $otherEntra.Count -gt 0) {
    $names = ($otherEntra | ForEach-Object { Split-Path $_.ProfilePath -Leaf }) -join ', '
    Add-Finding -Status 'WARN' -Section 'Coverage' `
        -Title "Audit covers ONE user; $($otherEntra.Count) other Entra profile(s) on this device not audited" `
        -Hypothesis 'Shared PC with multiple affected users - per-user findings (NGC keys, certutil, UPN drift, HKCU policy) are scoped to the running user only.' `
        -Detail "This run captured per-user data for $userDomain\$userName (SID $currentSid). Other Entra-joined local profiles present on this device: $names. Re-run the audit while signed in as each of those users to get complete per-user coverage. Device-wide signals (event logs, dsregcmd, TPM, network) cover all users regardless."
} elseif ($entraProfiles.Count -eq 1) {
    Add-Finding -Status 'INFO' -Section 'Coverage' `
        -Title 'Single Entra profile on this device - audit covers it' `
        -Detail "Per-user findings reflect $userDomain\$userName, which is the only Entra-joined local profile in HKLM ProfileList."
} elseif ($entraProfiles.Count -eq 0 -and $profileRows.Count -gt 0) {
    Add-Finding -Status 'INFO' -Section 'Coverage' `
        -Title 'No Entra-joined profiles detected via ProfileList' `
        -Detail 'Running user may be local/AD rather than Entra-joined, or the audit is running in an unusual context. Trust-model inference in Step 1 (dsregcmd) is authoritative.'
}

Add-Section -Id 'coverage' -Title '0a. User-profile coverage (per-user data is current-user only)' `
    -Description 'NGC keys, certutil output, whoami /upn, and HKCU PassportForWork policy in this report reflect the running user only. Device-wide signals (event logs, dsregcmd, TPM, network) cover all users. Re-run the audit as each affected user on shared PCs.' `
    -BodyHtml $coverageBody

# ---------- 1. dsregcmd /status ----------

Write-Host "[*] Step 1: dsregcmd /status"
$dsregOutput = ''
try {
    $dsregOutput = (& dsregcmd /status 2>&1 | Out-String)
} catch {
    Add-Finding -Status 'WARN' -Section 'dsregcmd' -Title 'dsregcmd failed to run' -Detail $_.Exception.Message
}
$dsregOutput | Out-File (Join-Path $rawDumpDir 'dsregcmd-status.txt') -Encoding utf8

function Get-DsregField {
    param([string]$Body, [string]$Key)
    if (-not $Body) { return $null }
    $rx = '(?m)^\s*' + [regex]::Escape($Key) + '\s*:\s*(.+?)\s*$'
    $m = [regex]::Match($Body, $rx)
    if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return $null }
}

$dsregFields = [ordered]@{
    AzureAdJoined         = Get-DsregField $dsregOutput 'AzureAdJoined'
    EnterpriseJoined      = Get-DsregField $dsregOutput 'EnterpriseJoined'
    DomainJoined          = Get-DsregField $dsregOutput 'DomainJoined'
    DomainName            = Get-DsregField $dsregOutput 'DomainName'
    DeviceId              = Get-DsregField $dsregOutput 'DeviceId'
    Thumbprint            = Get-DsregField $dsregOutput 'Thumbprint'
    DeviceCertValidity    = Get-DsregField $dsregOutput 'DeviceCertificateValidity'
    KeyContainerId        = Get-DsregField $dsregOutput 'KeyContainerId'
    KeyProvider           = Get-DsregField $dsregOutput 'KeyProvider'
    TpmProtected          = Get-DsregField $dsregOutput 'TpmProtected'
    DeviceAuthStatus      = Get-DsregField $dsregOutput 'DeviceAuthStatus'
    TenantName            = Get-DsregField $dsregOutput 'TenantName'
    TenantId              = Get-DsregField $dsregOutput 'TenantId'
    NgcSet                = Get-DsregField $dsregOutput 'NgcSet'
    NgcKeyId              = Get-DsregField $dsregOutput 'NgcKeyId'
    CanReachDC            = Get-DsregField $dsregOutput 'CanReachDC'
    WorkplaceJoined       = Get-DsregField $dsregOutput 'WorkplaceJoined'
    AzureAdPrt            = Get-DsregField $dsregOutput 'AzureAdPrt'
    AzureAdPrtUpdateTime  = Get-DsregField $dsregOutput 'AzureAdPrtUpdateTime'
    AzureAdPrtExpiryTime  = Get-DsregField $dsregOutput 'AzureAdPrtExpiryTime'
    AzureAdPrtAuthority   = Get-DsregField $dsregOutput 'AzureAdPrtAuthority'
    EnterprisePrt         = Get-DsregField $dsregOutput 'EnterprisePrt'
    OnPremTgt             = Get-DsregField $dsregOutput 'OnPremTgt'
    OnPremTgtUpdateTime   = Get-DsregField $dsregOutput 'OnPremTgtUpdateTime'
    UserKeyId             = Get-DsregField $dsregOutput 'UserKeyId'
    UserKeyName           = Get-DsregField $dsregOutput 'UserKeyName'
    WamDefaultSet         = Get-DsregField $dsregOutput 'WamDefaultSet'
    WamDefaultAuthority   = Get-DsregField $dsregOutput 'WamDefaultAuthority'
}

# Trust model inference
$trustModel = 'Unknown'
if ($dsregFields['OnPremTgt'] -eq 'YES') {
    $trustModel = 'Cloud Kerberos Trust (likely)'
} elseif ($dsregFields['DomainJoined'] -eq 'YES' -and $dsregFields['AzureAdJoined'] -eq 'YES') {
    $trustModel = 'Hybrid (Key Trust or Cert Trust — see policy section)'
} elseif ($dsregFields['AzureAdJoined'] -eq 'YES') {
    $trustModel = 'Cloud-only / Entra Joined'
} elseif ($dsregFields['DomainJoined'] -eq 'YES') {
    $trustModel = 'On-prem domain joined (no Entra join)'
}
$dsregFields['INFERRED_TrustModel'] = $trustModel

# Findings on the dsregcmd block
if ($dsregFields['AzureAdPrt'] -ne 'YES') {
    Add-Finding -Status 'CRITICAL' -Section 'dsregcmd' `
        -Title "AzureAdPrt is '$($dsregFields['AzureAdPrt'])'" `
        -Detail 'No PRT means user has no cached Entra session. WHFB unlock will fall back to password+MFA. After 14 days of failed renewals the PRT is invalidated.' `
        -Hypothesis 'Class 2: PRT renewal failure'
} else {
    if ($dsregFields['AzureAdPrtUpdateTime']) {
        $parsed = $null
        if ([datetime]::TryParse($dsregFields['AzureAdPrtUpdateTime'], [ref]$parsed)) {
            $age = (Get-Date) - $parsed
            if ($age.TotalHours -gt 4) {
                Add-Finding -Status 'WARN' -Section 'dsregcmd' `
                    -Title "PRT last refreshed $([int]$age.TotalHours)h ago (>4h)" `
                    -Detail 'CloudAP renews PRT every ~4h. Stale renewal time suggests blocked endpoint (login.microsoftonline.com / enterpriseregistration.windows.net), TPM/transport-key issue, or CA-policy bouncing. 14 consecutive days of failed renewals invalidates the PRT.' `
                    -Hypothesis 'Class 2: PRT renewal failure (sliding 14-day window)'
            }
        }
    }
}

if ($dsregFields['NgcSet'] -ne 'YES') {
    Add-Finding -Status 'CRITICAL' -Section 'dsregcmd' `
        -Title "NgcSet = $($dsregFields['NgcSet'])" `
        -Detail 'NGC container is not provisioned for this user. WHFB PIN is unavailable until provisioning completes (or destructive reset succeeds).' `
        -Hypothesis 'Class 8: NGC container corruption or provisioning failure'
}

if ($dsregFields['TpmProtected'] -ne 'YES') {
    Add-Finding -Status 'WARN' -Section 'dsregcmd' `
        -Title "TpmProtected = $($dsregFields['TpmProtected'])" `
        -Detail 'WHFB is using software KSP not TPM. Increases blast radius of corruption and reduces phishing-resistance guarantees.' `
        -Hypothesis 'Class 7: TPM not in use (lockout, firmware reset, or policy)'
}

if ($trustModel -like '*Hybrid*') {
    Add-Finding -Status 'INFO' -Section 'dsregcmd' `
        -Title 'Hybrid join detected — confirm Cloud Kerberos Trust vs Key Trust' `
        -Detail 'OnPremTgt is not YES. If WHFB is configured for hybrid sign-in, Cloud Kerberos Trust requires OnPremTgt=YES. A NO here on a hybrid box implies Key Trust or Cert Trust is in use, which exposes the deployment to msDS-KeyCredentialLink drift and CVE-2025-26647 NTAuth chain enforcement.' `
        -Hypothesis 'Class 1: Key Trust drift (if Key Trust is the configured model)'
}

# Pull AcquirePrtDiagnostics / RefreshPrtDiagnostics blocks for the report
$prtDiagBlock = ''
$rxBlock = '(?ms)(\+\-+\+\s*\|\s*(?:Acquire|Refresh)PrtDiagnostics.*?)(?=\+\-+\+\s*\||\Z)'
foreach ($m in [regex]::Matches($dsregOutput, $rxBlock)) {
    $prtDiagBlock += $m.Value + "`r`n"
}

$dsregBody = (Convert-ObjectToHtmlTable -Objects @([pscustomobject]$dsregFields)) +
    '<h4>PRT diagnostic blocks</h4>' + (Convert-PreToHtml $prtDiagBlock) +
    '<h4>Full dsregcmd /status</h4>' + (Convert-PreToHtml $dsregOutput)

Add-Section -Id 'dsreg' -Title '1. dsregcmd /status' `
    -Description 'Device join state, PRT freshness, NGC state, OnPremTgt (Cloud Kerberos Trust signal), TPM protection. Inferred trust model is at the bottom of the table.' `
    -BodyHtml $dsregBody -RawText $dsregOutput

# ---------- 2. HelloForBusiness/Operational ----------

Write-Host "[*] Step 2: HelloForBusiness/Operational"
$hfbIds = 5001,5002,8200,8202,8203,7054,7055,7201,7204
$hfbEvents = Get-EventsSafe -LogName 'Microsoft-Windows-HelloForBusiness/Operational' -Ids $hfbIds
$hfbProj = $hfbEvents | Select-Object @{n='Time';e={$_.TimeCreated}}, Id, LevelDisplayName,
    @{n='Message';e={ ($_.Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($_.Message.Length), 400)) }}

# 5001 carries deployment-type info
$evt5001 = $hfbEvents | Where-Object Id -eq 5001 | Select-Object -First 1
if ($evt5001) {
    Add-Finding -Status 'INFO' -Section 'HelloForBusiness' `
        -Title "Event 5001 (deployment type) most recent: $($evt5001.TimeCreated)" `
        -Detail (($evt5001.Message -replace '\s+',' ').Trim()) `
        -Hypothesis 'Deployment type recorded by client at provisioning'
}

$hfbBody = Convert-ObjectToHtmlTable -Objects $hfbProj -Properties Time,Id,LevelDisplayName,Message
Add-Section -Id 'hfb' -Title '2. HelloForBusiness/Operational events' `
    -Description "Last $EventLookbackDays days of WHFB client events. IDs 5001 (deployment type), 5002 (gesture), 8200/8202/8203 (provisioning), 7054/7201/7204 (prereq), 7055 (KB5060842 fingerprint)." `
    -BodyHtml $hfbBody

# ---------- 3. User Device Registration / Admin ----------

Write-Host "[*] Step 3: User Device Registration / Admin"
$udrIds = 300,360,362,363
$udrEvents = Get-EventsSafe -LogName 'Microsoft-Windows-User Device Registration/Admin' -Ids $udrIds
$udrProj = $udrEvents | Select-Object @{n='Time';e={$_.TimeCreated}}, Id, LevelDisplayName,
    @{n='Message';e={ ($_.Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($_.Message.Length), 600)) }}

$evt363 = $udrEvents | Where-Object Id -eq 363 | Select-Object -First 1
if ($evt363) {
    Add-Finding -Status 'CRITICAL' -Section 'User Device Registration' `
        -Title "Event 363 (NGC key missing) at $($evt363.TimeCreated)" `
        -Detail (($evt363.Message -replace '\s+',' ').Trim()) `
        -Hypothesis 'Class 1 (Key Trust drift) or Class 8 (NGC container corruption)'
}
$evt362 = $udrEvents | Where-Object Id -eq 362 | Select-Object -First 1
if ($evt362) {
    Add-Finding -Status 'WARN' -Section 'User Device Registration' `
        -Title "Event 362 (STS auth failure during NGC reg) at $($evt362.TimeCreated)" `
        -Detail (($evt362.Message -replace '\s+',' ').Trim()) `
        -Hypothesis 'Class 2 (PRT/STS failure) or Class 6 (UPN binding)'
}
$evt360 = $udrEvents | Where-Object Id -eq 360 | Select-Object -First 1
if ($evt360) {
    Add-Finding -Status 'WARN' -Section 'User Device Registration' `
        -Title "Event 360 (provisioning prereq failure) at $($evt360.TimeCreated)" `
        -Detail (($evt360.Message -replace '\s+',' ').Trim()) `
        -Hypothesis 'WHFB provisioning blocked by a prerequisite (body identifies which one)'
}

$udrBody = Convert-ObjectToHtmlTable -Objects $udrProj -Properties Time,Id,LevelDisplayName,Message
Add-Section -Id 'udr' -Title '3. User Device Registration / Admin events' `
    -Description 'IDs 300 (key registered with Entra), 360 (provisioning prereq), 362 (STS auth failure), 363 (NGC key missing).' `
    -BodyHtml $udrBody

# ---------- 4. AAD / Operational ----------

Write-Host "[*] Step 4: AAD / Operational"
$aadIds = 1006,1007,1081,1088,1098
$aadEvents = Get-EventsSafe -LogName 'Microsoft-Windows-AAD/Operational' -Ids $aadIds
$aadProj = $aadEvents | Select-Object @{n='Time';e={$_.TimeCreated}}, Id, LevelDisplayName,
    @{n='Message';e={ ($_.Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($_.Message.Length), 500)) }}

# Pull any AADSTS error codes appearing in the last $EventLookbackDays days
$aadstsRx = '(AADSTS\d{3,7})'
$aadstsHits = @()
foreach ($e in $aadEvents) {
    foreach ($m in [regex]::Matches($e.Message, $aadstsRx)) {
        $aadstsHits += [pscustomobject]@{
            Time   = $e.TimeCreated
            Id     = $e.Id
            Code   = $m.Groups[1].Value
        }
    }
}
$aadstsGroup = $aadstsHits | Group-Object Code | Sort-Object Count -Descending
foreach ($g in $aadstsGroup) {
    $hyp = switch -regex ($g.Name) {
        'AADSTS50034' { 'Class 6: 24H2 strict UPN binding (user not found)' }
        'AADSTS50126' { 'Class 2: credential validation failure' }
        'AADSTS50053' { 'Class 7/8: account locked or many failed attempts' }
        'AADSTS50158' { 'Class 3: external security challenge / CA reauth required' }
        'AADSTS135010' { 'Class 6: missing key binding' }
        'AADSTS50097' { 'Class 2: device authentication required (PRT)' }
        default { 'Inspect AADSTS code in Entra sign-in logs' }
    }
    Add-Finding -Status 'WARN' -Section 'AAD' -Title "$($g.Name) seen $($g.Count)x in AAD/Operational" `
        -Detail "Most recent: $($g.Group | Sort-Object Time -Descending | Select-Object -First 1 -ExpandProperty Time)" `
        -Hypothesis $hyp
}

$aadBody = Convert-ObjectToHtmlTable -Objects $aadProj -Properties Time,Id,LevelDisplayName,Message
if ($aadstsGroup) {
    $aadBody += '<h4>AADSTS error code summary</h4>'
    $aadBody += Convert-ObjectToHtmlTable -Objects ($aadstsGroup | Select-Object @{n='Code';e={$_.Name}}, Count)
}
Add-Section -Id 'aad' -Title '4. AAD / Operational events' `
    -Description 'IDs 1006/1007 PRT acquisition, 1081/1088 token errors, 1098 broker errors. AADSTS codes are extracted and tallied for fingerprinting.' `
    -BodyHtml $aadBody

# ---------- 5. Crypto-NCrypt / Operational ----------

Write-Host "[*] Step 5: Crypto-NCrypt / Operational"
$ncEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Crypto-NCrypt/Operational' -Ids @(1)
$ncFiltered = $ncEvents | Where-Object { $_.Message -like '*Microsoft Passport*' -or $_.Message -like '*Ngc*' }
$ncProj = $ncFiltered | Select-Object @{n='Time';e={$_.TimeCreated}}, Id, LevelDisplayName,
    @{n='Message';e={ ($_.Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($_.Message.Length), 500)) }}

# Hex error fingerprinting
$hexFingerprint = @{
    '0x80090010' = 'Class 4: NTE_PERM — KB5060842/KB5062553 UsePassportForWork user-scope bug fingerprint (with Event 7055/7703)'
    '0x80090011' = 'Class 8: NTE_NOT_FOUND — Key not found (NGC container missing the key)'
    '0x80090016' = 'Class 8: NTE_BAD_KEYSET — Keyset does not exist (corrupted container)'
    '0x80090029' = 'Class 7: TPM not setup'
    '0xC000005E' = 'Class 2: STATUS_NO_LOGON_SERVERS (cannot reach DC; PRT/Cloud Kerberos cascade)'
    '0xC000006D' = 'Class 6: STATUS_LOGON_FAILURE (24H2 UPN binding drift)'
}
foreach ($code in $hexFingerprint.Keys) {
    $hits = $ncFiltered | Where-Object { $_.Message -like "*$code*" }
    if ($hits) {
        Add-Finding -Status 'CRITICAL' -Section 'Crypto-NCrypt' `
            -Title "$code seen $($hits.Count)x in Crypto-NCrypt" `
            -Detail "Most recent: $($hits[0].TimeCreated). Message: $(($hits[0].Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($hits[0].Message.Length), 350)))" `
            -Hypothesis $hexFingerprint[$code]
    }
}

$ncBody = Convert-ObjectToHtmlTable -Objects $ncProj -Properties Time,Id,LevelDisplayName,Message
Add-Section -Id 'ncrypt' -Title '5. Crypto-NCrypt / Operational events (Microsoft Passport KSP)' `
    -Description 'NCrypt error events filtered to Microsoft Passport Key Storage Provider. Hex codes are fingerprinted against the nine root-cause classes.' `
    -BodyHtml $ncBody

# ---------- 6. Application log: 7055 / 7703 ----------

Write-Host "[*] Step 6: Application log 7055 / 7703 (KB5060842/KB5062553 fingerprint)"
$appEvents = Get-EventsSafe -LogName 'Application' -Ids @(7055,7703)
$appProj = $appEvents | Select-Object @{n='Time';e={$_.TimeCreated}}, Id, ProviderName, LevelDisplayName,
    @{n='Message';e={ ($_.Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($_.Message.Length), 600)) }}

$evt7055 = $appEvents | Where-Object Id -eq 7055
$evt7703 = $appEvents | Where-Object Id -eq 7703
if ($evt7055 -and $evt7703) {
    Add-Finding -Status 'CRITICAL' -Section 'Application log' `
        -Title "Application Events 7055 + 7703 BOTH present (the smoking-gun fingerprint)" `
        -Detail "7055 hits: $($evt7055.Count); 7703 hits: $($evt7703.Count). Most recent 7055: $($evt7055[0].TimeCreated). Most recent 7703: $($evt7703[0].TimeCreated). This pairing combined with 0x80090010 in NCrypt is the published fingerprint of the KB5060842/KB5062553 UsePassportForWork user-scope bug. Workaround: re-scope Intune profile from User to Device, OR set HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\UserPassportForWork=1 and reboot, OR install KB5065789." `
        -Hypothesis 'Class 4: KB5060842/KB5062553 UsePassportForWork user-scope bug — HIGHEST PRIORITY'
} elseif ($evt7055) {
    Add-Finding -Status 'WARN' -Section 'Application log' -Title "Event 7055 present (NGC provisioning failed)" `
        -Detail "Hits: $($evt7055.Count). Most recent: $($evt7055[0].TimeCreated)." `
        -Hypothesis 'Class 4 or Class 8'
} elseif ($evt7703) {
    Add-Finding -Status 'WARN' -Section 'Application log' -Title "Event 7703 present (WHFB policy disabled)" `
        -Detail "Hits: $($evt7703.Count). Most recent: $($evt7703[0].TimeCreated)." `
        -Hypothesis 'Class 4 (UsePassportForWork scope) or policy duplication'
}

$appBody = Convert-ObjectToHtmlTable -Objects $appProj -Properties Time,Id,ProviderName,LevelDisplayName,Message
Add-Section -Id 'app' -Title '6. Application log: Events 7055 and 7703 (KB5060842/KB5062553 fingerprint)' `
    -Description 'These two IDs together with 0x80090010 are the documented fingerprint of the UsePassportForWork user-scope regression introduced in summer 2025.' `
    -BodyHtml $appBody

# ---------- 7. KDC / Kerberos (DC only) ----------

Write-Host "[*] Step 7: KDC / Kerberos events (DC only)"
$kdcBody = ''
if ($IsDC -and -not $SkipDCEvents) {
    $kdcIds = 21,45,107
    $kdcEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational' -Ids $kdcIds
    $kdcProj = $kdcEvents | Select-Object @{n='Time';e={$_.TimeCreated}}, Id, LevelDisplayName,
        @{n='Message';e={ ($_.Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($_.Message.Length), 600)) }}
    $kdcBody = Convert-ObjectToHtmlTable -Objects $kdcProj -Properties Time,Id,LevelDisplayName,Message

    $evt45 = $kdcEvents | Where-Object Id -eq 45
    $evt21 = $kdcEvents | Where-Object Id -eq 21
    if ($evt21) {
        Add-Finding -Status 'CRITICAL' -Section 'KDC' -Title "KDC Event 21 (DENY) — CVE-2025-26647 enforcement active" `
            -Detail "Hits: $($evt21.Count). Client cert chain does NOT terminate at NTAuth. Key Trust authentication will fail until NTAuth store is corrected." `
            -Hypothesis 'Class 5: CVE-2025-26647 NTAuth chain enforcement'
    } elseif ($evt45) {
        Add-Finding -Status 'WARN' -Section 'KDC' -Title "KDC Event 45 (AUDIT) — CVE-2025-26647 audit warnings" `
            -Detail "Hits: $($evt45.Count). NTAuth chain not validated; deny mode (Aug+ 2025) will start failing these auths. Ensure issuing CA chain anchored in NTAuth before enforcement." `
            -Hypothesis 'Class 5: CVE-2025-26647 (audit, pre-enforcement)'
    }

    # Check AllowNtAuthPolicyBypass override (DC only)
    try {
        $kdcReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name AllowNtAuthPolicyBypass -ErrorAction Stop
        if ($null -ne $kdcReg.AllowNtAuthPolicyBypass) {
            $val = $kdcReg.AllowNtAuthPolicyBypass
            $kdcBody += '<h4>AllowNtAuthPolicyBypass override</h4>'
            $kdcBody += '<p>Value: <code>' + (HtmlEncode "$val") + '</code> (0=disabled/regression-only, 1=audit, 2=enforce)</p>'
            if ($val -eq 0) {
                Add-Finding -Status 'WARN' -Section 'KDC' -Title 'AllowNtAuthPolicyBypass = 0' `
                    -Detail 'NTAuth chain validation bypass is set to regression-only (0). This is a temporary override; expected to be removed by Microsoft.' `
                    -Hypothesis 'Class 5'
            }
        }
    } catch { }
} else {
    if (-not $IsDC) {
        $kdcBody = '<p class="muted">This host is not a domain controller; KDC operational log is not present here. Re-run this script on a DC, or check KDC logs separately.</p>'
    } else {
        $kdcBody = '<p class="muted">Skipped (-SkipDCEvents).</p>'
    }
}
Add-Section -Id 'kdc' -Title '7. KDC / Kerberos events (Domain Controller only)' `
    -Description 'Events 45 (audit) and 21 (deny) under Microsoft-Windows-Kerberos-Key-Distribution-Center indicate CVE-2025-26647 NTAuth chain enforcement. Event 107 = SAN mismatch. AllowNtAuthPolicyBypass override is also reported.' `
    -BodyHtml $kdcBody

# ---------- 8. TPM ----------

Write-Host "[*] Step 8: TPM"
$tpmInfo = $null
try {
    $tpmInfo = Get-Tpm -ErrorAction Stop
} catch {
    Add-Finding -Status 'INFO' -Section 'TPM' -Title 'Get-Tpm failed' -Detail $_.Exception.Message
}
$tpmBody = ''
if ($tpmInfo) {
    $tpmObj = [pscustomobject]@{
        TpmPresent          = $tpmInfo.TpmPresent
        TpmReady            = $tpmInfo.TpmReady
        TpmEnabled          = $tpmInfo.TpmEnabled
        TpmActivated        = $tpmInfo.TpmActivated
        TpmOwned            = $tpmInfo.TpmOwned
        ManufacturerVersion = $tpmInfo.ManufacturerVersion
        ManufacturerVersionFull20 = $tpmInfo.ManufacturerVersionFull20
        ManufacturerIdTxt   = $tpmInfo.ManufacturerIdTxt
        LockedOut           = $tpmInfo.LockedOut
        LockoutCount        = $tpmInfo.LockoutCount
        LockoutMax          = $tpmInfo.LockoutMax
        SelfTest            = $tpmInfo.SelfTest
    }
    $tpmBody = Convert-ObjectToHtmlTable -Objects @($tpmObj)

    if ($tpmInfo.LockedOut) {
        Add-Finding -Status 'CRITICAL' -Section 'TPM' -Title 'TPM is currently LOCKED OUT' `
            -Detail "LockoutCount=$($tpmInfo.LockoutCount) of LockoutMax=$($tpmInfo.LockoutMax). TPM heals one count per ~10 minutes after 32 failed authorisations. PIN unavailable until lockout clears." `
            -Hypothesis 'Class 7: TPM lockout (anti-hammering)'
    } elseif ($null -ne $tpmInfo.LockoutCount -and $null -ne $tpmInfo.LockoutMax -and $tpmInfo.LockoutMax -gt 0 -and $tpmInfo.LockoutCount -ge ([int]($tpmInfo.LockoutMax * 0.8))) {
        Add-Finding -Status 'WARN' -Section 'TPM' -Title "TPM lockout count near max ($($tpmInfo.LockoutCount)/$($tpmInfo.LockoutMax))" `
            -Detail 'Approaching anti-hammering lockout.' `
            -Hypothesis 'Class 7: imminent TPM lockout'
    }
    if (-not $tpmInfo.TpmReady) {
        Add-Finding -Status 'CRITICAL' -Section 'TPM' -Title 'TPM not ready' `
            -Detail "TpmPresent=$($tpmInfo.TpmPresent) Enabled=$($tpmInfo.TpmEnabled) Owned=$($tpmInfo.TpmOwned). WHFB cannot use a TPM-backed key." `
            -Hypothesis 'Class 7: TPM firmware reset / ownership issue'
    }
}

# TPM-WMI events
$tpmEvents = Get-EventsSafe -LogName 'System' -Ids @(1040,1041,1801,1802) -Days $EventLookbackDays
$tpmEventProj = $tpmEvents | Where-Object { $_.ProviderName -like '*TPM*' } |
    Select-Object @{n='Time';e={$_.TimeCreated}}, Id, ProviderName, LevelDisplayName,
                  @{n='Message';e={ ($_.Message -replace '\s+',' ').Trim().Substring(0, [Math]::Min(($_.Message.Length), 400)) }}
$tpmBody += '<h4>TPM-related System events (last ' + $EventLookbackDays + 'd)</h4>'
$tpmBody += Convert-ObjectToHtmlTable -Objects $tpmEventProj -Properties Time,Id,ProviderName,LevelDisplayName,Message

Add-Section -Id 'tpm' -Title '8. TPM state and TPM-WMI events' `
    -Description 'Get-Tpm summary plus System log filtered for TPM provider events 1040/1041/1801/1802.' `
    -BodyHtml $tpmBody

# ---------- 9. NGC keys via certutil + Ngc folder ----------

Write-Host "[*] Step 9: NGC keys (certutil + Ngc folder)"
$certutilOut = ''
try {
    $certutilOut = (& certutil -csp "Microsoft Passport Key Storage Provider" -key 2>&1 | Out-String)
} catch {
    $certutilOut = "certutil failed: $($_.Exception.Message)"
}
$certutilOut | Out-File (Join-Path $rawDumpDir 'certutil-passport-keys.txt') -Encoding utf8

# Parse key container names — they typically include the user UPN
$ngcKeys = @()
$rxKeyName = '(?m)^\s*(?<name>(login\.windows\.net|FIDO|FIDO_AUTHENTICATOR|//9DPC|.+ngc.+|.+Hello.+))\s*$'
$kc = [regex]::Matches($certutilOut, '(?ms)Key\s+Container\s*=\s*(.+?)\r?\n')
foreach ($m in $kc) {
    $ngcKeys += [pscustomobject]@{ KeyContainer = $m.Groups[1].Value.Trim() }
}
$ngcKeyHtml = '<h4>Microsoft Passport KSP key containers</h4>'
if ($ngcKeys.Count -gt 0) {
    $ngcKeyHtml += Convert-ObjectToHtmlTable -Objects $ngcKeys
} else {
    $ngcKeyHtml += '<p class="muted">No Microsoft Passport KSP keys returned. NGC may not be provisioned for this user.</p>'
    Add-Finding -Status 'WARN' -Section 'NGC keys' -Title 'No Microsoft Passport KSP keys for current user' `
        -Detail 'certutil returned no Key Container entries. Either NGC is not provisioned, or the container is corrupted.' `
        -Hypothesis 'Class 8: NGC container corruption'
}

# Try to detect UPN drift: compare current UPN against the bound key name (the bound key contains the UPN)
$currentUpn = $null
try {
    $ws = whoami /upn 2>&1 | Out-String
    $currentUpn = $ws.Trim()
} catch { }
$ngcKeyHtml += '<p>Current UPN (whoami /upn): <code>' + (HtmlEncode "$currentUpn") + '</code></p>'
if ($currentUpn -and $ngcKeys) {
    $upnMatch = $ngcKeys | Where-Object { $_.KeyContainer -like "*$currentUpn*" }
    if (-not $upnMatch) {
        Add-Finding -Status 'WARN' -Section 'NGC keys' -Title 'NGC key container does not match current UPN' `
            -Detail "Current UPN: $currentUpn. Bound key containers: $(($ngcKeys.KeyContainer -join '; '))" `
            -Hypothesis 'Class 6: 24H2 UPN binding drift (this is exactly what destructive PIN reset masks)'
    }
}

$ngcKeyHtml += '<h4>certutil output</h4>'
$ngcKeyHtml += Convert-PreToHtml $certutilOut

# Ngc directory listing (LocalService) — needs elevation
$ngcDirHtml = '<h4>Ngc / Crypto directory layout</h4>'
$ngcPaths = @(
    'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc',
    'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Crypto\Keys',
    'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Crypto\PCPKSP',
    'C:\ProgramData\Microsoft\Crypto\Keys',
    'C:\ProgramData\Microsoft\Crypto\PCPKSP'
)
$ngcDirInfo = @()
foreach ($p in $ngcPaths) {
    $exists = Test-Path -LiteralPath $p
    $count = $null
    $err = $null
    if ($exists) {
        try {
            $count = (Get-ChildItem -LiteralPath $p -Force -Recurse -ErrorAction Stop | Measure-Object).Count
        } catch {
            $err = $_.Exception.Message
        }
    }
    $ngcDirInfo += [pscustomobject]@{
        Path        = $p
        Exists      = $exists
        ItemCount   = $count
        ErrorIfAny  = $err
    }
}
$ngcDirHtml += Convert-ObjectToHtmlTable -Objects $ngcDirInfo
if (-not $IsElevated) {
    $ngcDirHtml += '<p class="muted">Note: not running elevated; some Ngc subpaths require admin to enumerate.</p>'
}

Add-Section -Id 'ngc' -Title '9. NGC / Microsoft Passport KSP keys + Ngc folder layout' `
    -Description 'Bound key containers (UPN drift fingerprint), certutil enumeration, and counts under the Ngc/Crypto folders.' `
    -BodyHtml ($ngcKeyHtml + $ngcDirHtml)

# ---------- 10. msDS-KeyCredentialLink (Key Trust only) ----------

Write-Host "[*] Step 10: msDS-KeyCredentialLink"
$adBody = ''
$adAvailable = $false
if (-not $SkipADQueries) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adAvailable = $true
    } catch {
        $adBody = '<p class="muted">ActiveDirectory module not available on this host. Re-run this script on a DC or admin workstation with RSAT to populate this section.</p>'
    }
}
if ($adAvailable) {
    if (-not $TargetUser) { $TargetUser = $userName }
    try {
        $u = Get-ADUser -Identity $TargetUser -Properties msDS-KeyCredentialLink,UserPrincipalName,whenChanged,whenCreated -ErrorAction Stop
        $kcl = $u.'msDS-KeyCredentialLink'
        $userTbl = [pscustomobject]@{
            sAMAccountName    = $u.SamAccountName
            UPN               = $u.UserPrincipalName
            DistinguishedName = $u.DistinguishedName
            KeyCredentialCount = ($kcl | Measure-Object).Count
            WhenChanged        = $u.whenChanged
        }
        $adBody = Convert-ObjectToHtmlTable -Objects @($userTbl)
        if ($kcl) {
            $adBody += '<h4>msDS-KeyCredentialLink raw entries</h4>'
            $kclProj = @()
            foreach ($entry in $kcl) {
                $kclProj += [pscustomobject]@{
                    Length = $entry.Length
                    First32 = ($entry | Select-Object -First 32) -join ' '
                }
            }
            $adBody += Convert-ObjectToHtmlTable -Objects $kclProj
            $adBody += '<p class="muted">For decoded views (created date, source, key usage) use DSInternals: <code>Get-ADReplAccount -SamAccountName ' + (HtmlEncode $TargetUser) + ' -Server &lt;dc&gt; | Select-Object -ExpandProperty KeyCredentials</code> on a DC.</p>'

            if (($kcl | Measure-Object).Count -gt 1) {
                Add-Finding -Status 'WARN' -Section 'AD' -Title "User has $($kcl.Count) entries in msDS-KeyCredentialLink" `
                    -Detail 'Multiple keys are normal for users with several devices, but fluctuating counts (3 -> 4 -> 3 over hours/days) is the documented Key Trust drift fingerprint. Track the count over a week.' `
                    -Hypothesis 'Class 1: Key Trust drift (under-patched DC writing/deleting key after auth)'
            }
        } else {
            Add-Finding -Status 'WARN' -Section 'AD' -Title "User has no msDS-KeyCredentialLink entries" `
                -Detail 'If the deployment is Key Trust, the absence of any key means WHFB sign-in cannot succeed. Either Entra Connect has not synced, the key was deleted, or the deployment is Cloud Kerberos Trust (in which case this attribute is not used).' `
                -Hypothesis 'Class 1 (if Key Trust); benign if Cloud Kerberos Trust'
        }
    } catch {
        $adBody = '<p class="muted">Get-ADUser failed for ' + (HtmlEncode $TargetUser) + ': ' + (HtmlEncode $_.Exception.Message) + '</p>'
    }

    # krbtgt_AzureAD presence (Cloud Kerberos Trust)
    try {
        $azKrb = Get-ADUser -Filter 'sAMAccountName -like "krbtgt_*"' -Properties whenCreated,whenChanged -ErrorAction Stop |
                 Where-Object { $_.SamAccountName -like 'krbtgt_*' }
        if ($azKrb) {
            $adBody += '<h4>krbtgt_AzureAD account(s)</h4>'
            $adBody += Convert-ObjectToHtmlTable -Objects ($azKrb | Select-Object SamAccountName,DistinguishedName,whenCreated,whenChanged)
        } else {
            Add-Finding -Status 'INFO' -Section 'AD' -Title 'No krbtgt_AzureAD account found' `
                -Detail 'If Cloud Kerberos Trust is the intended model, this account must exist in AD (created by Set-AzureADKerberosServer). Its absence on a hybrid environment expecting CKT means CKT is not actually configured.' `
                -Hypothesis 'Cloud Kerberos Trust misconfiguration (if CKT was intended)'
        }
    } catch { }
}
Add-Section -Id 'ad' -Title '10. AD msDS-KeyCredentialLink (Key Trust drift detection)' `
    -Description 'Number and content of WHFB key credentials bound to the AD user object. Only meaningful for Key Trust deployments.' `
    -BodyHtml $adBody

# ---------- 11. Entra Sign-in logs (manual) ----------

Add-Section -Id 'entra' -Title '11. Entra sign-in logs (manual capture required)' `
    -Description 'Sign-in logs require Microsoft Graph and a privileged role. This script does not authenticate to Graph automatically.' `
    -BodyHtml @"
<p>To capture the equivalent data manually:</p>
<ol>
<li>Open Entra admin center -&gt; Identity -&gt; Monitoring &amp; health -&gt; Sign-in logs</li>
<li>Filter: User = the affected user; Application = <code>Windows Sign In</code> (AppId <code>38aa3b87-a06d-4817-b275-7a316988d93b</code>); Date = last 30 days</li>
<li>Add columns: Authentication requirement, Conditional access, Authentication method, Status, Sign-in error code</li>
<li>Look for Authentication Method = <code>Windows Hello for Business</code> and any failures with AADSTS50034 (UPN), AADSTS135010 (key binding), or CA-driven re-auth</li>
</ol>
<p>Alternatively, with Graph PowerShell installed: <code>Connect-MgGraph -Scopes AuditLog.Read.All; Get-MgAuditLogSignIn -Filter \"userPrincipalName eq '$($currentUpn)' and appId eq '38aa3b87-a06d-4817-b275-7a316988d93b'\" -Top 100</code></p>
"@

# ---------- 12. WHFB policy: GPO + MDM duplication, registry ----------

Write-Host "[*] Step 12: WHFB policy keys (GPO vs MDM duplication)"
$polBody = ''

# Registry tree dump for WHFB-relevant policy paths
$polPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork',
    'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork',
    'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\PassportForWork',
    'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\PassportForWork',
    'HKCU:\SOFTWARE\Microsoft\Policies\PassportForWork',
    'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsHelloForBusiness'
)
$polEntries = @()
foreach ($p in $polPaths) {
    if (Test-Path -LiteralPath $p) {
        try {
            $items = Get-ChildItem -LiteralPath $p -Recurse -ErrorAction SilentlyContinue
            $allKeys = @($p) + ($items | ForEach-Object { $_.PSPath })
            foreach ($k in $allKeys) {
                try {
                    $vals = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
                    foreach ($prop in $vals.PSObject.Properties) {
                        if ($prop.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                        $polEntries += [pscustomobject]@{
                            Path  = ($k -replace '^Microsoft\.PowerShell\.Core\\Registry::','')
                            Name  = $prop.Name
                            Value = "$($prop.Value)"
                        }
                    }
                } catch { }
            }
        } catch { }
    }
}
if ($polEntries.Count -gt 0) {
    $polBody += '<h4>WHFB policy registry values</h4>'
    $polBody += Convert-ObjectToHtmlTable -Objects $polEntries
} else {
    $polBody += '<p class="muted">No WHFB policy registry values found at the standard paths.</p>'
}

# Both GPO and MDM paths populated == duplication risk
$gpoPathsHit = $polEntries | Where-Object { $_.Path -like '*Policies\Microsoft\PassportForWork*' -or $_.Path -like '*Microsoft\Policies\PassportForWork*' }
$mdmPathsHit = $polEntries | Where-Object { $_.Path -like '*PolicyManager*PassportForWork*' }
if ($gpoPathsHit -and $mdmPathsHit) {
    Add-Finding -Status 'WARN' -Section 'Policy' -Title 'Both GPO and MDM (Intune) WHFB policy paths populated' `
        -Detail 'Mixed WHFB policy state is unstable. Microsoft has been deprecating the GPO path. Choose one (GPO or Intune), disable the other.' `
        -Hypothesis 'Policy duplication producing cyclical instability'
}

# UsePassportForWork (the KB5060842 workaround flag)
$upfw = $polEntries | Where-Object Name -eq 'UserPassportForWork'
if ($upfw) {
    $polBody += '<h4>UserPassportForWork override (KB5060842/KB5062553 workaround flag)</h4>'
    $polBody += Convert-ObjectToHtmlTable -Objects $upfw
}

# UseCloudTrustForOnPremAuth, UseCertificateForOnPremAuth — trust model controls
$tm = $polEntries | Where-Object { $_.Name -in 'UseCloudTrustForOnPremAuth','UseCertificateForOnPremAuth','UseHelloCertificatesAsSmartCardCertificates','Enabled' }
if ($tm) {
    $polBody += '<h4>Trust-model and Enabled flags</h4>'
    $polBody += Convert-ObjectToHtmlTable -Objects $tm
    $cloudTrust = $tm | Where-Object { $_.Name -eq 'UseCloudTrustForOnPremAuth' -and $_.Value -eq '1' }
    $certTrust  = $tm | Where-Object { $_.Name -eq 'UseCertificateForOnPremAuth' -and $_.Value -eq '1' }
    if ($cloudTrust) {
        Add-Finding -Status 'OK' -Section 'Policy' -Title 'UseCloudTrustForOnPremAuth = 1 (Cloud Kerberos Trust configured)' `
            -Detail 'Confirm with dsregcmd OnPremTgt = YES to verify it is actually working.' `
            -Hypothesis 'Cloud Kerberos Trust intended (preferred model)'
    }
    if ($certTrust) {
        Add-Finding -Status 'INFO' -Section 'Policy' -Title 'UseCertificateForOnPremAuth = 1 (Cert Trust)' `
            -Detail 'Cert Trust is the legacy model; consider migration to Cloud Kerberos Trust.' `
            -Hypothesis 'Trust model = Cert Trust'
    }
    if (-not $cloudTrust -and -not $certTrust -and ($tm | Where-Object Name -eq 'Enabled' | Where-Object Value -eq '1')) {
        Add-Finding -Status 'INFO' -Section 'Policy' -Title 'WHFB enabled with no explicit trust-model flag' `
            -Detail 'Defaults to Key Trust unless overridden via Intune/GPO. Confirm intended trust model.' `
            -Hypothesis 'Trust model = Key Trust (default) -- Class 1 risk'
    }
}

# gpresult /h
$gpresultPath = Join-Path $rawDumpDir 'gpresult.html'
try {
    & gpresult /h $gpresultPath /f 2>&1 | Out-Null
    if (Test-Path -LiteralPath $gpresultPath) {
        $polBody += '<h4>gpresult /h</h4><p>Saved to: <code>' + (HtmlEncode $gpresultPath) + '</code></p>'
    }
} catch {
    Add-Finding -Status 'INFO' -Section 'Policy' -Title 'gpresult failed' -Detail $_.Exception.Message
}

Add-Section -Id 'policy' -Title '12. WHFB policy duplication and trust-model registry flags' `
    -Description 'GPO vs MDM/Intune policy paths, the UserPassportForWork workaround flag, UseCloudTrustForOnPremAuth, UseCertificateForOnPremAuth, and gpresult.' `
    -BodyHtml $polBody

# ---------- 13. Defender ASR rules + NGC AV exclusions (Class 9) ----------

Write-Host "[*] Step 13: Defender ASR + AV exclusions"
$avBody = ''
try {
    $mp = Get-MpPreference -ErrorAction Stop
    $asrIds = $mp.AttackSurfaceReductionRules_Ids
    $asrAct = $mp.AttackSurfaceReductionRules_Actions
    $asrTable = @()
    if ($asrIds -and $asrAct) {
        for ($i = 0; $i -lt $asrIds.Count; $i++) {
            $asrTable += [pscustomobject]@{
                RuleGuid = $asrIds[$i]
                Action   = switch ($asrAct[$i]) { 0 {'Disabled'}; 1 {'Block'}; 2 {'Audit'}; 6 {'Warn'}; default {"$($asrAct[$i])"} }
                Note     = if ($asrIds[$i] -eq '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2') { 'LSASS credential-stealing rule (the WHFB suspect)' } else { '' }
            }
        }
    }
    $avBody += '<h4>Defender ASR rules</h4>'
    $avBody += Convert-ObjectToHtmlTable -Objects $asrTable

    $lsaRule = $asrTable | Where-Object { $_.RuleGuid -eq '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' }
    if ($lsaRule -and $lsaRule.Action -eq 'Block') {
        Add-Finding -Status 'WARN' -Section 'Defender' -Title 'LSASS credential-stealing ASR rule is in Block mode' `
            -Detail 'Rule 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 in block mode has been correlated (in Q&A threads) with WHFB instability. Consider switching to Audit mode while investigating.' `
            -Hypothesis 'Class 9: Defender ASR interference'
    }

    $exPaths = $mp.ExclusionPath
    $avBody += '<h4>AV path exclusions</h4>'
    if ($exPaths) {
        $avBody += Convert-ObjectToHtmlTable -Objects ($exPaths | ForEach-Object { [pscustomobject]@{ Path = $_ } })
    } else {
        $avBody += '<p class="muted">(none)</p>'
    }

    $ngcExpected = @('Ngc','Crypto')
    $ngcCovered = $false
    foreach ($e in @($exPaths)) {
        if ($e -like '*Ngc*' -or $e -like '*Crypto*') { $ngcCovered = $true; break }
    }
    if (-not $ngcCovered) {
        Add-Finding -Status 'INFO' -Section 'Defender' -Title 'No NGC/Crypto path exclusion in Defender' `
            -Detail 'Microsoft Q&A recommends excluding C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc and C:\ProgramData\Microsoft\Crypto from real-time scanning when AV-correlated PIN failures are suspected.' `
            -Hypothesis 'Class 9: AV interference (low priority unless evidence supports it)'
    }
} catch {
    $avBody = '<p class="muted">Get-MpPreference unavailable: ' + (HtmlEncode $_.Exception.Message) + '</p>'
}

# Third-party AV detection
try {
    $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    if ($av) {
        $avBody += '<h4>Registered antivirus products</h4>'
        $avBody += Convert-ObjectToHtmlTable -Objects ($av | Select-Object displayName,pathToSignedProductExe,productState)
    }
} catch { }

Add-Section -Id 'av' -Title '13. Defender ASR rules and AV exclusions (Class 9 fingerprint)' `
    -Description 'LSASS credential-stealing ASR rule status, AV exclusion paths, and registered AV products.' `
    -BodyHtml $avBody

# ---------- 14. Network reachability of WHFB endpoints ----------

Write-Host "[*] Step 14: WHFB endpoint reachability"
$endpoints = @(
    'login.microsoftonline.com',
    'enterpriseregistration.windows.net',
    'device.login.microsoftonline.com',
    'autologon.microsoftazuread-sso.com',
    'aadcdn.msftauth.net'
)
$reachRows = @()
foreach ($ep in $endpoints) {
    $row = [pscustomobject]@{
        Endpoint   = $ep
        DnsResolves = $false
        TcpReachable = $false
        Notes       = ''
    }
    try {
        $dns = Resolve-DnsName -Name $ep -ErrorAction Stop
        $row.DnsResolves = $true
        $row.Notes = ($dns | Where-Object IPAddress | Select-Object -First 1 -ExpandProperty IPAddress)
    } catch {
        $row.Notes = 'DNS failed: ' + $_.Exception.Message
    }
    if ($row.DnsResolves) {
        try {
            $tnc = Test-NetConnection -ComputerName $ep -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            $row.TcpReachable = $tnc
        } catch {
            $row.Notes += ' tcp443: ' + $_.Exception.Message
        }
    }
    $reachRows += $row
}
$reachBody = Convert-ObjectToHtmlTable -Objects $reachRows
$unreachable = $reachRows | Where-Object { -not $_.TcpReachable }
if ($unreachable) {
    Add-Finding -Status 'WARN' -Section 'Network' -Title "$($unreachable.Count) WHFB endpoint(s) unreachable on TCP/443" `
        -Detail (($unreachable.Endpoint) -join ', ') `
        -Hypothesis 'Class 2: PRT renewal failure (blocked endpoint = stale PRT after 14 days)'
}
Add-Section -Id 'net' -Title '14. WHFB endpoint reachability' `
    -Description 'login.microsoftonline.com and enterpriseregistration.windows.net being blocked is the typical cause of PRT renewal failure leading to the 14-day cadence.' `
    -BodyHtml $reachBody

# ---------- Build executive summary / triage ranking ----------

Write-Host "[*] Building executive summary"

$crit = @($script:Findings | Where-Object Status -eq 'CRITICAL')
$warn = @($script:Findings | Where-Object Status -eq 'WARN')
$ok   = @($script:Findings | Where-Object Status -eq 'OK')
$info = @($script:Findings | Where-Object Status -eq 'INFO')

# Score the nine root cause classes based on evidence
$classScores = [ordered]@{
    'Class 1: Hybrid Key Trust drift in msDS-KeyCredentialLink' = 0
    'Class 2: PRT renewal failure (14-day sliding window)' = 0
    'Class 3: Conditional Access Sign-in Frequency cadence' = 0
    'Class 4: KB5060842/KB5062553 UsePassportForWork user-scope bug' = 0
    'Class 5: CVE-2025-26647 Kerberos NTAuth chain enforcement' = 0
    'Class 6: 24H2 strict UPN binding drift' = 0
    'Class 7: TPM lockout / firmware reset' = 0
    'Class 8: NGC container corruption' = 0
    'Class 9: Defender ASR / AV interference' = 0
}
$classKeys = @($classScores.Keys)
foreach ($f in $script:Findings) {
    $weight = switch ($f.Status) { 'CRITICAL' {3}; 'WARN' {2}; 'INFO' {1}; default {0} }
    foreach ($k in $classKeys) {
        $key = $k.Substring(0, [Math]::Min($k.Length, 8))  # 'Class 1:'
        if ($f.Hypothesis -like "*$key*") {
            $classScores[$k] = $classScores[$k] + $weight
        }
    }
}
$ranked = $classScores.GetEnumerator() | Where-Object { $_.Value -gt 0 } | Sort-Object Value -Descending

$rankRows = @()
foreach ($r in $ranked) {
    $rankRows += [pscustomobject]@{ Class = $r.Key; EvidenceScore = $r.Value }
}

# ---------- Render HTML ----------

Write-Host "[*] Rendering HTML"

$css = @"
<style>
body { font-family: 'Segoe UI', Calibri, Arial, sans-serif; background: #f4f6fa; color: #1a1a1a; margin: 0; padding: 0; }
header { background: #0b3a5b; color: #fff; padding: 24px 32px; }
header h1 { margin: 0 0 6px 0; font-size: 22px; }
header .meta { color: #cbd9e4; font-size: 13px; }
nav { background: #143b59; color: #cbd9e4; padding: 8px 32px; font-size: 13px; }
nav a { color: #9bd2ff; margin-right: 14px; text-decoration: none; }
nav a:hover { text-decoration: underline; }
main { padding: 24px 32px; }
section { background: #fff; border: 1px solid #d6dee7; border-radius: 6px; margin: 0 0 18px 0; padding: 18px 22px; }
section h2 { margin-top: 0; font-size: 17px; color: #0b3a5b; border-bottom: 1px solid #e2e7ee; padding-bottom: 6px; }
section h4 { margin: 14px 0 6px 0; font-size: 13px; color: #444; }
section p.desc { color: #4a5a6b; font-size: 13px; margin: 0 0 10px 0; }
table.data { border-collapse: collapse; width: 100%; font-size: 12px; margin: 6px 0; }
table.data th { background: #eef3f8; text-align: left; padding: 6px 8px; border: 1px solid #d6dee7; }
table.data td { padding: 5px 8px; border: 1px solid #e2e7ee; vertical-align: top; word-break: break-word; }
pre.raw { background: #0d1117; color: #c9d1d9; padding: 10px 12px; border-radius: 4px; font-size: 11.5px; white-space: pre-wrap; max-height: 360px; overflow: auto; }
.status-CRITICAL { background: #c62828; color: #fff; padding: 2px 8px; border-radius: 3px; font-weight: 600; font-size: 11px; }
.status-WARN { background: #ef8b00; color: #fff; padding: 2px 8px; border-radius: 3px; font-weight: 600; font-size: 11px; }
.status-OK { background: #2e7d32; color: #fff; padding: 2px 8px; border-radius: 3px; font-weight: 600; font-size: 11px; }
.status-INFO { background: #455a64; color: #fff; padding: 2px 8px; border-radius: 3px; font-weight: 600; font-size: 11px; }
.muted { color: #888; font-style: italic; font-size: 12px; }
.summary-box { padding: 14px 18px; border-left: 4px solid #0b3a5b; background: #eef5fb; margin-bottom: 14px; }
.findings-list { font-size: 13px; }
.findings-list li { margin: 4px 0; }
code { background: #f0f3f7; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
.tag-class { background: #d6e6f5; color: #0b3a5b; padding: 1px 6px; border-radius: 3px; font-size: 11px; }
</style>
"@

$nav = '<nav>' + (
    ($script:Sections | ForEach-Object { '<a href="#' + $_.Id + '">' + (HtmlEncode ($_.Title -replace '^\d+\.\s*','')) + '</a>' }) -join ''
) + '</nav>'

# Findings table
$findingsHtml = '<table class="data"><thead><tr><th>Status</th><th>Section</th><th>Title</th><th>Hypothesis</th><th>Detail</th></tr></thead><tbody>'
foreach ($f in ($script:Findings | Sort-Object @{e={ switch ($_.Status) { 'CRITICAL' {0}; 'WARN' {1}; 'INFO' {2}; 'OK' {3} } }}, Section)) {
    $findingsHtml += '<tr>'
    $findingsHtml += '<td><span class="status-' + $f.Status + '">' + $f.Status + '</span></td>'
    $findingsHtml += '<td>' + (HtmlEncode $f.Section) + '</td>'
    $findingsHtml += '<td>' + (HtmlEncode $f.Title) + '</td>'
    $findingsHtml += '<td>' + (HtmlEncode $f.Hypothesis) + '</td>'
    $findingsHtml += '<td>' + (HtmlEncode $f.Detail) + '</td>'
    $findingsHtml += '</tr>'
}
$findingsHtml += '</tbody></table>'

# Class ranking
$rankHtml = '<table class="data"><thead><tr><th>Rank</th><th>Root-cause class</th><th>Evidence score</th></tr></thead><tbody>'
$ix = 0
foreach ($r in $ranked) {
    $ix++
    $rankHtml += '<tr><td>' + $ix + '</td><td>' + (HtmlEncode $r.Key) + '</td><td>' + $r.Value + '</td></tr>'
}
$rankHtml += '</tbody></table>'
if (-not $ranked) {
    $rankHtml = '<p class="muted">No findings mapped to root-cause classes. Review the per-section evidence directly.</p>'
}

$execSummary = @"
<section>
  <h2>Executive summary</h2>
  <div class="summary-box">
    <p><strong>Host:</strong> $(HtmlEncode $hostName) &nbsp; <strong>User:</strong> $(HtmlEncode "$userDomain\$userName") &nbsp; <strong>Inferred trust model:</strong> $(HtmlEncode $trustModel)</p>
    <p><strong>OS build:</strong> $(HtmlEncode "$($envInfo['BuildDotUBR']) ($($envInfo['DisplayVersion']))") &nbsp; <strong>TPM ready:</strong> $(if ($tpmInfo) { HtmlEncode ([string]$tpmInfo.TpmReady) } else { 'unknown' }) &nbsp; <strong>NgcSet:</strong> $(HtmlEncode $dsregFields['NgcSet']) &nbsp; <strong>AzureAdPrt:</strong> $(HtmlEncode $dsregFields['AzureAdPrt'])</p>
    <p><strong>Findings:</strong> $($crit.Count) critical, $($warn.Count) warn, $($info.Count) info, $($ok.Count) ok</p>
  </div>
  <h4>Root-cause class ranking by evidence weight</h4>
  $rankHtml
  <h4>All findings (sorted by severity)</h4>
  $findingsHtml
</section>
"@

# Section bodies
$sectionsHtml = ''
foreach ($s in $script:Sections) {
    $sectionsHtml += '<section id="' + $s.Id + '">'
    $sectionsHtml += '<h2>' + (HtmlEncode $s.Title) + '</h2>'
    if ($s.Description) {
        $sectionsHtml += '<p class="desc">' + (HtmlEncode $s.Description) + '</p>'
    }
    $sectionsHtml += $s.BodyHtml
    $sectionsHtml += '</section>'
}

$elapsed = (Get-Date) - $script:StartTime

$html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WHFB Audit Report - $(HtmlEncode $hostName) - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</title>
$css
</head><body>
<header>
  <h1>Windows Hello for Business - Diagnostic and Audit Report</h1>
  <div class="meta">Host <strong>$(HtmlEncode $hostName)</strong> | User <strong>$(HtmlEncode "$userDomain\$userName")</strong> | Generated <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')</strong> | Elapsed <strong>$([int]$elapsed.TotalSeconds)s</strong> | Elevated <strong>$IsElevated</strong> | DC <strong>$IsDC</strong> | Lookback <strong>${EventLookbackDays}d</strong></div>
</header>
$nav
<main>
$execSummary
$sectionsHtml
</main>
<footer style="padding:18px 32px;color:#789;font-size:12px;">Diagnostic capture only — no remediation actions performed. Raw outputs saved to <code>$(HtmlEncode $rawDumpDir)</code>.</footer>
</body></html>
"@

$html | Out-File -LiteralPath $reportPath -Encoding utf8
Write-Host ""
Write-Host "[+] Report: $reportPath"
Write-Host "[+] Raw dump dir: $rawDumpDir"
Write-Host "[+] Findings: $($crit.Count) CRITICAL, $($warn.Count) WARN, $($info.Count) INFO, $($ok.Count) OK"
Write-Host "[+] Elapsed: $([int]$elapsed.TotalSeconds)s"
