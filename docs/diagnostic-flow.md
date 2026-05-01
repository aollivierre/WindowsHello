# Manual 12-step WHFB diagnostic flow

The capture sequence the [audit script](audit-tool.md) automates. Use this when the script can't run (locked-down environment, can't get PowerShell, or you're walking a remote tech through it on the phone).

> **Run this on the next user that breaks. Capture output BEFORE remediation.** The destructive PIN reset (`certutil -DeleteHelloContainer`) destroys the very evidence needed to localize root cause.

The output of steps **1, 2, 3, and 6** localizes root cause in 80% of cases. Steps 7 and 10 catch Key-Trust-specific issues; 8 and 9 catch TPM/UPN-binding issues; 11 catches Conditional Access cadence.

---

## 1. `dsregcmd /status`

**Run as:** affected user on affected workstation, **not elevated**.

```powershell
dsregcmd /status > C:\Temp\dsreg.txt
```

**What you're looking for:**

| Field | Healthy value | Diagnostic meaning if not |
|---|---|---|
| `AzureAdJoined` / `DomainJoined` | YES per deployment model | Wrong join state |
| `DeviceAuthStatus` | SUCCESS | Device cert / transport key broken |
| `TpmProtected` | YES | Falling back to software KSP — Class 7 |
| `NgcSet` | YES | Container missing — Class 8 (or 4) |
| `AzureAdPrt` | YES | No PRT — Class 2 |
| `AzureAdPrtUpdateTime` | < 4 hours old | PRT renewal failing — Class 2 |
| `OnPremTgt` | YES (Cloud Kerberos Trust only) | CKT not actually working |
| AcquirePrtDiagnostics | (no errors) | HTTP 400 + AADSTS code identifies the failure |
| RefreshPrtDiagnostics | (no errors) | Renewal-path failure |

The `AcquirePrtDiagnostics` and `RefreshPrtDiagnostics` blocks at the bottom of the output contain the most actionable information for Class 2 — pull the `Server Error Code` and look up the AADSTS code.

---

## 2. HelloForBusiness/Operational

**Path:** Event Viewer → Applications and Services Logs → Microsoft → Windows → HelloForBusiness/Operational

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-HelloForBusiness/Operational' -MaxEvents 200 |
    Where-Object Id -in 5001,5002,8200,8202,8203,7054,7055,7201,7204
```

| ID | Meaning |
|---|---|
| 5001 | Deployment type — confirms which trust model is actually in use |
| 5002 | Gesture (PIN, fingerprint, face) |
| 8200 / 8202 / 8203 | Provisioning steps |
| 7054 / 7201 / 7204 | Prerequisite failures |
| 7055 | NGC container provisioning failed (paired with App log 7055 — Class 4 fingerprint) |

---

## 3. User Device Registration / Admin

**Path:** Event Viewer → Applications and Services Logs → Microsoft → Windows → User Device Registration / Admin

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-User Device Registration/Admin' -MaxEvents 200 |
    Where-Object Id -in 300,360,362,363
```

| ID | Meaning |
|---|---|
| 300 | Key registered with Entra — match against a known good baseline date |
| 360 | Provisioning won't launch — body lists which prerequisite failed |
| 362 | STS authentication failure during NGC registration |
| 363 | NGC key missing — Class 1 or Class 8 |

The body of Event 360 enumerates every prerequisite (`IsDeviceJoined`, `IsUserAzureAD`, `PolicyEnabled`, `PostLogonEnabled`, `DeviceEligible`, `SessionIsNotRemote`, `CertEnrollment`) — this is the single most informative event for "PIN won't provision at all" cases.

---

## 4. AAD/Operational

**Path:** Event Viewer → Applications and Services Logs → Microsoft → Windows → AAD → Operational

(For deeper troubleshooting also enable AAD/Analytic in the View → Show Analytic and Debug Logs menu.)

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-AAD/Operational' -MaxEvents 200 |
    Where-Object Id -in 1006,1007,1081,1088,1098
```

| ID | Meaning |
|---|---|
| 1006 / 1007 | PRT acquisition begin / end — non-zero result codes localize PRT failures |
| 1081 / 1088 | Token errors — body contains AADSTS codes |
| 1098 | Token broker (WAM) errors |

Extract every `AADSTS\d+` code that appears, count occurrences, and look up the codes at <https://login.microsoftonline.com/error>.

Common codes:

- `AADSTS50034` — user not found (Class 6 UPN drift)
- `AADSTS50097` — device authentication required
- `AADSTS50158` — external security challenge / CA reauth required (Class 3)
- `AADSTS135010` — missing key binding (Class 6)

---

## 5. Crypto-NCrypt/Operational

**Path:** Event Viewer → Applications and Services Logs → Microsoft → Windows → Crypto-NCrypt → Operational

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Crypto-NCrypt/Operational' -MaxEvents 200 |
    Where-Object { $_.Id -eq 1 -and $_.Message -like '*Microsoft Passport*' }
```

Look for these hex codes:

| Code | Meaning |
|---|---|
| `0x80090010` | NTE_PERM — **Class 4** fingerprint (with Event 7055/7703) |
| `0x80090011` | NTE_NOT_FOUND — Class 8 |
| `0x80090016` | NTE_BAD_KEYSET — Class 8 (corrupted container) |
| `0x80090029` | TPM not setup — Class 7 |
| `0xC000005E` | STATUS_NO_LOGON_SERVERS — Class 2 (Cloud Kerberos cascade) |
| `0xC000006D` | STATUS_LOGON_FAILURE — Class 6 (UPN drift) |

---

## 6. Application log: Events 7055 and 7703

**Path:** Event Viewer → Windows Logs → Application

```powershell
Get-WinEvent -LogName Application -MaxEvents 500 | Where-Object Id -in 7055,7703
```

| ID | Source | Meaning |
|---|---|---|
| 7055 | (varies) | Windows Hello container provisioning failed with error 0x80090010 |
| 7703 | (varies) | Windows Hello for Business policy is disabled, causing operation failure |

**If both are present together with `0x80090010` in NCrypt, this is the published fingerprint of the KB5060842/KB5062553 `UsePassportForWork` user-scope bug (Class 4).** Look at this combination first if failures started after June 2025 — workaround takes minutes.

---

## 7. KDC operational log (DC only)

**Path:** Event Viewer on a DC → Applications and Services Logs → Microsoft → Windows → Kerberos-Key-Distribution-Center → Operational

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational' -MaxEvents 200 |
    Where-Object Id -in 21,45,107
```

| ID | Meaning |
|---|---|
| 45 | NTAuth chain audit (CVE-2025-26647 audit phase) |
| 21 | NTAuth chain deny (CVE-2025-26647 enforcement — auth fails) |
| 107 | KDC certificate SAN mismatch |

Also check the registry override:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name AllowNtAuthPolicyBypass -ErrorAction SilentlyContinue
# 0 = disabled (regression-only, temporary)
# 1 = audit
# 2 = enforce
```

This is **Class 5**. Migrate to Cloud Kerberos Trust to remove the dependency entirely.

---

## 8. TPM state

```powershell
Get-Tpm | Select TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,
    ManufacturerVersionFull20,LockedOut,LockoutCount,LockoutMax

Get-WinEvent -LogName System -MaxEvents 500 |
    Where-Object { $_.ProviderName -like '*TPM*' -and $_.Id -in 1040,1041,1801,1802 }
```

| Signal | Meaning |
|---|---|
| `LockedOut: True` | Anti-hammering lockout — heals one count per ~10 min |
| `LockoutCount` near `LockoutMax` | Approaching lockout |
| `TpmReady: False` | Firmware reset / ownership issue |
| Event 1040 | Measured boot failure |
| Event 1801 | TPM not ready |

`Get-Tpm | Select ManufacturerVersionFull20` reveals fTPM/PTT firmware version — important for Ryzen and Intel platforms with known firmware drift.

---

## 9. NGC keys via certutil

```powershell
certutil -csp "Microsoft Passport Key Storage Provider" -key
whoami /upn
```

The Key Container names typically include the user UPN. **If the bound UPN does not match the current `whoami /upn`**, you have Class 6 UPN binding drift — that's exactly what destructive PIN reset masks.

`NgcKeyImplType: 1` in the output confirms TPM-backed; absence indicates software KSP fallback.

If `certutil` returns no Key Container entries at all, NGC is not provisioned for this user — Class 8.

---

## 10. `msDS-KeyCredentialLink` (Key Trust only)

**Run on:** a DC, or an admin workstation with the AD module / RSAT installed.

```powershell
Get-ADUser -Identity <sam> -Properties msDS-KeyCredentialLink |
    Select-Object SamAccountName, UserPrincipalName,
        @{n='KeyCount';e={ ($_.'msDS-KeyCredentialLink' | Measure-Object).Count }}
```

For decoded views (creation date, source, key usage) install **DSInternals** and use:

```powershell
# On a DC, against the local replica
Get-ADReplAccount -SamAccountName <sam> -Server $env:COMPUTERNAME |
    Select-Object -ExpandProperty KeyCredentials
```

**Track the count over a week.** A count fluctuating between 3 → 4 → 3 → 4 is the documented Class 1 Key Trust drift fingerprint.

Also verify Cloud Kerberos Trust setup:

```powershell
Get-AzureADKerberosServer -Domain <fqdn>
# Expect a healthy AzureADKerberos RODC object
Get-ADUser -Filter 'sAMAccountName -like "krbtgt_*"' | Where-Object SamAccountName -like 'krbtgt_*'
# Expect a krbtgt_AzureAD account if CKT is configured
```

If Cloud Kerberos Trust is intended but the `krbtgt_AzureAD` account is missing, CKT was never properly configured — that's the Rahul Jindal failure mode.

---

## 11. Entra Sign-in logs

**Where:** Entra admin center → Identity → Monitoring & health → Sign-in logs

**Filter:**

- User: the affected user
- Application: `Windows Sign In` (App ID `38aa3b87-a06d-4817-b275-7a316988d93b`)
- Date: last 30 days

**Add columns:** Authentication requirement, Conditional access, Authentication method, Status, Sign-in error code

**Look for:**

- Authentication Method = `Windows Hello for Business`
- Failure correlation IDs paired with AADSTS50034 / AADSTS135010 / CA-driven reauth
- The CA policy that triggered any reauth (column "Conditional access" → expand → policy name)

Or via Microsoft Graph PowerShell:

```powershell
Connect-MgGraph -Scopes AuditLog.Read.All
Get-MgAuditLogSignIn -Filter "userPrincipalName eq '<upn>' and appId eq '38aa3b87-a06d-4817-b275-7a316988d93b'" -Top 100 |
    Select-Object createdDateTime, appDisplayName, status, conditionalAccessStatus,
        @{n='AuthMethod';e={ $_.authenticationDetails.authenticationMethod -join ', ' }},
        @{n='ErrorCode';e={ $_.status.errorCode }}
```

This is the only place the Conditional Access cadence (Class 3) is conclusively visible.

---

## 12. Policy duplication and trust-model flags

```powershell
gpresult /h C:\Temp\gpresult.html /f

# WHFB-relevant policy registry tree
reg query 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\PassportForWork' /s
reg query 'HKLM\SOFTWARE\Policies\Microsoft\PassportForWork' /s
reg query 'HKLM\SOFTWARE\Microsoft\Policies\PassportForWork' /s
```

**Look for these conflicts and flags:**

| Path / Value | Meaning |
|---|---|
| Both `Policies\Microsoft\PassportForWork` (GPO) AND `PolicyManager\current\device\PassportForWork` (MDM) populated | Policy duplication — unstable, choose one |
| `UseCloudTrustForOnPremAuth = 1` | Cloud Kerberos Trust intended; verify with `dsregcmd OnPremTgt: YES` |
| `UseCertificateForOnPremAuth = 1` | Cert Trust (legacy) |
| Neither flag set, `Enabled = 1` | Defaults to Key Trust — Class 1 risk |
| `UserPassportForWork` (note: under `Microsoft\Policies\PassportForWork`, not `Policies\Microsoft\…`) | Class 4 workaround flag |

In hybrid MSP environments it is common to see the legacy "Use Windows Hello for Business" GPO applied via Domain GPO, the Intune Account Protection profile, and the tenant-wide WHFB enrollment toggle in Entra all in play simultaneously. **Pick one source of truth**, disable the others.

---

## What you should have when done

A folder containing:

- `dsreg.txt` (step 1)
- HelloForBusiness, User Device Registration, AAD, Crypto-NCrypt event exports (steps 2–5)
- Application log filtered for 7055/7703 (step 6)
- KDC log if you ran on a DC (step 7)
- `Get-Tpm` output and TPM-WMI events (step 8)
- `certutil -csp "Microsoft Passport Key Storage Provider" -key` and `whoami /upn` (step 9)
- `msDS-KeyCredentialLink` count for the user (step 10)
- Entra sign-in log CSV export filtered to Windows Sign In (step 11)
- `gpresult /h` and registry exports (step 12)

Then map findings to the [nine root-cause classes](root-causes.md) and pick the dominant one.

If running this manually feels tedious — that's exactly why [`Invoke-WHFBAudit.ps1`](audit-tool.md) exists. One invocation, one HTML report, all 12 steps.
