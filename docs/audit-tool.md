# Invoke-WHFBAudit.ps1 — Operator Guide

A read-only diagnostic and audit tool for Windows Hello for Business (WHFB) PIN failures. Captures all 12 data points from the field-guide flow and renders a self-contained HTML report. **Diagnosis only — performs no remediation.**

## When to use it

Run this **before** any destructive action (PIN reset, container delete, profile reassignment) on a user that is hitting recurring "That option is temporarily unavailable" / "Your PIN isn't available" failures. The script collects every signal needed to localize root cause to one of the [nine documented classes](root-causes.md), so the next remediation can be deterministic instead of trial-and-error.

Typical scenarios:

- A user PIN is failing **right now** — run as that user on that workstation, before resetting
- Triaging a 2–4 week recurrence pattern across a fleet — run on each affected machine and compare reports
- Validating a recent migration (e.g., Key Trust → Cloud Kerberos Trust) — run on a sample of machines after the change
- Pre-change baseline — run before pushing an Intune profile change so you have a known-good capture to diff against

## Where to run it

| Run on | What works | What is skipped |
|---|---|---|
| Affected workstation, **as the affected user**, not elevated | dsregcmd, NGC certutil, all client event logs, policy registry, network reachability, AV/ASR | TPM details (need elevation), AD attributes, KDC events |
| Affected workstation, **as the affected user**, **elevated** | All of the above plus `Get-Tpm`, full Ngc directory enumeration, gpresult | AD attributes, KDC events |
| **Domain controller**, elevated | KDC operational log (CVE-2025-26647), `msDS-KeyCredentialLink`, `krbtgt_AzureAD` lookup | User-side NGC/PRT (this is a DC, not the user's machine) |
| Admin workstation with RSAT, elevated, `-TargetUser <sam>` | Adds `msDS-KeyCredentialLink` lookup for the named user | Same as elevated workstation run |

The richest single capture is **as the affected user, elevated, on the affected workstation, while the failure is reproducible**. Run the DC-side capture separately and combine the two reports.

## Parameters

```powershell
.\Invoke-WHFBAudit.ps1 [-OutputPath <string>] [-EventLookbackDays <int>] [-SkipADQueries] [-SkipDCEvents] [-TargetUser <sam>]
```

| Parameter | Default | Purpose |
|---|---|---|
| `-OutputPath` | `C:\code\WHFB\Reports` | Folder where the HTML report and raw-dump folder are written. Created if missing. |
| `-EventLookbackDays` | `60` | Event-log scan window. 60 days covers two cycles of the typical 14–30 day recurrence; raise to 90 for slower cadences. |
| `-SkipADQueries` | off | Skip `Get-ADUser` and `krbtgt_AzureAD` lookups. Use when the AD module isn't loaded and you don't care to install RSAT. |
| `-SkipDCEvents` | off | Skip the KDC operational log scan. Auto-skipped when not running on a DC. |
| `-TargetUser` | current user's `sAMAccountName` | sAMAccountName for AD-side `msDS-KeyCredentialLink` lookup. Only meaningful when AD module is available. |

## Examples

```powershell
# Most common: run on the affected workstation, elevated, as the affected user
.\Invoke-WHFBAudit.ps1

# Triage with longer history and a custom output path
.\Invoke-WHFBAudit.ps1 -OutputPath C:\Temp\WHFB -EventLookbackDays 90

# DC-side capture for a specific user
.\Invoke-WHFBAudit.ps1 -TargetUser jsmith -EventLookbackDays 90

# Workstation run where AD/RSAT isn't installed
.\Invoke-WHFBAudit.ps1 -SkipADQueries
```

## Output

Two artifacts per run, both under `-OutputPath`:

- `WHFB-Audit-<host>-<user>-<timestamp>.html` — self-contained HTML report (single file, no external assets)
- `WHFB-Audit-Raw-<host>-<user>-<timestamp>\` — raw-dump folder containing `dsregcmd-status.txt`, `certutil-passport-keys.txt`, and `gpresult.html`

A typical report is 30–80 KB and renders cleanly in any modern browser. There are no external network requests in the rendered page.

## How to read the report

The report is structured as:

1. **Executive summary** — host, user, inferred trust model, OS build, and finding counts
2. **Root-cause class ranking** — the [nine classes](root-causes.md) ranked by total evidence weight (each finding contributes CRITICAL=3, WARN=2, INFO=1 to the class it points to). The top 1–2 classes are where to look first.
3. **All findings** sorted CRITICAL → WARN → INFO → OK, with a Hypothesis column tying each finding to a class
4. **Section-by-section captures** — every data point with both parsed tables and raw output

### Triage flow

1. Look at the **class ranking**. If one class dominates by a large margin, start there.
2. Read the **CRITICAL findings** in order. Each finding's "Hypothesis" column names the class. The "Detail" column has the evidence.
3. If `7055 + 7703` are both present in the Application log section, **stop reading** — that's the [KB5060842/KB5062553 fingerprint](root-causes.md#class-4--kb5060842kb5062553-usepassportforwork-user-scope-bug) and the workaround is well-documented.
4. If `OnPremTgt: NO` and the policy section shows `UseCloudTrustForOnPremAuth = 1`, Cloud Kerberos Trust is configured but not working — see the on-prem `krbtgt_AzureAD` requirement in the AD section.
5. If the AD section shows the user's `msDS-KeyCredentialLink` count fluctuating across runs done a day apart, that's [Class 1 Key Trust drift](root-causes.md#class-1--hybrid-key-trust-drift-in-msds-keycredentiallink).
6. If `AzureAdPrt: YES` but `AzureAdPrtUpdateTime` is more than 4 hours old, the section flags that — that's [Class 2 PRT renewal failure](root-causes.md#class-2--prt-renewal-failure-14-day-sliding-window).
7. Anything left? Walk the full findings table.

## What the script does NOT do

- **No remediation.** It will not delete the NGC container, reset the PIN, restart services, modify registry, or change Intune assignments.
- **No Microsoft Graph calls.** Entra sign-in logs must be captured manually (the report includes the recommended filter).
- **No data exfiltration.** Everything stays on the local filesystem under `-OutputPath`. Nothing is uploaded.
- **No fix recommendations in the report itself.** The Hypothesis column points to a class; the [root-causes doc](root-causes.md) has the corresponding remediation context.

## Privacy and what gets captured

The HTML report contains:

- Hostname, username, domain, UPN of the running user
- Tenant ID and Tenant Name (from `dsregcmd`)
- Device ID, device certificate thumbprint
- Build numbers, hotfix list, BIOS version, manufacturer/model
- Event-log snippets (truncated to ~400–600 chars per event)
- Policy registry values under `PassportForWork`
- AADSTS error codes seen in client logs

The report does **not** contain plaintext passwords, PINs, private keys, or recovery keys. Treat the report and raw-dump folder as **internal IT troubleshooting data** — don't post the full HTML to public forums without sanitizing UPN, Tenant ID, and Device ID first.

## Performance

- Typical run on a domain-joined workstation: 8–15 seconds
- Domain controller with 90-day event lookback: 30–60 seconds
- Network reachability checks add ~5 seconds (Test-NetConnection per endpoint, sequentially)

## PowerShell compatibility

- **Required:** PowerShell 5.1 (the inbox version on Windows 10/11)
- Tested on Windows 11 24H2 (build 26100.x) and 25H2 (build 26200.x)
- No external module dependencies for the workstation run; the AD module is only required for the `msDS-KeyCredentialLink` section

## Re-running and comparing

Each run produces a uniquely-named report. To detect Key Trust drift specifically:

```powershell
# Run today
.\Invoke-WHFBAudit.ps1 -TargetUser jsmith
# Wait 24 hours, run again
.\Invoke-WHFBAudit.ps1 -TargetUser jsmith
# Diff the AD section: KeyCredentialCount and the entry hashes
```

A `msDS-KeyCredentialLink` count that goes 3 → 4 → 3 → 4 across runs hours apart is the documented Key Trust drift fingerprint.

## See also

- [Root-cause classes](root-causes.md)
- [Manual 12-step diagnostic flow](diagnostic-flow.md) — for cases where running the script isn't possible
