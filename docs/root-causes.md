# WHFB recurring PIN failures — the nine root-cause classes

Field-evidence-derived taxonomy of cyclical WHFB PIN failures. Drawn from Microsoft Q&A threads, Microsoft Learn known-issue articles, MVP write-ups, and Microsoft release-health entries 2023–2026. The [audit script](audit-tool.md) tags each finding it surfaces with one of these class labels so the per-run report ranks them by evidence weight.

## Why a 2–4 week cadence is diagnostic

WHFB has very few moving parts whose lifetimes fall in a 2–4 week window. Mapping the recurrence to documented Microsoft component lifetimes narrows the suspect list immediately:

| Component | Lifetime | Maps to recurrence? |
|---|---|---|
| Primary Refresh Token (PRT) | 90d cap, **14-day sliding inactivity window** | YES — strong fortnightly match |
| Refresh tokens | Identical 14-day sliding window | YES |
| Conditional Access Sign-in Frequency | Commonly 1 / 7 / **14** / **30** days | YES at 14 and 30 |
| Cloud Kerberos partial TGT | Issued with the PRT | YES — cascades from PRT |
| WHFB auth cert (Cert Trust) | 1 year default | NO |
| AzureAD device cert | 1 day, renewed daily | NO |
| Kerberos TGT | 10h / 7d renewable | NO |
| `msDS-KeyCredentialLink` | No expiry on the attribute itself | NO — but attribute drift is bug-driven |
| TPM AIK | Long-lived | NO |
| Group Policy refresh | 90 minutes | Too frequent |
| Intune sync | ~8 hours | Too frequent |

**Failure interval near 2 weeks** → prioritize Class 2 (PRT) and Class 3 (CA SIF=14d). **Failure interval near a month** → prioritize Class 3 (CA SIF=30d) and Class 1 (Key Trust drift, which often shows up monthly as cumulative replication divergence).

---

## Class 1 — Hybrid Key Trust drift in `msDS-KeyCredentialLink`

**Affects:** Hybrid environments running **Key Trust** (not Cloud Kerberos Trust, not Cert Trust).

**Mechanism:** The user's WHFB public key is written to AD as `msDS-KeyCredentialLink` by Entra Connect. Specific unpatched DC builds *delete* the attribute after authenticating the user. Subsequent sign-ins fail until the next Entra Connect delta sync (default 30 minutes) re-writes the key. With a mixed-patch DC fleet, this presents as intermittent failures that worsen over days/weeks until users hit a hard wall.

**Affected DC builds:** Server 2016 14393.3930–14393.4048 (fixed in 14393.4104 / KB4593226); Server 2019 17763.1457–17763.1613 (fixed in 17763.1637 / KB4592440). Mixed-fleet environments are at highest risk.

**Fingerprint in audit report:**

- AD section: `msDS-KeyCredentialLink` count fluctuates across runs done hours/days apart (e.g., 3 → 4 → 3)
- User Device Registration/Admin Event 363 (NGC key missing)
- `dsregcmd` shows `OnPremTgt: NO` while policy registry shows neither `UseCloudTrustForOnPremAuth` nor `UseCertificateForOnPremAuth = 1` (i.e., default = Key Trust)

**Strategic fix:** Migrate to **Cloud Kerberos Trust**. This single move eliminates the entire failure class plus Class 5 (CVE-2025-26647) NTAuth fragility plus the AD-replication coupling. Microsoft's recommended hybrid model since 2024.

**Tactical fix (if migration is blocked):** Patch all DCs to or past the fix builds above. Verify via `Get-ADDomainController -Filter * | Select Name,OperatingSystemVersion`.

---

## Class 2 — PRT renewal failure (14-day sliding window)

**Affects:** Any device that authenticates against Entra (hybrid, Entra-joined, Azure AD-registered).

**Mechanism:** CloudAP renews the Primary Refresh Token every ~4 hours. If renewal fails for 14 consecutive days the PRT is invalidated and the WHFB-partitioned credential session must be rebuilt with fresh password+MFA. Common causes: blocked endpoints, TPM transport-key issues, expired device certificate, broken WAM plugin, Conditional Access bouncing the PRT.

**Fingerprint in audit report:**

- `dsregcmd`: `AzureAdPrt: YES` but `AzureAdPrtUpdateTime` more than 4 hours old (script flags this automatically)
- `dsregcmd`: AcquirePrtDiagnostics block contains an HTTP 400 with an `AADSTSxxxxx` server error
- AAD/Operational Events 1006/1007 with non-zero error codes
- Network section: TCP/443 unreachable to `login.microsoftonline.com` or `enterpriseregistration.windows.net`
- Cloud Kerberos Trust deployments: `STATUS_NO_LOGON_SERVERS 0xC000005E` cascades into PIN unlock failures

**Common blockers:**

- TLS-inspecting proxy that strips device cert auth
- WPAD broken / captive portal / VPN split-tunnel mis-scoped
- TPM transport key corrupted (also flag for Class 7)
- Conditional Access policy with Token Protection or strict device-state requirement bouncing the PRT

**Remediation context:** Restore endpoint reachability, validate TPM, audit CA policies. The script does not auto-remediate.

---

## Class 3 — Conditional Access Sign-in Frequency cadence

**Affects:** Tenants with Conditional Access "Sign-in frequency" or "Require reauthentication" policies.

**Mechanism:** A SIF policy set to **14** or **30 days** deterministically forces users to re-authenticate at that cadence. If the user's WHFB enrollment is partially broken (any other class), the forced reauth surfaces the broken state. SIF=14d also exactly matches the Class 2 PRT sliding window — they compound.

**Fingerprint in audit report:**

- AAD/Operational events showing AADSTS50158 (external security challenge / CA reauth required) at the recurrence cadence
- This is the only class where the audit script can't directly confirm — confirm in the Entra admin center at **Conditional Access → Policies → filter by "Sign-in frequency"**

**Joey Verlinden corollary:** Per-user MFA "Disabled" state co-existing with CA-enforced MFA causes WHFB sign-ins to be reported as single-factor in Entra logs and may interact badly with CA strong-auth claims. Confirm per-user MFA state in the legacy MFA portal.

**Token Protection corollary:** The CA "Require token protection for sign-in sessions" feature binds tokens to the device's session key. Field reports of breakage when scoped too broadly. If you have this enabled, verify scope.

---

## Class 4 — KB5060842/KB5062553 `UsePassportForWork` user-scope bug

**Affects:** Windows 11 24H2 devices (build 26100.x) with WHFB Intune profile **assigned to a user group** (User scope), introduced in Microsoft updates KB5060842 / KB5063060 / KB5062553 (June/July 2025).

**Mechanism:** The `UsePassportForWork` policy stops applying correctly when scoped to User. PIN setup and use fail with `0x80090010` (NTE_PERM). Microsoft tracking entry: **WI1121302**.

**Fingerprint in audit report (the smoking gun):**

- Application log Event **7055** ("Windows Hello container provisioning failed with error 0x80090010")
- Application log Event **7703** ("Windows Hello for Business policy is disabled, causing operation failure")
- Crypto-NCrypt Event 1 with `0x80090010` and Microsoft Passport KSP

When all three are present together on a 24H2 device, this is almost certainly the bug. The audit script flags this combination as CRITICAL.

**Workarounds (in increasing order of permanence):**

1. **Re-scope** the Intune WHFB profile from User to Device (assign to a device group, not a user group). This is the recommended fix.
2. Push registry value `HKLM\SOFTWARE\Microsoft\Policies\PassportForWork\UserPassportForWork = 1` and reboot.
3. Install **KB5065789** (Sept 29 2025 optional preview) which fixes the regression at the OS level.

**If failures at the affected site started after June 2025, suspect this class first.** It takes minutes to confirm and the workaround is well-documented.

---

## Class 5 — CVE-2025-26647 Kerberos NTAuth chain enforcement

**Affects:** Domain controllers running Windows updates from **April 2025** onward (audit) or **July 2025** onward (default-on enforcement). Hits Key Trust deployments with NTAuth store hygiene problems.

**Mechanism:** DCs validate that client certificates used in PKINIT-style flows (which includes WHFB Key Trust) chain to a CA in the **NTAuth store**. If the issuing CA chain isn't anchored in NTAuth, KDC denies the authentication.

**Fingerprint in audit report (DC-side):**

- KDC Event **45** (audit warning) — pre-enforcement, NTAuth chain not validated
- KDC Event **21** (deny) — enforcement active, auth failing
- KDC Event 107 — KDC certificate SAN mismatch (separate but related)
- Registry `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\AllowNtAuthPolicyBypass` reported by script (0=disabled/regression-only, 1=audit, 2=enforce)

**Remediation context:** Add the issuing CA chain to the NTAuth store (`certutil -dspublish -f <ca.cer> NTAuthCA`). The `AllowNtAuthPolicyBypass=0` registry override is **temporary only** — Microsoft has signaled it will be removed.

**Strategic fix:** Migrate to Cloud Kerberos Trust; CKT does not depend on PKINIT and is unaffected by this enforcement.

---

## Class 6 — Windows 11 24H2 strict UPN binding drift

**Affects:** Windows 11 24H2 onward. Identity-binding edge cases that worked silently on earlier builds now fail.

**Mechanism:** WHFB keys are bound to the UPN at provisioning time. Since 24H2 (LSA Protection default-on, stricter NGC binding), any UPN drift produces sign-in failures. The destructive `certutil -DeleteHelloContainer` reset works because it forces re-binding to the current UPN.

Common UPN drift triggers:

- M&A activity (domain rename, new tenant)
- Federated-identity edge cases
- Specific PRT refresh paths after sleep/hibernate
- Manual UPN change in AD without coordinated client-side reset

**Fingerprint in audit report:**

- AAD/Operational events with **AADSTS50034** (user not found) or **AADSTS135010** (missing key binding)
- Crypto-NCrypt error `0xC000006D` (STATUS_LOGON_FAILURE)
- NGC keys section: bound key container UPN does not match `whoami /upn` output (script flags this automatically)

**Why destructive reset works:** It re-binds to current UPN. **But it's masking the underlying drift** — find and fix the source (M&A workflow, federation config, sleep-handling) instead of resetting fortnightly.

---

## Class 7 — TPM lockout / firmware reset

**Affects:** All TPM-backed WHFB deployments, especially AMD fTPM and Intel PTT systems with firmware drift.

**Mechanism:**

- **Anti-hammering lockout** — TPMs lock after 32 failed authorisations and heal one count per ~10 minutes. A user repeatedly entering wrong PIN, or a misbehaving service, can lock the TPM.
- **Ownership change** — BIOS updates can clear or rotate TPM ownership; AMD fTPM resets after AGESA updates (the 2022 stuttering-bug fix in AGESA 1.2.0.7 explicitly cleared keys); Intel PTT firmware updates can do the same.
- **EK certificate problems** on AMD fTPM systems block AIK enrollment.

**Fingerprint in audit report:**

- TPM section: `Get-Tpm` shows `LockedOut: True` or `LockoutCount` near `LockoutMax` (script flags this)
- TPM section: `TpmReady: False` or `TpmEnabled: False`
- System log: `Microsoft-Windows-TPM-WMI` events 1040 (measured-boot fail), 1041, 1801 (not ready), 1802
- `dsregcmd`: `TpmProtected: NO` despite hardware TPM being present

**Inventory pivot:** `Get-Tpm | Select ManufacturerVersionFull20` across affected machines. AMD fTPM systems on Ryzen platforms with old BIOS are a known WHFB risk.

---

## Class 8 — NGC container corruption

**Affects:** All WHFB deployments. Almost always **downstream** of another class — the container at `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc` (and related `Crypto\Keys` and TPM-backed `Crypto\PCPKSP`) gets corrupted by aborted writes, AV interference, or mid-update reboots, but the underlying trigger is usually one of the eight other classes.

**Fingerprint in audit report:**

- `dsregcmd`: `NgcSet: NO`
- Crypto-NCrypt errors `0x80090011` (NTE_NOT_FOUND) or `0x80090016` (NTE_BAD_KEYSET)
- Application Event 7055
- NGC keys section: `certutil -csp "Microsoft Passport Key Storage Provider" -key` returns no Key Container entries
- User Device Registration Event 363 (NGC key missing)

**Treat container reset as a remediation, not a diagnosis.** `certutil -DeleteHelloContainer` (run in user context, not elevated) is the correct supported way to reset; it deletes the user's NGC keys without touching the device transport key, AIK, or BitLocker. **Use it last, not first** — figure out which other class is corrupting the container every fortnight.

---

## Class 9 — Defender ASR / AV interference

**Affects:** Managed estates with Defender ASR rules in block mode, especially the LSASS credential-stealing rule.

**Mechanism:** The Defender ASR rule **"Block credential stealing from the Windows local security authority subsystem"** (GUID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`), enabled by default on managed estates, has been correlated with WHFB instability. Microsoft Q&A threads explicitly recommend excluding the NGC path from real-time scanning when on-access scans correlate with PIN failures.

**Fingerprint in audit report:**

- Defender section: rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` in **Block** mode (action=1)
- Defender section: no AV exclusion for `*Ngc*` or `*Crypto*` paths

**Note:** There is **no widespread evidence** that CrowdStrike, SentinelOne, or Sophos break NGC in this exact pattern. If a third-party AV is present, treat as a contributing factor only and verify with quarantine/file-access logs before pursuing.

**Mitigation context:** Switch the LSASS ASR rule to Audit mode (action=2) while investigating; add path exclusions for `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc`, `…\Crypto`, and `C:\ProgramData\Microsoft\Crypto`.

---

## Triage priority

When the audit report lands, work the classes in this order:

1. **Class 4** if Application 7055+7703 are both present on a 24H2 device — this is the easiest win and most common since June 2025
2. **Class 1** if the deployment is hybrid Key Trust — strategic migration to Cloud Kerberos Trust closes this and Class 5 in one move
3. **Class 3** check Conditional Access SIF=14d / 30d before chasing client-side issues
4. **Class 2** if PRT update time is stale — fix endpoint reachability and TPM transport key
5. **Class 7** if TPM is locked out or `TpmReady: False`
6. **Class 6** if NGC bound UPN doesn't match current UPN
7. **Class 5** on the DC if Event 45/21 are present
8. **Class 9** as a contributing factor; rarely the only cause
9. **Class 8** is the symptom not the cause — only "treat" it after you know which other class is upstream

## Strategic verdict

For most hybrid environments today, **migrating to Cloud Kerberos Trust eliminates 60–70% of the recurring-failure modes** (Classes 1 and 5 entirely; reduces exposure to Class 6 by removing the on-prem PKI binding). It is Microsoft's recommended deployment model since 2024 and is now exposed directly in the Intune Settings Catalog. If a deployment is on Key Trust or Cert Trust today, the durable fix is migration; everything else is whack-a-mole.

The destructive `certutil -DeleteHelloContainer` reset that has been keeping users limping along is a legitimate tool for fixing a corrupted container — but it is not a substitute for fixing whatever is corrupting the container every fortnight.
