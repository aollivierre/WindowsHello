# Post-mortem — WHFB cyclical PIN-unavailable failure on a shared front-desk PC

**Date:** 2026-05-15
**Status:** Completed — tooling shipped to this repo, tenant objects created **unassigned**
**Tooling delivered:** [`Invoke-WHFBAudit.ps1` Step 0a + Shared-PCs section (PR #3)](https://github.com/aollivierre/WindowsHello/pull/3) · [`WHFB-Remediation-AppReg/` (PR #4)](https://github.com/aollivierre/WindowsHello/pull/4) · [`Remove-NgcContainer.ps1`](Remove-NgcContainer.ps1) deployed via Intune `deviceManagementScripts`

> Customer-identifying values (tenant GUID, hostname, UPNs, app/policy/group/script IDs) are deliberately redacted from this file. The full identifiers live in the local workstation's session transcript and the deleted customer-specific run artefacts (see *Hygiene* below).

---

## 1. Symptom

A shared front-desk Windows 11 25H2 device (cloud-only / Entra-joined) was throwing the lock-screen error **"Something happened and your PIN isn't available"** for two distinct staff accounts. Both users could still sign in with password; the WHFB PIN was the only failing surface.

Vendor support had previously advised clearing the TPM. That recommendation was **wrong**.

## 2. Root cause

**Class 8 — NGC / Microsoft Passport container corruption, in a re-provisioning loop.**

- Local audit (run as one of the affected users) reported:
  - 1 × **CRITICAL** Event 363 ("Microsoft Passport key missing") for the running user.
  - "No Microsoft Passport KSP keys for current user" — `certutil -csp "Microsoft Passport Key Storage Provider" -key` returned nothing.
  - ~140 AADSTS errors over 60 days in the local AAD/Operational event log (50076, 65002, 54006, 700082, 50126, 50011) — fingerprint of token churn caused by repeated NGC failures.
- **TPM was healthy** (Ready, Owned, not locked out, `KeySignTest` passed; device cert valid to 2035). Clearing it would not have helped and would have invalidated the existing device identity.
- Trust model: Cloud-only / Entra-joined, no on-prem AD reachable. No federation, no Cloud Kerberos Trust needed.

The mechanism is the documented one: the corrupt NGC container fails on each sign-in, Windows tries to re-provision Hello, the new key registers with Entra and breaks on the next reboot — repeat. Microsoft's own WHFB FAQ flags this and prescribes the same sequence we used.

## 3. Remediation built (all inert / unassigned)

Six objects were created in the tenant via Microsoft Graph using a single-tenant, cert-auth Entra app registration with 12 admin-consented application permissions:

| # | Object | Surface | What it does |
|---|---|---|---|
| 1 | App registration | Entra ID | Workload identity for the Graph-API automation — cert auth, 24 h ephemeral cert, 12 perms |
| 2 | Security group | Entra ID | Targeting container; contains the affected device as the single member |
| 3 | Account Protection policy | Endpoint Security (`configurationPolicies` with template reference) | `UsePassportForWork` (device) = **Disabled** |
| 4 | Settings Catalog policy | Intune Settings Catalog | `UseSecurityKeyForSignin` = **Enabled** |
| 5 | Settings Catalog policy | Intune Settings Catalog | `EnableWebSignin` = **Enabled** — additive, password tile preserved, default tile unchanged |
| 6 | PowerShell script | Intune `deviceManagementScripts` (`runAsAccount: user`) | `certutil -deleteHelloContainer` for each signed-in user; transcript-logged |

Two earlier Custom OMA-URI `deviceConfigurations` (created during initial automation) were deleted once their Endpoint Security / Settings Catalog equivalents were proven to work. The Custom OMA-URI path was a shortcut for delivery speed and is not best practice — the surface priority below is what shipped.

## 4. Key decisions

| Decision | Rationale |
|---|---|
| Single-tenant app reg, **cert auth only**, no secret | Cert-auth limits the credential lifetime to a key rotation; no secret = no long-lived bearer to manage. |
| Cert TTL: **24 hours** | The app reg has 12 privileged perms (Intune RW, AppRoleAssignment RW indirectly via consent, Group RW, etc.). A 24 h key means a leak window is bounded to one day. Re-generate before each major run. |
| `KeyUsage = digitalSignature` only, BasicConstraints CA=False, SubjectKeyIdentifier | App-only auth never needs key encipherment; tighter than the default the repo's older cert tooling produced. |
| **Device-code** sign-in for GA actions (create app + consent) | Compatible with MFA (which the GA had); ROPC would have hard-failed on AADSTS50158. CA can still block device-code via "Authentication Flows" — none was present here. Fallback documented: `MSAL.acquire_token_interactive()`. |
| **Programmatic admin consent** via `appRoleAssignedTo` POSTs | Matches the repo's `Grant-GraphAdminConsent.ps1` pattern; idempotent; survives the brand-new-app replication-delay AADSTS650051 that bites the browser `/adminconsent` URL. |
| Surface priority: **Endpoint Security → Settings Catalog → Custom OMA-URI** | Matches OpenIntuneBaseline (SkipToTheEndpoint / James Robinson MVP) and the audit's own findings. `Rebuild-WHFBPolicies.py` discovers the highest-priority surface that actually carries each setting, live from `configurationPolicyTemplates` + `configurationSettings`. Nothing is hardcoded. |
| **Everything created unassigned** | Service desk gets to verify in the portal and assign on their schedule. Nothing goes live until an admin clicks Save. |
| Step 2 (NGC reset) shipped as a user-context **Intune PS script**, not a Win32 app or detection/remediation | Simplest surface that fires once per user on next check-in, in the right security context for `certutil -deleteHelloContainer`. Script also embeds a GitHub permalink in its Intune description, because Intune does not surface uploaded script content to admins post-upload. |

## 5. Deliberately not done

- **Step 3 — enable Passkey/FIDO2 method in Entra.** This is a live tenant toggle with no "unassigned" form. Left for the operator (1 click in Entra → Authentication methods → Policies).
- **`Authentication/EnablePasswordlessExperience`** (one of the three settings OpenIntuneBaseline's "Passwordless" policy uses). This setting *hides* the password credential provider from the lock screen. The handover's documented fallback for a lost YubiKey is the password — we deliberately preserved that fallback. The two additive settings we shipped (`UseSecurityKeyForSignin`, `EnableWebSignin`) add tiles without removing any.
- **Step 5 — per-user YubiKey enrolment.** User self-service at `aka.ms/mysecurityinfo`. Out of automation scope.
- **TPM clear.** Vendor's prior advice. Confirmed unnecessary and risky.
- **Tenant-wide WHFB disable** under Devices → Enrollment. Avoided per the handover — too broad a blast radius; targeted ES policy hits only the front-desk device group.

## 6. Hygiene / secrets cleanup

The cert-auth setup writes an obfuscated PFX (XOR 0x5A + base64 — **trivially reversible, treat as plaintext**) plus a `Config-Reference-PLAIN-TEXT-DELETE-ME.txt` containing the 128-character PFX password. After the session wrap:

- Local artefacts (three timestamped run folders + two live-catalog dumps) **deleted** on the workstation that drove the automation. Recursive find for `*config*.json`, `*config*.psd1`, `*PLAIN-TEXT*`, `*with-cert*`, `*.pfx`, `*.p12`, `*.cer`, `*.pem`, `*.key` returned zero matches post-cleanup.
- The app reg's public `keyCredential` remains in Entra until its natural expiry (~24 h after issue). The private half is now gone from disk; if no copy leaked the cert is effectively dead at expiry. Decision recorded: **let it expire** rather than `PATCH /applications/{id}` to clear `keyCredentials` early.
- `.gitignore` in `WHFB-Remediation-AppReg/` excludes every file class that could leak a credential or identifier (timestamped run folders, PFX-bearing configs, plaintext password reference, result/objects JSON, live catalog dumps, `*.pfx|.p12|.pem|.key`).

## 7. Service-desk handoff (assignment runbook)

1. Microsoft Intune admin centre → **Endpoint security → Account protection** → open **`FrontDesk - Disable Windows Hello for Business`** → **Assignments** → target the `FrontDesk-SharedPCs` group → **Save**.
2. Force a sync on the affected device (or wait one check-in cycle). Confirm the policy shows **Succeeded** in the device's Policy results.
3. Intune → **Devices → Scripts and remediations** → **`FrontDesk - Clear NGC Container (WHFB Step 2)`** → **Assignments** → target the same device group (or a user group containing the affected staff) → **Save**. On the user's next sign-in / check-in the script runs once and `certutil -deleteHelloContainer` clears the corrupt container in their context.
4. Optionally assign **`Security Keys for Windows Sign-In`** and **`FrontDesk - Enable Web Sign-In (Additive)`** to the same group.
5. Entra → **ID → Authentication methods → Policies → Passkey (FIDO2)** → set to **Enable**, target the appropriate user group, allow self-service registration. (Step 3 — manual.)
6. Per-user enrolment at `aka.ms/mysecurityinfo` → add primary + backup security key per staff member. (Step 5 — user-driven.)

## 8. Lessons learned

1. **The repo's audit script silently treated per-user data as device-wide.** `Invoke-WHFBAudit.ps1` captures `dsregcmd`, event logs, TPM, network as device-scoped — but `certutil`, `whoami /upn`, and `HKCU\PassportForWork` reflect *only* the running user. On a shared PC with multiple affected accounts, one run was being read as the device's full state. Fixed in PR #3: new Step 0a enumerates `ProfileList`, filters to `S-1-12-1-*` (Entra) SIDs under `C:\Users\`, and emits a `WARN` when other Entra profiles exist that weren't audited. README gained an explicit "Shared PCs / multiple affected users" section.
2. **Microsoft's Graph docs for `/deviceManagement/deviceManagementScripts` are misleading.** They list `DeviceManagementConfiguration.ReadWrite.All` as sufficient. The Intune downstream service rejects with 403 unless the app has `DeviceManagementScripts.Read.All` *or* `DeviceManagementScripts.ReadWrite.All` — a dedicated scope that has to be added + consented separately. Documented in `Grant-ScriptsPermission.py`.
3. **PATCH on `deviceManagementScripts` is unreliable.** Without `@odata.type` in the body, the Intune backend returns a misleading 404 ResourceNotFound. With it, the request is throttled and sometimes succeeds. The deterministic path that always works: **DELETE + POST** (idempotent via displayName lookup). That's what `Update-IntuneScriptDescription.py` does.
4. **Brand-new app regs hit `/adminconsent` propagation delay.** AADSTS650051 fires for the freshly-created app id because Entra hasn't replicated it yet. Programmatic consent via `POST /servicePrincipals/{spId}/appRoleAssignedTo` is unaffected; the browser consent URL needs a 5–10 min wait. Captured in `Create-WHFBRemediationApp.py`'s flow ordering.
5. **Custom OMA-URI is the wrong default.** It was the fastest path to "definitely works" because it only needs the documented CSP path and tenant id — no live setting-definition discovery. But it has no per-setting compliance reporting, doesn't appear under Endpoint Security where admins expect WHFB, and is the legacy surface. Live tenant discovery (`Discover-IntuneSurfaces.py` + `Inspect-WHFBSettingDefs.py`) showed both target settings are available on better surfaces; the rebuild took ~30 minutes and the deltas were minor.
6. **Permalinks for Intune scripts close the audit gap.** Intune doesn't surface the uploaded `.ps1` body to admins. Embedding `https://github.com/<owner>/<repo>/blob/<commit-sha>/<path>` in the description (pinned to a commit SHA, not a branch) gives any admin a one-click path to the actual source, immortal for the life of the repository.

## 9. Compute environment

| | |
|---|---|
| Driver workstation OS | Windows 11 Pro, build 26200.x (25H2) |
| PowerShell | 7.x (PSCore) for the harness; the deployed remediation script is PS 5.1-compatible |
| Python | 3.14, `cryptography` + `requests` + `pyjwt` + `msal` + `playwright` (Chromium 1187) |
| Repo authentication | `gh` CLI, `repo` + `workflow` + `read:org` + `gist` scopes |
| Tenant authentication | Initial: MSAL device-code flow against the Microsoft Graph Command Line Tools public client (`14d82eec-204b-4c2f-b7e8-296a70dab67e`). Steady-state: cert-auth (`client_credentials` + JWT assertion) against the new app reg. |

## 10. References

### This session
- **Conversation ID:** `c69a7d36-c69b-4ff1-8df1-34e171c8b419`
- **Workstation transcript path:** `C:\Users\IT.XYZ\.claude\projects\C--code-WindowsHello\c69a7d36-c69b-4ff1-8df1-34e171c8b419.jsonl`
- **Working directory:** `C:\code\WindowsHello`
- **Local-only artefacts (not in this repo):**
  - `WHFB-Remediation-Handover.md` — original engineering handover that informed the action plan
  - `evidence/WHFB-Audit-DESKTOP-OHDEMD0-20260514.html` — diagnostic auditor output that confirmed root cause
  - `evidence/lockscreen-reservations-pin-unavailable.png` — lock-screen failure screenshot
  - `evidence/INC-1529318-CanadaComputing-ticket.pdf` — prior vendor ticket (the TPM-clear advice that was incorrect)

### This repo
- [PR #3](https://github.com/aollivierre/WindowsHello/pull/3) — Audit: multi-profile coverage warning + Step 2 NGC-reset script
- [PR #4](https://github.com/aollivierre/WindowsHello/pull/4) — Add `WHFB-Remediation-AppReg/`: cert-auth app reg + Intune automation
- [`WHFB-Remediation-AppReg/README.md`](WHFB-Remediation-AppReg/README.md) — workflow + security model + permission table
- [`Invoke-WHFBAudit.ps1`](Invoke-WHFBAudit.ps1) — diagnostic auditor
- [`Remove-NgcContainer.ps1`](Remove-NgcContainer.ps1) — Step 2 payload

### Upstream
- WHFB FAQ — `certutil -deleteHelloContainer` behaviour, re-prompt if WHFB is still enabled by policy, Win 11 passkey-wipe caveat
  https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/faq
- WHFB known deployment issues
  https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-deployment-issues
- Intune Account Protection settings reference
  https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/ref-account-protection-settings
- Configure WHFB tenant policy with Intune (`UsePassportForWork`, `UseSecurityKeyForSignin`)
  https://learn.microsoft.com/en-us/intune/intune-service/protect/windows-hello
- FIDO2 security-key sign-in to Windows
  https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-windows
- Enable passkeys (FIDO2) in Microsoft Entra ID
  https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-passkey-fido2
- OpenIntuneBaseline by **SkipToTheEndpoint** (James Robinson, Microsoft MVP — Intune + Windows)
  https://github.com/SkipToTheEndpoint/OpenIntuneBaseline
