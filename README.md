# WindowsHello

Windows Hello for Business diagnostics and management.

## What's in this repo

| Path | Purpose |
|---|---|
| [`Invoke-WHFBAudit.ps1`](Invoke-WHFBAudit.ps1) | **Diagnostic auditor.** Captures all 12 data points needed to triage recurring PIN failures and produces a self-contained HTML report. Diagnosis only — no remediation. |
| [`Enable-WindowsHello.ps1`](Enable-WindowsHello.ps1) | Configures the `PassportForWork` policy and other registry values to enable WHFB on a workstation. |
| [`Module/WHfB-Diagnostics/`](Module/WHfB-Diagnostics) | PowerShell module with focused diagnostic cmdlets (e.g., `Get-WhfbAuthStatus`). |
| [`Archive/`](Archive) | Older interactive diagnostic script kept for reference. |
| [`docs/`](docs) | Reference documentation — see below. |

## Documentation

- [`docs/audit-tool.md`](docs/audit-tool.md) — full operator guide for `Invoke-WHFBAudit.ps1`: parameters, where to run, how to read the report
- [`docs/root-causes.md`](docs/root-causes.md) — the nine documented root-cause classes for cyclical WHFB PIN failures, with fingerprints and remediation context
- [`docs/diagnostic-flow.md`](docs/diagnostic-flow.md) — manual 12-step capture procedure for cases where running the auditor is not possible

## Quick start

### Triage a user that's failing right now

Run on the affected workstation, **as the affected user**, ideally elevated, **before** any destructive PIN reset:

```powershell
git clone https://github.com/aollivierre/WindowsHello.git
cd WindowsHello
.\Invoke-WHFBAudit.ps1
# Open the HTML report under .\Reports\ — start with the executive summary and class ranking
```

Typical run takes 8–15 seconds and produces a single self-contained HTML report (~30–80 KB) plus a raw-dump folder.

### Configure WHFB on a fresh workstation

```powershell
.\Enable-WindowsHello.ps1   # requires elevation
```

## Prerequisites

- Windows 10 / 11 with PowerShell 5.1 (the inbox version)
- The audit tool needs no external modules for the workstation run
- AD module / RSAT only required for `msDS-KeyCredentialLink` lookups (Key Trust drift detection)
- Domain controller scope: run the audit tool elevated on a DC for the KDC operational log + AD attribute checks

## What the audit tool captures

`Invoke-WHFBAudit.ps1` automates the [12-step diagnostic flow](docs/diagnostic-flow.md) and tags each finding with one of the [nine root-cause classes](docs/root-causes.md):

1. Environment, OS build (24H2/25H2), WHFB-relevant hotfix inventory (KB5060842, KB5062553, KB5065789, etc.)
2. `dsregcmd /status` — full parse + PRT freshness check + trust-model inference
3. HelloForBusiness/Operational events (5001, 5002, 8200/8202/8203, 7054/7055/7201/7204)
4. User Device Registration/Admin events (300, 360, 362, 363)
5. AAD/Operational events with AADSTS code extraction and tally
6. Crypto-NCrypt errors fingerprinted against `0x80090010`, `0x80090011`, `0x80090016`, `0xC000005E`, `0xC000006D`
7. **Application log 7055 + 7703** — the smoking-gun fingerprint for the KB5060842/KB5062553 user-scope bug
8. KDC operational events 21/45/107 and `AllowNtAuthPolicyBypass` (CVE-2025-26647) — DC only
9. `Get-Tpm` lockout/firmware state + TPM-WMI System events
10. NGC keys via `certutil` with UPN-drift detection against `whoami /upn`
11. `msDS-KeyCredentialLink` count and `krbtgt_AzureAD` presence (Key Trust drift / Cloud Kerberos Trust verification)
12. WHFB policy registry tree — GPO vs MDM duplication detection, `UseCloudTrustForOnPremAuth`, `UseCertificateForOnPremAuth`
13. Defender ASR rules (LSASS rule `9e6c4e1f-…`) and AV path exclusions
14. Network reachability of `login.microsoftonline.com`, `enterpriseregistration.windows.net`, etc.

## Strategic context

For most hybrid environments, **migrating to Cloud Kerberos Trust** eliminates 60–70% of the recurring PIN failure modes (Class 1 Key Trust drift and Class 5 CVE-2025-26647 NTAuth fragility). It is Microsoft's recommended deployment model since 2024 and is exposed directly in the Intune Settings Catalog. See [`docs/root-causes.md`](docs/root-causes.md) for the full rationale.

## Compatibility

| Platform | Audit tool | Enable script | Module |
|---|---|---|---|
| Windows 10 (1809+) | Yes | Yes | Yes |
| Windows 11 22H2/23H2 | Yes | Yes | Yes |
| Windows 11 24H2 (build 26100) | Yes — flags missing KB5065789 | Yes | Yes |
| Windows 11 25H2 (build 26200) | Yes | Yes | Yes |
| Windows Server 2016/2019/2022 (DCs) | Yes — adds DC-side KDC + AD checks | N/A | N/A |

## Privacy

The audit report contains hostname, username, UPN, tenant ID, device ID, build numbers, and event-log snippets. It does **not** contain plaintext passwords, PINs, private keys, or recovery keys. Treat the report as internal IT troubleshooting data — sanitize tenant ID and device ID before posting publicly.

## Contributing

Issues and pull requests welcome. For changes to the audit tool, please run it on a representative test machine and attach the report (or a screenshot of the executive summary) to the PR.

## License

MIT (see `LICENSE` if present).

## Author

**Abdullah Ollivierre** — initial work and ongoing maintenance.

## Acknowledgments

- Microsoft Learn known-issue documentation (KB5060842, WI1121302, CVE-2025-26647)
- Microsoft Q&A community threads on hybrid Key Trust drift
- MVP write-ups: Rudy Ooms, Sander Berkouwer, Joey Verlinden, Rahul Jindal, MSEndpointMgr, Awakecoding
