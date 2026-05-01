# Changelog
All notable changes to the WHfB-Diagnostics module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [DEPRECATED] - 2026-05-01

This module is deprecated and has been moved from `Module/WHfB-Diagnostics/` to
`Archive/Module-WHfB-Diagnostics-v0.1.0/`. It is preserved for historical
reference only and is no longer maintained.

**Why it was archived:**

- **Ambiguous registry signals.** `Get-WhfbAuthStatus -AuthType PIN` reads the
  Credential Provider `IsEnabled` flag at
  `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}`,
  which is the *credential provider* toggle and not the per-user WHFB
  enrollment state. Similarly the biometric path reads a global toggle, not
  per-user enrollment. The authoritative signals are `dsregcmd /status NgcSet:`
  plus NGC key existence via `certutil -csp "Microsoft Passport Key Storage Provider" -key`.
- **Narrow scope.** Two booleans (IsEnabled, IsEnrolled) are insufficient for
  triaging recurring PIN failures.
- **Stale.** Last updated 2025-02-20 and predates the KB5060842/KB5062553
  cluster, CVE-2025-26647 NTAuth chain enforcement, and Windows 11 24H2 strict
  UPN-binding changes.

**Replacement:** Use [`Invoke-WHFBAudit.ps1`](../../Invoke-WHFBAudit.ps1) at
the repo root for diagnostics. See [`docs/audit-tool.md`](../../docs/audit-tool.md).

If a composable inventory cmdlet is needed in the future, a fresh module
emitting structured objects derived from `dsregcmd` and the NGC key store
should be written from scratch rather than reviving this one.

## [0.1.0] - 2025-02-20

### Added
- Initial module structure with basic components:
  - Module manifest (WHfB-Diagnostics.psd1)
  - Module script (WHfB-Diagnostics.psm1)
  - Public functions directory
- First public function `Get-WhfbAuthStatus`:
  - Support for checking PIN authentication status
  - Support for checking Biometric authentication status
  - Comprehensive error handling and status reporting
  - Full comment-based help with examples
  - Backward compatibility with Windows PowerShell 5.1
  - Fallback mechanisms for systems without WinBio API
- Administrative privilege requirement for secure access
- Registry-based status checking for both authentication methods
