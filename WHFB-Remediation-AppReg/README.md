# WHFB Remediation - App Registration & Automation

Cert-auth Entra app registration plus the Python tooling that uses it to carry
out a Windows Hello for Business remediation in Intune:

| Handover step | What is automated | Surface |
|---|---|---|
| **Step 1** - disable WHFB on the device | Group + Account-protection policy (Endpoint Security) | `configurationPolicies` (template-bound) |
| **Step 2** - clear corrupt NGC container | User-context PowerShell script | `deviceManagementScripts` (`runAsAccount: user`) |
| **Step 3** - enable Passkey/FIDO2 auth method | *(not automated by design - live tenant toggle)* | Skipped |
| **Step 4** - security-key Windows sign-in | Settings Catalog policy | `configurationPolicies` |
| **Step 4b** (additive) - Web Sign-In tile | Settings Catalog policy | `configurationPolicies` |
| Step 5 - user FIDO2 enrolment | *(user self-service at aka.ms/mysecurityinfo)* | Out of scope |

Everything is created **unassigned**. Assigning policies / scripts to the
target group is a deliberate manual step in Intune, kept outside the
automation so nothing goes live until an admin clicks Save.

## Security model

The setup generates an ephemeral cert (RSA-4096 / SHA-512, 24h TTL by default,
key-usage `digitalSignature` only) which becomes the app's `keyCredential`.
The PFX is *never* written to disk - it lives only inside an obfuscated
JSON/PSD1 config in a timestamped run folder. The obfuscation is
XOR 0x5A + base64; **treat the obfuscated PFX exactly like a plaintext PFX**.

`.gitignore` in this folder excludes every artefact that could leak a
credential or tenant identifier:

- Timestamped output folders (`YYYYMMDD_HHMMSS/`)
- `whfb-remediation-config.{json,psd1}` (PFX bearer)
- `Config-Reference-PLAIN-TEXT-DELETE-ME.txt` (plaintext password)
- `whfb-remediation-app-{manifest-with-cert,result}.json`,
  `whfb-remediation-objects.json` (customer IDs)
- `intune-surface-discovery.json`, `whfb-setting-defs.json` (live catalog dumps)
- `*.pfx`, `*.p12`, `*.pem`, `*.key`

Audit the `.gitignore` before committing changes here.

## Required Microsoft Graph permissions (12)

The app needs these **application** scopes. `whfb-remediation-permissions-manifest.json` is the source of truth (it's a `requiredResourceAccess` block you can paste straight into Entra's manifest editor).

| Permission | GUID | Why |
|---|---|---|
| `DeviceManagementConfiguration.ReadWrite.All` | `9241abd9-d0e6-425a-bd4f-47ba86e767a4` | create/update ES + Settings Catalog policies |
| `DeviceManagementScripts.ReadWrite.All` | `9255e99d-faf5-445e-bbf7-cb71482737c4` | upload the Step 2 user-context PS script |
| `Group.ReadWrite.All` | `62a82d76-70ea-41e2-9197-370581804d09` | create the target device group |
| `Policy.ReadWrite.AuthenticationMethod` | `29c18626-4985-4dcd-85c0-193eef327366` | (reserved for Step 3 - currently unused) |
| `DeviceManagementManagedDevices.PrivilegedOperations.All` | `5b07b0dd-2377-4e44-a38d-703f09a0dc3c` | trigger device sync |
| `Device.Read.All` | `7438b122-aefc-4978-80ed-43db9fcc7715` | resolve the Entra device object |
| `DeviceManagementManagedDevices.Read.All` | `2f51be20-0bb4-4fed-bf7b-db946066c75e` | resolve the Intune managed device |
| `UserAuthenticationMethod.Read.All` | `38d9df27-64da-44fd-b7c5-a6fbac20248f` | verify FIDO2 enrolment |
| `User.Read.All` | `df021288-bdef-4463-88db-98f22de89214` | resolve affected staff accounts |
| `AuditLog.Read.All` | `b0afded3-3588-46d8-8b3d-9842eff778da` | verify token churn has quieted |
| `Directory.Read.All` | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` | general directory reads |
| `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | verify auth-methods policy state |

All require **admin consent**.

## Before you run anything

Open these and fill in your tenant-specific values (they ship with
`00000000-0000-0000-0000-000000000000` / `<TARGET-DEVICE-NAME>` placeholders):

- `Generate-WHFBRemediationCert.py` -> `DEFAULT_TENANT_ID`
- `Create-WHFBRemediationApp.py` -> `TENANT_ID`
- `Grant-WHFBConsent.py` -> `TENANT_ID`
- `Grant-ScriptsPermission.py` -> *(reads from config; no edit needed once the config exists)*
- `Invoke-WHFBRemediation.py` -> `TARGET_DEVICE_NAME` (defaults to a placeholder)
- `Update-IntuneScriptDescription.py` -> `COMMIT_SHA` (pin to the commit your `Remove-NgcContainer.ps1` came from)

Most scripts pick up the tenant id automatically from the obfuscated config
once it exists. The first one (`Generate-WHFBRemediationCert.py`) needs it
explicitly because the config doesn't exist yet.

## Workflow

> Requires Python 3.10+ with `cryptography`, `requests`, `pyjwt`, `msal`, `playwright`.
> Install Playwright Chromium once: `python -m playwright install chromium`.

### Phase 1 - Create the app reg + cert (one-time)

```
python Create-WHFBRemediationApp.py
```

This calls `Generate-WHFBRemediationCert.py` internally for the cert,
launches a headed Chromium at `microsoft.com/devicelogin`, asks you to sign
in as a Global Administrator, then creates the application + service
principal via Graph. Writes the obfuscated config + the public `.cer` into
a timestamped folder.

### Phase 2 - Grant admin consent (programmatic)

```
python Grant-WHFBConsent.py            # 11 of the 12 perms (initial)
python Grant-ScriptsPermission.py      # adds DeviceManagementScripts.ReadWrite.All
```

Both do device-code sign-in as the GA and use the
`servicePrincipals/{id}/appRoleAssignedTo` pattern (idempotent - re-running
is safe).

### Phase 3 - Verify cert auth + Graph reach

```
python Test-WHFBAuth.py
```

Acquires a token via the cert (client-credentials JWT assertion) and
exercises three consented permissions. Pure dry-run.

### Phase 4 - Build the remediation objects (everything unassigned)

```
python Discover-IntuneSurfaces.py        # find ES/Settings-Catalog surfaces
python Inspect-WHFBSettingDefs.py        # dump exact settingTemplate JSON
python Rebuild-WHFBPolicies.py           # ES Account Protection + Settings Catalog
python Add-WebSignInPolicy.py            # additive Web Sign-In tile
python Add-NgcResetScript.py             # Step 2 user-context PS script
python Update-IntuneScriptDescription.py # backfill GitHub permalink in the desc
```

`Invoke-WHFBRemediation.py` is kept as a one-shot equivalent of the older
Custom-OMA-URI path; the `Rebuild-WHFBPolicies.py` flow is preferred (matches
OpenIntuneBaseline's surface preference: Endpoint Security > Settings Catalog
> Custom OMA-URI).

### Phase 5 - Verify

```
python Verify-WHFBObjects.py             # group + policies exist, 0 assignments
python Check-SettingsDeprecation.py      # confirm settings aren't deprecated
```

Both are read-only.

## Files

- `Generate-WHFBRemediationCert.py` - ephemeral RSA-4096 / SHA-512 cert + obfuscated config emitter
- `Create-WHFBRemediationApp.py` - device-code GA sign-in + create app + SP + cert
- `Grant-WHFBConsent.py` - programmatic admin consent for the 11-perm set
- `Grant-ScriptsPermission.py` - add + consent `DeviceManagementScripts.ReadWrite.All`
- `Test-WHFBAuth.py` - cert-auth smoke test against three Graph endpoints
- `Discover-IntuneSurfaces.py` - find which surface (ES / Settings Catalog) carries a setting
- `Inspect-WHFBSettingDefs.py` - dump the exact `settingInstanceTemplate` JSON needed for ES policies
- `Rebuild-WHFBPolicies.py` - create the two policies on best-practice surfaces (ES + Catalog), idempotent
- `Add-WebSignInPolicy.py` - additive Web Sign-In Settings Catalog policy (does not touch password tile or default tile)
- `Add-NgcResetScript.py` - upload `Remove-NgcContainer.ps1` as a user-context Intune script
- `Update-IntuneScriptDescription.py` - delete + recreate the Intune script so the description embeds a GitHub permalink
- `Invoke-WHFBRemediation.py` - older one-shot equivalent (uses Custom OMA-URI; kept for reference)
- `Verify-WHFBObjects.py` - empirical "everything is inert" check
- `Check-SettingsDeprecation.py` - read `deprecatedInfo` straight from the live catalog
- `Remove-NgcContainer.ps1` - the Step 2 PS script body that gets uploaded to Intune
- `whfb-remediation-app-manifest.json` - full Entra app manifest template (id/appId null - for fresh creation)
- `whfb-remediation-permissions-manifest.json` - just the `requiredResourceAccess` block (12 perms)
- `whfb-remediation-permissions-catalog.json` - flat `{id, name, description, category}` reference
- `whfb-remediation-permissions.md` - permission table + setup notes

## Companion repo content

The Step 2 PS script (`Remove-NgcContainer.ps1`) lives at the repo root too,
because it is also useful manually or for non-Intune deployment paths. The
copy in this folder is the one the upload script consumes.

The diagnostic auditor that informed this remediation
(`Invoke-WHFBAudit.ps1`) is at the repo root - run that first to confirm
the symptoms match Class 8 (NGC container corruption) before deploying
anything here.
