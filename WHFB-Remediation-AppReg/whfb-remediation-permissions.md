# WHFB-Remediation-Automation - Graph Permissions Manifest

App registration to automate the Front Desk WHFB remediation.
Site: <tenant-name>. Tenant: `00000000-0000-0000-0000-000000000000`.
signInAudience: `AzureADMyOrg` (single-tenant). Auth type: app-only (client credentials)
- add a certificate or client secret after the app is created.

Source handover: `C:\code\WindowsHello\WHFB-Remediation-Handover.md`

## Files in this folder

| File | Purpose |
|------|---------|
| `whfb-remediation-app-manifest.json` | Full Entra app manifest. `id` / `appId` are null - see "How to use" below. |
| `whfb-remediation-permissions-manifest.json` | Just the `requiredResourceAccess` block (paste into an existing app's manifest). |
| `whfb-remediation-permissions-catalog.json` | Flat `{id, name, description, category}` list - human-readable reference. |
| `whfb-remediation-permissions.md` | This file. |

## Microsoft Graph application permissions (app roles)

Resource: Microsoft Graph - `resourceAppId` = `00000003-0000-0000-c000-000000000000`.
All entries are `"type": "Role"` (application permission). All require tenant admin consent.

Total: 11 permissions (6 write/action, 5 verification-read).

| # | Permission | GUID | Type | Handover step |
|---|------------|------|------|---------------|
| 1 | `DeviceManagementConfiguration.ReadWrite.All` | `9241abd9-d0e6-425a-bd4f-47ba86e767a4` | write | Step 1 (disable WHFB - Account protection policy) + Step 4 (security-key Custom OMA-URI profile) |
| 2 | `Group.ReadWrite.All` | `62a82d76-70ea-41e2-9197-370581804d09` | write | Step 1 - create the `FrontDesk-SharedPCs` device group and add members |
| 3 | `Policy.ReadWrite.AuthenticationMethod` | `29c18626-4985-4dcd-85c0-193eef327366` | write | Step 3 - enable the Passkey (FIDO2) authentication method |
| 4 | `DeviceManagementManagedDevices.PrivilegedOperations.All` | `5b07b0dd-2377-4e44-a38d-703f09a0dc3c` | write | Step 1 note - trigger device sync so the policy applies before Step 2 |
| 5 | `Device.Read.All` | `7438b122-aefc-4978-80ed-43db9fcc7715` | write | Step 1 - locate <TARGET-DEVICE-NAME> device object for group membership |
| 6 | `DeviceManagementManagedDevices.Read.All` | `2f51be20-0bb4-4fed-bf7b-db946066c75e` | write | Step 1 - resolve the Intune managed-device record, confirm assignment |
| 7 | `UserAuthenticationMethod.Read.All` | `38d9df27-64da-44fd-b7c5-a6fbac20248f` | read | Verify (Step 5) - confirm staff registered primary + backup YubiKey |
| 8 | `User.Read.All` | `df021288-bdef-4463-88db-98f22de89214` | read | Resolve affected staff accounts (affected staff) |
| 9 | `AuditLog.Read.All` | `b0afded3-3588-46d8-8b3d-9842eff778da` | read | Verify - confirm AADSTS token churn has quieted post-remediation |
| 10 | `Directory.Read.All` | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` | read | General directory resolution support |
| 11 | `Policy.Read.All` | `246dd0d5-5bd0-4def-940b-0421030a5b68` | read | Verify - confirm the auth methods policy reflects FIDO2 enablement |

### Steps NOT covered by this app reg

- **Step 2** (`certutil.exe -deleteHelloContainer`) runs locally in each user's session on
  <TARGET-DEVICE-NAME> - there is no Graph API for it.
- **Step 5** YubiKey enrollment is user self-service at `https://aka.ms/mysecurityinfo`.
  The app can only *verify* registration (perms 7/8), not register keys for users.

## How to use

The Entra Manifest blade only edits an *existing* app and validates `appId`/`id`, so the
full manifest ships with those as `null`. Pick one path:

**Path A - new app, then patch permissions (recommended)**
1. Entra admin centre -> App registrations -> New registration.
   - Name: `WHFB-Remediation-Automation`
   - Supported account types: **Accounts in this organizational directory only** (single-tenant)
2. Open the new app -> **Manifest** -> replace the `requiredResourceAccess` array with the
   contents of `whfb-remediation-permissions-manifest.json` -> Save.
3. **API permissions** -> **Grant admin consent for <tenant>** -> confirm all 11 show
   "Granted".
4. Generate the ephemeral cert: `python Generate-WHFBRemediationCert.py` (see
   "Certificate" below), then **Certificates & secrets** -> Upload certificate ->
   `whfb-remediation-public.cer`.
5. Record `appId` (client id) into `whfb-remediation-config.json/.psd1`
   (`ObfuscatedClientId`) for the automation. Run the remediation within the TTL.

**Path B - full manifest**
   Use `whfb-remediation-app-manifest.json` if your tooling creates the app via
   `POST /applications` (Graph) - it accepts the whole body. Drop the `id`/`appId` nulls;
   Graph assigns them. Then grant admin consent as in step 3 above.

## Certificate (ephemeral, 24h TTL)

The manifest ships with `keyCredentials: []` - **no cert is baked in**, by design.
This app reg does privileged Intune / auth-method *writes*, so the credential is
deliberately short-lived: generate it, upload it, run the remediation, let it die.
A 24-hour cert cannot be a committed file - it must be generated right before use.

Generate it with `Generate-WHFBRemediationCert.py` (in this folder):

```
python Generate-WHFBRemediationCert.py            # default 24h TTL
python Generate-WHFBRemediationCert.py --ttl-hours 12
```

Hardening (RSA-4096 / SHA-512, on top of this repo's cert baseline):
- `KeyUsage = digitalSignature` only - app-only auth never needs key encipherment
- `BasicConstraints CA=False` (critical), `SubjectKeyIdentifier` extension
- `notBefore` backdated 5 min for clock skew; `notAfter = now + TTL`
- PFX: 128-char CSPRNG password, `BestAvailableEncryption`
- Private key is embedded **only** in the obfuscated config (XOR 0x5A + base64);
  no `.pfx` is written to disk

Outputs land in `WHFB-Remediation-AppReg/<timestamp>/`:

| File | Use |
|------|-----|
| `whfb-remediation-public.cer` | Upload via the app's **Certificates & secrets** blade (reliable path). |
| `whfb-remediation-app-manifest-with-cert.json` | Full manifest with `keyCredentials` populated - for the Graph `POST/PATCH /applications` path. |
| `whfb-remediation-config.json` / `.psd1` | Obfuscated config holding the private key, for the automation. Paste the app's Client ID into `ObfuscatedClientId` after creation. |
| `Config-Reference-PLAIN-TEXT-DELETE-ME.txt` | Verification only - delete after use. |

> Only the **public** cert ever goes in the manifest / app reg. The private key
> (PFX) stays in the obfuscated config with whatever runs the automation.

## Least-privilege notes

- All 11 are application permissions (no signed-in user). They are broad by Graph design -
  `DeviceManagementConfiguration.ReadWrite.All` is the narrowest role that still covers both
  endpoint-security policies and Custom OMA-URI profiles; there is no per-policy scope.
- Consider an Intune scope tag and/or an Entra custom role + RBAC scoping on the service
  principal if you want to constrain it to the front-desk device group only.
- If you later drop the verification-read tier, remove perms 7-11 and re-consent.
