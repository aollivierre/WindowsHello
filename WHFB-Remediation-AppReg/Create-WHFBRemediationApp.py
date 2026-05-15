#!/usr/bin/env python3
"""
Create the WHFB-Remediation-Automation app registration end to end.

Flow:
  1. Regenerate a fresh 24h cert + manifest (subprocess: Generate-WHFBRemediationCert.py).
  2. Start an MSAL device-code sign-in against the well-known Microsoft Graph
     Command Line Tools public client, requesting the Graph scopes needed to
     create an app and grant consent.
  3. Launch a HEADED Chromium window at https://microsoft.com/devicelogin with
     the one-time code pre-filled. You sign in as a Global Administrator and
     approve. MSAL receives a token with the requested scopes - the script
     never sees your password.
  4. Graph API: POST /applications (single-tenant, cert + 11 permissions) and
     POST /servicePrincipals.
  5. Navigates the SAME browser to the admin-consent URL so you review and click
     Accept on the 11 permissions yourself.
  6. Polls the new service principal's appRoleAssignments to confirm consent,
     writes the new client id back into the obfuscated config, prints a summary.

Why device-code instead of scraping the portal: the Azure portal proxies its
Graph calls server-side, so no usable token is ever exposed to the browser.
Device-code flow returns a real delegated Graph token with deterministic
scopes. You stay in control of the only irreversible step (admin consent).

Usage:
    python Create-WHFBRemediationApp.py

Requires: msal, playwright (+ chromium), requests, cryptography
"""

import base64
import datetime
import json
import subprocess
import sys
import time
from pathlib import Path

import msal
import requests
from playwright.sync_api import sync_playwright

SCRIPT_DIR = Path(__file__).resolve().parent
GENERATOR = SCRIPT_DIR / "Generate-WHFBRemediationCert.py"

GRAPH = "https://graph.microsoft.com/v1.0"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
TENANT_ID = "00000000-0000-0000-0000-000000000000"  # <tenant-name>
OBFUSCATION_KEY = 0x5A

# Microsoft Graph Command Line Tools - a Microsoft-owned public client used by
# Connect-MgGraph. Pre-authorised in tenants; a GA can consent to its scopes.
DEVICE_FLOW_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = [
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.ReadWrite.All",
]

DEVICE_LOGIN_URL = "https://microsoft.com/devicelogin"
SIGN_IN_BUDGET_SECONDS = 300   # bound the device-code wait
CONSENT_POLL_SECONDS = 150     # how long to poll for the 11 consented roles


def obfuscate(value):
    if not value:
        return ""
    data = value.encode("utf-8")
    return base64.b64encode(bytes(b ^ OBFUSCATION_KEY for b in data)).decode("ascii")


# ---------------------------------------------------------------------------
# Step 1 - fresh cert + manifest
# ---------------------------------------------------------------------------

def regenerate_cert():
    print("[*] Regenerating a fresh 24h certificate + manifest...")
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--ttl-hours", "24",
         "--tenant-id", TENANT_ID],
        capture_output=True, text=True,
    )
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise RuntimeError("Certificate generation failed.")

    dirs = sorted(
        (p for p in SCRIPT_DIR.iterdir()
         if p.is_dir() and p.name[:8].isdigit()),
        reverse=True,
    )
    if not dirs:
        raise RuntimeError("No generator output directory found.")
    out_dir = dirs[0]
    manifest = json.loads(
        (out_dir / "whfb-remediation-app-manifest-with-cert.json")
        .read_text(encoding="utf-8")
    )
    print(f"[OK] Using generator output: {out_dir.name}")
    return out_dir, manifest


# ---------------------------------------------------------------------------
# Step 2-3 - device-code sign-in with a headed browser
# ---------------------------------------------------------------------------

def sign_in_and_run(out_dir, manifest):
    app_client = msal.PublicClientApplication(
        DEVICE_FLOW_CLIENT_ID, authority=AUTHORITY
    )
    flow = app_client.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise RuntimeError(
            f"Failed to start device flow: {json.dumps(flow, indent=2)}"
        )
    flow["expires_at"] = min(
        flow.get("expires_at", time.time() + SIGN_IN_BUDGET_SECONDS),
        time.time() + SIGN_IN_BUDGET_SECONDS,
    )
    user_code = flow["user_code"]

    print()
    print("=" * 70)
    print("  ACTION REQUIRED - sign in in the browser window")
    print("=" * 70)
    print("  A Chromium window just opened at microsoft.com/devicelogin.")
    print(f"  One-time code: {user_code}")
    print("  The code is pre-filled if possible - just confirm it, then sign")
    print("  in as a Global Administrator of the <tenant-name> tenant")
    print("  and approve. Leave the window open; the script continues itself.")
    print("=" * 70)
    print()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.goto(DEVICE_LOGIN_URL, wait_until="domcontentloaded")

        # Best-effort: pre-fill the one-time code. If the page layout differs,
        # no harm done - the user types the code shown above.
        try:
            page.fill("input[name='otc'], #otc", user_code, timeout=8000)
            page.click("#idSIButton9", timeout=4000)
        except Exception:
            print("[*] Could not auto-fill the code - type it manually: "
                  f"{user_code}")

        # Blocks (polling) until the user completes sign-in or the flow expires.
        # The browser is a separate process and stays interactive throughout.
        token_result = app_client.acquire_token_by_device_flow(flow)

        if "access_token" not in token_result:
            browser.close()
            raise RuntimeError(
                "Device-code sign-in failed: "
                f"{token_result.get('error_description', token_result)}"
            )
        token = token_result["access_token"]
        print("[OK] Signed in. Graph token acquired with scopes: "
              f"{token_result.get('scope', '(unknown)')}")

        # Steps 4-6 - browser stays open, reused for the consent screen.
        app = create_application(token, manifest)
        sp_id = create_service_principal(token, app["appId"])

        consent_url = (
            f"https://login.microsoftonline.com/{TENANT_ID}/adminconsent"
            f"?client_id={app['appId']}"
        )
        print()
        print("=" * 70)
        print("  ACTION REQUIRED - grant admin consent in the browser")
        print("=" * 70)
        print("  Navigating the browser to the admin-consent screen.")
        print("  Review the 11 Microsoft Graph permissions and click Accept.")
        print("  A redirect / 'page not found' AFTER you click Accept is")
        print("  HARMLESS (this app has no reply URL) - consent is recorded.")
        print("=" * 70)
        print()
        page.goto(consent_url, wait_until="domcontentloaded")

        granted = poll_consent(token, sp_id)
        browser.close()
        return app, sp_id, granted


# ---------------------------------------------------------------------------
# Step 4 - create the application + service principal
# ---------------------------------------------------------------------------

def create_application(token, manifest):
    print("[*] Creating app registration via Graph API...")

    key_creds = []
    for kc in manifest.get("keyCredentials", []):
        # Let Graph derive validity + customKeyIdentifier from the cert itself.
        key_creds.append({
            "type": kc["type"],
            "usage": kc["usage"],
            "key": kc["key"],
            "displayName": kc.get(
                "displayName", "WHFB-Remediation-Automation-Cert"),
        })

    body = {
        "displayName": manifest["displayName"],
        "description": manifest.get("description"),
        "signInAudience": manifest["signInAudience"],
        "requiredResourceAccess": manifest["requiredResourceAccess"],
        "keyCredentials": key_creds,
        "web": manifest.get("web", {}),
    }

    r = requests.post(
        f"{GRAPH}/applications",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json=body, timeout=30,
    )
    if r.status_code != 201:
        raise RuntimeError(
            f"POST /applications failed: {r.status_code}\n{r.text}"
        )
    app = r.json()
    print("[OK] App created")
    print(f"     displayName: {app['displayName']}")
    print(f"     appId (client id): {app['appId']}")
    print(f"     objectId: {app['id']}")
    return app


def create_service_principal(token, app_id):
    print("[*] Creating service principal...")
    r = requests.post(
        f"{GRAPH}/servicePrincipals",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json={"appId": app_id}, timeout=30,
    )
    if r.status_code == 201:
        sp_id = r.json()["id"]
        print(f"[OK] Service principal created: {sp_id}")
        return sp_id
    if r.status_code == 409:  # already exists
        r2 = requests.get(
            f"{GRAPH}/servicePrincipals(appId='{app_id}')?$select=id",
            headers={"Authorization": f"Bearer {token}"}, timeout=30,
        )
        r2.raise_for_status()
        sp_id = r2.json()["id"]
        print(f"[OK] Service principal already existed: {sp_id}")
        return sp_id
    raise RuntimeError(
        f"POST /servicePrincipals failed: {r.status_code}\n{r.text}"
    )


# ---------------------------------------------------------------------------
# Step 6 - confirm admin consent landed
# ---------------------------------------------------------------------------

def poll_consent(token, sp_id):
    print(f"[*] Polling for admin consent (up to {CONSENT_POLL_SECONDS}s)...")
    graph_sp = requests.get(
        f"{GRAPH}/servicePrincipals(appId='{MS_GRAPH_APP_ID}')?$select=id",
        headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    graph_sp.raise_for_status()
    graph_sp_id = graph_sp.json()["id"]

    deadline = time.time() + CONSENT_POLL_SECONDS
    last = 0
    while time.time() < deadline:
        r = requests.get(
            f"{GRAPH}/servicePrincipals/{sp_id}/appRoleAssignments",
            headers={"Authorization": f"Bearer {token}"}, timeout=30,
        )
        if r.status_code == 200:
            roles = [a for a in r.json().get("value", [])
                     if a.get("resourceId") == graph_sp_id]
            if len(roles) != last:
                last = len(roles)
                print(f"    {last}/11 Graph permissions consented...")
            if last >= 11:
                print("[OK] All 11 Graph permissions consented.")
                return 11
        time.sleep(5)
    print(f"[!] Only {last}/11 consented within the poll window. "
          "Consent may still be propagating - verify in the portal.")
    return last


# ---------------------------------------------------------------------------
# Wrap up
# ---------------------------------------------------------------------------

def write_results(out_dir, app, sp_id, granted):
    obf_client = obfuscate(app["appId"])

    cfg_json_path = out_dir / "whfb-remediation-config.json"
    data = json.loads(cfg_json_path.read_text(encoding="utf-8"))
    data["client_id_obfuscated"] = obf_client
    cfg_json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    psd1 = out_dir / "whfb-remediation-config.psd1"
    if psd1.exists():
        txt = psd1.read_text(encoding="utf-8-sig").replace(
            "ObfuscatedClientId = ''",
            f"ObfuscatedClientId = '{obf_client}'",
        )
        psd1.write_text(txt, encoding="utf-8-sig")

    result = {
        "displayName": app["displayName"],
        "appId": app["appId"],
        "objectId": app["id"],
        "servicePrincipalId": sp_id,
        "tenantId": TENANT_ID,
        "signInAudience": app.get("signInAudience"),
        "graphPermissionsConsented": granted,
        "createdUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    (out_dir / "whfb-remediation-app-result.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    return result


def main():
    print()
    print("=" * 70)
    print("  CREATE WHFB-REMEDIATION-AUTOMATION APP REGISTRATION")
    print("=" * 70)

    out_dir, manifest = regenerate_cert()
    app, sp_id, granted = sign_in_and_run(out_dir, manifest)
    result = write_results(out_dir, app, sp_id, granted)

    print()
    print("=" * 70)
    print("  DONE")
    print("=" * 70)
    print(f"  App name:   {result['displayName']}")
    print(f"  Client id:  {result['appId']}")
    print(f"  Object id:  {result['objectId']}")
    print(f"  SP id:      {result['servicePrincipalId']}")
    print(f"  Tenant:     {result['tenantId']}")
    print(f"  Consented:  {result['graphPermissionsConsented']}/11 Graph perms")
    print(f"  Output dir: {out_dir}")
    print()
    if granted < 11:
        print("  [!] Finish/verify admin consent in the portal, then the app")
        print("      is fully functional.")
    else:
        print("  [OK] App is fully functional - cert auth + all 11 perms "
              "consented.")
    print("  [!] Certificate is valid 24h only. Run the remediation within")
    print("      that window. Delete Config-Reference-PLAIN-TEXT-DELETE-ME.txt")
    print("      when done.")
    print()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, TimeoutError) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
