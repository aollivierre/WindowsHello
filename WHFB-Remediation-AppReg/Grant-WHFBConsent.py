#!/usr/bin/env python3
"""
Programmatically grant admin consent to the WHFB-Remediation-Automation app for
all 11 Microsoft Graph application permissions.

Same approach as the repo's Grant-GraphAdminConsent.ps1 (per-permission
appRoleAssignment POSTs, idempotent) - but auth is device-code instead of ROPC,
because the <tenant-name> GA is MFA-enforced and ROPC hard-fails on MFA
(AADSTS50158). Device-code sign-in already worked when the app was created.

Flow:
  1. Load the newest whfb-remediation-app-result.json (appId, servicePrincipalId)
     and the 11 permission GUIDs from whfb-remediation-permissions-manifest.json.
  2. Device-code sign-in (headed Chromium at microsoft.com/devicelogin, code
     pre-filled). You sign in as Global Admin and approve.
  3. Resolve the Microsoft Graph service principal object id in the tenant.
  4. GET the app SP's existing appRoleAssignments - skip any already granted.
  5. POST one appRoleAssignment per missing permission.
  6. Verify 11/11 and update whfb-remediation-app-result.json.

Usage:
    python Grant-WHFBConsent.py

Requires: msal, playwright (+ chromium), requests
"""

import json
import sys
import time
from pathlib import Path

import msal
import requests
from playwright.sync_api import sync_playwright

SCRIPT_DIR = Path(__file__).resolve().parent
PERMS_MANIFEST = SCRIPT_DIR / "whfb-remediation-permissions-manifest.json"

GRAPH = "https://graph.microsoft.com/v1.0"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
TENANT_ID = "00000000-0000-0000-0000-000000000000"  # <tenant-name>

DEVICE_FLOW_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Graph CLI tools
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["AppRoleAssignment.ReadWrite.All", "Directory.Read.All"]

DEVICE_LOGIN_URL = "https://microsoft.com/devicelogin"
SIGN_IN_BUDGET_SECONDS = 300


def latest_result_file():
    """Newest WHFB-Remediation-AppReg/<ts>/whfb-remediation-app-result.json."""
    candidates = sorted(
        SCRIPT_DIR.glob("*/whfb-remediation-app-result.json"),
        key=lambda p: p.parent.name,
        reverse=True,
    )
    if not candidates:
        raise RuntimeError(
            "No whfb-remediation-app-result.json found - run "
            "Create-WHFBRemediationApp.py first."
        )
    return candidates[0]


def load_inputs():
    result_path = latest_result_file()
    result = json.loads(result_path.read_text(encoding="utf-8"))

    manifest = json.loads(PERMS_MANIFEST.read_text(encoding="utf-8"))
    role_ids = [
        ra["id"]
        for rra in manifest["requiredResourceAccess"]
        if rra["resourceAppId"] == MS_GRAPH_APP_ID
        for ra in rra["resourceAccess"]
        if ra["type"] == "Role"
    ]
    if not role_ids:
        raise RuntimeError("No Graph app-role GUIDs found in the manifest.")

    print(f"[*] App:        {result['displayName']} ({result['appId']})")
    print(f"[*] SP id:      {result['servicePrincipalId']}")
    print(f"[*] Result file:{result_path}")
    print(f"[*] Permissions:{len(role_ids)} Graph app-roles to consent")
    return result, result_path, role_ids


def device_code_sign_in():
    """Headed device-code sign-in. Returns a Graph access token."""
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
    print("  Confirm the code (pre-filled if possible), sign in as a Global")
    print("  Administrator of the <tenant-name> tenant, and approve.")
    print("  Leave the window open; the script continues by itself.")
    print("=" * 70)
    print()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        page = browser.new_context().new_page()
        page.goto(DEVICE_LOGIN_URL, wait_until="domcontentloaded")
        try:
            page.fill("input[name='otc'], #otc", user_code, timeout=8000)
            page.click("#idSIButton9", timeout=4000)
        except Exception:
            print(f"[*] Auto-fill unavailable - type the code manually: "
                  f"{user_code}")

        token_result = app_client.acquire_token_by_device_flow(flow)
        browser.close()

    if "access_token" not in token_result:
        raise RuntimeError(
            "Device-code sign-in failed: "
            f"{token_result.get('error_description', token_result)}"
        )
    print("[OK] Signed in. Graph token acquired.")
    return token_result["access_token"]


def graph_sp_object_id(token):
    r = requests.get(
        f"{GRAPH}/servicePrincipals(appId='{MS_GRAPH_APP_ID}')?$select=id",
        headers={"Authorization": f"Bearer {token}"}, timeout=30,
    )
    r.raise_for_status()
    return r.json()["id"]


def existing_assignments(token, sp_id, graph_sp_id):
    """Set of appRoleId already assigned against Microsoft Graph (idempotent)."""
    granted = set()
    url = f"{GRAPH}/servicePrincipals/{sp_id}/appRoleAssignments"
    while url:
        r = requests.get(
            url, headers={"Authorization": f"Bearer {token}"}, timeout=30
        )
        r.raise_for_status()
        data = r.json()
        for a in data.get("value", []):
            if a.get("resourceId") == graph_sp_id:
                granted.add(a["appRoleId"])
        url = data.get("@odata.nextLink")
    return granted


def grant_role(token, sp_id, graph_sp_id, role_id):
    r = requests.post(
        f"{GRAPH}/servicePrincipals/{sp_id}/appRoleAssignedTo",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json={
            "principalId": sp_id,
            "resourceId": graph_sp_id,
            "appRoleId": role_id,
        },
        timeout=30,
    )
    if r.status_code in (200, 201):
        return True, ""
    # 400 with "Permission being assigned already exists" => treat as success
    if r.status_code == 400 and "already exists" in r.text.lower():
        return True, "already existed"
    return False, f"{r.status_code} {r.text}"


def main():
    print()
    print("=" * 70)
    print("  GRANT ADMIN CONSENT - WHFB-Remediation-Automation")
    print("=" * 70)

    result, result_path, role_ids = load_inputs()
    sp_id = result["servicePrincipalId"]

    token = device_code_sign_in()

    print("[*] Resolving Microsoft Graph service principal in the tenant...")
    graph_sp_id = graph_sp_object_id(token)
    print(f"[OK] Graph SP: {graph_sp_id}")

    print("[*] Checking existing appRoleAssignments (idempotent)...")
    already = existing_assignments(token, sp_id, graph_sp_id)
    print(f"[OK] {len(already)} of {len(role_ids)} already consented")

    granted, failed = 0, []
    for role_id in role_ids:
        if role_id in already:
            continue
        ok, detail = grant_role(token, sp_id, graph_sp_id, role_id)
        if ok:
            granted += 1
            print(f"  granted: {role_id} {detail}".rstrip())
        else:
            failed.append((role_id, detail))
            print(f"  FAILED:  {role_id} -> {detail}")

    # verify final state
    final = existing_assignments(token, sp_id, graph_sp_id)
    total = len(final)
    print()
    print("=" * 70)
    print("  RESULT")
    print("=" * 70)
    print(f"  Newly granted:    {granted}")
    print(f"  Already existed:  {len(already)}")
    print(f"  Failed:           {len(failed)}")
    print(f"  Total consented:  {total}/{len(role_ids)}")

    result["graphPermissionsConsented"] = total
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if total >= len(role_ids) and not failed:
        print()
        print("  [OK] App is fully functional - cert auth + all "
              f"{len(role_ids)} permissions consented.")
        print("  [!] Certificate is valid 24h only - run the remediation")
        print("      within that window.")
        return 0
    print()
    for role_id, detail in failed:
        print(f"  [!] {role_id}: {detail}")
    print("  [!] Some permissions did not consent - see above.")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
