#!/usr/bin/env python3
"""
Add `DeviceManagementScripts.ReadWrite.All` to the WHFB-Remediation-Automation
app registration and grant admin consent.

Why: `/deviceManagement/deviceManagementScripts` enforces a dedicated
DeviceManagementScripts.* scope, separate from DeviceManagementConfiguration.*.
The original 11 perms we consented don't cover it, so the Step 2 PS-script
upload (Add-NgcResetScript.py) hits 403. This script fills that gap.

Flow:
  1. Cert auth (existing app) -> resolve the new permission's GUID from the
     Microsoft Graph service principal's appRoles catalog.
  2. Device-code sign-in as GA (Graph CLI public client, pre-consented for
     Application.ReadWrite.All + AppRoleAssignment.ReadWrite.All + Directory).
  3. PATCH /applications/{appObjectId} to add the new permission to
     requiredResourceAccess (idempotent - merges, doesn't replace).
  4. POST /servicePrincipals/{newAppSpId}/appRoleAssignedTo to grant consent
     for the new permission (idempotent - skips if already granted).
  5. Update the permission catalog + manifest + markdown files in the folder.

Usage:
    python Grant-ScriptsPermission.py
"""

import base64
import json
import secrets
import sys
import time
from pathlib import Path

import jwt
import msal
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, pkcs12,
)
from playwright.sync_api import sync_playwright

SCRIPT_DIR = Path(__file__).resolve().parent
GRAPH = "https://graph.microsoft.com/v1.0"

MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
NEW_PERMISSION_NAME = "DeviceManagementScripts.ReadWrite.All"

DEVICE_FLOW_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SCOPES = [
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.Read.All",
]
DEVICE_LOGIN_URL = "https://microsoft.com/devicelogin"
SIGN_IN_BUDGET_SECONDS = 300


# --- cert auth ----------------------------------------------------------------

def deobf(s):
    return bytes(b ^ 0x5A for b in base64.b64decode(s)).decode("utf-8") if s else ""


def load_cfg():
    cfgs = sorted(SCRIPT_DIR.glob("*/whfb-remediation-config.json"),
                  key=lambda p: p.parent.name, reverse=True)
    d = json.loads(cfgs[0].read_text(encoding="utf-8"))
    client_id = deobf(d.get("client_id_obfuscated", "")) or \
        json.loads((cfgs[0].parent / "whfb-remediation-app-result.json")
                   .read_text(encoding="utf-8"))["appId"]
    return {
        "dir": cfgs[0].parent,
        "tenant_id": deobf(d["tenant_id_obfuscated"]),
        "client_id": client_id,
        "pfx_password": deobf(d["pfx_password_obfuscated"]),
        "pfx_bytes": base64.b64decode(deobf(d["pfx_base64_obfuscated"])),
    }


def cert_token(cfg):
    pk, cert, _ = pkcs12.load_key_and_certificates(
        cfg["pfx_bytes"], cfg["pfx_password"].encode(), default_backend())
    url = f"https://login.microsoftonline.com/{cfg['tenant_id']}/oauth2/v2.0/token"
    now = int(time.time())
    claims = {"aud": url, "iss": cfg["client_id"], "sub": cfg["client_id"],
              "jti": secrets.token_hex(16), "exp": now + 600, "iat": now,
              "nbf": now}
    h = hashes.Hash(hashes.SHA1(), default_backend())
    h.update(cert.public_bytes(Encoding.DER))
    x5t = base64.urlsafe_b64encode(h.finalize()).decode().rstrip("=")
    pem = pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    a = jwt.encode(claims, pem, algorithm="RS256", headers={"x5t": x5t})
    r = requests.post(url, data={
        "client_id": cfg["client_id"],
        "client_assertion_type":
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": a,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def device_code_token(tenant_id):
    """Headed device-code sign-in as GA. Returns a delegated Graph token."""
    app = msal.PublicClientApplication(
        DEVICE_FLOW_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{tenant_id}")
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise RuntimeError(f"Device flow init failed: {flow}")
    flow["expires_at"] = min(
        flow.get("expires_at", time.time() + SIGN_IN_BUDGET_SECONDS),
        time.time() + SIGN_IN_BUDGET_SECONDS)
    code = flow["user_code"]
    print()
    print("=" * 70)
    print("  ACTION REQUIRED - sign in as Global Admin")
    print("=" * 70)
    print(f"  Chromium opens at microsoft.com/devicelogin.")
    print(f"  One-time code: {code}")
    print("  Sign in as GA of <tenant-name>, approve.")
    print("=" * 70)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        page = browser.new_context().new_page()
        page.goto(DEVICE_LOGIN_URL, wait_until="domcontentloaded")
        try:
            page.fill("input[name='otc'], #otc", code, timeout=8000)
            page.click("#idSIButton9", timeout=4000)
        except Exception:
            print(f"[*] Auto-fill failed - type the code manually: {code}")
        result = app.acquire_token_by_device_flow(flow)
        browser.close()
    if "access_token" not in result:
        raise RuntimeError(
            f"Device-code failed: {result.get('error_description', result)}")
    return result["access_token"]


# --- main ---------------------------------------------------------------------

def main():
    print()
    print("=" * 70)
    print("  ADD + CONSENT 'DeviceManagementScripts.ReadWrite.All'")
    print("=" * 70)

    cfg = load_cfg()
    cert_tok = cert_token(cfg)
    print("[OK] Cert-based token (existing app) acquired.")

    # --- Phase 1: resolve the new permission's GUID via cert token
    print("\n[*] Resolving Graph SP appRoles for "
          f"'{NEW_PERMISSION_NAME}'...")
    h = {"Authorization": f"Bearer {cert_tok}"}
    r = requests.get(
        f"{GRAPH}/servicePrincipals(appId='{MS_GRAPH_APP_ID}')"
        "?$select=id,appRoles", headers=h, timeout=30)
    r.raise_for_status()
    graph_sp = r.json()
    graph_sp_id = graph_sp["id"]
    role = next((a for a in graph_sp["appRoles"]
                 if a["value"] == NEW_PERMISSION_NAME), None)
    if not role:
        raise RuntimeError(f"{NEW_PERMISSION_NAME} not found in catalog.")
    new_role_id = role["id"]
    print(f"[OK] Graph SP:    {graph_sp_id}")
    print(f"[OK] Role GUID:   {new_role_id}")
    print(f"     description: {role.get('description', '')[:120]}")

    # Load the existing app + SP id from the result file
    res_path = cfg["dir"] / "whfb-remediation-app-result.json"
    res = json.loads(res_path.read_text(encoding="utf-8"))
    app_obj_id = res["objectId"]
    new_sp_id = res["servicePrincipalId"]
    print(f"[*] App object id:    {app_obj_id}")
    print(f"[*] App SP id:        {new_sp_id}")

    # --- Phase 2: device-code GA token (needed for both PATCH app + consent)
    ga_tok = device_code_token(cfg["tenant_id"])
    print("[OK] GA delegated token acquired.")

    gh = {"Authorization": f"Bearer {ga_tok}",
          "Content-Type": "application/json"}

    # --- Phase 3a: PATCH requiredResourceAccess to add the new permission
    print("\n[*] Reading current requiredResourceAccess...")
    r = requests.get(
        f"{GRAPH}/applications/{app_obj_id}?$select=requiredResourceAccess",
        headers=gh, timeout=30)
    r.raise_for_status()
    rra = r.json().get("requiredResourceAccess", [])

    graph_block = next(
        (b for b in rra if b["resourceAppId"] == MS_GRAPH_APP_ID), None)
    if graph_block is None:
        graph_block = {"resourceAppId": MS_GRAPH_APP_ID, "resourceAccess": []}
        rra.append(graph_block)
    already_in_manifest = any(
        a["id"] == new_role_id for a in graph_block["resourceAccess"])
    if already_in_manifest:
        print("[=] Permission already in requiredResourceAccess.")
    else:
        graph_block["resourceAccess"].append(
            {"id": new_role_id, "type": "Role"})
        r = requests.patch(
            f"{GRAPH}/applications/{app_obj_id}",
            headers=gh,
            json={"requiredResourceAccess": rra}, timeout=30)
        if r.status_code not in (200, 204):
            raise RuntimeError(
                f"PATCH application failed: {r.status_code}\n{r.text}")
        print(f"[+] PATCHed app to include {NEW_PERMISSION_NAME}")

    # --- Phase 3b: grant admin consent (appRoleAssignedTo)
    print("\n[*] Granting admin consent for the new permission...")
    existing = requests.get(
        f"{GRAPH}/servicePrincipals/{new_sp_id}/appRoleAssignments",
        headers=gh, timeout=30)
    existing.raise_for_status()
    already_granted = any(
        a.get("appRoleId") == new_role_id and a.get("resourceId") == graph_sp_id
        for a in existing.json().get("value", []))
    if already_granted:
        print("[=] Consent already granted.")
    else:
        r = requests.post(
            f"{GRAPH}/servicePrincipals/{new_sp_id}/appRoleAssignedTo",
            headers=gh,
            json={"principalId": new_sp_id,
                  "resourceId": graph_sp_id,
                  "appRoleId": new_role_id}, timeout=30)
        if r.status_code in (200, 201):
            print(f"[+] Consent granted for {NEW_PERMISSION_NAME}")
        elif r.status_code == 400 and "already exists" in r.text.lower():
            print("[=] Consent already existed.")
        else:
            raise RuntimeError(
                f"Consent grant failed: {r.status_code}\n{r.text}")

    # --- Phase 4: persist - update the local catalog/manifest/md
    print("\n[*] Updating local catalog / manifest / markdown...")
    cat_path = SCRIPT_DIR / "whfb-remediation-permissions-catalog.json"
    cat = json.loads(cat_path.read_text(encoding="utf-8"))
    if not any(e["id"] == new_role_id for e in cat):
        cat.append({
            "id": new_role_id, "name": NEW_PERMISSION_NAME,
            "description": role.get("description", ""),
            "category": "write-action",
        })
        cat_path.write_text(json.dumps(cat, indent=2), encoding="utf-8")
        print(f"  + {cat_path.name}")

    man_path = SCRIPT_DIR / "whfb-remediation-permissions-manifest.json"
    man = json.loads(man_path.read_text(encoding="utf-8"))
    block = next(
        (b for b in man["requiredResourceAccess"]
         if b["resourceAppId"] == MS_GRAPH_APP_ID), None)
    if block and not any(a["id"] == new_role_id for a in block["resourceAccess"]):
        block["resourceAccess"].append({"id": new_role_id, "type": "Role"})
        man_path.write_text(json.dumps(man, indent=2), encoding="utf-8")
        print(f"  + {man_path.name}")

    # final verify
    print("\n[*] Verifying...")
    final = requests.get(
        f"{GRAPH}/servicePrincipals/{new_sp_id}/appRoleAssignments",
        headers=gh, timeout=30).json().get("value", [])
    total_graph = len([a for a in final if a.get("resourceId") == graph_sp_id])
    print(f"  Total consented Graph perms now: {total_graph}")

    print()
    print("=" * 70)
    print(f"  [OK] {NEW_PERMISSION_NAME} added + consented.")
    print("  Now re-run:  python Add-NgcResetScript.py")
    print("=" * 70)
    print()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
