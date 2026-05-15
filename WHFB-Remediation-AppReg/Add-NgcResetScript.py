#!/usr/bin/env python3
"""
Upload Remove-NgcContainer.ps1 as an Intune user-context PowerShell script
(/deviceManagement/deviceManagementScripts), unassigned.

Fills the WHFB remediation Step 2 gap. Step 2 is `certutil -deleteHelloContainer`
which has to run in each affected user's session - there's no Graph
*configuration policy* surface for it, but Intune's classic PowerShell scripts
support exactly this (runAsAccount=user, fires on the next user check-in).

Idempotent: existing scripts with the same displayName are reused, not
duplicated. Created UNASSIGNED so it doesn't fire until you explicitly target
the FrontDesk-SharedPCs (or a user group) in Intune.

Usage:
    python Add-NgcResetScript.py
"""

import base64
import datetime
import json
import secrets
import sys
import time
from pathlib import Path

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, pkcs12,
)

SCRIPT_DIR = Path(__file__).resolve().parent
PS_FILE = SCRIPT_DIR / "Remove-NgcContainer.ps1"
GRAPH_BETA = "https://graph.microsoft.com/beta"

DISPLAY_NAME = "FrontDesk - Clear NGC Container (WHFB Step 2)"
FILE_NAME = "Remove-NgcContainer.ps1"


def deobf(s):
    return bytes(b ^ 0x5A for b in base64.b64decode(s)).decode("utf-8") if s else ""


def load_cfg():
    cfgs = sorted(SCRIPT_DIR.glob("*/whfb-remediation-config.json"),
                  key=lambda p: p.parent.name, reverse=True)
    d = json.loads(cfgs[0].read_text(encoding="utf-8"))
    client_id = deobf(d.get("client_id_obfuscated", "")) or \
        json.loads((cfgs[0].parent / "whfb-remediation-app-result.json")
                   .read_text(encoding="utf-8"))["appId"]
    return {"dir": cfgs[0].parent,
            "tenant_id": deobf(d["tenant_id_obfuscated"]),
            "client_id": client_id,
            "pfx_password": deobf(d["pfx_password_obfuscated"]),
            "pfx_bytes": base64.b64decode(deobf(d["pfx_base64_obfuscated"]))}


def token(cfg):
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


class G:
    def __init__(self, tok):
        self.h = {"Authorization": f"Bearer {tok}",
                  "Content-Type": "application/json"}

    def get(self, p):
        r = requests.get(f"{GRAPH_BETA}{p}", headers=self.h, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(
                f"GET {p} -> HTTP {r.status_code}\nBody: {r.text}"
            )
        return r.json()

    def post(self, p, b):
        return requests.post(f"{GRAPH_BETA}{p}", headers=self.h, json=b,
                             timeout=60)


def find_existing(g, name):
    res = g.get(
        f"/deviceManagement/deviceManagementScripts"
        f"?$filter=displayName eq '{name}'&$select=id,displayName"
    ).get("value", [])
    return res[0]["id"] if res else None


def main():
    print()
    print("=" * 70)
    print("  UPLOAD STEP 2 INTUNE POWERSHELL SCRIPT (UNASSIGNED)")
    print("=" * 70)

    if not PS_FILE.exists():
        raise RuntimeError(f"Missing {PS_FILE.name} next to this script.")

    cfg = load_cfg()
    g = G(token(cfg))
    print(f"  Tenant: {cfg['tenant_id']}")
    print(f"  Script: {PS_FILE}")
    print("  [OK] Cert-based token acquired.")

    ps_bytes = PS_FILE.read_bytes()
    script_b64 = base64.b64encode(ps_bytes).decode("ascii")
    print(f"  Script size: {len(ps_bytes)} bytes -> "
          f"{len(script_b64)} base64 chars")

    existing = find_existing(g, DISPLAY_NAME)
    if existing:
        sid = existing
        created = False
        print(f"  [=] Intune script already exists: {DISPLAY_NAME} ({sid})")
    else:
        body = {
            "@odata.type": "#microsoft.graph.deviceManagementScript",
            "displayName": DISPLAY_NAME,
            "description": (
                "WHFB remediation Step 2 - runs certutil -deleteHelloContainer "
                "in user context to clear the corrupt NGC / Microsoft Passport "
                "container for the signed-in user.\n\n"
                "SEQUENCING: assign the WHFB-disable Account Protection "
                "policy first and confirm it has applied. THEN assign this "
                "script. If WHFB is still enabled by policy when this runs, "
                "Windows re-provisions immediately and the loop resumes "
                "(Microsoft WHFB FAQ).\n\n"
                "Windows 11 caveat: also wipes device-bound passkeys on the "
                "machine. Ensure each affected user has an alternative "
                "sign-in (password / registered YubiKey) before assigning.\n\n"
                "Runs in user context. Logs to %TEMP%\\Remove-NgcContainer-"
                "<user>-<ts>.log. UNASSIGNED on creation."
            ),
            "runAsAccount": "user",
            "enforceSignatureCheck": False,
            "runAs32Bit": False,
            "fileName": FILE_NAME,
            "scriptContent": script_b64,
            "roleScopeTagIds": ["0"],
        }
        r = g.post("/deviceManagement/deviceManagementScripts", body)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"create failed: {r.status_code}\n{r.text}")
        sid = r.json()["id"]
        created = True
        print(f"  [+] Intune script created: {DISPLAY_NAME} ({sid})")

    # Self-verify: properties + ZERO assignments + groupAssignments
    print("\n--- Verify (no assignments, expected runAsAccount/file) ---")
    obj = g.get(f"/deviceManagement/deviceManagementScripts/{sid}")
    assigns = g.get(
        f"/deviceManagement/deviceManagementScripts/{sid}/assignments"
    ).get("value", [])
    grp_assigns = g.get(
        f"/deviceManagement/deviceManagementScripts/{sid}/groupAssignments"
    ).get("value", [])
    print(f"  displayName:    {obj.get('displayName')}")
    print(f"  fileName:       {obj.get('fileName')}")
    print(f"  runAsAccount:   {obj.get('runAsAccount')}  (expected: user)")
    print(f"  enforceSig:     {obj.get('enforceSignatureCheck')}")
    print(f"  runAs32Bit:     {obj.get('runAs32Bit')}")
    print(f"  assignments:    {len(assigns)}  (expected: 0)")
    print(f"  groupAssigns:   {len(grp_assigns)}  (expected: 0)")
    ok = (
        obj.get("runAsAccount") == "user"
        and obj.get("fileName") == FILE_NAME
        and not assigns
        and not grp_assigns
    )

    # Persist
    obj_path = cfg["dir"] / "whfb-remediation-objects.json"
    objects = json.loads(obj_path.read_text(encoding="utf-8"))
    objects["step2NgcResetScript"] = {
        "displayName": DISPLAY_NAME,
        "id": sid,
        "created": created,
        "surface": "Intune deviceManagementScripts",
        "runAsAccount": "user",
        "fileName": FILE_NAME,
        "addedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sequencingNote":
            "Must run AFTER WHFB-disable policy is assigned + applied.",
    }
    obj_path.write_text(json.dumps(objects, indent=2), encoding="utf-8")

    print()
    print("=" * 70)
    if ok:
        print("  [SUCCESS] Step 2 script uploaded. Inert (0 assignments).")
    else:
        print("  [FAIL] Verification did not match expectations - see above.")
    print(f"  Script id: {sid}")
    print(f"  Objects file updated: {obj_path}")
    print()
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
