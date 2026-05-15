#!/usr/bin/env python3
"""
Replace the WHFB Step 2 Intune PowerShell script with a new one whose
description embeds a permalink to the script source on GitHub.

Background: Intune's PATCH for deviceManagementScripts is unreliable
(downstream service returns misleading 404 / 429 depending on body). Far
simpler and more deterministic to DELETE the existing record and POST a
fresh one. Script content is identical; only the description and the
record id change. The new id is written back to whfb-remediation-objects.json.

Usage:
    python Update-IntuneScriptDescription.py
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

GITHUB_OWNER = "aollivierre"
GITHUB_REPO = "WindowsHello"
COMMIT_SHA = "54cb8d5f7164071a85a752d6f61dd5d9f5a05b1e"
SCRIPT_PATH_IN_REPO = "Remove-NgcContainer.ps1"

BLOB_URL = (
    f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/blob/"
    f"{COMMIT_SHA}/{SCRIPT_PATH_IN_REPO}"
)
RAW_URL = (
    f"https://raw.githubusercontent.com/{GITHUB_OWNER}/{GITHUB_REPO}/"
    f"{COMMIT_SHA}/{SCRIPT_PATH_IN_REPO}"
)

NEW_DESCRIPTION = (
    "WHFB remediation Step 2 - clears the corrupt NGC / Microsoft Passport "
    "container for the signed-in user via certutil -deleteHelloContainer.\n"
    "\n"
    f"SOURCE (immortal permalink at commit {COMMIT_SHA[:7]}):\n"
    f"  {BLOB_URL}\n"
    f"  Raw: {RAW_URL}\n"
    "\n"
    "Intune does not surface the uploaded script body to admins, so the "
    "URLs above are the only way to review what this script actually does. "
    "The permalink points at a specific commit SHA and is stable for the "
    "life of the repository.\n"
    "\n"
    "SEQUENCING: assign the WHFB-disable Account Protection policy first "
    "and confirm it has applied to the device. THEN assign this script. "
    "If WHFB is still enabled by policy when this runs, Windows re-"
    "provisions Hello immediately and the loop resumes (Microsoft WHFB FAQ).\n"
    "\n"
    "Windows 11 caveat: certutil -deleteHelloContainer also wipes device-"
    "bound passkeys stored on the machine, not just the Hello PIN. Ensure "
    "each affected user has an alternative sign-in available "
    "(password / registered FIDO2 security key) before assigning.\n"
    "\n"
    "Runs in user context (runAsAccount = user). Logs to "
    "%TEMP%\\Remove-NgcContainer-<user>-<ts>.log."
)


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


def main():
    print()
    print("=" * 70)
    print("  RECREATE INTUNE PS SCRIPT WITH GITHUB PERMALINK IN DESCRIPTION")
    print("=" * 70)

    if not PS_FILE.exists():
        raise RuntimeError(f"Missing {PS_FILE.name} next to this script.")

    cfg = load_cfg()
    h = {"Authorization": f"Bearer {token(cfg)}",
         "Content-Type": "application/json"}
    print(f"  Tenant:    {cfg['tenant_id']}")
    print(f"  Permalink: {BLOB_URL}")

    # 1. Find existing script(s) with our displayName (idempotent re-runs).
    existing = requests.get(
        f"{GRAPH_BETA}/deviceManagement/deviceManagementScripts"
        f"?$filter=displayName eq '{DISPLAY_NAME}'&$select=id,displayName",
        headers=h, timeout=30,
    )
    existing.raise_for_status()
    old_ids = [s["id"] for s in existing.json().get("value", [])]
    print(f"  Existing scripts matching name: {len(old_ids)}")

    # 2. DELETE each existing one.
    for old_id in old_ids:
        r = requests.delete(
            f"{GRAPH_BETA}/deviceManagement/deviceManagementScripts/{old_id}",
            headers=h, timeout=30,
        )
        if r.status_code in (200, 204):
            print(f"  [-] Deleted {old_id}")
        elif r.status_code == 404:
            print(f"  [=] {old_id} already absent")
        else:
            raise RuntimeError(
                f"DELETE {old_id} failed: {r.status_code}\n{r.text}"
            )

    # 3. POST a fresh script with the new description.
    script_b64 = base64.b64encode(PS_FILE.read_bytes()).decode("ascii")
    body = {
        "@odata.type": "#microsoft.graph.deviceManagementScript",
        "displayName": DISPLAY_NAME,
        "description": NEW_DESCRIPTION,
        "runAsAccount": "user",
        "enforceSignatureCheck": False,
        "runAs32Bit": False,
        "fileName": FILE_NAME,
        "scriptContent": script_b64,
        "roleScopeTagIds": ["0"],
    }
    r = requests.post(
        f"{GRAPH_BETA}/deviceManagement/deviceManagementScripts",
        headers=h, json=body, timeout=60,
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"POST failed: {r.status_code}\n{r.text}")
    new_id = r.json()["id"]
    print(f"  [+] Created new script: {new_id}")

    # 4. Verify: description contains the permalink, runAsAccount, 0 assignments.
    obj = requests.get(
        f"{GRAPH_BETA}/deviceManagement/deviceManagementScripts/{new_id}",
        headers=h, timeout=30,
    ).json()
    assigns = requests.get(
        f"{GRAPH_BETA}/deviceManagement/deviceManagementScripts/{new_id}"
        "/assignments", headers=h, timeout=30,
    ).json().get("value", [])
    desc = obj.get("description", "")
    print("\n--- Verification ---")
    print(f"  displayName:      {obj.get('displayName')}")
    print(f"  runAsAccount:     {obj.get('runAsAccount')}")
    print(f"  description bytes:{len(desc)}")
    print(f"  contains blob URL:{BLOB_URL in desc}")
    print(f"  contains raw URL: {RAW_URL in desc}")
    print(f"  assignments:      {len(assigns)}")
    ok = (
        BLOB_URL in desc and RAW_URL in desc
        and obj.get("runAsAccount") == "user"
        and not assigns
    )

    # 5. Update objects file with new id.
    obj_path = cfg["dir"] / "whfb-remediation-objects.json"
    objects = json.loads(obj_path.read_text(encoding="utf-8"))
    prev_id = objects.get("step2NgcResetScript", {}).get("id")
    objects["step2NgcResetScript"] = {
        "displayName": DISPLAY_NAME,
        "id": new_id,
        "previousId": prev_id,
        "surface": "Intune deviceManagementScripts",
        "runAsAccount": "user",
        "fileName": FILE_NAME,
        "githubSourcePermalink": BLOB_URL,
        "githubSourceRaw": RAW_URL,
        "recreatedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sequencingNote":
            "Must run AFTER WHFB-disable policy is assigned + applied.",
    }
    obj_path.write_text(json.dumps(objects, indent=2), encoding="utf-8")

    print()
    print("=" * 70)
    print(f"  {'[OK]' if ok else '[FAIL]'} Script recreated.")
    print(f"  New id: {new_id}")
    if prev_id:
        print(f"  (replaces old id: {prev_id})")
    print(f"  Objects file updated: {obj_path}")
    print()
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
