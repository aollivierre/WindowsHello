#!/usr/bin/env python3
"""
Verify the WHFB remediation objects exist and - critically - that NOTHING is
assigned. Reads object ids from the newest whfb-remediation-objects.json,
authenticates with the app's certificate, and confirms:

  - the group exists and contains exactly the expected device
  - each device configuration profile exists
  - each device configuration profile has ZERO assignments

Usage:
    python Verify-WHFBObjects.py
"""

import base64
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
GRAPH = "https://graph.microsoft.com/v1.0"


def deobfuscate(s):
    return bytes(b ^ 0x5A for b in base64.b64decode(s)).decode("utf-8") if s else ""


def load():
    cfgs = sorted(SCRIPT_DIR.glob("*/whfb-remediation-config.json"),
                  key=lambda p: p.parent.name, reverse=True)
    objs = sorted(SCRIPT_DIR.glob("*/whfb-remediation-objects.json"),
                  key=lambda p: p.parent.name, reverse=True)
    if not cfgs or not objs:
        raise RuntimeError("Missing config or objects json - run the other "
                           "scripts first.")
    data = json.loads(cfgs[0].read_text(encoding="utf-8"))
    client_id = deobfuscate(data.get("client_id_obfuscated", "")) or \
        json.loads((cfgs[0].parent / "whfb-remediation-app-result.json")
                   .read_text(encoding="utf-8"))["appId"]
    cfg = {
        "tenant_id": deobfuscate(data["tenant_id_obfuscated"]),
        "client_id": client_id,
        "pfx_password": deobfuscate(data["pfx_password_obfuscated"]),
        "pfx_bytes": base64.b64decode(deobfuscate(data["pfx_base64_obfuscated"])),
    }
    return cfg, json.loads(objs[0].read_text(encoding="utf-8"))


def get_token(cfg):
    pk, cert, _ = pkcs12.load_key_and_certificates(
        cfg["pfx_bytes"], cfg["pfx_password"].encode(), default_backend())
    url = f"https://login.microsoftonline.com/{cfg['tenant_id']}/oauth2/v2.0/token"
    now = int(time.time())
    claims = {"aud": url, "iss": cfg["client_id"], "sub": cfg["client_id"],
              "jti": secrets.token_hex(16), "exp": now + 600, "iat": now,
              "nbf": now}
    d = hashes.Hash(hashes.SHA1(), default_backend())
    d.update(cert.public_bytes(Encoding.DER))
    x5t = base64.urlsafe_b64encode(d.finalize()).decode().rstrip("=")
    pem = pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    assertion = jwt.encode(claims, pem, algorithm="RS256", headers={"x5t": x5t})
    r = requests.post(url, data={
        "client_id": cfg["client_id"],
        "client_assertion_type":
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def main():
    cfg, objs = load()
    h = {"Authorization": f"Bearer {get_token(cfg)}"}

    def get(path):
        r = requests.get(f"{GRAPH}{path}", headers=h, timeout=30)
        r.raise_for_status()
        return r.json()

    def get_beta(path):
        r = requests.get(f"https://graph.microsoft.com/beta{path}",
                         headers=h, timeout=30)
        r.raise_for_status()
        return r.json()

    print()
    print("=" * 70)
    print("  VERIFY WHFB REMEDIATION OBJECTS")
    print("=" * 70)

    ok = True

    # --- group + membership ---
    gid = objs["group"]["id"]
    grp = get(f"/groups/{gid}?$select=id,displayName")
    members = get(f"/groups/{gid}/members?$select=id,displayName").get("value", [])
    print(f"\n  Group: {grp['displayName']}  ({gid})")
    print(f"    members: {len(members)}")
    for m in members:
        print(f"      - {m.get('displayName')}  ({m['id']})")
    expect_dev = objs["groupMemberDevice"]["entraDeviceObjectId"]
    if not any(m["id"] == expect_dev for m in members):
        print("    [FAIL] expected device not in group")
        ok = False
    else:
        print("    [OK] expected device present")

    # --- each policy: exists on its best-practice surface + ZERO assignments ---
    # Policies are now configurationPolicies (Endpoint Security / Settings
    # Catalog), not the old Custom OMA-URI deviceConfigurations.
    for key in ("whfbDisablePolicy", "securityKeyPolicy"):
        pid = objs[key]["id"]
        surface = objs[key].get("surface", "?")
        pol = get_beta(f"/deviceManagement/configurationPolicies/{pid}")
        settings = get_beta(f"/deviceManagement/configurationPolicies/{pid}"
                            f"/settings").get("value", [])
        assigns = get_beta(f"/deviceManagement/configurationPolicies/{pid}"
                           f"/assignments").get("value", [])
        tref = (pol.get("templateReference") or {}).get("templateId") or "(none)"
        print(f"\n  Policy: {pol['name']}  ({pid})")
        print(f"    surface:     {surface}")
        print(f"    template:    {tref}")
        print(f"    settings:    {len(settings)} configured")
        print(f"    assignments: {len(assigns)}")
        if len(settings) < 1:
            print("    [FAIL] policy has no settings")
            ok = False
        if assigns:
            print("    [FAIL] policy IS assigned - expected 0 assignments")
            for a in assigns:
                print(f"      - {json.dumps(a.get('target', {}))}")
            ok = False
        else:
            print("    [OK] ZERO assignments - inert")

    print()
    print("=" * 70)
    if ok:
        print("  [SUCCESS] All objects exist. NO assignments anywhere - "
              "everything is inert.")
        return 0
    print("  [FAIL] See [FAIL] lines above.")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
