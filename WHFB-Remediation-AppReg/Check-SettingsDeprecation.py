#!/usr/bin/env python3
"""
Check the deprecation / lifecycle status of the two setting definitions we
used, straight from the live Graph beta configurationSettings catalog.

Looks at:
  - deprecatedInfo  (if Microsoft has flagged it deprecated)
  - applicability   (platform / technologies / deviceMode)
  - visibility / accessTypes
  - the Account Protection template's lifecycleState + version

Usage:
    python Check-SettingsDeprecation.py
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
GRAPH_BETA = "https://graph.microsoft.com/beta"

WHFB_DEV = (
    "device_vendor_msft_passportforwork_{tenantid}_policies_usepassportforwork"
)
SECKEY = (
    "device_vendor_msft_passportforwork_securitykey_usesecuritykeyforsignin"
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
    return {"tenant_id": deobf(d["tenant_id_obfuscated"]),
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


def report(name, sd):
    print(f"\n  {name}:")
    print(f"    id:                {sd.get('id')}")
    print(f"    displayName:       {sd.get('displayName')}")
    print(f"    @odata.type:       {sd.get('@odata.type')}")
    print(f"    visibility:        {sd.get('visibility')}")
    print(f"    accessTypes:       {sd.get('accessTypes')}")
    dep = sd.get("deprecatedInfo")
    print(f"    deprecatedInfo:    {json.dumps(dep) if dep else '(none - NOT deprecated)'}")
    app = sd.get("applicability", {})
    print(f"    applicability:")
    print(f"      platform:        {app.get('platform')}")
    print(f"      technologies:    {app.get('technologies')}")
    print(f"      deviceMode:      {app.get('deviceMode')}")
    print(f"      minOS:           {app.get('minimumSupportedVersion')}")
    print(f"      maxOS:           {app.get('maximumSupportedVersion')}")
    print(f"    riskLevel:         {sd.get('riskLevel')}")
    print(f"    rootDefinitionId:  {sd.get('rootDefinitionId')}")


def main():
    cfg = load_cfg()
    h = {"Authorization": f"Bearer {token(cfg)}"}

    def get(path):
        r = requests.get(f"{GRAPH_BETA}{path}", headers=h, timeout=30)
        r.raise_for_status()
        return r.json()

    print("=" * 70)
    print("  DEPRECATION / LIFECYCLE CHECK")
    print("=" * 70)
    print(f"  Tenant: {cfg['tenant_id']}")

    # ES Account Protection template lifecycle
    templates = get("/deviceManagement/configurationPolicyTemplates"
                    "?$filter=templateFamily eq 'endpointSecurityAccountProtection'"
                    "&$select=id,displayName,lifecycleState,version,"
                    "platforms,technologies").get("value", [])
    print("\n  Endpoint Security: Account Protection template versions in tenant:")
    for t in templates:
        print(f"    - {t.get('displayName')} v{t.get('version')}  "
              f"lifecycleState={t.get('lifecycleState')}  "
              f"id={t.get('id')}")

    # Setting definitions
    whfb = get(f"/deviceManagement/configurationSettings/{WHFB_DEV}")
    seckey = get(f"/deviceManagement/configurationSettings/{SECKEY}")
    report("WHFB disable (device) - used in ES Account Protection", whfb)
    report("UseSecurityKeyForSignin - used in Settings Catalog", seckey)

    print()
    print("=" * 70)
    flagged = []
    if whfb.get("deprecatedInfo"):
        flagged.append("WHFB disable")
    if seckey.get("deprecatedInfo"):
        flagged.append("UseSecurityKeyForSignin")
    if flagged:
        print(f"  [!] DEPRECATED: {', '.join(flagged)} - review deprecatedInfo above")
        return 1
    active_templates = [t for t in templates
                        if t.get("lifecycleState") == "active"]
    if not active_templates:
        print("  [!] No ACTIVE Account Protection template version in tenant.")
        return 1
    print("  [OK] Neither setting has a deprecatedInfo flag; an ACTIVE "
          f"Account Protection template exists ({len(active_templates)} "
          "active version(s)).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
