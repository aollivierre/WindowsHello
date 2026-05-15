#!/usr/bin/env python3
"""
Read-only: dump the exact structure of the two setting definitions we need to
rebuild the WHFB policies on their best-practice surfaces:

  - WHFB disable  -> Endpoint Security 'Account Protection' template:
        device_vendor_msft_passportforwork_{tenantid}_policies_usepassportforwork
    Dumps the template id + the settingTemplate (settingInstanceTemplate,
    choice option ids, value template references) needed for a template-bound
    configurationPolicies POST.

  - Security-key  -> Settings Catalog:
        device_vendor_msft_passportforwork_securitykey_usesecuritykeyforsignin
    Dumps the configurationSettings definition (choice options) needed for a
    plain Settings Catalog configurationPolicies POST.

Writes whfb-setting-defs.json so the rebuild script can consume it.

Usage:
    python Inspect-WHFBSettingDefs.py
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

WHFB_DEVICE_SETTING = (
    "device_vendor_msft_passportforwork_{tenantid}_policies_usepassportforwork"
)
SECKEY_SETTING = (
    "device_vendor_msft_passportforwork_securitykey_usesecuritykeyforsignin"
)


def deobfuscate(s):
    return bytes(b ^ 0x5A for b in base64.b64decode(s)).decode("utf-8") if s else ""


def load_cfg():
    cfgs = sorted(SCRIPT_DIR.glob("*/whfb-remediation-config.json"),
                  key=lambda p: p.parent.name, reverse=True)
    data = json.loads(cfgs[0].read_text(encoding="utf-8"))
    client_id = deobfuscate(data.get("client_id_obfuscated", "")) or \
        json.loads((cfgs[0].parent / "whfb-remediation-app-result.json")
                   .read_text(encoding="utf-8"))["appId"]
    return {
        "tenant_id": deobfuscate(data["tenant_id_obfuscated"]),
        "client_id": client_id,
        "pfx_password": deobfuscate(data["pfx_password_obfuscated"]),
        "pfx_bytes": base64.b64decode(deobfuscate(data["pfx_base64_obfuscated"])),
    }


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


def pages(h, url, cap=40):
    if url.startswith("/"):
        url = GRAPH_BETA + url
    n = 0
    while url and n < cap:
        r = requests.get(url, headers=h, timeout=60)
        r.raise_for_status()
        data = r.json()
        for it in data.get("value", []):
            yield it
        url = data.get("@odata.nextLink")
        n += 1


def get(h, url):
    if url.startswith("/"):
        url = GRAPH_BETA + url
    r = requests.get(url, headers=h, timeout=60)
    r.raise_for_status()
    return r.json()


def main():
    cfg = load_cfg()
    h = {"Authorization": f"Bearer {get_token(cfg)}"}
    print("=" * 70)
    print("  INSPECT WHFB SETTING DEFINITIONS  (read-only)")
    print("=" * 70)
    print(f"  Tenant: {cfg['tenant_id']}")

    out = {"tenantId": cfg["tenant_id"]}

    # --- 1. Account Protection template + the usepassportforwork settingTemplate
    print("\n--- Endpoint Security: Account Protection template ---")
    templates = list(pages(
        h, "/deviceManagement/configurationPolicyTemplates"
        "?$select=id,displayName,templateFamily,lifecycleState,version"))
    ap = [t for t in templates
          if (t.get("templateFamily") or "").lower()
          == "endpointsecurityaccountprotection"]
    if not ap:
        print("  [!] No Account Protection template found.")
    else:
        # prefer the active, highest-version one
        ap.sort(key=lambda t: (t.get("lifecycleState") == "active",
                               t.get("version", 0)), reverse=True)
        tpl = ap[0]
        print(f"  template id:      {tpl['id']}")
        print(f"  displayName:      {tpl.get('displayName')}")
        print(f"  templateFamily:   {tpl.get('templateFamily')}")
        print(f"  version / state:  v{tpl.get('version')} "
              f"{tpl.get('lifecycleState')}")
        out["accountProtectionTemplate"] = {
            "id": tpl["id"], "displayName": tpl.get("displayName"),
            "templateFamily": tpl.get("templateFamily"),
            "version": tpl.get("version"),
        }

        sts = list(pages(
            h, f"/deviceManagement/configurationPolicyTemplates/{tpl['id']}"
            f"/settingTemplates?$expand=settingDefinitions"))
        match = None
        for st in sts:
            for sd in st.get("settingDefinitions", []):
                if sd.get("id") == WHFB_DEVICE_SETTING:
                    match = st
                    break
            if match:
                break
        if not match:
            print(f"  [!] settingTemplate for {WHFB_DEVICE_SETTING} not found")
        else:
            print(f"  [OK] found settingTemplate for the device WHFB toggle")
            out["whfbDeviceSettingTemplate"] = match
            print("  --- settingTemplate JSON (truncated to key bits) ---")
            sit = match.get("settingInstanceTemplate", {})
            print(f"    settingInstanceTemplateId: "
                  f"{sit.get('settingInstanceTemplateId')}")
            print(f"    @odata.type:               {sit.get('@odata.type')}")
            print(f"    settingDefinitionId:       "
                  f"{sit.get('settingDefinitionId')}")
            # choice options for the WHFB device setting
            for sd in match.get("settingDefinitions", []):
                if sd.get("id") == WHFB_DEVICE_SETTING:
                    print(f"    options for {WHFB_DEVICE_SETTING}:")
                    for opt in sd.get("options", []):
                        print(f"      - itemId={opt.get('itemId')}  "
                              f"name={opt.get('name')}  "
                              f"displayName="
                              f"{opt.get('displayName')}")

    # --- 2. Settings Catalog: usesecuritykeyforsignin definition
    print("\n--- Settings Catalog: UseSecurityKeyForSignin ---")
    try:
        sk = get(h, f"/deviceManagement/configurationSettings/{SECKEY_SETTING}")
        print(f"  id:           {sk.get('id')}")
        print(f"  @odata.type:  {sk.get('@odata.type')}")
        print(f"  displayName:  {sk.get('displayName')}")
        out["securityKeySetting"] = sk
        for opt in sk.get("options", []):
            print(f"    option: itemId={opt.get('itemId')}  "
                  f"name={opt.get('name')}  "
                  f"displayName={opt.get('displayName')}")
        # default value template reference, if any
        dv = sk.get("defaultValue")
        if dv:
            print(f"  defaultValue: {json.dumps(dv)[:200]}")
    except requests.HTTPError as e:
        print(f"  [!] could not fetch {SECKEY_SETTING}: {e}")

    out_path = SCRIPT_DIR / "whfb-setting-defs.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\n  Full definitions written to: {out_path}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
