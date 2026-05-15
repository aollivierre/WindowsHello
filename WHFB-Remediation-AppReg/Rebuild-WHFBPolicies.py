#!/usr/bin/env python3
"""
Rebuild the two WHFB policies on their best-practice surfaces, replacing the
Custom OMA-URI shortcut. Confirmed by Discover-IntuneSurfaces.py:

  - WHFB disable -> ENDPOINT SECURITY 'Account Protection' template
                    (template-bound configurationPolicy)
  - Security-key -> SETTINGS CATALOG (plain configurationPolicy; ES has no
                    UseSecurityKeyForSignin setting)

All template / instance / value GUIDs are DERIVED from whfb-setting-defs.json
(produced by Inspect-WHFBSettingDefs.py) - nothing hardcoded, tenant-correct.

Steps:
  1. Cert auth.
  2. Build + POST the Endpoint Security Account Protection policy
     (UsePassportForWork (Device) = Disabled). UNASSIGNED.
  3. Build + POST the Settings Catalog policy
     (Use Security Key For Signin = Enabled). UNASSIGNED.
  4. Verify both exist with ZERO assignments.
  5. Only then DELETE the two superseded Custom OMA-URI deviceConfigurations
     (ids read from whfb-remediation-objects.json).
  6. Update whfb-remediation-objects.json.

Idempotent: existing configurationPolicies are reused by name.

Usage:
    python Rebuild-WHFBPolicies.py
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
GRAPH_BETA = "https://graph.microsoft.com/beta"
DEFS_FILE = SCRIPT_DIR / "whfb-setting-defs.json"

WHFB_POLICY_NAME = "FrontDesk - Disable Windows Hello for Business"
SECKEY_POLICY_NAME = "Security Keys for Windows Sign-In"

WHFB_DEVICE_SETTING = (
    "device_vendor_msft_passportforwork_{tenantid}_policies_usepassportforwork"
)
SECKEY_SETTING = (
    "device_vendor_msft_passportforwork_securitykey_usesecuritykeyforsignin"
)


# --------------------------------------------------------------------------
# cert auth
# --------------------------------------------------------------------------

def deobfuscate(s):
    return bytes(b ^ 0x5A for b in base64.b64decode(s)).decode("utf-8") if s else ""


def load_cfg():
    cfgs = sorted(SCRIPT_DIR.glob("*/whfb-remediation-config.json"),
                  key=lambda p: p.parent.name, reverse=True)
    if not cfgs:
        raise RuntimeError("No whfb-remediation-config.json found.")
    data = json.loads(cfgs[0].read_text(encoding="utf-8"))
    client_id = deobfuscate(data.get("client_id_obfuscated", "")) or \
        json.loads((cfgs[0].parent / "whfb-remediation-app-result.json")
                   .read_text(encoding="utf-8"))["appId"]
    return {
        "dir": cfgs[0].parent,
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


class G:
    def __init__(self, token):
        self.h = {"Authorization": f"Bearer {token}",
                  "Content-Type": "application/json"}

    def get(self, path):
        r = requests.get(f"{GRAPH_BETA}{path}", headers=self.h, timeout=60)
        r.raise_for_status()
        return r.json()

    def post(self, path, body):
        return requests.post(f"{GRAPH_BETA}{path}", headers=self.h,
                             json=body, timeout=60)

    def delete(self, path):
        return requests.delete(f"{GRAPH_BETA}{path}", headers=self.h, timeout=60)


# --------------------------------------------------------------------------
# derive template GUIDs from the saved definitions
# --------------------------------------------------------------------------

def derive_whfb_template():
    if not DEFS_FILE.exists():
        raise RuntimeError(
            f"{DEFS_FILE.name} missing - run Inspect-WHFBSettingDefs.py first."
        )
    defs = json.loads(DEFS_FILE.read_text(encoding="utf-8"))
    template_id = defs["accountProtectionTemplate"]["id"]
    sit = defs["whfbDeviceSettingTemplate"]["settingInstanceTemplate"]

    group_def_id = sit["settingDefinitionId"]                       # ..._{tenantid}
    group_instance_tpl = sit["settingInstanceTemplateId"]
    gscv = sit["groupSettingCollectionValueTemplate"][0]
    group_value_tpl = gscv["settingValueTemplateId"]

    child = next(
        c for c in gscv["children"]
        if c["settingDefinitionId"] == WHFB_DEVICE_SETTING
    )
    return {
        "templateId": template_id,
        "groupDefId": group_def_id,
        "groupInstanceTpl": group_instance_tpl,
        "groupValueTpl": group_value_tpl,
        "childInstanceTpl": child["settingInstanceTemplateId"],
        "childValueTpl": child["choiceSettingValueTemplate"]["settingValueTemplateId"],
    }


# --------------------------------------------------------------------------
# policy bodies
# --------------------------------------------------------------------------

def whfb_es_policy_body(g, t):
    """Endpoint Security Account Protection policy: UsePassportForWork=Disabled."""
    # platforms / technologies straight from the template object
    tpl = g.get(f"/deviceManagement/configurationPolicyTemplates/{t['templateId']}")
    platforms = tpl.get("platforms", "windows10")
    technologies = tpl.get("technologies", "mdm")

    return {
        "name": WHFB_POLICY_NAME,
        "description": (
            "WHFB remediation Step 1. Endpoint Security > Account Protection: "
            "Use Windows Hello for Business (Device) = Disabled. UNASSIGNED - "
            "assign to FrontDesk-SharedPCs in Intune when ready."
        ),
        "platforms": platforms,
        "technologies": technologies,
        "roleScopeTagIds": ["0"],
        "templateReference": {"templateId": t["templateId"]},
        "settings": [
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type":
                        "#microsoft.graph."
                        "deviceManagementConfigurationGroupSettingCollectionInstance",
                    "settingDefinitionId": t["groupDefId"],
                    "settingInstanceTemplateReference": {
                        "settingInstanceTemplateId": t["groupInstanceTpl"],
                    },
                    "groupSettingCollectionValue": [
                        {
                            "settingValueTemplateReference": {
                                "settingValueTemplateId": t["groupValueTpl"],
                                "useTemplateDefault": False,
                            },
                            "children": [
                                {
                                    "@odata.type":
                                        "#microsoft.graph."
                                        "deviceManagementConfigurationChoiceSettingInstance",
                                    "settingDefinitionId": WHFB_DEVICE_SETTING,
                                    "settingInstanceTemplateReference": {
                                        "settingInstanceTemplateId":
                                            t["childInstanceTpl"],
                                    },
                                    "choiceSettingValue": {
                                        "value":
                                            f"{WHFB_DEVICE_SETTING}_false",
                                        "settingValueTemplateReference": {
                                            "settingValueTemplateId":
                                                t["childValueTpl"],
                                            "useTemplateDefault": False,
                                        },
                                        "children": [],
                                    },
                                }
                            ],
                        }
                    ],
                },
            }
        ],
    }


def seckey_catalog_policy_body():
    """Settings Catalog policy: UseSecurityKeyForSignin = Enabled."""
    return {
        "name": SECKEY_POLICY_NAME,
        "description": (
            "WHFB remediation Step 4. Settings Catalog > Windows Hello For "
            "Business: Use Security Key For Signin = Enabled. UNASSIGNED - "
            "assign to FrontDesk-SharedPCs in Intune when ready."
        ),
        "platforms": "windows10",
        "technologies": "mdm",
        "roleScopeTagIds": ["0"],
        "settings": [
            {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type":
                        "#microsoft.graph."
                        "deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": SECKEY_SETTING,
                    "choiceSettingValue": {
                        "value": f"{SECKEY_SETTING}_1",
                        "children": [],
                    },
                },
            }
        ],
    }


# --------------------------------------------------------------------------
# create / verify / cleanup
# --------------------------------------------------------------------------

def find_policy(g, name):
    res = g.get(
        f"/deviceManagement/configurationPolicies?$filter=name eq '{name}'"
        "&$select=id,name"
    ).get("value", [])
    return res[0]["id"] if res else None


def ensure_policy(g, name, body):
    existing = find_policy(g, name)
    if existing:
        print(f"[=] configurationPolicy already exists: {name} ({existing})")
        return existing, False
    r = g.post("/deviceManagement/configurationPolicies", body)
    if r.status_code not in (200, 201):
        raise RuntimeError(
            f"Create failed ({name}): {r.status_code}\n{r.text}"
        )
    pid = r.json()["id"]
    print(f"[+] configurationPolicy created: {name} ({pid})")
    return pid, True


def assignment_count(g, pid):
    return len(g.get(
        f"/deviceManagement/configurationPolicies/{pid}/assignments"
    ).get("value", []))


def main():
    print()
    print("=" * 70)
    print("  REBUILD WHFB POLICIES ON BEST-PRACTICE SURFACES (UNASSIGNED)")
    print("=" * 70)

    cfg = load_cfg()
    g = G(get_token(cfg))
    print(f"[*] Tenant: {cfg['tenant_id']}")
    print("[OK] Cert-based token acquired.")

    t = derive_whfb_template()
    print(f"[*] Account Protection template: {t['templateId']}")

    # 2. Endpoint Security - WHFB disable
    print("\n--- Endpoint Security: WHFB disable ---")
    whfb_id, whfb_new = ensure_policy(
        g, WHFB_POLICY_NAME, whfb_es_policy_body(g, t)
    )

    # 3. Settings Catalog - security-key sign-in
    print("\n--- Settings Catalog: security-key sign-in ---")
    seckey_id, seckey_new = ensure_policy(
        g, SECKEY_POLICY_NAME, seckey_catalog_policy_body()
    )

    # 4. Verify ZERO assignments before touching the old objects
    print("\n--- Verify (zero assignments) ---")
    whfb_assigns = assignment_count(g, whfb_id)
    seckey_assigns = assignment_count(g, seckey_id)
    print(f"  WHFB ES policy assignments:        {whfb_assigns}")
    print(f"  Security-key catalog assignments:  {seckey_assigns}")
    if whfb_assigns or seckey_assigns:
        raise RuntimeError(
            "New policy has assignments - unexpected. Aborting before "
            "deleting the old Custom OMA-URI profiles."
        )
    print("  [OK] both new policies are inert.")

    # 5. Delete the superseded Custom OMA-URI deviceConfigurations
    print("\n--- Remove superseded Custom OMA-URI profiles ---")
    obj_path = cfg["dir"] / "whfb-remediation-objects.json"
    objects = json.loads(obj_path.read_text(encoding="utf-8"))
    deleted = []
    for key in ("whfbDisablePolicy", "securityKeyPolicy"):
        old = objects.get(key, {})
        old_id = old.get("id")
        if not old_id:
            continue
        # only delete if it is actually a (legacy) deviceConfiguration
        r = g.delete(f"/deviceManagement/deviceConfigurations/{old_id}")
        if r.status_code in (200, 204):
            print(f"[-] Deleted Custom OMA-URI profile: {old.get('name')} "
                  f"({old_id})")
            deleted.append(old_id)
        elif r.status_code == 404:
            print(f"[=] Custom OMA-URI profile already gone: {old_id}")
        else:
            print(f"[!] Could not delete {old_id}: {r.status_code} {r.text}")

    # 6. Update objects file
    objects["whfbDisablePolicy"] = {
        "name": WHFB_POLICY_NAME, "id": whfb_id, "created": whfb_new,
        "surface": "EndpointSecurity/AccountProtection",
        "templateId": t["templateId"],
    }
    objects["securityKeyPolicy"] = {
        "name": SECKEY_POLICY_NAME, "id": seckey_id, "created": seckey_new,
        "surface": "SettingsCatalog",
    }
    objects["customOmaUriRemoved"] = deleted
    objects["rebuiltUtc"] = datetime.datetime.now(
        datetime.timezone.utc).isoformat()
    obj_path.write_text(json.dumps(objects, indent=2), encoding="utf-8")

    print()
    print("=" * 70)
    print("  DONE - REBUILT ON BEST-PRACTICE SURFACES")
    print("=" * 70)
    print(f"  WHFB disable   -> Endpoint Security / Account Protection")
    print(f"                    {whfb_id}")
    print(f"  Security-key   -> Settings Catalog")
    print(f"                    {seckey_id}")
    print(f"  Custom OMA-URI removed: {len(deleted)}")
    print(f"  ASSIGNMENTS: 0  -- both policies target nothing.")
    print(f"  Objects file updated: {obj_path}")
    print()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
