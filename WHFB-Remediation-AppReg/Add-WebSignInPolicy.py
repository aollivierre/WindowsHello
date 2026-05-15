#!/usr/bin/env python3
"""
Add a single purely-additive Settings Catalog policy that enables the
Web Sign-In credential-provider tile on the Windows lock screen.

EXPLICITLY DOES NOT:
  - hide the password tile (does not include
    Authentication/EnablePasswordlessExperience).
  - change which tile is the default (does not include
    CredentialProviders/DefaultCredentialProvider).

So this only ADDS the Web Sign-In option. Password sign-in remains fully
functional and remains the default tile. Created UNASSIGNED.

Setting (live-discovered from the tenant catalog):
  device_vendor_msft_policy_config_authentication_enablewebsignin = Enabled (_1)

Usage:
    python Add-WebSignInPolicy.py
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

POLICY_NAME = "FrontDesk - Enable Web Sign-In (Additive)"
SETTING_ID = "device_vendor_msft_policy_config_authentication_enablewebsignin"


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
        r.raise_for_status()
        return r.json()

    def post(self, p, b):
        return requests.post(f"{GRAPH_BETA}{p}", headers=self.h, json=b,
                             timeout=60)


def discover_enabled_option(g):
    """Confirm the setting exists + isn't deprecated, return its 'enabled' option id."""
    sd = g.get(f"/deviceManagement/configurationSettings/{SETTING_ID}")
    if sd.get("deprecatedInfo"):
        raise RuntimeError(
            f"{SETTING_ID} is DEPRECATED per the catalog: "
            f"{json.dumps(sd['deprecatedInfo'])}"
        )
    options = sd.get("options", [])
    # Option name is the human-readable description (e.g. "Enabled. Web
    # Sign-in will be enabled..."). Match anything starting with 'Enabled'
    # and explicitly excluding 'Disabled'.
    def _is_enabled(o):
        n = (o.get("name") or "").lower().strip()
        dn = (o.get("displayName") or "").lower().strip()
        return ((n.startswith("enabled") or dn.startswith("enabled"))
                and not n.startswith("disabled")
                and not dn.startswith("disabled"))
    enabled = next((o for o in options if _is_enabled(o)), None)
    if not enabled:
        raise RuntimeError(
            f"No 'enabled' option found on {SETTING_ID}: "
            f"{[(o.get('itemId'), o.get('name')) for o in options]}"
        )
    print(f"  catalog: {sd.get('displayName')!r}")
    print(f"  enabled option itemId: {enabled['itemId']}")
    print(f"  riskLevel:    {sd.get('riskLevel')}")
    print(f"  applicability: platform={sd.get('applicability', {}).get('platform')}, "
          f"minOS={sd.get('applicability', {}).get('minimumSupportedVersion')}")
    return enabled["itemId"]


def build_body(enabled_option_id):
    return {
        "name": POLICY_NAME,
        "description": (
            "WHFB remediation - ADDITIVE Web Sign-In enabler.\n"
            "\n"
            "Adds the 'Web Sign-In' credential-provider tile to the Windows "
            "lock screen (Authentication CSP - EnableWebSignin = Enabled).\n"
            "\n"
            "EXPLICITLY DOES NOT do either of these:\n"
            "  1. Does NOT hide the password tile - the password "
            "credential provider remains visible and usable on the lock "
            "screen. (Authentication/EnablePasswordlessExperience is "
            "deliberately NOT configured by this policy.)\n"
            "  2. Does NOT change the default credential provider - "
            "whichever tile is the user's default today remains the default. "
            "(CredentialProviders/DefaultCredentialProvider is deliberately "
            "NOT configured by this policy.)\n"
            "\n"
            "Effect: one extra tile becomes available. Nothing is removed; "
            "nothing about the default selection changes.\n"
            "\n"
            "UNASSIGNED - assign to FrontDesk-SharedPCs in Intune when ready."
        ),
        "platforms": "windows10",
        "technologies": "mdm",
        "roleScopeTagIds": ["0"],
        "settings": [
            {
                "@odata.type":
                    "#microsoft.graph.deviceManagementConfigurationSetting",
                "settingInstance": {
                    "@odata.type":
                        "#microsoft.graph."
                        "deviceManagementConfigurationChoiceSettingInstance",
                    "settingDefinitionId": SETTING_ID,
                    "choiceSettingValue": {
                        "value": enabled_option_id,
                        "children": [],
                    },
                },
            }
        ],
    }


def find_existing(g, name):
    res = g.get(
        f"/deviceManagement/configurationPolicies?$filter=name eq '{name}'"
        "&$select=id,name").get("value", [])
    return res[0]["id"] if res else None


def main():
    print()
    print("=" * 70)
    print("  ADD WEB SIGN-IN POLICY (ADDITIVE - PASSWORD TILE PRESERVED)")
    print("=" * 70)

    cfg = load_cfg()
    g = G(token(cfg))
    print(f"  Tenant: {cfg['tenant_id']}")
    print("  [OK] Cert-based token acquired.")

    print("\n--- Live catalog: confirm setting + enabled option ---")
    enabled_id = discover_enabled_option(g)

    print("\n--- Create / reuse the Settings Catalog policy ---")
    existing = find_existing(g, POLICY_NAME)
    if existing:
        pid = existing
        created = False
        print(f"  [=] policy already exists: {POLICY_NAME} ({pid})")
    else:
        body = build_body(enabled_id)
        r = g.post("/deviceManagement/configurationPolicies", body)
        if r.status_code not in (200, 201):
            raise RuntimeError(f"create failed: {r.status_code}\n{r.text}")
        pid = r.json()["id"]
        created = True
        print(f"  [+] policy created: {POLICY_NAME} ({pid})")

    # Self-verify: zero assignments, exactly the one setting we asked for
    print("\n--- Verify (zero assignments, expected setting) ---")
    pol = g.get(f"/deviceManagement/configurationPolicies/{pid}")
    settings = g.get(
        f"/deviceManagement/configurationPolicies/{pid}/settings"
    ).get("value", [])
    assigns = g.get(
        f"/deviceManagement/configurationPolicies/{pid}/assignments"
    ).get("value", [])
    tref = (pol.get("templateReference") or {}).get("templateId") or "(none)"
    sid_seen = (
        settings[0]["settingInstance"]["settingDefinitionId"] if settings else None
    )
    val_seen = (
        settings[0]["settingInstance"]
        .get("choiceSettingValue", {})
        .get("value") if settings else None
    )
    print(f"  template:       {tref}  (expected: (none))")
    print(f"  settings count: {len(settings)}  (expected: 1)")
    print(f"  setting id:     {sid_seen}")
    print(f"  setting value:  {val_seen}")
    print(f"  assignments:    {len(assigns)}  (expected: 0)")
    ok = (
        tref == "(none)"
        and len(settings) == 1
        and sid_seen == SETTING_ID
        and val_seen == enabled_id
        and len(assigns) == 0
    )

    # Persist into the objects inventory
    obj_path = cfg["dir"] / "whfb-remediation-objects.json"
    objects = json.loads(obj_path.read_text(encoding="utf-8"))
    objects["webSignInPolicy"] = {
        "name": POLICY_NAME,
        "id": pid,
        "created": created,
        "surface": "SettingsCatalog",
        "setting": SETTING_ID,
        "value": enabled_id,
        "preservesPasswordTile": True,
        "changesDefaultTile": False,
        "addedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    obj_path.write_text(json.dumps(objects, indent=2), encoding="utf-8")

    print()
    print("=" * 70)
    if ok:
        print("  [SUCCESS] Web Sign-In policy is in place. Inert (0 assignments).")
        print("            Password tile NOT removed. Default tile NOT changed.")
    else:
        print("  [FAIL] Verification did not match expectations - see above.")
    print(f"  Policy id:   {pid}")
    print(f"  Objects file updated: {obj_path}")
    print()
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
