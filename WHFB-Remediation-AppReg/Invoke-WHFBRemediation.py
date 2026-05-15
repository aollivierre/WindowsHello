#!/usr/bin/env python3
"""
Carry out the WHFB remediation handover - CREATE ONLY, NOTHING ASSIGNED.

Authenticates as the WHFB-Remediation-Automation app reg via its embedded
certificate (client-credentials) and creates the inert objects from
WHFB-Remediation-Handover.md:

  1. Security group  'FrontDesk-SharedPCs'  (handover Step 1)
  2. Adds device     <TARGET-DEVICE-NAME> to that group so it is READY
  3. Device config   'FrontDesk - Disable Windows Hello for Business'
                     Custom OMA-URI, PassportForWork/UsePassportForWork = false
                     (handover Step 1 - the Account protection policy's
                      underlying CSP, expressed as a deterministic OMA-URI)
  4. Device config   'Security Keys for Windows Sign-In'
                     Custom OMA-URI, UseSecurityKeyForSignin = 1 (Step 4)

Deliberately NOT done:
  - No assignments. No /assign calls. The group has the device but no policy
    targets it; the two profiles target nothing. Everything is inert until
    someone assigns it in Intune.
  - Step 3 (enable Passkey/FIDO2 method) is skipped - it is a live tenant
    toggle with no 'unassigned' form.
  - Step 2 (certutil -deleteHelloContainer) and Step 5 (YubiKey enrolment)
    are local / user self-service - not app-automatable.

Idempotent: re-running reuses existing objects by displayName instead of
creating duplicates.

Usage:
    python Invoke-WHFBRemediation.py

Requires: jwt (PyJWT), requests, cryptography
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
GRAPH = "https://graph.microsoft.com/v1.0"

GROUP_NAME = "FrontDesk-SharedPCs"
GROUP_NICK = "FrontDesk-SharedPCs"
TARGET_DEVICE_NAME = "<TARGET-DEVICE-NAME>"

WHFB_POLICY_NAME = "FrontDesk - Disable Windows Hello for Business"
SECKEY_POLICY_NAME = "Security Keys for Windows Sign-In"


# ---------------------------------------------------------------------------
# Cert auth (same pattern as Test-WHFBAuth.py / build_permissions_manifest.py)
# ---------------------------------------------------------------------------

def deobfuscate(s):
    if not s:
        return ""
    return bytes(b ^ 0x5A for b in base64.b64decode(s)).decode("utf-8")


def load_config():
    candidates = sorted(
        SCRIPT_DIR.glob("*/whfb-remediation-config.json"),
        key=lambda p: p.parent.name, reverse=True,
    )
    if not candidates:
        raise RuntimeError("No whfb-remediation-config.json found.")
    cfg_path = candidates[0]
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    client_id = deobfuscate(data.get("client_id_obfuscated", ""))
    if not client_id:
        res = cfg_path.parent / "whfb-remediation-app-result.json"
        if res.exists():
            client_id = json.loads(res.read_text(encoding="utf-8"))["appId"]
    if not client_id:
        raise RuntimeError(f"No client id in {cfg_path}.")
    return {
        "dir": cfg_path.parent,
        "tenant_id": deobfuscate(data["tenant_id_obfuscated"]),
        "client_id": client_id,
        "pfx_password": deobfuscate(data["pfx_password_obfuscated"]),
        "pfx_bytes": base64.b64decode(
            deobfuscate(data["pfx_base64_obfuscated"])),
        "expires": data.get("expires", "?"),
    }


def get_token(cfg):
    private_key, certificate, _ = pkcs12.load_key_and_certificates(
        cfg["pfx_bytes"], cfg["pfx_password"].encode(), default_backend()
    )
    token_url = (
        f"https://login.microsoftonline.com/{cfg['tenant_id']}"
        "/oauth2/v2.0/token"
    )
    now = int(time.time())
    claims = {
        "aud": token_url, "iss": cfg["client_id"], "sub": cfg["client_id"],
        "jti": secrets.token_hex(16), "exp": now + 600, "iat": now, "nbf": now,
    }
    digest = hashes.Hash(hashes.SHA1(), default_backend())
    digest.update(certificate.public_bytes(Encoding.DER))
    x5t = base64.urlsafe_b64encode(digest.finalize()).decode().rstrip("=")
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    assertion = jwt.encode(
        claims, private_pem, algorithm="RS256", headers={"x5t": x5t}
    )
    r = requests.post(
        token_url,
        data={
            "client_id": cfg["client_id"],
            "client_assertion_type":
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Token request failed: {r.status_code}\n{r.text}")
    return r.json()["access_token"]


# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------

class Graph:
    def __init__(self, token):
        self.h = {"Authorization": f"Bearer {token}",
                  "Content-Type": "application/json"}

    def get(self, path):
        r = requests.get(f"{GRAPH}{path}", headers=self.h, timeout=30)
        r.raise_for_status()
        return r.json()

    def get_retry(self, path, tries=12, delay=5):
        """GET that tolerates post-creation replication lag (transient 404)."""
        last = None
        for _ in range(tries):
            r = requests.get(f"{GRAPH}{path}", headers=self.h, timeout=30)
            if r.status_code == 200:
                return r.json()
            last = r
            if r.status_code == 404:
                time.sleep(delay)
                continue
            r.raise_for_status()
        last.raise_for_status()

    def post(self, path, body):
        return requests.post(
            f"{GRAPH}{path}", headers=self.h, json=body, timeout=30
        )


# ---------------------------------------------------------------------------
# Step 1 - group
# ---------------------------------------------------------------------------

def ensure_group(g):
    found = g.get(
        f"/groups?$filter=displayName eq '{GROUP_NAME}'&$select=id,displayName"
    ).get("value", [])
    if found:
        gid = found[0]["id"]
        print(f"[=] Group already exists: {GROUP_NAME} ({gid})")
        return gid, False
    r = g.post("/groups", {
        "displayName": GROUP_NAME,
        "description": (
            "Front-desk shared PCs for the WHFB remediation. Created by "
            "WHFB-Remediation-Automation. Members are ready; NO policies are "
            "assigned to this group yet - assign in Intune when ready."
        ),
        "mailEnabled": False,
        "mailNickname": GROUP_NICK,
        "securityEnabled": True,
    })
    if r.status_code != 201:
        raise RuntimeError(f"Group create failed: {r.status_code}\n{r.text}")
    gid = r.json()["id"]
    print(f"[+] Group created: {GROUP_NAME} ({gid})")
    # New group - wait for directory replication before touching membership.
    g.get_retry(f"/groups/{gid}?$select=id")
    print("[i] Group is queryable (replicated).")
    return gid, True


def resolve_device_object_id(g, device_name):
    """Intune managedDevice -> azureADDeviceId -> Entra /devices object id."""
    md = g.get(
        f"/deviceManagement/managedDevices?$filter=deviceName eq "
        f"'{device_name}'&$select=id,deviceName,azureADDeviceId"
    ).get("value", [])
    if not md:
        raise RuntimeError(
            f"Managed device '{device_name}' not found in Intune."
        )
    aad_device_id = md[0].get("azureADDeviceId")
    if not aad_device_id or aad_device_id == "00000000-0000-0000-0000-000000000000":
        raise RuntimeError(
            f"'{device_name}' has no azureADDeviceId - cannot map to an "
            "Entra device object."
        )
    dev = g.get(
        f"/devices?$filter=deviceId eq '{aad_device_id}'"
        f"&$select=id,displayName,deviceId"
    ).get("value", [])
    if not dev:
        raise RuntimeError(
            f"No Entra device object with deviceId {aad_device_id}."
        )
    print(f"[i] Resolved {device_name}: Entra device object {dev[0]['id']}")
    return dev[0]["id"]


def add_device_to_group(g, group_id, device_obj_id):
    members = g.get_retry(
        f"/groups/{group_id}/members?$select=id"
    ).get("value", [])
    if any(m["id"] == device_obj_id for m in members):
        print(f"[=] Device already a member of {GROUP_NAME}")
        return False
    for _ in range(6):
        r = g.post(f"/groups/{group_id}/members/$ref", {
            "@odata.id": f"{GRAPH}/devices/{device_obj_id}",
        })
        if r.status_code == 204:
            print(f"[+] Device {TARGET_DEVICE_NAME} added to {GROUP_NAME}")
            return True
        if r.status_code == 400 and "already exist" in r.text.lower():
            print(f"[=] Device already a member of {GROUP_NAME}")
            return False
        if r.status_code == 404:  # group still replicating
            time.sleep(5)
            continue
        raise RuntimeError(f"Add member failed: {r.status_code}\n{r.text}")
    raise RuntimeError(
        "Add member failed: group not replicated after retries."
    )


# ---------------------------------------------------------------------------
# Steps 1 & 4 - Custom OMA-URI device configuration profiles (UNASSIGNED)
# ---------------------------------------------------------------------------

def find_device_config(g, name):
    configs = g.get(
        "/deviceManagement/deviceConfigurations?$select=id,displayName"
    ).get("value", [])
    for c in configs:
        if c.get("displayName") == name:
            return c["id"]
    return None


def ensure_device_config(g, name, body):
    existing = find_device_config(g, name)
    if existing:
        print(f"[=] Device config already exists: {name} ({existing})")
        return existing, False
    r = g.post("/deviceManagement/deviceConfigurations", body)
    if r.status_code != 201:
        raise RuntimeError(
            f"Device config create failed ({name}): {r.status_code}\n{r.text}"
        )
    cid = r.json()["id"]
    print(f"[+] Device config created: {name} ({cid})")
    return cid, True


def whfb_disable_body(tenant_id):
    oma_uri = (
        f"./Device/Vendor/MSFT/PassportForWork/{tenant_id}"
        "/Policies/UsePassportForWork"
    )
    return {
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": WHFB_POLICY_NAME,
        "description": (
            "WHFB remediation Step 1: disables Windows Hello for Business at "
            "device scope (PassportForWork CSP). UNASSIGNED - assign to "
            f"'{GROUP_NAME}' in Intune when ready."
        ),
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingBoolean",
                "displayName": "UsePassportForWork (device)",
                "description": "Disable Windows Hello for Business (device scope)",
                "omaUri": oma_uri,
                "value": False,
            }
        ],
    }


def security_key_body():
    return {
        "@odata.type": "#microsoft.graph.windows10CustomConfiguration",
        "displayName": SECKEY_POLICY_NAME,
        "description": (
            "WHFB remediation Step 4: enables FIDO2 security keys at the "
            "Windows lock screen. UNASSIGNED - assign to "
            f"'{GROUP_NAME}' in Intune when ready."
        ),
        "omaSettings": [
            {
                "@odata.type": "#microsoft.graph.omaSettingInteger",
                "displayName": "UseSecurityKeyForSignin",
                "description": "Enable security-key sign-in credential provider",
                "omaUri": (
                    "./Device/Vendor/MSFT/PassportForWork/SecurityKey/"
                    "UseSecurityKeyForSignin"
                ),
                "value": 1,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print()
    print("=" * 70)
    print("  WHFB REMEDIATION - CREATE ONLY (NOTHING ASSIGNED)")
    print("=" * 70)

    cfg = load_config()
    print(f"[*] App (client id): {cfg['client_id']}")
    print(f"[*] Tenant:          {cfg['tenant_id']}")
    print(f"[*] Cert expires:    {cfg['expires']}")
    print("[*] Authenticating with the embedded certificate...")
    g = Graph(get_token(cfg))
    print("[OK] Cert-based token acquired.")
    print()

    # Step 1a - group
    print("--- Step 1a: security group ---")
    group_id, group_new = ensure_group(g)

    # Step 1b - add the device so the group is READY (no assignment)
    print("--- Step 1b: add <TARGET-DEVICE-NAME> to the group ---")
    device_obj_id = resolve_device_object_id(g, TARGET_DEVICE_NAME)
    device_added = add_device_to_group(g, group_id, device_obj_id)

    # Step 1c - WHFB-disable profile (UNASSIGNED)
    print("--- Step 1c: WHFB-disable device config (unassigned) ---")
    whfb_id, whfb_new = ensure_device_config(
        g, WHFB_POLICY_NAME, whfb_disable_body(cfg["tenant_id"])
    )

    # Step 4 - security-key sign-in profile (UNASSIGNED)
    print("--- Step 4: security-key sign-in device config (unassigned) ---")
    seckey_id, seckey_new = ensure_device_config(
        g, SECKEY_POLICY_NAME, security_key_body()
    )

    # Persist what was created/used
    objects = {
        "createdUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tenantId": cfg["tenant_id"],
        "appClientId": cfg["client_id"],
        "group": {"name": GROUP_NAME, "id": group_id, "created": group_new},
        "groupMemberDevice": {
            "deviceName": TARGET_DEVICE_NAME,
            "entraDeviceObjectId": device_obj_id,
            "addedThisRun": device_added,
        },
        "whfbDisablePolicy": {
            "name": WHFB_POLICY_NAME, "id": whfb_id, "created": whfb_new,
        },
        "securityKeyPolicy": {
            "name": SECKEY_POLICY_NAME, "id": seckey_id, "created": seckey_new,
        },
        "assignmentsCreated": 0,
        "step3Fido2Method": "SKIPPED (live tenant toggle - left for operator)",
    }
    out_path = cfg["dir"] / "whfb-remediation-objects.json"
    out_path.write_text(json.dumps(objects, indent=2), encoding="utf-8")

    print()
    print("=" * 70)
    print("  DONE - CREATE ONLY")
    print("=" * 70)
    print(f"  Group:              {GROUP_NAME}")
    print(f"                      {group_id}")
    print(f"  Group member:       {TARGET_DEVICE_NAME} "
          f"({'added' if device_added else 'already present'})")
    print(f"  WHFB-disable policy:{WHFB_POLICY_NAME}")
    print(f"                      {whfb_id}")
    print(f"  Security-key policy:{SECKEY_POLICY_NAME}")
    print(f"                      {seckey_id}")
    print()
    print("  ASSIGNMENTS CREATED: 0  -- nothing is targeted at anything.")
    print("  The group has the device; the two profiles target nothing.")
    print("  Everything is inert until you assign it in Intune.")
    print()
    print("  Skipped by design: Step 3 (FIDO2 method - live toggle),")
    print("  Step 2 (certutil, local), Step 5 (YubiKey enrolment, user).")
    print(f"  Object ids written to: {out_path}")
    print()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
