#!/usr/bin/env python3
"""
End-to-end verification of the WHFB-Remediation-Automation app registration.

Proves the whole chain works: the embedded certificate authenticates as the
app (client-credentials / JWT assertion), and the consented Graph permissions
actually return data. Same auth pattern as the repo's build_permissions_manifest.py.

Checks performed:
  1. Cert-based token acquisition (proves keyCredential + app reg are wired up).
  2. GET /organization                    -> Directory.Read.All / Organization
  3. GET /deviceManagement/deviceConfigurations?$top=1
                                           -> DeviceManagementConfiguration.*
  4. GET /policies/authenticationMethodsPolicy
                                           -> Policy.Read* / AuthenticationMethod

Usage:
    python Test-WHFBAuth.py
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
        # fall back to the result file's plaintext appId
        res = cfg_path.parent / "whfb-remediation-app-result.json"
        if res.exists():
            client_id = json.loads(res.read_text(encoding="utf-8"))["appId"]
    if not client_id:
        raise RuntimeError(
            f"No client id in {cfg_path} - run Create-WHFBRemediationApp.py."
        )

    return {
        "path": cfg_path,
        "tenant_id": deobfuscate(data["tenant_id_obfuscated"]),
        "client_id": client_id,
        "pfx_password": deobfuscate(data["pfx_password_obfuscated"]),
        "pfx_bytes": base64.b64decode(
            deobfuscate(data["pfx_base64_obfuscated"])),
        "thumbprint": data.get("cert_thumbprint", ""),
        "expires": data.get("expires", "?"),
    }


def get_token_via_cert(cfg):
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
    cert_der = certificate.public_bytes(Encoding.DER)
    digest = hashes.Hash(hashes.SHA1(), default_backend())
    digest.update(cert_der)
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


def check(token, label, url):
    try:
        r = requests.get(
            url, headers={"Authorization": f"Bearer {token}"}, timeout=30
        )
    except requests.RequestException as e:
        print(f"  [FAIL] {label}: {e}")
        return False
    if r.status_code == 200:
        n = len(r.json().get("value", [])) if "value" in r.json() else 1
        print(f"  [OK]   {label}: HTTP 200 ({n} item(s))")
        return True
    print(f"  [FAIL] {label}: HTTP {r.status_code} {r.text[:160]}")
    return False


def main():
    print()
    print("=" * 70)
    print("  VERIFY WHFB-Remediation-Automation - cert auth + Graph access")
    print("=" * 70)

    cfg = load_config()
    print(f"[*] Config:     {cfg['path']}")
    print(f"[*] Tenant:     {cfg['tenant_id']}")
    print(f"[*] Client id:  {cfg['client_id']}")
    print(f"[*] Cert SHA-1: {cfg['thumbprint']}")
    print(f"[*] Cert expires: {cfg['expires']}")

    print("[*] Acquiring token via certificate (client credentials)...")
    token = get_token_via_cert(cfg)
    print("[OK] Cert-based token acquired - the app reg + keyCredential work.")
    print()
    print("[*] Exercising the consented Graph permissions:")
    results = [
        check(token, "Directory / Organization",
              f"{GRAPH}/organization"),
        check(token, "Intune device configuration",
              f"{GRAPH}/deviceManagement/deviceConfigurations?$top=1"),
        check(token, "Authentication methods policy",
              f"{GRAPH}/policies/authenticationMethodsPolicy"),
    ]
    print()
    if all(results):
        print("  [SUCCESS] App is fully functional - cert authenticates and "
              "the consented permissions return data.")
        return 0
    print("  [PARTIAL] Cert auth works, but some permission checks failed "
          "above (consent may still be propagating - retry in a few minutes).")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
