#!/usr/bin/env python3
"""
Generate an ephemeral, max-security certificate for the WHFB-Remediation-Automation
app registration, and emit a manifest with the public cert embedded.

Why ephemeral: this app reg performs privileged Intune / auth-method writes for a
one-shot remediation (see WHFB-Remediation-Handover.md). A 24-hour cert means the
credential is dead long before it could be abused. Regenerate + re-upload each run.

Hardening vs. the repo's create_bitlocker_cert_auth.py pattern:
  - RSA 4096-bit key, SHA-512 signature (same as repo baseline)
  - KeyUsage = digitalSignature ONLY (cert auth never needs key_encipherment)
  - BasicConstraints CA=False (critical), SubjectKeyIdentifier extension
  - notBefore backdated 5 min for clock skew; notAfter = now + TTL (default 24h)
  - PFX: 128-char CSPRNG password, BestAvailableEncryption
  - Private key embedded ONLY in the obfuscated config; no .pfx left on disk
  - Public cert (.cer) emitted for the Certificates & secrets blade

Outputs (under WHFB-Remediation-AppReg/<timestamp>/):
  whfb-remediation-public.cer                    <- upload via Certificates & secrets
  whfb-remediation-app-manifest-with-cert.json   <- full manifest, keyCredentials populated
  whfb-remediation-config.json                   <- obfuscated config (private key) for Python
  whfb-remediation-config.psd1                   <- obfuscated config (private key) for PowerShell
  Config-Reference-PLAIN-TEXT-DELETE-ME.txt      <- verification only, delete after

Usage:
  python Generate-WHFBRemediationCert.py
  python Generate-WHFBRemediationCert.py --ttl-hours 24 --tenant-id 00000000-0000-0000-0000-000000000000

Requires: cryptography  (pip install cryptography)
"""

import argparse
import base64
import datetime
import json
import secrets
import string
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

SCRIPT_DIR = Path(__file__).resolve().parent
TEMPLATE_MANIFEST = SCRIPT_DIR / "whfb-remediation-app-manifest.json"

APP_NAME = "WHFB-Remediation-Automation"
DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000000"  # <tenant-name>
OBFUSCATION_KEY = 0x5A  # XOR key, matches the repo's other configs


def generate_secure_password(length=128):
    """128-char CSPRNG password with guaranteed character-class coverage."""
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    pool = upper + lower + digits + special
    chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    chars += [secrets.choice(pool) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def obfuscate(value):
    """XOR 0x5A + base64 - same scheme the repo's BitLocker config uses."""
    if not value:
        return ""
    data = value.encode("utf-8")
    return base64.b64encode(bytes(b ^ OBFUSCATION_KEY for b in data)).decode("ascii")


def create_certificate(ttl_hours):
    """Generate an RSA-4096 / SHA-512 self-signed cert hardened for app-only auth."""
    print(f"[*] Generating RSA-4096 key, SHA-512 signature, TTL {ttl_hours}h ...")

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WHFB-Remediation"),
        x509.NameAttribute(NameOID.COMMON_NAME, APP_NAME),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)   # clock-skew tolerance
    not_after = now + datetime.timedelta(hours=ttl_hours)

    pub = private_key.public_key()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,   # the only usage app-only auth needs
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub), critical=False
        )
        .sign(private_key, hashes.SHA512(), default_backend())
    )

    pfx_password = generate_secure_password(128)
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=APP_NAME.encode(),
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            pfx_password.encode()
        ),
    )

    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    thumbprint = certificate.fingerprint(hashes.SHA1()).hex().upper()

    print(f"[OK] Certificate created")
    print(f"     Thumbprint (SHA-1): {thumbprint}")
    print(f"     Not before: {not_before.isoformat()}")
    print(f"     Not after:  {not_after.isoformat()}")

    return {
        "private_key": private_key,
        "certificate": certificate,
        "pfx_data": pfx_data,
        "pfx_password": pfx_password,
        "pfx_base64": base64.b64encode(pfx_data).decode("ascii"),
        "cert_base64": base64.b64encode(cert_der).decode("ascii"),
        "cert_pem": cert_pem,
        "thumbprint": thumbprint,
        "not_before": not_before,
        "not_after": not_after,
    }


def build_manifest_with_cert(cert_info):
    """Load the permissions-only template manifest and inject keyCredentials."""
    if not TEMPLATE_MANIFEST.exists():
        raise FileNotFoundError(
            f"Template manifest not found: {TEMPLATE_MANIFEST}\n"
            "Run this script from the WHFB-Remediation-AppReg folder."
        )
    manifest = json.loads(TEMPLATE_MANIFEST.read_text(encoding="utf-8"))
    manifest["keyCredentials"] = [
        {
            "type": "AsymmetricX509Cert",
            "usage": "Verify",
            "key": cert_info["cert_base64"],
            "displayName": f"{APP_NAME}-Cert",
            "startDateTime": cert_info["not_before"]
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "endDateTime": cert_info["not_after"]
                .strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    ]
    return manifest


def write_outputs(cert_info, tenant_id, ttl_hours):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = SCRIPT_DIR / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Public cert for the Certificates & secrets blade
    cer_path = out_dir / "whfb-remediation-public.cer"
    cer_path.write_bytes(cert_info["cert_pem"])

    # 2. Full manifest with keyCredentials populated (Graph create/patch path)
    manifest = build_manifest_with_cert(cert_info)
    manifest_path = out_dir / "whfb-remediation-app-manifest-with-cert.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # 3. Obfuscated config - JSON (Python consumers)
    cfg_json = {
        "app_name": APP_NAME,
        "tenant_id_obfuscated": obfuscate(tenant_id),
        "client_id_obfuscated": "",  # fill in after the app reg is created
        "pfx_password_obfuscated": obfuscate(cert_info["pfx_password"]),
        "pfx_base64_obfuscated": obfuscate(cert_info["pfx_base64"]),
        "cert_thumbprint": cert_info["thumbprint"],
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "expires": cert_info["not_after"].isoformat(),
        "ttl_hours": ttl_hours,
    }
    json_path = out_dir / "whfb-remediation-config.json"
    json_path.write_text(json.dumps(cfg_json, indent=2), encoding="utf-8")

    # 4. Obfuscated config - PSD1 (PowerShell consumers)
    psd1 = (
        "@{\n"
        "    # WHFB-Remediation-Automation - cert-auth config\n"
        f"    # Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"    # Certificate expires: {cert_info['not_after'].isoformat()}\n"
        f"    # Obfuscation: XOR 0x{OBFUSCATION_KEY:02X} + Base64\n"
        "\n"
        f"    ObfuscatedTenantId = '{obfuscate(tenant_id)}'\n"
        "    ObfuscatedClientId = ''  # fill in after the app reg is created\n"
        f"    ObfuscatedPassword = '{obfuscate(cert_info['pfx_password'])}'\n"
        f"    ObfuscatedBase64   = '{obfuscate(cert_info['pfx_base64'])}'\n"
        f"    CertThumbprint     = '{cert_info['thumbprint']}'\n"
        f"    TtlHours           = {ttl_hours}\n"
        "}\n"
    )
    psd1_path = out_dir / "whfb-remediation-config.psd1"
    psd1_path.write_text(psd1, encoding="utf-8-sig")

    # 5. Plain-text reference - delete after verification
    ref = (
        "WHFB-Remediation-Automation - PLAIN TEXT REFERENCE - DELETE AFTER USE\n"
        "=" * 68 + "\n\n"
        f"Generated:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"App name:    {APP_NAME}\n"
        f"Tenant ID:   {tenant_id}\n"
        f"Thumbprint:  {cert_info['thumbprint']}\n"
        f"Not before:  {cert_info['not_before'].isoformat()}\n"
        f"Not after:   {cert_info['not_after'].isoformat()}  (TTL {ttl_hours}h)\n\n"
        "PFX password (private key is embedded obfuscated in the config files):\n"
        f"  {cert_info['pfx_password']}\n\n"
        "Next steps:\n"
        "  1. Create the app reg (single-tenant) OR open the existing one.\n"
        "  2. Certificates & secrets -> Upload certificate -> whfb-remediation-public.cer\n"
        "     (or PATCH the app via Graph using whfb-remediation-app-manifest-with-cert.json)\n"
        "  3. Copy the app's Client ID into whfb-remediation-config.json/.psd1\n"
        "     (ObfuscatedClientId) - obfuscate it XOR 0x5A + base64 first.\n"
        "  4. Grant admin consent for the 11 Graph permissions.\n"
        "  5. Run the remediation within the TTL window - the cert dies after it.\n"
        "  6. DELETE this file.\n"
    )
    ref_path = out_dir / "Config-Reference-PLAIN-TEXT-DELETE-ME.txt"
    ref_path.write_text(ref, encoding="utf-8")

    return out_dir, [cer_path, manifest_path, json_path, psd1_path, ref_path]


def main():
    parser = argparse.ArgumentParser(
        description="Generate an ephemeral max-security cert for the "
                    "WHFB-Remediation-Automation app reg."
    )
    parser.add_argument(
        "--ttl-hours", type=int, default=24,
        help="Certificate lifetime in hours (default: 24).",
    )
    parser.add_argument(
        "--tenant-id", default=DEFAULT_TENANT_ID,
        help=f"Tenant ID to embed in the config (default: {DEFAULT_TENANT_ID}).",
    )
    args = parser.parse_args()

    if args.ttl_hours < 1:
        print("[ERROR] --ttl-hours must be >= 1")
        sys.exit(1)

    print()
    print("=" * 70)
    print("  WHFB-REMEDIATION-AUTOMATION - EPHEMERAL CERT GENERATOR")
    print("=" * 70)
    print()

    cert_info = create_certificate(args.ttl_hours)
    out_dir, files = write_outputs(cert_info, args.tenant_id, args.ttl_hours)

    print()
    print(f"[OK] Output directory: {out_dir}")
    for f in files:
        print(f"     - {f.name}")
    print()
    print(f"[!] Certificate is valid for {args.ttl_hours}h only - expires "
          f"{cert_info['not_after'].isoformat()}.")
    print("[!] Upload and run the remediation within that window, then delete")
    print("    the plain-text reference file.")
    print()


if __name__ == "__main__":
    main()
