#!/usr/bin/env python3
"""
Discover which Intune surface exposes the WHFB-disable and security-key
sign-in settings, by querying the LIVE tenant via Microsoft Graph (beta).

Authoritative for THIS tenant - reflects exactly what is available to POST,
with the real setting definition IDs / template ids. Community catalog sites
are handy references but this is the source of truth.

Looks at, in best-practice priority order:
  1. Endpoint Security  -> /deviceManagement/configurationPolicyTemplates
                           (templateFamily endpointSecurity*) + their
                           settingTemplates / settingDefinitions
  2. Settings Catalog   -> /deviceManagement/configurationCategories +
                           /deviceManagement/configurationSettings
  3. (Custom OMA-URI is the fallback we already used.)

Reports, for each target setting, which surface carries it and the exact id.

Usage:
    python Discover-IntuneSurfaces.py
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

# What we are hunting for (case-insensitive substring match on id / name).
WHFB_KEYS = ["passportforwork", "usepassportforwork",
             "windows hello for business", "passport for work"]
SECKEY_KEYS = ["usesecuritykeyforsignin", "securitykey/usesecuritykey",
               "security key for sign", "use security key for sign"]
# Generic noise we don't want to over-match on:
HELLO_BROAD = ["hello"]


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
        self.h = {"Authorization": f"Bearer {token}"}

    def get(self, url):
        if url.startswith("/"):
            url = GRAPH_BETA + url
        r = requests.get(url, headers=self.h, timeout=60)
        r.raise_for_status()
        return r.json()

    def pages(self, url, cap_pages=40):
        """Yield items across @odata.nextLink, capped."""
        if url.startswith("/"):
            url = GRAPH_BETA + url
        pages = 0
        while url and pages < cap_pages:
            r = requests.get(url, headers=self.h, timeout=60)
            r.raise_for_status()
            data = r.json()
            for item in data.get("value", []):
                yield item
            url = data.get("@odata.nextLink")
            pages += 1


def hit(text, keys):
    t = (text or "").lower()
    return any(k in t for k in keys)


# ---------------------------------------------------------------------------
# 1. Endpoint Security templates
# ---------------------------------------------------------------------------

def discover_endpoint_security(g):
    print()
    print("=" * 70)
    print("  1. ENDPOINT SECURITY  (configurationPolicyTemplates)")
    print("=" * 70)
    findings = {"whfb": [], "seckey": []}
    try:
        templates = list(g.pages(
            "/deviceManagement/configurationPolicyTemplates"
            "?$select=id,displayName,templateFamily,lifecycleState,version"
        ))
    except requests.HTTPError as e:
        print(f"  [!] Could not list configurationPolicyTemplates: {e}")
        return findings

    es = [t for t in templates
          if (t.get("templateFamily") or "").lower().startswith("endpointsecurity")]
    fams = sorted({t.get("templateFamily") for t in es})
    print(f"  {len(es)} Endpoint Security template(s); families: {', '.join(fams)}")

    # Account protection is the family that historically carried WHFB.
    interesting = [t for t in es if "accountprotection" in
                   (t.get("templateFamily") or "").lower()]
    # If none, scan all ES templates (cheap enough for one-time discovery).
    scan = interesting or es
    print(f"  Inspecting {len(scan)} template(s) for WHFB / security-key "
          "settings...")

    for t in scan:
        tid = t["id"]
        label = f"{t.get('displayName')} [{t.get('templateFamily')}] " \
                f"v{t.get('version')} ({t.get('lifecycleState')})"
        try:
            sts = list(g.pages(
                f"/deviceManagement/configurationPolicyTemplates/{tid}"
                f"/settingTemplates?$expand=settingDefinitions", cap_pages=10))
        except requests.HTTPError as e:
            print(f"    [!] {label}: settingTemplates failed ({e})")
            continue
        for st in sts:
            for sd in st.get("settingDefinitions", []):
                sid = sd.get("id", "")
                name = sd.get("displayName") or sd.get("name") or ""
                if hit(sid, WHFB_KEYS) or hit(name, WHFB_KEYS):
                    findings["whfb"].append(
                        {"surface": "EndpointSecurity", "template": label,
                         "templateId": tid, "settingId": sid, "name": name})
                if hit(sid, SECKEY_KEYS) or hit(name, SECKEY_KEYS):
                    findings["seckey"].append(
                        {"surface": "EndpointSecurity", "template": label,
                         "templateId": tid, "settingId": sid, "name": name})

    for label, items in (("WHFB", findings["whfb"]),
                         ("Security-key", findings["seckey"])):
        if items:
            print(f"  [FOUND] {label}: {len(items)} setting(s) in Endpoint "
                  "Security")
            for it in items:
                print(f"     - {it['name']}")
                print(f"       template:  {it['template']}")
                print(f"       settingId: {it['settingId']}")
        else:
            print(f"  [none]  {label}: not exposed by any Endpoint Security "
                  "template scanned")
    return findings


# ---------------------------------------------------------------------------
# 2. Settings Catalog
# ---------------------------------------------------------------------------

def discover_settings_catalog(g):
    print()
    print("=" * 70)
    print("  2. SETTINGS CATALOG  (configurationCategories + configurationSettings)")
    print("=" * 70)
    findings = {"whfb": [], "seckey": []}

    # Find candidate categories first - far cheaper than scanning all settings.
    try:
        cats = list(g.pages(
            "/deviceManagement/configurationCategories"
            "?$select=id,name,displayName,platforms,technologies"))
    except requests.HTTPError as e:
        print(f"  [!] Could not list configurationCategories: {e}")
        cats = []

    cat_keys = ["passport", "hello", "security key", "securitykey"]
    cand = [c for c in cats
            if hit(c.get("name"), cat_keys) or hit(c.get("displayName"), cat_keys)]
    print(f"  {len(cats)} categories total; {len(cand)} match "
          "passport/hello/security-key:")
    for c in cand:
        print(f"     - {c.get('displayName')}  (id={c.get('id')})")

    seen = set()
    for c in cand:
        cid = c.get("id")
        try:
            settings = list(g.pages(
                "/deviceManagement/configurationSettings"
                f"?$filter=categoryId eq '{cid}'"
                "&$select=id,displayName,name,categoryId", cap_pages=20))
        except requests.HTTPError as e:
            print(f"  [!] settings for category {cid} failed ({e})")
            continue
        for s in settings:
            sid = s.get("id", "")
            if sid in seen:
                continue
            seen.add(sid)
            name = s.get("displayName") or s.get("name") or ""
            if hit(sid, WHFB_KEYS) or hit(name, WHFB_KEYS):
                findings["whfb"].append(
                    {"surface": "SettingsCatalog", "settingId": sid,
                     "name": name, "categoryId": c.get("id"),
                     "category": c.get("displayName")})
            if hit(sid, SECKEY_KEYS) or hit(name, SECKEY_KEYS):
                findings["seckey"].append(
                    {"surface": "SettingsCatalog", "settingId": sid,
                     "name": name, "categoryId": c.get("id"),
                     "category": c.get("displayName")})

    for label, items in (("WHFB", findings["whfb"]),
                         ("Security-key", findings["seckey"])):
        if items:
            print(f"  [FOUND] {label}: {len(items)} setting(s) in Settings "
                  "Catalog")
            for it in items:
                print(f"     - {it['name']}  [{it['category']}]")
                print(f"       settingId: {it['settingId']}")
        else:
            print(f"  [none]  {label}: not found via candidate categories")
    return findings


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def recommend(name, es_items, sc_items):
    if es_items:
        return f"  {name}: -> ENDPOINT SECURITY (preferred surface carries it)"
    if sc_items:
        return f"  {name}: -> SETTINGS CATALOG (not in Endpoint Security; " \
               "catalog carries it)"
    return f"  {name}: -> no managed surface found; Custom OMA-URI stays the " \
           "only option"


def main():
    cfg = load_cfg()
    print("=" * 70)
    print("  INTUNE SURFACE DISCOVERY  (live tenant via Graph beta)")
    print("=" * 70)
    print(f"  Tenant:    {cfg['tenant_id']}")
    print(f"  App:       {cfg['client_id']}")
    g = G(get_token(cfg))
    print("  Auth:      cert-based token OK")

    es = discover_endpoint_security(g)
    sc = discover_settings_catalog(g)

    print()
    print("=" * 70)
    print("  RECOMMENDATION  (ES -> Settings Catalog -> Custom OMA-URI)")
    print("=" * 70)
    print(recommend("WHFB disable    ", es["whfb"], sc["whfb"]))
    print(recommend("Security-key    ", es["seckey"], sc["seckey"]))
    print()

    out = SCRIPT_DIR / "intune-surface-discovery.json"
    out.write_text(json.dumps({"endpointSecurity": es,
                               "settingsCatalog": sc}, indent=2),
                   encoding="utf-8")
    print(f"  Full results written to: {out}")
    print()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, requests.RequestException) as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
