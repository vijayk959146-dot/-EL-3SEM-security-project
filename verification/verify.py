"""
Domain ownership verification module.

Security terms explained for 3rd semester students:
- Ownership Verification: A challenge-response mechanism (similar to Let's Encrypt or Google Search Console)
  that requires a user to prove administrative control over a DNS zone or web root before authorizing active scans.
- DNS TXT Record: A type of DNS entry used to associate arbitrary human or machine-readable text with a domain name.
- .well-known URI: Standardized directory (RFC 8615) for site-wide metadata and automated verification challenges.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import DATA_DIR
from discovery.safe_fetch import safe_fetch, SafeFetchError

VERIFIED_TARGETS_FILE = DATA_DIR / "verified_targets.json"
VERIFICATION_TTL_SECONDS = 30 * 86400  # 30 days validity


def _load_verified_data() -> dict[str, dict[str, Any]]:
    """Load the verified targets store."""
    if not VERIFIED_TARGETS_FILE.exists():
        return {}
    try:
        return json.loads(VERIFIED_TARGETS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_verified_data(data: dict[str, dict[str, Any]]) -> None:
    """Save the verified targets store."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    VERIFIED_TARGETS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def is_domain_verified(domain: str) -> bool:
    """Check if a domain is currently verified and within its 30-day validity window."""
    clean_domain = domain.strip().lower()
    data = _load_verified_data()
    record = data.get(clean_domain)
    if not record:
        return False
    
    if not record.get("verified"):
        return False

    expires_at = record.get("expires_at", 0)
    if time.time() > expires_at:
        return False  # Expired

    return True


def start_verification(domain: str) -> dict[str, str]:
    """
    Generate a cryptographic token and print instructions for DNS TXT and HTTP verification.
    """
    clean_domain = domain.strip().lower()
    data = _load_verified_data()

    token = secrets.token_urlsafe(24)
    record = {
        "domain": clean_domain,
        "token": token,
        "verified": False,
        "method": None,
        "created_at": time.time(),
        "verified_at": None,
        "expires_at": None,
    }
    data[clean_domain] = record
    _save_verified_data(data)

    txt_record_name = f"_attacksurface-verify.{clean_domain}"
    well_known_url = f"https://{clean_domain}/.well-known/attacksurface-verify.txt"

    instructions = {
        "domain": clean_domain,
        "token": token,
        "dns_record": txt_record_name,
        "dns_value": token,
        "file_url": well_known_url,
        "file_content": token,
    }
    return instructions


def _check_dns_txt_record(domain: str, expected_token: str) -> bool:
    """Query DNS TXT records for _attacksurface-verify.<domain> using standard nslookup."""
    txt_host = f"_attacksurface-verify.{domain}"
    try:
        # Run nslookup -type=TXT
        proc = subprocess.run(
            ["nslookup", "-type=TXT", txt_host],
            capture_output=True,
            text=True,
            timeout=8,
        )
        output = proc.stdout
        if expected_token in output:
            return True
    except Exception:
        pass
    return False


def _check_well_known_file(domain: str, expected_token: str) -> bool:
    """Fetch https://<domain>/.well-known/attacksurface-verify.txt using safe_fetch."""
    url = f"https://{domain}/.well-known/attacksurface-verify.txt"
    try:
        response = safe_fetch(url, timeout=5.0)
        if response.status_code == 200:
            content = response.text.strip()
            if expected_token in content:
                return True
    except SafeFetchError:
        pass
    except Exception:
        pass
    return False


def check_verification(domain: str) -> tuple[bool, str]:
    """
    Check both DNS TXT record and .well-known HTTP file to verify domain control.
    Returns (success, message).
    """
    clean_domain = domain.strip().lower()
    data = _load_verified_data()
    record = data.get(clean_domain)

    if not record or not record.get("token"):
        return False, f"No verification in progress for '{clean_domain}'. Run 'python -m verification start {clean_domain}' first."

    token = record["token"]

    # 1. Check DNS TXT
    if _check_dns_txt_record(clean_domain, token):
        now = time.time()
        record["verified"] = True
        record["method"] = "dns-txt"
        record["verified_at"] = now
        record["expires_at"] = now + VERIFICATION_TTL_SECONDS
        data[clean_domain] = record
        _save_verified_data(data)
        return True, f"Domain '{clean_domain}' successfully verified via DNS TXT record! Active scans are now authorized for 30 days."

    # 2. Check HTTP .well-known file
    if _check_well_known_file(clean_domain, token):
        now = time.time()
        record["verified"] = True
        record["method"] = "http-well-known"
        record["verified_at"] = now
        record["expires_at"] = now + VERIFICATION_TTL_SECONDS
        data[clean_domain] = record
        _save_verified_data(data)
        return True, f"Domain '{clean_domain}' successfully verified via HTTP .well-known file! Active scans are now authorized for 30 days."

    return False, f"Verification failed for '{clean_domain}'. Neither DNS TXT record (_attacksurface-verify.{clean_domain}) nor https://{clean_domain}/.well-known/attacksurface-verify.txt matched the expected token."
