"""
Project-wide settings and the scan allowlist guard.

Every discovery function must call `require_allowed_target()` before talking
to a host. That keeps this tool from being used as a general scanner.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

ALLOWLIST_PATH = ROOT / "targets.allowlist"
DATA_DIR = ROOT / "data"

# CVE = Common Vulnerabilities and Exposures — a public ID for a known software flaw.
# CVSS = Common Vulnerability Scoring System — a 0–10 severity number attached to many CVEs.
DEFAULT_TARGET = os.getenv("DEFAULT_TARGET", "localhost")
DEFAULT_PORTS = [
    int(p.strip())
    for p in os.getenv("DEFAULT_PORTS", "80,443,3000,8000,8080").split(",")
    if p.strip().isdigit()
]
AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
BEDROCK_MODEL_ID = os.getenv(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
)
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()


def _normalize_host(raw: str) -> str:
    """
    Turn URLs, host:port strings, bracketed IPv6, and trailing-dot hostnames
    into a canonical lowercase hostname or compressed IP address.
    
    Examples:
    - '::1' -> '::1'
    - '[::1]:3000' -> '::1'
    - 'http://[::1]:3000/path' -> '::1'
    - '127.0.0.1:3000' -> '127.0.0.1'
    - 'LOCALHOST:3000' -> 'localhost'
    - 'example.com.' -> 'example.com'
    """
    val = (raw or "").strip()
    if not val:
        return ""

    if "://" in val:
        try:
            parsed = urlparse(val)
            host = parsed.hostname or ""
        except Exception:
            host = ""
    elif "/" in val:
        try:
            parsed = urlparse(f"http://{val}")
            host = parsed.hostname or ""
        except Exception:
            host = ""
    else:
        if val.startswith("[") and "]" in val:
            bracket_end = val.find("]")
            host = val[1:bracket_end]
        elif ":" in val and val.count(":") == 1:
            host, _, _ = val.partition(":")
        else:
            host = val

    host = host.strip().lower().rstrip(".")
    if not host:
        return ""

    # Validate / compress IP addresses
    try:
        ip_obj = ipaddress.ip_address(host)
        return ip_obj.compressed
    except ValueError:
        pass

    return host


def load_allowlist() -> set[str]:
    if not ALLOWLIST_PATH.exists():
        raise FileNotFoundError(
            f"Missing {ALLOWLIST_PATH}. Create it and list allowed hosts, one per line."
        )
    allowed: set[str] = set()
    for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            norm = _normalize_host(line)
            if norm:
                allowed.add(norm)
    return allowed


def is_target_allowed(target: str) -> bool:
    host = _normalize_host(target)
    if not host:
        return False
    allowed = load_allowlist()
    aliases = {host}
    if host in {"localhost", "127.0.0.1", "::1"}:
        aliases.update({"localhost", "127.0.0.1", "::1"})
    if bool(aliases & allowed):
        return True
    
    # Check if domain has been ownership-verified
    try:
        from verification.verify import is_domain_verified
        if is_domain_verified(host):
            return True
    except Exception:
        pass

    return False


def require_allowed_target(target: str) -> str:
    """Return the normalized host, or raise if it is not on the allowlist."""
    host = _normalize_host(target)
    if not host:
        raise ValueError("Target is empty.")
    if not is_target_allowed(host):
        raise PermissionError(
            f"Refusing to scan '{host}'. Add it to targets.allowlist only if you own it."
        )
    return host


def is_loopback(host: str) -> bool:
    return _normalize_host(host) in {"localhost", "127.0.0.1", "::1"}
