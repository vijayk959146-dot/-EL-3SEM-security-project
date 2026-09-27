"""
Project-wide settings and the scan allowlist guard.

Every discovery function must call `require_allowed_target()` before talking
to a host. That keeps this tool from being used as a general scanner.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

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
    """Turn 'http://localhost:3000' into 'localhost' (lowercase, no brackets)."""
    value = (raw or "").strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0]
    value = value.split(":")[0]
    value = value.strip("[]")
    if value in {"::1", "0:0:0:0:0:0:0:1"}:
        return "::1"
    return value


def load_allowlist() -> set[str]:
    if not ALLOWLIST_PATH.exists():
        raise FileNotFoundError(
            f"Missing {ALLOWLIST_PATH}. Create it and list allowed hosts, one per line."
        )
    allowed: set[str] = set()
    for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            allowed.add(_normalize_host(line))
    return allowed


def is_target_allowed(target: str) -> bool:
    host = _normalize_host(target)
    allowed = load_allowlist()
    aliases = {host}
    if host in {"localhost", "127.0.0.1"}:
        aliases.update({"localhost", "127.0.0.1"})
    return bool(aliases & allowed)


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
