"""
TLS / certificate grading via the public SSL Labs API.

TLS (Transport Layer Security) encrypts HTTP into HTTPS. SSL Labs grades how
well a *public* site configures that encryption (A+ to F).

It cannot scan localhost, so we skip cleanly for the Juice Shop Docker target.
"""

from __future__ import annotations

import time

import requests

from config import is_loopback, require_allowed_target
from schemas import TlsGrade

SSL_LABS_ANALYZE = "https://api.ssllabs.com/api/v3/analyze"


def check_tls(target: str) -> TlsGrade:
    host = require_allowed_target(target)
    if is_loopback(host):
        return TlsGrade(
            skipped=True,
            reason="SSL Labs only grades public hostnames, not localhost/Docker.",
            host=host,
        )

    params = {"host": host, "fromCache": "on", "maxAge": 24, "all": "done"}
    try:
        response = requests.get(SSL_LABS_ANALYZE, params=params, timeout=20)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        return TlsGrade(
            skipped=True,
            reason=f"SSL Labs request failed: {exc.__class__.__name__}",
            host=host,
        )

    status = payload.get("status", "")
    if status in {"DNS", "IN_PROGRESS"}:
        time.sleep(5)
        return TlsGrade(
            skipped=True,
            reason="SSL Labs assessment not cached yet; skipped to keep the lab run fast.",
            host=host,
            raw={"status": status},
        )

    endpoints = payload.get("endpoints") or []
    grade = ""
    if endpoints:
        grade = str(endpoints[0].get("grade") or endpoints[0].get("gradeTrustIgnored") or "")
    return TlsGrade(skipped=False, host=host, grade=grade, raw={"status": status})
