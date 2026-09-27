"""
Passive HTTP checks: reachability, page title, TLS vs plain HTTP, security headers.

This does not send attack payloads. It only GETs the home page of an allowlisted
URL and records missing *security headers* — extra HTTP fields browsers use to
harden a site (for example CSP limits which scripts can run).
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlparse

import requests
import urllib3

from config import is_loopback, require_allowed_target

# Local Docker Juice Shop often uses HTTP; we skip TLS verify only on loopback.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from schemas import HttpCheck

# Headers we look for. Missing them is a misconfiguration signal, not a CVE.
SECURITY_HEADERS = (
    "content-security-policy",  # CSP: restricts scripts/images the page may load
    "x-content-type-options",
    "x-frame-options",  # reduces clickjacking (site loaded inside another page)
    "referrer-policy",
    "strict-transport-security",  # HSTS: force HTTPS — rarely present on localhost HTTP
)


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def _extract_title(html: str) -> str:
    parser = _TitleParser()
    try:
        parser.feed(html)
    except Exception:
        return ""
    return parser.title.strip()[:200]


def probe_http(target: str, port: int = 3000, use_tls: bool = False) -> HttpCheck:
    host = require_allowed_target(target)
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    notes: list[str] = []
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            verify=False if is_loopback(host) else True,
        )
    except requests.RequestException as exc:
        return HttpCheck(
            url=url,
            reachable=False,
            uses_tls=use_tls,
            notes=[f"HTTP probe failed: {exc.__class__.__name__}"],
        )

    parsed = urlparse(response.url)
    if parsed.hostname and not (
        parsed.hostname.lower() in {host, "localhost", "127.0.0.1"}
    ):
        notes.append("Refused to follow a redirect off the allowlisted host.")
        return HttpCheck(url=url, reachable=True, status_code=response.status_code, notes=notes)

    header_map = {k.lower(): v for k, v in response.headers.items()}
    missing = [name for name in SECURITY_HEADERS if name not in header_map]
    if not use_tls:
        # HSTS only applies to HTTPS; do not flag it on plain HTTP localhost.
        missing = [h for h in missing if h != "strict-transport-security"]
        notes.append("Service is HTTP, not HTTPS (no TLS on this probe).")

    title = _extract_title(response.text) if "html" in header_map.get("content-type", "") else ""
    if "juice shop" in title.lower() or "juice shop" in response.text[:2000].lower():
        notes.append("Page identifies as OWASP Juice Shop (expected lab target).")

    return HttpCheck(
        url=url,
        reachable=True,
        status_code=response.status_code,
        title=title,
        uses_tls=use_tls,
        missing_security_headers=missing,
        notes=notes,
    )
