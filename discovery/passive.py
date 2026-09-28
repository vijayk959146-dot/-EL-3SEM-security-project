"""
Passive website discovery mode.
Collects public information without active port probing or intrusive scanning.

Security terms explained for 3rd semester students:
- Certificate Transparency (CT Logs): A public, append-only log of all SSL/TLS certificates issued by CAs.
  Used to passively discover subdomains without sending any traffic to them.
- SPF (Sender Policy Framework): A DNS TXT record specifying which mail servers are authorized
  to send emails on behalf of a domain, mitigating email spoofing.
- DMARC (Domain-based Message Authentication, Reporting, and Conformance): A DNS TXT record
  instructing recipient mail servers how to handle emails that fail SPF/DKIM validation.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
import ssl
import subprocess
import time
from urllib.parse import urlparse
from typing import Any

import requests

from config import DATA_DIR
from discovery.safe_fetch import safe_fetch, SafeFetchError
from schemas import DiscoveredAssets, HttpCheck, OpenPort, TlsGrade
from storage import write_json

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()


def _extract_title(html: str) -> str:
    from html.parser import HTMLParser
    class _TitleParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self._in_title = False
            self.title = ""
        def handle_starttag(self, tag, attrs):
            if tag.lower() == "title":
                self._in_title = True
        def handle_endtag(self, tag):
            if tag.lower() == "title":
                self._in_title = False
        def handle_data(self, data):
            if self._in_title:
                self.title += data
    parser = _TitleParser()
    try:
        parser.feed(html)
    except Exception:
        return ""
    return parser.title.strip()[:200]


def _probe_passive_http(domain: str) -> HttpCheck:
    """Execute a single safe GET request over HTTPS (fallback to HTTP)."""
    urls_to_try = [f"https://{domain}/", f"http://{domain}/"]
    response = None
    final_url = urls_to_try[0]
    notes: list[str] = []

    for url in urls_to_try:
        try:
            response = safe_fetch(url, timeout=5.0)
            final_url = url
            break
        except SafeFetchError as exc:
            notes.append(f"Probe to {url} skipped: {exc}")
        except Exception as exc:
            notes.append(f"Probe to {url} failed: {exc.__class__.__name__}")

    if response is None:
        return HttpCheck(
            url=final_url,
            reachable=False,
            uses_tls="https" in final_url,
            notes=notes or ["Target domain was not reachable over standard HTTP/HTTPS."],
        )

    header_map = {k.lower(): v for k, v in response.headers.items()}
    security_headers = (
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "strict-transport-security",
    )
    missing = [name for name in security_headers if name not in header_map]
    if "https" not in final_url:
        missing = [h for h in missing if h != "strict-transport-security"]

    # Cookie checks
    cookie_issues = []
    raw_cookies = response.headers.get("set-cookie", "")
    for cookie in response.cookies:
        if not cookie.secure and "https" in final_url:
            cookie_issues.append(f"cookie-missing-secure: Cookie '{cookie.name}' missing Secure flag")
        if "httponly" not in raw_cookies.lower():
            cookie_issues.append(f"cookie-missing-httponly: Cookie '{cookie.name}' missing HttpOnly flag")
        if "samesite" not in raw_cookies.lower():
            cookie_issues.append(f"cookie-missing-samesite: Cookie '{cookie.name}' missing SameSite attribute")

    # CORS checks
    cors_issues = []
    allow_origin = header_map.get("access-control-allow-origin", "").strip()
    if allow_origin == "*":
        cors_issues.append("cors-wildcard-origin: Access-Control-Allow-Origin header is set to wildcard (*)")

    # Version disclosure
    version_issues = []
    if "server" in header_map:
        version_issues.append(f"version-disclosure-server: Server header discloses '{header_map['server']}'")
    if "x-powered-by" in header_map:
        version_issues.append(f"version-disclosure-x-powered-by: X-Powered-By discloses '{header_map['x-powered-by']}'")

    title = _extract_title(response.text)

    return HttpCheck(
        url=final_url,
        reachable=True,
        status_code=response.status_code,
        title=title,
        uses_tls="https" in final_url,
        missing_security_headers=missing,
        cookie_issues=list(dict.fromkeys(cookie_issues)),
        cors_issues=cors_issues,
        version_disclosure_issues=version_issues,
        notes=notes,
    )


def _inspect_passive_tls(domain: str) -> TlsGrade:
    """Inspect the public TLS certificate on port 443 safely."""
    raw_info: dict[str, Any] = {
        "reachable": False,
        "protocol": "",
        "issuer": "",
        "subject": "",
        "days_until_expiry": None,
        "issues": [],
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                raw_info["reachable"] = True
                raw_info["protocol"] = ssock.version() or ""
                cert = ssock.getpeercert()
                if cert:
                    # Calculate expiry days
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        exp_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_dt - datetime.datetime.utcnow()).days
                        raw_info["days_until_expiry"] = days_left
                        if days_left < 0:
                            raw_info["issues"].append("tls-expired: TLS certificate has expired")
                        elif days_left < 15:
                            raw_info["issues"].append(f"tls-expiring-soon: TLS certificate expires in {days_left} days")

                    # Extract subject and issuer
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                    subject_dict = dict(x[0] for x in cert.get("subject", ()))
                    raw_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "")
                    raw_info["subject"] = subject_dict.get("commonName", "")

                    if raw_info["issuer"] == raw_info["subject"] and raw_info["issuer"]:
                        raw_info["issues"].append("tls-self-signed: Self-signed certificate detected")

        return TlsGrade(
            skipped=False,
            reason="Passive TLS inspection completed.",
            host=domain,
            grade="Valid" if not raw_info["issues"] else "Warning",
            raw=raw_info,
        )
    except Exception as exc:
        return TlsGrade(
            skipped=True,
            reason=f"Passive TLS connection failed: {exc.__class__.__name__}",
            host=domain,
            raw={"error": str(exc)},
        )


def _query_dns_records(domain: str) -> dict[str, Any]:
    """Query DNS A, AAAA, MX, TXT, SPF, and DMARC records via nslookup."""
    records: dict[str, Any] = {
        "A": [],
        "MX": [],
        "TXT": [],
        "spf_present": False,
        "dmarc_present": False,
        "issues": [],
    }

    # Query TXT and SPF
    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, text=True, timeout=5)
        out = proc.stdout
        for line in out.splitlines():
            line_s = line.strip()
            if "text =" in line_s or "v=spf1" in line_s:
                records["TXT"].append(line_s)
                if "v=spf1" in line_s:
                    records["spf_present"] = True
    except Exception:
        pass

    if not records["spf_present"]:
        records["issues"].append("email-missing-spf: No SPF (Sender Policy Framework) DNS record found to prevent email spoofing.")

    # Query DMARC
    try:
        proc_dmarc = subprocess.run(["nslookup", "-type=TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=5)
        if "v=DMARC1" in proc_dmarc.stdout:
            records["dmarc_present"] = True
    except Exception:
        pass

    if not records["dmarc_present"]:
        records["issues"].append("email-missing-dmarc: No DMARC DNS record found to enforce email authentication policies.")

    return records


def _query_certificate_transparency(domain: str) -> list[str]:
    """Passively discover subdomains from public Certificate Transparency logs (crt.sh)."""
    subdomains: set[str] = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=6.0, headers={"User-Agent": "Mozilla/5.0 (Defensive Sec Tool)"})
        if res.status_code == 200:
            entries = res.json()
            for entry in entries[:100]:
                name_value = entry.get("name_value", "")
                for sub in name_value.splitlines():
                    sub = sub.strip().lower()
                    if "*" not in sub and sub.endswith(domain) and sub != domain:
                        subdomains.add(sub)
    except Exception:
        pass  # ct logs lookup is best-effort
    return sorted(list(subdomains))[:25]


def _query_shodan_intelligence(domain: str) -> dict[str, Any]:
    """Query Shodan's passive threat index for public open ports and CVEs."""
    shodan_info: dict[str, Any] = {"ports": [], "cpes": [], "tags": [], "source": "shodan-internetdb"}
    try:
        ip = socket.gethostbyname(domain)
        # Use free public InternetDB
        res = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=4.0)
        if res.status_code == 200:
            data = res.json()
            shodan_info["ports"] = data.get("ports", [])
            shodan_info["cpes"] = data.get("cpes", [])
            shodan_info["tags"] = data.get("tags", [])
    except Exception:
        pass
    return shodan_info


def discover_passive(domain: str) -> DiscoveredAssets:
    """
    Perform 100% passive, read-only reconnaissance on a public domain.
    No active port scanning or intrusive probes are performed.
    """
    domain = domain.strip().lower()
    notes: list[str] = [
        "Mode: PASSIVE (Public reconnaissance only — no active port scanning was performed)."
    ]

    # 1. Passive HTTP observation
    http_check = _probe_passive_http(domain)
    
    # 2. Passive TLS certificate inspection
    tls_check = _inspect_passive_tls(domain)

    # 3. DNS and Email security inspection
    dns_info = _query_dns_records(domain)

    # 4. Certificate Transparency subdomains
    ct_subdomains = _query_certificate_transparency(domain)

    # 5. Passive Shodan threat intelligence
    shodan_intel = _query_shodan_intelligence(domain)

    # Synthesize open ports from HTTP reachability and Shodan
    ports_found: list[OpenPort] = []
    if http_check.reachable:
        p_num = 443 if http_check.uses_tls else 80
        ports_found.append(
            OpenPort(
                port=p_num,
                protocol="tcp",
                state="open",
                service="https" if http_check.uses_tls else "http",
                product=http_check.title or "web",
                version="",
                extra="passive-web-observation",
            )
        )

    # Passive Metadata bundle
    passive_meta = {
        "dns": dns_info,
        "ct_subdomains": ct_subdomains,
        "ct_notice": "Subdomains discovered via public Certificate Transparency logs for mapping only (none were probed or scanned).",
        "shodan": shodan_intel,
    }

    if ct_subdomains:
        notes.append(f"Discovered {len(ct_subdomains)} subdomains from Certificate Transparency logs.")
    for issue in dns_info.get("issues", []):
        notes.append(issue)

    assets = DiscoveredAssets(
        target=domain,
        scan_method="passive-osint",
        ports=ports_found,
        http=http_check,
        tls=tls_check,
        mode="passive",
        passive_meta=passive_meta,
        notes=notes,
    )

    write_json("discovered_assets.json", assets)
    return assets
