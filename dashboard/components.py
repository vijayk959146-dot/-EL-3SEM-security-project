"""
Shared UI components for Modern Enterprise SecOps cybersecurity assessment interface.
Strict HTML escaping, modern security pills, high legibility sans-serif typography.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any
import streamlit as st


def esc(text: Any) -> str:
    """Safely escape untrusted text for HTML injection."""
    return html.escape(str(text if text is not None else ""), quote=True)


def severity_class(sev: str) -> str:
    """Normalize severity key."""
    s = str(sev or "info").strip().lower()
    if s in {"critical", "crit"}:
        return "critical"
    if s in {"high"}:
        return "high"
    if s in {"medium", "med"}:
        return "medium"
    if s in {"low"}:
        return "low"
    return "info"


def render_mode_badge(mode: str, is_active_authorized: bool = False) -> str:
    """Render modern bordered mode badge with pulse dot."""
    m = str(mode or "passive").strip().lower()
    if m == "active" or is_active_authorized:
        label = "ACTIVE PROBE (VERIFIED)"
        cls = "mode-badge mode-badge-active"
    else:
        label = "PASSIVE RECON (OSINT)"
        cls = "mode-badge"
    return f'<span class="{cls}"><span class="pulse-dot"></span>{esc(label)}</span>'


def render_severity_mark(sev: str) -> str:
    """Render a modern security pill with colored dot indicator."""
    cls = severity_class(sev)
    name = cls.capitalize()
    return (
        f'<span class="sev-pill sev-pill-{cls}">'
        f'<span class="sev-dot"></span>'
        f'<span class="sev-badge-text {cls}">{esc(name)}</span>'
        f'</span>'
    )


def generate_verdict_text(report: dict[str, Any]) -> str:
    """Generate a deterministic, technical security posture summary."""
    target = report.get("target") or "Unknown target"
    findings = report.get("findings") or []
    total = len(findings)

    if total == 0:
        return f"{target}: Zero external exposures detected. Perimeter matches hardened defensive baselines."

    crit = sum(1 for f in findings if severity_class(f.get("severity", "")) == "critical")
    high = sum(1 for f in findings if severity_class(f.get("severity", "")) == "high")
    med = sum(1 for f in findings if severity_class(f.get("severity", "")) == "medium")
    crit_high = crit + high

    # Identify primary theme
    categories: list[str] = []
    titles_lower = " ".join(str(f.get("title", "")).lower() for f in findings)
    if any(k in titles_lower for k in ["header", "hsts", "csp", "x-frame", "cookie"]):
        categories.append("transport security headers")
    if any(k in titles_lower for k in ["tls", "ssl", "cert", "cipher"]):
        categories.append("TLS configuration")
    if any(k in titles_lower for k in ["port", "ssh", "telnet", "ftp"]):
        categories.append("exposed service ports")
    if any(k in titles_lower for k in ["cve", "vulnerability", "rce", "injection"]):
        categories.append("unpatched CVE vulnerabilities")
    if not categories:
        categories.append("host configuration hardening")

    theme_str = " and ".join(categories[:2])
    top_finding = findings[0]
    top_title = str(top_finding.get("title", "")).strip()

    count_phrase = f"{total} finding{'s' if total != 1 else ''}"
    if crit_high > 0:
        sev_phrase = f"{crit_high} high or critical priority"
    elif med > 0:
        sev_phrase = f"{med} medium priority"
    else:
        sev_phrase = "all low or informational priority"

    return (
        f"{target}: Identified {count_phrase} ({sev_phrase}). "
        f"Primary risk exposure focuses on {theme_str}. "
        f"Immediate mitigation recommendation: address '{top_title}'."
    )


def render_field_header(target: str, mode: str, is_active: bool = False) -> None:
    """Render the top console title bar."""
    badge_html = render_mode_badge(mode, is_active)
    st.markdown(
        f"""
        <div class="report-header">
            <div class="report-header-titles">
                <p class="subtitle">ATTACK SURFACE & VULNERABILITY CONSOLE</p>
                <h1>🛡️ {esc(target)}</h1>
            </div>
            <div>
                {badge_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
