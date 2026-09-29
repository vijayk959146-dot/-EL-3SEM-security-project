"""
Streamlit dashboard for the prioritized report and scan history diffs.
Run from repo root: streamlit run dashboard/app.py
"""

from __future__ import annotations

import html
import io
import json
import os
import sys
import time as _time
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from config import DATA_DIR, DEFAULT_PORTS, DEFAULT_TARGET, get_target_allowlist, is_target_allowed
from run_pipeline import run_target
from storage import diff_reports, generate_csv_report, generate_html_report, list_run_history, read_json, target_data_dir
from verification.verify import (
    check_domain_verification,
    generate_verification_token,
    is_domain_verified,
    load_verified_targets,
)

# --- Page Setup & Cyber Dark SOC Theme ---
st.set_page_config(
    page_title="AI Attack Surface Correlation & SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    code, pre, [class*="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 3.5rem;
        max-width: 1550px;
    }

    /* Top Hero Header */
    .hero-container {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(30, 41, 59, 0.7) 100%);
        border: 1px solid rgba(56, 189, 248, 0.18);
        border-radius: 14px;
        padding: 1.5rem 1.8rem;
        margin-bottom: 1.5rem;
        backdrop-filter: blur(12px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
    }

    .hero-title-group h1 {
        font-size: 1.85rem;
        font-weight: 800;
        margin: 0;
        background: linear-gradient(90deg, #f8fafc 0%, #38bdf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .hero-title-group p {
        color: #94a3b8;
        font-size: 0.95rem;
        margin: 0.25rem 0 0 0;
    }

    /* Metric Cards */
    .kpi-card {
        background: linear-gradient(145deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.8) 100%);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 12px;
        padding: 1.1rem 1.25rem;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.3);
        height: 100%;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.4);
        box-shadow: 0 8px 25px -4px rgba(56, 189, 248, 0.15);
    }
    .kpi-label {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        font-weight: 700;
        color: #94a3b8;
        margin-bottom: 0.35rem;
        display: flex;
        align-items: center;
        gap: 0.4rem;
    }
    .kpi-value {
        font-size: 1.75rem;
        font-weight: 800;
        color: #f8fafc;
        line-height: 1.2;
    }
    .kpi-sub {
        font-size: 0.8rem;
        color: #64748b;
        margin-top: 0.25rem;
    }

    /* Risk Score Gauge Pill */
    .risk-pill-crit { background: rgba(220, 38, 38, 0.18); border: 1px solid #ef4444; color: #fca5a5; }
    .risk-pill-high { background: rgba(234, 88, 12, 0.18); border: 1px solid #f97316; color: #fdba74; }
    .risk-pill-med { background: rgba(217, 119, 6, 0.18); border: 1px solid #eab308; color: #fde047; }
    .risk-pill-low { background: rgba(37, 99, 235, 0.18); border: 1px solid #3b82f6; color: #93c5fd; }
    .risk-pill-info { background: rgba(75, 85, 99, 0.18); border: 1px solid #64748b; color: #cbd5e1; }

    /* Severity Badges & Chips */
    .risk-strip {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
        margin: 0.75rem 0 1.25rem 0;
    }
    .risk-chip {
        border-radius: 9999px;
        padding: 6px 14px;
        font-size: 0.84rem;
        font-weight: 700;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.2s ease;
    }
    .risk-chip:hover {
        filter: brightness(1.15);
    }
    .risk-critical { background: #450a0a; color: #fecaca; border: 1px solid #b91c1c; }
    .risk-high { background: #431407; color: #fed7aa; border: 1px solid #c2410c; }
    .risk-medium { background: #451a03; color: #fde68a; border: 1px solid #b45309; }
    .risk-low { background: #172554; color: #bfdbfe; border: 1px solid #1d4ed8; }
    .risk-info { background: #1e293b; color: #cbd5e1; border: 1px solid #475569; }

    /* Finding Card Container */
    .finding-card {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(148, 163, 184, 0.16);
        border-radius: 10px;
        padding: 1.2rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
    }

    /* Subtle Glassmorphism for expanders and tabs */
    [data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.5) !important;
        border: 1px solid rgba(148, 163, 184, 0.16) !important;
        border-radius: 10px !important;
        margin-bottom: 0.75rem !important;
    }

    /* Status Badge */
    .mode-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 5px 13px;
        border-radius: 9999px;
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

import hmac

# 1. Authentication & Security Guard
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()
ALLOW_ANONYMOUS_DASHBOARD = os.getenv("ALLOW_ANONYMOUS_DASHBOARD", "true").strip().lower() in {
    "1",
    "true",
    "yes",
}
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 30

if not DASHBOARD_PASSWORD and not ALLOW_ANONYMOUS_DASHBOARD:
    st.markdown(
        """
        <div class="hero-container">
            <div class="hero-title-group">
                <h1>🔒 Security Assessment Dashboard</h1>
                <p>Private defensive reporting workspace</p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.error("🛡️ **Dashboard access is currently locked.**")
    st.info("Set `DASHBOARD_PASSWORD` in your deployment environment or set `ALLOW_ANONYMOUS_DASHBOARD=true` in `.env` to enable access.")
    st.stop()

if DASHBOARD_PASSWORD:
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "login_attempts" not in st.session_state:
        st.session_state.login_attempts = 0
    if "lockout_until" not in st.session_state:
        st.session_state.lockout_until = 0.0

    if not st.session_state.authenticated:
        st.markdown(
            """
            <div class="hero-container">
                <div class="hero-title-group">
                    <h1>🔒 Security Assessment Portal</h1>
                    <p>Enter your authorized access token to view defensive reports</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        now = _time.monotonic()
        locked = now < st.session_state.lockout_until
        if locked:
            remaining = int(st.session_state.lockout_until - now)
            st.error(f"⛔ Too many failed attempts. Locked out for {remaining} seconds.")
        else:
            col_l1, col_l2, _ = st.columns([2, 1, 1])
            with col_l1:
                pwd = st.text_input("Dashboard Access Password", type="password", key="login_pwd_input")
                if st.button("🔑 Authenticate & Enter", key="login_btn", use_container_width=True):
                    if hmac.compare_digest(pwd.encode("utf-8"), DASHBOARD_PASSWORD.encode("utf-8")):
                        st.session_state.authenticated = True
                        st.session_state.login_attempts = 0
                        st.rerun()
                    else:
                        st.session_state.login_attempts += 1
                        if st.session_state.login_attempts >= _MAX_LOGIN_ATTEMPTS:
                            st.session_state.lockout_until = _time.monotonic() + _LOCKOUT_SECONDS
                            st.error(f"⛔ Maximum attempts reached. Locked for {_LOCKOUT_SECONDS}s.")
                        else:
                            rem = _MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
                            st.error(f"❌ Invalid credentials. {rem} attempt(s) remaining.")
        st.stop()


# --- Target & Report Discovery ---
def _discover_available_targets() -> list[str]:
    """Find all targets across per-target subdirectories, report files, and legacy storage."""
    targets: set[str] = set()
    if DATA_DIR.exists():
        for item in DATA_DIR.iterdir():
            if item.is_dir() and item.name not in {"cache", "history", "scratch"}:
                if (item / "prioritized_report.json").exists() or (item / "history").exists():
                    targets.add(item.name)
            elif item.is_file() and item.name.startswith("report_") and item.name.endswith(".json"):
                name = item.name[len("report_"):-len(".json")]
                if name:
                    targets.add(name)
        # Check flat prioritized report
        flat_report = DATA_DIR / "prioritized_report.json"
        if flat_report.exists():
            try:
                d = json.loads(flat_report.read_text(encoding="utf-8"))
                if d.get("target"):
                    targets.add(d["target"])
            except Exception:
                pass
    return sorted(list(targets))


available_targets = _discover_available_targets()

# Sidebar: Controls & Quick Scans
st.sidebar.markdown(
    """
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:1rem;">
        <span style="font-size:1.6rem;">🛡️</span>
        <div>
            <h3 style="margin:0;font-size:1.15rem;font-weight:700;color:#f8fafc;">Project Controls</h3>
            <span style="font-size:0.75rem;color:#38bdf8;">AI Attack Surface SOC</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Target Selector
selected_target: str | None = None
if available_targets:
    default_idx = 0
    if "localhost" in available_targets:
        default_idx = available_targets.index("localhost")
    selected_target = st.sidebar.selectbox("🎯 Target Workspace", available_targets, index=default_idx)
else:
    st.sidebar.caption("No target reports detected yet.")

# Quick Scan Launcher in Sidebar
with st.sidebar.expander("🚀 Run New Scan / Assessment", expanded=False):
    st.caption("Trigger an authorized active probe or passive OSINT scan directly:")
    scan_input_target = st.text_input("Target Host/Domain", value=selected_target or "localhost", key="scan_input_target")
    scan_ports_input = st.text_input("Ports (Active scan)", value=",".join(str(p) for p in DEFAULT_PORTS), key="scan_ports")
    force_passive = st.checkbox("Force Passive OSINT only", value=False, key="scan_passive_cb")

    if st.button("⚡ Start Assessment Pipeline", use_container_width=True, type="primary"):
        target_name = scan_input_target.strip()
        if not target_name:
            st.error("Please specify a target domain or IP.")
        else:
            ports_list = [int(p.strip()) for p in scan_ports_input.split(",") if p.strip().isdigit()]
            with st.spinner(f"Running defensive pipeline against {target_name}..."):
                try:
                    run_target(target_name, ports_list, force_passive=force_passive)
                    st.success(f"Assessment completed for {target_name}!")
                    _time.sleep(1)
                    st.rerun()
                except Exception as ex:
                    st.error(f"Scan failed: {ex}")


def _load_report(target: str | None = None) -> dict[str, Any]:
    """Load the prioritized security report safely."""
    if target:
        try:
            return read_json("prioritized_report.json", target=target)
        except Exception:
            pass
        target_file = DATA_DIR / f"report_{target}.json"
        if target_file.exists():
            try:
                return json.loads(target_file.read_text(encoding="utf-8"))
            except Exception:
                pass
    try:
        return read_json("prioritized_report.json")
    except Exception:
        return {}


report = _load_report(selected_target)

# History Selector
history_files = list_run_history(target=selected_target)
selected_history: Path | None = None

if history_files:
    st.sidebar.markdown("---")
    st.sidebar.markdown("**📜 Scan History Timeline**")
    history_options = ["Latest Scan (Current)"] + [f.name for f in history_files]
    choice = st.sidebar.selectbox("Select Snapshot", history_options, label_visibility="collapsed")
    if choice != "Latest Scan (Current)":
        target_path = next((f for f in history_files if f.name == choice), None)
        if target_path:
            try:
                report = json.loads(target_path.read_text(encoding="utf-8"))
                selected_history = target_path
            except Exception:
                pass

# Domain Verification Panel in Sidebar
with st.sidebar.expander("🔑 Domain Ownership Verification", expanded=False):
    st.markdown("<small style='color:#94a3b8;'>Prove administrative control over a domain to authorize active scans:</small>", unsafe_allow_html=True)
    v_domain = st.text_input("Target Domain", placeholder="example.com", key="v_dom_input")
    
    col_v1, col_v2 = st.columns(2)
    with col_v1:
        if st.button("1. Get Token", use_container_width=True):
            if v_domain:
                tok = generate_verification_token(v_domain.strip())
                st.session_state["v_token"] = tok
                st.session_state["v_domain_curr"] = v_domain.strip()
            else:
                st.error("Enter a domain.")
    with col_v2:
        if st.button("2. Verify", use_container_width=True):
            if v_domain:
                with st.spinner("Checking DNS TXT & HTTP challenge..."):
                    ok, msg = check_domain_verification(v_domain.strip())
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
            else:
                st.error("Enter a domain.")

    if "v_token" in st.session_state and st.session_state.get("v_domain_curr") == v_domain:
        st.markdown(
            f"""
            <div style="background:rgba(15,23,42,0.9);border:1px solid rgba(56,189,248,0.3);border-radius:8px;padding:10px;margin-top:8px;">
                <div style="font-size:0.75rem;color:#38bdf8;font-weight:700;">CHALLENGE TOKEN</div>
                <code style="font-size:0.85rem;color:#f8fafc;word-break:break-all;">{st.session_state['v_token']}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(f"**Method A (DNS TXT):**\n`_attacksurface-verify.{v_domain}`")
        st.markdown(f"**Method B (HTTP):**\n`https://{v_domain}/.well-known/attacksurface-verify.txt`")

    active_verified = load_verified_targets()
    if active_verified:
        st.markdown("---")
        st.caption("✅ Currently Verified Domains (30-Day TTL):")
        for dom, info in active_verified.items():
            st.code(f"{dom} [{info.get('method')}]", language="text")

# Glossary in Sidebar
with st.sidebar.expander("📚 Security Terms Glossary", expanded=False):
    st.markdown("""
    - **SSRF**: Server-Side Request Forgery — tricking backend servers into fetching internal network resources.
    - **DNS Rebinding**: Weaponizing DNS TTL to bypass same-origin & network isolation.
    - **CT Logs**: Certificate Transparency public audit log of all issued TLS certs.
    - **SPF / DMARC**: DNS TXT records to stop email spoofing and phishing.
    - **CISA KEV**: Known Exploited Vulnerabilities actively attacked in the wild.
    - **EPSS**: Probability (0–100%) of weaponized exploitation in the next 30 days.
    - **CVSS v3.1**: 0.0–10.0 standard severity rating framework.
    """)

# Sidebar footer status
st.sidebar.markdown("---")
auth_status_text = "🔒 Password Protected" if DASHBOARD_PASSWORD else "🟢 Public Demo Mode"
st.sidebar.caption(f"Status: {auth_status_text} | Engine: Amazon Nova / Bedrock")


# --- Main Dashboard Header ---
target_display = report.get("target") or (selected_target or "No Target Selected")
mode = report.get("mode") or ("active" if is_target_allowed(target_display) or is_domain_verified(target_display) else "passive")

if is_target_allowed(target_display):
    mode_pill = '<span class="mode-pill" style="background:#1e3a8a;border:1px solid #3b82f6;color:#bfdbfe;">🧪 Local Lab (Active Probing Allowed)</span>'
elif is_domain_verified(target_display) or mode == "active":
    mode_pill = '<span class="mode-pill" style="background:#064e3b;border:1px solid #10b981;color:#a7f3d0;">🛡️ Verified Active (Authorized)</span>'
else:
    mode_pill = '<span class="mode-pill" style="background:#4c1d95;border:1px solid #8b5cf6;color:#ddd6fe;">🌐 Passive OSINT (Zero Probing)</span>'

st.markdown(
    f"""
    <div class="hero-container">
        <div class="hero-title-group">
            <h1>🛡️ AI Attack Surface & Defense SOC</h1>
            <p>Automated defensive intelligence, CVE/KEV correlation, and AI-prioritized remediation</p>
        </div>
        <div>
            {mode_pill}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# --- Empty State Handler ---
if not report or not report.get("findings"):
    st.markdown(
        """
        <div style="background:rgba(30,41,59,0.5);border:1px solid rgba(148,163,184,0.2);border-radius:12px;padding:2.5rem;text-align:center;margin:2rem 0;">
            <div style="font-size:3rem;margin-bottom:1rem;">🎯</div>
            <h2 style="color:#f8fafc;margin:0 0 0.5rem 0;">No Assessment Report Loaded</h2>
            <p style="color:#94a3b8;max-width:600px;margin:0 auto 1.5rem auto;">
                Select an existing target from the sidebar, launch an instant scan, or load sample lab data to evaluate the defensive intelligence engine.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        if st.button("⚡ Run Instant Localhost Scan", use_container_width=True, type="primary"):
            with st.spinner("Executing defensive pipeline for localhost..."):
                run_target("localhost", DEFAULT_PORTS, force_passive=False)
                st.success("Localhost scan complete!")
                _time.sleep(1)
                st.rerun()
    with col_e2:
        if st.button("🌐 Run Passive OSINT on example.com", use_container_width=True):
            with st.spinner("Gathering passive intelligence for example.com..."):
                run_target("example.com", DEFAULT_PORTS, force_passive=True)
                st.success("Passive OSINT scan complete!")
                _time.sleep(1)
                st.rerun()
    st.stop()


findings = report.get("findings") or []
target = report.get("target") or "Unknown"

# Compute Severity Analytics
severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
for finding in findings:
    sev = str(finding.get("severity") or "Info").title()
    severity_counts[sev if sev in severity_counts else "Info"] += 1

high_risk_count = severity_counts["Critical"] + severity_counts["High"]
related_cves = {cve for finding in findings for cve in (finding.get("related_cves") or [])}
cve_count = len(related_cves)

# Composite Risk Score Calculation (0-100)
raw_score = (
    severity_counts["Critical"] * 30
    + severity_counts["High"] * 18
    + severity_counts["Medium"] * 8
    + severity_counts["Low"] * 3
    + severity_counts["Info"] * 1
)
risk_score = min(100, raw_score)

if risk_score >= 70:
    score_pill_class = "risk-pill-crit"
    score_label = "HIGH THREAT"
elif risk_score >= 40:
    score_pill_class = "risk-pill-high"
    score_label = "ELEVATED"
elif risk_score >= 20:
    score_pill_class = "risk-pill-med"
    score_label = "MODERATE"
else:
    score_pill_class = "risk-pill-low"
    score_label = "SECURE / LOW"


# --- Executive KPI Grid ---
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

with kpi1:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">🎯 Assessed Target</div>
            <div class="kpi-value" style="font-size:1.4rem;word-break:break-all;">{target}</div>
            <div class="kpi-sub">Mode: {mode.upper()}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi2:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">🚨 Total Findings</div>
            <div class="kpi-value">{len(findings)}</div>
            <div class="kpi-sub">{high_risk_count} Critical / High</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi3:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">⚡ Threat Index</div>
            <div class="kpi-value">
                <span class="risk-chip {score_pill_class}" style="padding:4px 10px;font-size:1.15rem;">
                    {risk_score}/100
                </span>
            </div>
            <div class="kpi-sub">{score_label} POSTURE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi4:
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">🏷️ Public CVEs</div>
            <div class="kpi-value">{cve_count}</div>
            <div class="kpi-sub">NVD & CISA KEV Linked</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi5:
    engine_name = "Amazon Bedrock AI" if report.get("used_llm") else "Heuristic Engine"
    model_str = report.get("model_id") or "CVSS 3.1 Fallback"
    st.markdown(
        f"""
        <div class="kpi-card">
            <div class="kpi-label">🧠 Prioritization</div>
            <div class="kpi-value" style="font-size:1.25rem;color:#38bdf8;">{engine_name}</div>
            <div class="kpi-sub" style="font-size:0.75rem;overflow:hidden;text-overflow:ellipsis;">{model_str}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Severity Chip Summary Bar
chips = []
for severity, css_name in (
    ("Critical", "critical"),
    ("High", "high"),
    ("Medium", "medium"),
    ("Low", "low"),
    ("Info", "info"),
):
    count = severity_counts[severity]
    chips.append(f"<span class='risk-chip risk-{css_name}'>● {severity}: {count}</span>")

st.markdown("<div class='risk-strip'>" + "".join(chips) + "</div>", unsafe_allow_html=True)


# --- Dashboard Tabs ---
tab_findings, tab_overview, tab_osint, tab_diff, tab_export = st.tabs(
    [
        "📋 Ranked Findings & Remediation",
        "📊 Executive Insights & Vectors",
        "🌐 OSINT & Attack Surface",
        "🔄 History & Diff Tracking",
        "📥 Export Reports",
    ]
)


# ==========================================
# TAB 1: Ranked Findings & Remediation Playbook
# ==========================================
with tab_findings:
    st.markdown("### 📋 Prioritized Vulnerabilities & Actionable Fixes")
    st.caption("Issues are ranked in order of defensive urgency using CVSS, exploit probability, and environmental risk.")

    f_col1, f_col2, f_col3 = st.columns([2.5, 1.2, 1])
    with f_col1:
        search_query = st.text_input("🔍 Filter findings", placeholder="Search title, CVE, description, or action...", label_visibility="collapsed")
    with f_col2:
        selected_sev = st.selectbox("Severity Filter", ["All Severities", "Critical", "High", "Medium", "Low", "Info"], label_visibility="collapsed")
    with f_col3:
        sort_by = st.selectbox("Sort", ["Rank (Urgency)", "Severity (High→Low)"], label_visibility="collapsed")

    filtered_findings = []
    q = search_query.strip().lower()
    for f in findings:
        f_sev = str(f.get("severity") or "Info").title()
        if selected_sev != "All Severities" and f_sev != selected_sev:
            continue
        searchable_text = " ".join([
            str(f.get("title") or ""),
            str(f.get("why_it_matters") or ""),
            str(f.get("exploitability") or ""),
            str(f.get("suggested_action") or ""),
            " ".join(f.get("related_cves") or []),
        ]).lower()
        if q and q not in searchable_text:
            continue
        filtered_findings.append(f)

    if sort_by == "Severity (High→Low)":
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        filtered_findings.sort(key=lambda x: sev_order.get(str(x.get("severity") or "Info").title(), 5))
    else:
        filtered_findings.sort(key=lambda x: int(x.get("rank") or 999))

    # Findings Table Overview
    if filtered_findings:
        table_data = []
        for item in filtered_findings:
            table_data.append({
                "Rank": f"#{item.get('rank', '-')}",
                "Severity": str(item.get("severity", "Info")).upper(),
                "Title": item.get("title", "Untitled"),
                "Exploitability / Threat Context": item.get("exploitability", "-"),
                "CVEs": ", ".join(item.get("related_cves") or []) or "None",
                "Source": item.get("source", "configuration"),
            })
        st.dataframe(
            table_data,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Rank": st.column_config.TextColumn(width="small"),
                "Severity": st.column_config.TextColumn(width="small"),
                "Title": st.column_config.TextColumn(width="medium"),
                "Exploitability / Threat Context": st.column_config.TextColumn(width="large"),
                "CVEs": st.column_config.TextColumn(width="small"),
            },
        )
    else:
        st.info("No vulnerabilities match your search query.")

    st.markdown("---")
    st.subheader("🛡️ Detailed Remediation Cards")

    for item in filtered_findings:
        sev = str(item.get("severity") or "Info").title()
        rank = item.get("rank", "?")
        title = item.get("title", "Finding")
        color_map = {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#eab308",
            "Low": "#3b82f6",
            "Info": "#64748b",
        }
        accent = color_map.get(sev, "#64748b")
        
        with st.expander(f"#{rank} • [{sev.upper()}] {title}", expanded=(sev in ["Critical", "High"] and rank == 1)):
            c_info1, c_info2 = st.columns([2, 1])
            with c_info1:
                st.markdown(f"**⚡ Exploitability & Threat:** `{item.get('exploitability', 'Standard exposure')}`")
                st.markdown(f"**🔍 Why It Matters:**\n\n{item.get('why_it_matters', 'No description provided.')}")
            with c_info2:
                st.markdown(f"**🏷️ Discovery Vector:** `{item.get('source', 'config')}`")
                cves = item.get("related_cves") or []
                if cves:
                    st.markdown("**Public CVEs:**")
                    for cve in cves:
                        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
                        st.markdown(f"- [`{cve}`]({nvd_url})")
                else:
                    st.caption("No linked CVE identifiers.")

            action = item.get("suggested_action", "")
            if action:
                st.markdown(
                    f"""
                    <div style="background:rgba(6,78,59,0.25);border:1px solid #10b981;border-radius:8px;padding:12px 16px;margin-top:10px;">
                        <div style="color:#6ee7b7;font-weight:700;font-size:0.9rem;margin-bottom:6px;">
                            🛡️ Recommended Defensive Fix & Configuration
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.markdown(action)


# ==========================================
# TAB 2: Executive Insights & Attack Surface
# ==========================================
with tab_overview:
    st.markdown("### 📊 Executive Summary & Strategic Risk Posture")
    
    col_s1, col_s2 = st.columns([1.8, 1.2])
    with col_s1:
        st.markdown("**Executive Assessment**")
        st.info(report.get("summary") or "No executive summary available.")
        
        top_risks = report.get("top_risks") or []
        if top_risks:
            st.markdown("**🎯 Top Strategic Threats to Mitigate First:**")
            for idx, r in enumerate(top_risks, 1):
                st.markdown(f"**{idx}.** {r}")

    with col_s2:
        st.markdown("**📈 Severity Distribution**")
        chart_data = {
            "Severity": list(severity_counts.keys()),
            "Findings": list(severity_counts.values()),
        }
        st.bar_chart(chart_data, x="Severity", y="Findings", color="Severity")

    st.markdown("---")
    st.markdown("### 🔬 Attack Surface Vector Breakdown")
    v_c1, v_c2, v_c3 = st.columns(3)
    
    config_issues = sum(1 for f in findings if f.get("source") in ["config_issues", "headers", "http_headers"])
    net_issues = sum(1 for f in findings if f.get("source") in ["port_scan", "services", "open_ports"])
    cve_findings = sum(1 for f in findings if f.get("related_cves"))

    with v_c1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">⚙️ Configuration & Headers</div>
                <div class="kpi-value">{config_issues}</div>
                <div class="kpi-sub">Missing CSP, HSTS, X-Frame, Info Leaks</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with v_c2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">🔌 Open Ports & Services</div>
                <div class="kpi-value">{net_issues}</div>
                <div class="kpi-sub">Exposed network service banners</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with v_c3:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">⚠️ Known CVE Vulnerabilities</div>
                <div class="kpi-value">{cve_findings}</div>
                <div class="kpi-sub">Correlated against NVD database</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ==========================================
# TAB 3: OSINT & Attack Surface Intelligence
# ==========================================
with tab_osint:
    st.markdown("### 🌐 Passive Intelligence & Attack Surface Inspector")
    st.caption("Non-intrusive metadata gathered from public DNS, TLS certificates, and Certificate Transparency (crt.sh) logs.")

    assets_loaded = False
    try:
        assets_data = read_json("discovered_assets.json", target=selected_target)
        assets_loaded = True
    except Exception:
        try:
            assets_data = read_json("discovered_assets.json")
            assets_loaded = True
        except Exception:
            assets_data = {}

    if assets_loaded and assets_data:
        passive_meta = assets_data.get("passive_meta") or {}
        o_tab1, o_tab2, o_tab3, o_tab4 = st.tabs(["📧 DNS & Email Security", "🔒 TLS/SSL Certificate", "📜 CT Subdomains", "🔌 Open Ports"])
        
        with o_tab1:
            dns_data = passive_meta.get("dns", {})
            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.markdown("**IP Address Records**")
                st.write(f"- **A Records:** `{', '.join(dns_data.get('A', [])) or 'None'}`")
                st.write(f"- **AAAA (IPv6):** `{', '.join(dns_data.get('AAAA', [])) or 'None'}`")
                st.write(f"- **MX (Mail Servers):** `{', '.join(dns_data.get('MX', [])) or 'None'}`")
            with col_d2:
                st.markdown("**Email Spoofing Defenses**")
                spf = dns_data.get("SPF")
                dmarc = dns_data.get("DMARC")
                st.markdown(f"- **SPF Record:** {'`' + spf + '`' if spf else '❌ **Missing SPF Record (High Spoofing Risk)**'}")
                st.markdown(f"- **DMARC Record:** {'`' + dmarc + '`' if dmarc else '❌ **Missing DMARC Policy (High Phishing Risk)**'}")

        with o_tab2:
            tls_data = passive_meta.get("tls", {})
            if tls_data.get("available"):
                t_col1, t_col2 = st.columns(2)
                with t_col1:
                    st.write(f"**Subject Common Name:** `{tls_data.get('subject')}`")
                    st.write(f"**Certificate Authority:** `{tls_data.get('issuer')}`")
                    st.write(f"**TLS Protocol:** `{tls_data.get('version')}`")
                with t_col2:
                    days = tls_data.get("days_remaining", 0)
                    exp_badge = "🟢 Valid" if days > 30 else "⚠️ Expiring Soon"
                    st.write(f"**Valid Until:** `{tls_data.get('notAfter')}` ({days} days remaining — {exp_badge})")
                    st.write(f"**Self-Signed Certificate:** `{'❌ Yes (Untrusted)' if tls_data.get('self_signed') else '✅ No (Signed CA)'}`")
            else:
                st.info(f"TLS info: {tls_data.get('error', 'Not available for this target or port 443 closed.')}")

        with o_tab3:
            ct_subdomains = passive_meta.get("certificate_transparency", [])
            st.markdown(f"Found **{len(ct_subdomains)}** public subdomains in Certificate Transparency logs (`crt.sh`):")
            if ct_subdomains:
                st.code("\n".join(ct_subdomains), language="text")
                st.caption("ℹ️ Note: Subdomains from public CT logs are mapped for reconnaissance awareness only. Active port scanning requires domain verification.")
            else:
                st.info("No subdomains found in CT logs.")

        with o_tab4:
            ports = assets_data.get("ports", [])
            if ports:
                st.markdown(f"**Discovered Open TCP Ports ({len(ports)}):**")
                port_rows = []
                for p in ports:
                    if isinstance(p, dict):
                        port_rows.append({
                            "Port": p.get("port"),
                            "Service": p.get("service", "unknown"),
                            "Product": p.get("product", "-"),
                            "Version": p.get("version", "-"),
                        })
                    else:
                        port_rows.append({"Port": p, "Service": "open", "Product": "-", "Version": "-"})
                st.dataframe(port_rows, use_container_width=True)
            else:
                st.info("No active open ports logged (or scan run in passive mode).")
    else:
        st.info("Run an active or passive scan to populate deep OSINT asset telemetry.")


# ==========================================
# TAB 4: History & Remediation Diff
# ==========================================
with tab_diff:
    st.markdown("### 🔄 Historical Remediation & Regression Analysis")
    st.caption("Compare security reports over time to verify whether fixes took effect and catch newly introduced risks.")

    if len(history_files) > 1:
        prev_options = [f.name for f in history_files if not (selected_history and f.name == selected_history.name)]
        comp_file = st.selectbox("Select Baseline Comparison Scan:", prev_options, key="baseline_diff_sel")
        
        if comp_file:
            comp_path = next((f for f in history_files if f.name == comp_file), None)
            if comp_path:
                try:
                    baseline_report = json.loads(comp_path.read_text(encoding="utf-8"))
                    diff = diff_reports(report, baseline_report)
                    
                    d_c1, d_c2, d_c3 = st.columns(3)
                    d_c1.metric("🆕 New Vulnerabilities", len(diff["new"]), delta=f"+{len(diff['new'])}" if diff["new"] else "0", delta_color="inverse")
                    d_c2.metric("✅ Remediated Issues", len(diff["resolved"]), delta=f"-{len(diff['resolved'])}" if diff["resolved"] else "0", delta_color="normal")
                    d_c3.metric("🔄 Persisting Issues", len(diff["unchanged"]))

                    dt_new, dt_res, dt_unc = st.tabs(["🆕 New Issues", "✅ Remediated Issues", "🔄 Persisting Issues"])
                    with dt_new:
                        if diff["new"]:
                            for item in diff["new"]:
                                st.error(f"**[NEW]** {item.get('title')} ({item.get('severity')}) — {item.get('exploitability')}")
                        else:
                            st.success("No new vulnerabilities detected since baseline!")
                    with dt_res:
                        if diff["resolved"]:
                            for item in diff["resolved"]:
                                st.success(f"**[RESOLVED]** {item.get('title')} ({item.get('severity')})")
                        else:
                            st.info("No previously open vulnerabilities were resolved in this run.")
                    with dt_unc:
                        if diff["unchanged"]:
                            for item in diff["unchanged"]:
                                st.warning(f"**[PERSISTING]** {item.get('title')} ({item.get('severity')})")
                        else:
                            st.info("No overlapping findings.")
                except Exception as ex:
                    st.error(f"Failed to diff reports: {ex}")
    else:
        st.info("Run multiple assessments over time to generate historical diffs and remediation metrics.")


# ==========================================
# TAB 5: Export & Reports
# ==========================================
with tab_export:
    st.markdown("### 📥 Executive Reports & Data Export")
    st.caption("Download formatted reports for technical stakeholders, compliance teams, or external auditors.")

    exp_col1, exp_col2, exp_col3 = st.columns(3)
    
    with exp_col1:
        st.markdown(
            """
            <div class="kpi-card" style="text-align:center;">
                <div style="font-size:2rem;margin-bottom:0.5rem;">📄</div>
                <div style="font-weight:700;color:#f8fafc;margin-bottom:0.5rem;">HTML Executive Report</div>
                <p style="font-size:0.8rem;color:#94a3b8;margin-bottom:1rem;">Standalone interactive HTML briefing with full finding breakdown</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        html_bytes = generate_html_report(report)
        st.download_button(
            label="Download HTML Briefing",
            data=html_bytes,
            file_name=f"security_assessment_{target}.html",
            mime="text/html",
            use_container_width=True,
            type="primary",
        )

    with exp_col2:
        st.markdown(
            """
            <div class="kpi-card" style="text-align:center;">
                <div style="font-size:2rem;margin-bottom:0.5rem;">📊</div>
                <div style="font-weight:700;color:#f8fafc;margin-bottom:0.5rem;">CSV Findings Matrix</div>
                <p style="font-size:0.8rem;color:#94a3b8;margin-bottom:1rem;">Spreadsheet-ready findings with formula injection protection</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        csv_bytes = generate_csv_report(report)
        st.download_button(
            label="Download CSV Matrix",
            data=csv_bytes,
            file_name=f"security_findings_{target}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with exp_col3:
        st.markdown(
            """
            <div class="kpi-card" style="text-align:center;">
                <div style="font-size:2rem;margin-bottom:0.5rem;">💾</div>
                <div style="font-weight:700;color:#f8fafc;margin-bottom:0.5rem;">Raw JSON Schema</div>
                <p style="font-size:0.8rem;color:#94a3b8;margin-bottom:1rem;">Direct machine-readable JSON for SIEM / CI/CD integration</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        raw_json_str = json.dumps(report, indent=2)
        st.download_button(
            label="Download Raw JSON",
            data=raw_json_str,
            file_name=f"report_{target}.json",
            mime="application/json",
            use_container_width=True,
        )


# --- Pipeline Diagnostic Notes ---
notes = report.get("notes") or []
if notes:
    st.markdown("---")
    with st.expander("ℹ️ AI Engine & Pipeline Diagnostic Telemetry", expanded=False):
        for note in notes:
            st.markdown(f"- `{note}`")
