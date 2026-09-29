"""
Streamlit dashboard for the prioritized report and scan history diffs.
Run from repo root: streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from storage import diff_reports, generate_csv_report, generate_html_report, list_run_history, read_json
from verification.verify import check_domain_verification, generate_verification_token, get_verification_record, is_domain_verified, load_verified_targets
from config import get_target_allowlist

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#4b5563",
}

st.set_page_config(page_title="AI Attack Surface Correlation", layout="wide", initial_sidebar_state="expanded")

st.markdown(
    """
    <style>
    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1500px; }
    [data-testid="stMetric"] { background: rgba(255,255,255,0.04); border: 1px solid rgba(148,163,184,0.20); padding: 0.8rem 1rem; border-radius: 8px; }
    [data-testid="stMetricLabel"] { color: #94a3b8; }
    [data-testid="stMetricValue"] { color: #f8fafc; }
    .risk-strip { display:flex; gap:10px; flex-wrap:wrap; margin: 0.5rem 0 1.25rem; }
    .risk-chip { border-radius: 999px; padding: 5px 11px; font-size: 0.82rem; font-weight: 700; border: 1px solid rgba(255,255,255,0.12); }
    .risk-critical { background:#450a0a; color:#fecaca; }
    .risk-high { background:#431407; color:#fed7aa; }
    .risk-medium { background:#451a03; color:#fde68a; }
    .risk-low { background:#172554; color:#bfdbfe; }
    .risk-info { background:#1e293b; color:#cbd5e1; }
    </style>
    """,
    unsafe_allow_html=True,
)

import hmac
import time as _time

# 1. Optional Password Protection
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()
ALLOW_ANONYMOUS_DASHBOARD = os.getenv("ALLOW_ANONYMOUS_DASHBOARD", "false").strip().lower() in {
    "1",
    "true",
    "yes",
}
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 30

if not DASHBOARD_PASSWORD and not ALLOW_ANONYMOUS_DASHBOARD:
    st.title("Security Assessment Dashboard")
    st.caption("Private defensive reporting workspace")
    st.error("Dashboard access is currently locked.")
    st.info("An administrator must configure DASHBOARD_PASSWORD in the deployment environment before reports can be viewed.")
    st.stop()

if DASHBOARD_PASSWORD:
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "login_attempts" not in st.session_state:
        st.session_state.login_attempts = 0
    if "lockout_until" not in st.session_state:
        st.session_state.lockout_until = 0.0

    if not st.session_state.authenticated:
        st.title("Security Assessment Dashboard")
        st.caption("Sign in to view authorized scan reports and remediation guidance.")

        now = _time.monotonic()
        locked = now < st.session_state.lockout_until
        if locked:
            remaining = int(st.session_state.lockout_until - now)
            st.error(f"Too many failed attempts. Try again in {remaining} seconds.")
        else:
            pwd = st.text_input("Enter Dashboard Password", type="password", key="login_pwd_input")
            if st.button("Log In", key="login_btn"):
                # constant-time comparison — immune to timing oracle attacks
                if hmac.compare_digest(pwd.encode("utf-8"), DASHBOARD_PASSWORD.encode("utf-8")):
                    st.session_state.authenticated = True
                    st.session_state.login_attempts = 0
                    st.rerun()
                else:
                    st.session_state.login_attempts += 1
                    if st.session_state.login_attempts >= _MAX_LOGIN_ATTEMPTS:
                        st.session_state.lockout_until = _time.monotonic() + _LOCKOUT_SECONDS
                        st.error(f"Too many failed attempts. Locked for {_LOCKOUT_SECONDS} seconds.")
                    else:
                        remaining_attempts = _MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
                        st.error(f"Incorrect password. {remaining_attempts} attempt(s) remaining.")
        st.stop()



from config import DATA_DIR


def _discover_available_targets() -> list[str]:
    """Find all scan targets with stored reports in data/<target>/."""
    targets: list[str] = []
    if DATA_DIR.exists():
        for item in DATA_DIR.iterdir():
            if item.is_dir() and item.name not in {"cache", "history", "scratch"}:
                if (item / "prioritized_report.json").exists() or (item / "history").exists():
                    targets.append(item.name)
    return sorted(targets)


available_targets = _discover_available_targets()

# Sidebar: Scan History & Target Selector
st.sidebar.title("🛡️ Project Controls")

selected_target: str | None = None
if available_targets:
    selected_target = st.sidebar.selectbox("🎯 Target Selector", available_targets, index=0)


def _load_report(target: str | None = None) -> dict:
    try:
        return read_json("prioritized_report.json", target=target)
    except FileNotFoundError:
        try:
            return read_json("prioritized_report.json")
        except FileNotFoundError:
            return {}


report = _load_report(selected_target)

# Domain Verification Panel in Sidebar
with st.sidebar.expander("🔑 Domain Ownership Verification", expanded=False):
    st.markdown("Prove control of a domain to authorize active scans:")
    v_domain = st.text_input("Target Domain", placeholder="example.com", key="v_dom_input")
    
    col_v1, col_v2 = st.columns(2)
    with col_v1:
        if st.button("1. Start / Token", use_container_width=True):
            if v_domain:
                tok = generate_verification_token(v_domain.strip())
                st.session_state["v_token"] = tok
                st.session_state["v_domain_curr"] = v_domain.strip()
            else:
                st.error("Enter a domain name.")
    with col_v2:
        if st.button("2. Verify Now", use_container_width=True):
            if v_domain:
                with st.spinner("Checking DNS & HTTP endpoints..."):
                    ok, msg = check_domain_verification(v_domain.strip())
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
            else:
                st.error("Enter a domain name.")

    if "v_token" in st.session_state and st.session_state.get("v_domain_curr") == v_domain:
        st.info(f"**Verification Token:** `{st.session_state['v_token']}`")
        st.markdown(f"**Method A: DNS TXT Record**\n- Name: `_attacksurface-verify.{v_domain}`\n- Value: `{st.session_state['v_token']}`")
        st.markdown(f"**Method B: HTTP Endpoint**\n- URL: `https://{v_domain}/.well-known/attacksurface-verify.txt`\n- File Body: `{st.session_state['v_token']}`")

    # List active verified domains
    active_verified = load_verified_targets()
    if active_verified:
        st.markdown("---")
        st.caption("Currently Verified Targets (30-Day Expiry):")
        for dom, info in active_verified.items():
            st.code(f"{dom} ({info.get('method')}) until {info.get('expires_at', '')[:10]}", language="text")

history_files = list_run_history(target=selected_target)

st.sidebar.subheader("Scan History & Diffs")
selected_history = None
if history_files:
    history_options = ["Latest Scan (prioritized_report.json)"] + [f.name for f in history_files]
    choice = st.sidebar.selectbox("Select Report to View", history_options)
    if choice != "Latest Scan (prioritized_report.json)":
        target_path = next(f for f in history_files if f.name == choice)
        try:
            report = json.loads(target_path.read_text(encoding="utf-8"))
            selected_history = target_path
        except Exception:
            pass

# Sidebar: Educational Terms for 3rd Sem Students
with st.sidebar.expander("📚 Security Terms Glossary"):
    st.markdown("""
    - **SSRF**: Server-Side Request Forgery — tricking servers into fetching internal/private network assets.
    - **DNS Rebinding**: Attacking resolved IPs by altering DNS responses between check and connect.
    - **CT Logs**: Certificate Transparency logs recording public TLS certificates.
    - **SPF / DMARC**: DNS records defining authorized email senders to prevent domain spoofing.
    - **CPE**: Structured identifier for vendor/product/version.
    - **CVSS**: 0–10 score for vulnerability severity.
    - **CISA KEV**: Known Exploited Vulnerabilities in the wild.
    - **EPSS**: Probability (0–100%) of exploitation in 30 days.
    """)

st.title("Security Assessment Dashboard")
st.caption("AI-assisted attack-surface discovery and defensive vulnerability prioritization")

if not report:
    st.info("This dashboard is ready, but no assessment report has been loaded yet.")
    st.subheader("Next step")
    st.markdown(
        "Run an authorized assessment from the project environment, then reload this page. "
        "The dashboard will automatically show the generated findings."
    )
    st.code(
        "python run_pipeline.py --target example.com --passive-only\n"
        "# or, for an authorized local lab target:\n"
        "python run_pipeline.py --target localhost",
        language="bash",
    )
    st.caption("Reports are loaded from data/<target>/prioritized_report.json.")
    st.stop()

findings = report.get("findings") or []
target = report.get("target") or "Unknown"
mode = report.get("mode") or ("active" if target in get_target_allowlist() or is_domain_verified(target) else "passive")

severity_counts = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Info")}
for finding in findings:
    severity = str(finding.get("severity") or "Info").title()
    severity_counts[severity if severity in severity_counts else "Info"] += 1
high_risk_count = severity_counts["Critical"] + severity_counts["High"]
related_cve_count = len({cve for finding in findings for cve in (finding.get("related_cves") or [])})

# Mode Badge
import html

if target in get_target_allowlist():
    mode_badge = "🧪 Local Lab (Active Probing Allowed)"
    badge_color = "#3b82f6"
elif is_domain_verified(target) or mode == "active":
    mode_badge = "🛡️ Verified Active (Authorized Active Scans Allowed)"
    badge_color = "#10b981"
else:
    mode_badge = "🌐 Passive OSINT (Read-Only, Zero Active Probing)"
    badge_color = "#8b5cf6"

esc_mode_badge = html.escape(str(mode_badge), quote=True)
st.markdown(
    f"<div style='display:inline-block;padding:4px 12px;border-radius:16px;background:{badge_color};color:white;font-weight:600;font-size:0.9rem;margin-bottom:12px;'>"
    f"{esc_mode_badge}</div>",
    unsafe_allow_html=True,
)

if mode == "passive" or mode == "passive-osint":
    st.info(
        "ℹ️ **Passive OSINT Mode Active**: Ports, services, and local paths were **not actively scanned** against this unverified target. "
        "Findings are gathered solely from public DNS, TLS certificates, HTTP root headers, and public Certificate Transparency records. "
        "Subdomains from Certificate Transparency logs are listed for awareness only and are not scanned."
    )

# Security overview
st.subheader("Security Overview")
overview_cols = st.columns(5)
overview_cols[0].metric("Target", target)
overview_cols[1].metric("Total Findings", len(findings))
overview_cols[2].metric("Critical + High", high_risk_count)
overview_cols[3].metric("Related CVEs", related_cve_count)
overview_cols[4].metric("Prioritization", "AI" if report.get("used_llm") else "Heuristic")

chips = []
for severity, css_name in (("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low"), ("Info", "info")):
    chips.append(f"<span class='risk-chip risk-{css_name}'>{severity}: {severity_counts[severity]}</span>")
st.markdown("<div class='risk-strip'>" + "".join(chips) + "</div>", unsafe_allow_html=True)

with st.expander("How to read this assessment", expanded=False):
    st.markdown(
        "**Critical/High** findings deserve attention first. **Related CVEs** are public vulnerability identifiers "
        "linked to detected software or configuration evidence. This report is an assessment aid, not proof that a "
        "target is exploitable. Only scan systems you own or are authorized to test."
    )

# Export Buttons
col_exp1, col_exp2, _ = st.columns([1.5, 2, 4])
with col_exp1:
    csv_data = generate_csv_report(report)
    st.download_button(
        label="📥 Export Findings (CSV)",
        data=csv_data,
        file_name=f"security_report_{target}.csv",
        mime="text/csv",
        use_container_width=True,
    )
with col_exp2:
    html_data = generate_html_report(report)
    st.download_button(
        label="📄 Download HTML Report",
        data=html_data,
        file_name=f"security_report_{target}.html",
        mime="text/html",
        use_container_width=True,
    )

st.markdown("---")

# Executive Summary & Top Risks
st.subheader("Executive Summary")
st.info(report.get("summary") or "No executive summary was generated for this scan.")
top = report.get("top_risks") or []
if top:
    st.markdown("**Top Strategic Risks**")
    for i, risk in enumerate(top, start=1):
        st.write(f"{i}. {risk}")

# History Diff Section
if len(history_files) > 1:
    with st.expander("🔄 Scan History & Diff Analysis", expanded=False):
        st.write("Compare the current report against a previous historical run to track remediation progress:")
        prev_file = st.selectbox(
            "Baseline comparison run:",
            [f.name for f in history_files if not (selected_history and f.name == selected_history.name)],
            key="diff_selector",
        )
        if prev_file:
            prev_path = next((f for f in history_files if f.name == prev_file), None)
            if prev_path:
                prev_report = json.loads(prev_path.read_text(encoding="utf-8"))
                diff = diff_reports(report, prev_report)
            
            d1, d2, d3 = st.columns(3)
            d1.metric("🆕 New Issues", len(diff["new"]), delta=f"+{len(diff['new'])}" if diff["new"] else None, delta_color="inverse")
            d2.metric("✅ Resolved Issues", len(diff["resolved"]), delta=f"-{len(diff['resolved'])}" if diff["resolved"] else None, delta_color="normal")
            d3.metric("🔄 Unchanged Issues", len(diff["unchanged"]))

            tab_new, tab_resolved, tab_unchanged = st.tabs(["New Findings", "Resolved Findings", "Unchanged Findings"])
            with tab_new:
                for item in diff["new"]:
                    st.warning(f"**[NEW]** {item.get('title')} ({item.get('severity')}) — {item.get('exploitability')}")
            with tab_resolved:
                for item in diff["resolved"]:
                    st.success(f"**[RESOLVED]** {item.get('title')} ({item.get('severity')})")
            with tab_unchanged:
                for item in diff["unchanged"]:
                    st.info(f"**[PERSISTING]** {item.get('title')} ({item.get('severity')})")

st.markdown("---")

# Ranked Findings Table & Detailed Breakdown
st.subheader("Ranked Findings")
st.caption("Use the filters to focus on the issues that need action first.")

filter_col1, filter_col2 = st.columns([2, 1])
with filter_col1:
    finding_search = st.text_input("Search findings", placeholder="Search by title, CVE, source, or exploitability", label_visibility="collapsed")
with filter_col2:
    severity_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low", "Info"], label_visibility="collapsed")

filtered_findings = []
search_term = finding_search.strip().lower()
for item in findings:
    searchable = " ".join(
        str(item.get(key) or "") for key in ("title", "severity", "exploitability", "source", "why_it_matters")
    ).lower() + " " + " ".join(str(cve) for cve in (item.get("related_cves") or [])).lower()
    if severity_filter != "All" and str(item.get("severity") or "Info").title() != severity_filter:
        continue
    if search_term and search_term not in searchable:
        continue
    filtered_findings.append(item)

# Formatted Table
table_rows = []
for item in filtered_findings:
    exploit_str = item.get("exploitability") or ""
    table_rows.append(
        {
            "Rank": item.get("rank"),
            "Severity": item.get("severity"),
            "Title": item.get("title"),
            "Exploitability / Intelligence": exploit_str,
            "CVEs": ", ".join(item.get("related_cves") or []),
            "Source": item.get("source") or "config",
        }
    )
if table_rows:
    st.dataframe(table_rows, use_container_width=True, hide_index=True, column_config={
        "Rank": st.column_config.NumberColumn(width="small"),
        "Severity": st.column_config.TextColumn(width="small"),
        "Title": st.column_config.TextColumn(width="large"),
        "CVEs": st.column_config.TextColumn(width="medium"),
    })
else:
    st.success("No findings match the current filters.")

# Detailed Cards using native Streamlit widgets (no raw HTML injection)
st.subheader("Defensive Remediation Cards")
for item in sorted(filtered_findings, key=lambda f: int(f.get("rank") or 0)):
    severity = item.get("severity") or "Info"
    header = f"#{item.get('rank', '?')} {item.get('title', 'Finding')} [{severity}]"
    
    with st.expander(header):
        st.markdown(f"**Why It Matters:**\n\n{item.get('why_it_matters', '')}")
        st.markdown(f"**Exploitability Context:** `{item.get('exploitability', '')}`")
        st.markdown(f"**Discovery Source:** `{item.get('source', '')}`")
        
        cves = item.get("related_cves") or []
        if cves:
            st.markdown(f"**Related Public CVEs:** `{'`, `'.join(cves)}`")

        action = item.get("suggested_action", "")
        if action:
            st.info(f"🛡️ **Recommended Defensive Fix:**\n\n`{action}`")

if not findings:
    st.success("No prioritized vulnerabilities were found in this report.")

# Pipeline Notes
notes = report.get("notes") or []
if notes:
    with st.expander("ℹ️ Pipeline Diagnostic Notes"):
        for note in notes:
            st.write(f"- {note}")

# Passive OSINT Details (DNS, TLS, Certificate Transparency)
try:
    assets_data = read_json("discovered_assets.json")
    passive_meta = assets_data.get("passive_meta") or {}
    if passive_meta:
        with st.expander("🌐 Passive Intelligence Inspector (DNS, TLS, CT Logs)", expanded=False):
            st.caption("OSINT data gathered without active port probing. Subdomains are for inventory awareness only and are not scanned.")
            p_tab1, p_tab2, p_tab3 = st.tabs(["DNS & Email Security", "TLS Certificate", "Certificate Transparency Logs"])
            
            with p_tab1:
                dns_data = passive_meta.get("dns", {})
                st.write(f"**A Records:** `{', '.join(dns_data.get('A', [])) or 'None'}`")
                st.write(f"**AAAA Records:** `{', '.join(dns_data.get('AAAA', [])) or 'None'}`")
                st.write(f"**MX Records:** `{', '.join(dns_data.get('MX', [])) or 'None'}`")
                st.write(f"**SPF Record:** `{dns_data.get('SPF') or 'Missing'}`")
                st.write(f"**DMARC Record:** `{dns_data.get('DMARC') or 'Missing'}`")
            
            with p_tab2:
                tls_data = passive_meta.get("tls", {})
                if tls_data.get("available"):
                    st.write(f"**Subject:** `{tls_data.get('subject')}`")
                    st.write(f"**Issuer:** `{tls_data.get('issuer')}`")
                    st.write(f"**Protocol Version:** `{tls_data.get('version')}`")
                    st.write(f"**Valid Until:** `{tls_data.get('notAfter')}` ({tls_data.get('days_remaining')} days remaining)")
                    st.write(f"**Self-Signed:** `{'Yes (Untrusted)' if tls_data.get('self_signed') else 'No (Valid CA)'}`")
                else:
                    st.write(f"TLS info: {tls_data.get('error', 'Not available')}")
            
            with p_tab3:
                ct_subdomains = passive_meta.get("certificate_transparency", [])
                st.write(f"Found **{len(ct_subdomains)}** unique subdomains in public Certificate Transparency logs (`crt.sh`):")
                if ct_subdomains:
                    st.code("\n".join(ct_subdomains), language="text")
                    st.caption("⚠️ Note: Subdomains from CT logs require individual authorization and ownership verification before active scanning.")
except Exception:
    pass


