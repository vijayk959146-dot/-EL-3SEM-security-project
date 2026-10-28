"""
Field Report &mdash; Surface Review.
Restrained, high-density defensive security assessment interface.
"""

from __future__ import annotations

import hmac
import html
import json
import os
import sys
import time as _time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from backend.service import build_scan_request, run_scan
from config import DATA_DIR, DEFAULT_PORTS, DEFAULT_TARGET, get_target_allowlist, is_target_allowed
from storage import diff_reports, list_run_history, read_json
from verification.verify import (
    check_domain_verification,
    generate_verification_token,
    is_domain_verified,
    load_verified_targets,
)
from dashboard.theme import apply_theme
from dashboard.components import esc, render_field_header
from dashboard.sections.summary import render_summary_section
from dashboard.sections.findings import render_findings_section
from dashboard.sections.exposure import render_exposure_section
from dashboard.sections.fixes import render_fixes_section
from dashboard.sections.evidence import render_evidence_section
from dashboard.sections.copilot import render_copilot_panel

# --- 1. Page Configuration ---
st.set_page_config(
    page_title="Surface Review",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Theme selection in sidebar
if "theme_mode" not in st.session_state:
    st.session_state["theme_mode"] = "Light"

theme_choice = st.sidebar.radio(
    "Theme",
    ["Light", "Dark"],
    index=0 if st.session_state["theme_mode"] == "Light" else 1,
    horizontal=True,
    label_visibility="collapsed",
    key="theme_mode_selector",
)
st.session_state["theme_mode"] = theme_choice
apply_theme(theme_choice.lower())

# --- 2. Authentication & Access Guard ---
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
        <div class="report-header">
            <div class="report-header-titles">
                <p class="subtitle">Field Review &mdash; Access Locked</p>
                <h1>Security Assessment Portal</h1>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.error("Dashboard access is locked. Configure DASHBOARD_PASSWORD or set ALLOW_ANONYMOUS_DASHBOARD=true in environment.")
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
            <div class="report-header">
                <div class="report-header-titles">
                    <p class="subtitle">Access Authentication</p>
                    <h1>Surface Review Portal</h1>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        now = _time.monotonic()
        locked = now < st.session_state.lockout_until
        if locked:
            remaining = int(st.session_state.lockout_until - now)
            st.error(f"Too many failed attempts. Locked for {remaining} seconds.")
        else:
            col_l1, col_l2, _ = st.columns([2, 1, 1])
            with col_l1:
                pwd = st.text_input("Access Password", type="password", key="login_pwd_input")
                if st.button("Authenticate", key="login_btn", use_container_width=True):
                    if hmac.compare_digest(pwd.encode("utf-8"), DASHBOARD_PASSWORD.encode("utf-8")):
                        st.session_state.authenticated = True
                        st.session_state.login_attempts = 0
                        st.rerun()
                    else:
                        st.session_state.login_attempts += 1
                        if st.session_state.login_attempts >= _MAX_LOGIN_ATTEMPTS:
                            st.session_state.lockout_until = _time.monotonic() + _LOCKOUT_SECONDS
                            st.error(f"Maximum attempts reached. Locked for {_LOCKOUT_SECONDS}s.")
                        else:
                            rem = _MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
                            st.error(f"Invalid credentials. {rem} attempt(s) remaining.")
        st.stop()


# --- 3. Target Discovery & Workspace Sync ---
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

# Sidebar Brand Heading
st.sidebar.markdown(
    """
    <div style="border-bottom: 1px solid var(--border-hairline); padding-bottom: 12px; margin-bottom: 16px;">
        <h2 style="font-size: 20px; margin: 0; font-family: var(--font-serif); font-weight: 600;">Surface Review</h2>
        <p style="font-size: 12px; color: var(--text-muted); font-family: var(--font-mono); margin: 2px 0 0 0; text-transform: uppercase; letter-spacing: 0.05em;">Attack surface assessment</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if "active_target" not in st.session_state:
    st.session_state["active_target"] = (
        "localhost" if "localhost" in available_targets
        else (available_targets[0] if available_targets else None)
    )

# Process any pending workspace switch BEFORE the selectbox is instantiated
pending = st.session_state.pop("pending_target", None)
if pending:
    st.session_state["active_target"] = pending
    if pending in available_targets:
        st.session_state["target_workspace_select"] = pending

selected_target: str | None = None
if available_targets:
    if st.session_state.get("active_target") not in available_targets:
        st.session_state["active_target"] = available_targets[0]
    if "target_workspace_select" not in st.session_state or \
            st.session_state["target_workspace_select"] not in available_targets:
        st.session_state["target_workspace_select"] = st.session_state["active_target"]
    selected_target = st.sidebar.selectbox(
        "Target Workspace", available_targets, key="target_workspace_select"
    )
    st.session_state["active_target"] = selected_target
else:
    st.sidebar.caption("No target reports detected yet.")


# --- 4. Sidebar: New Scan Launcher ---
with st.sidebar.expander("New scan", expanded=False):
    scan_input_target = st.text_input("Target host or domain", value=selected_target or "localhost", key="scan_input_target")
    scan_ports_input = st.text_input("Ports (Active scan)", value=",".join(str(p) for p in DEFAULT_PORTS), key="scan_ports")
    force_passive = st.checkbox("Force passive OSINT only", value=False, key="scan_passive_cb")

    target_candidate = scan_input_target.strip()
    is_allowed = is_target_allowed(target_candidate)
    is_verified = is_domain_verified(target_candidate)

    if force_passive:
        st.caption("Passive: DNS, TLS, headers and CT logs only. No port probing.")
    elif is_allowed:
        st.caption("Active probing allowed: target is listed in targets.allowlist.")
    elif is_verified:
        st.caption("Active probing allowed: domain ownership confirmed via verification token.")
    else:
        st.caption("Passive: target not allowlisted/verified. Probe will execute in 100% passive OSINT mode.")

    if st.button("Start assessment pipeline", use_container_width=True, type="primary"):
        if not target_candidate:
            st.error("Please specify a target domain or IP.")
        else:
            scan_ok = False
            with st.status("Executing defensive assessment pipeline...") as status:
                try:
                    status.update(label=f"Phase 1/3: Discovery & telemetry on {target_candidate}...")
                    scan_request = build_scan_request(
                        target_candidate,
                        scan_ports_input,
                        force_passive=force_passive,
                        requested_by="field-report-dashboard",
                    )
                    status.update(label="Phase 2/3: Correlation against NVD, KEV, and EPSS...")
                    scan_result = run_scan(scan_request)
                    status.update(label="Phase 3/3: Prioritizing exposures and generating report...")
                    st.session_state["pending_target"] = scan_result.target
                    st.success(
                        f"Assessment complete for {scan_result.target} "
                        f"({scan_result.mode}, {scan_result.finding_count} finding(s))."
                    )
                    scan_ok = True
                except Exception as ex:
                    st.error(f"Scan failed: {ex}")
            if scan_ok:
                _time.sleep(1)
                st.rerun()


# --- 5. Sidebar: Domain Ownership Verification ---
with st.sidebar.expander("Domain ownership verification", expanded=False):
    st.caption("Prove administrative control over a domain to authorize active scans:")
    v_domain = st.text_input("Domain", placeholder="example.com", key="v_dom_input")

    col_v1, col_v2 = st.columns(2)
    with col_v1:
        if st.button("1. Get Token", use_container_width=True):
            if v_domain:
                tok = generate_verification_token(v_domain.strip())
                st.session_state["v_token"] = tok
                st.session_state["v_domain_curr"] = v_domain.strip()
            else:
                st.error("Enter domain.")
    with col_v2:
        if st.button("2. Verify", use_container_width=True):
            if v_domain:
                with st.spinner("Validating DNS TXT and HTTP challenge..."):
                    ok, msg = check_domain_verification(v_domain.strip())
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
            else:
                st.error("Enter domain.")

    if "v_token" in st.session_state and st.session_state.get("v_domain_curr") == v_domain:
        st.markdown(
            f"""
            <div style="background:var(--bg-subtle); border:1px solid var(--border-hairline); padding:8px; margin-top:8px;">
                <div style="font-family:var(--font-mono); font-size:10px; color:var(--text-muted); text-transform:uppercase;">Challenge Token</div>
                <code style="font-size:11px; word-break:break-all;">{esc(st.session_state['v_token'])}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(f"**DNS TXT:** `_attacksurface-verify.{v_domain}`")
        st.markdown(f"**HTTP:** `https://{v_domain}/.well-known/attacksurface-verify.txt`")

    active_verified = load_verified_targets()
    if active_verified:
        st.markdown("---")
        st.caption("Verified Domains (30-Day TTL):")
        for dom, info in active_verified.items():
            st.code(f"{dom} [{info.get('method')}]", language="text")


# --- 6. Load Target Report & Snapshot Timeline ---
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
    history_options = ["Latest Scan (Current)"] + [f.name for f in history_files]
    choice = st.sidebar.selectbox("Historical snapshot", history_options)
    if choice != "Latest Scan (Current)":
        target_path = next((f for f in history_files if f.name == choice), None)
        if target_path:
            try:
                report = json.loads(target_path.read_text(encoding="utf-8"))
                selected_history = target_path
            except Exception:
                pass

# Diff calculation against previous snapshot
diff_data: dict[str, Any] | None = None
if history_files and len(history_files) > 1 and not selected_history:
    try:
        second_latest = history_files[1]
        baseline_report = json.loads(second_latest.read_text(encoding="utf-8"))
        diff_data = diff_reports(report, baseline_report)
    except Exception:
        diff_data = None


# --- 7. Sidebar: 5-Section Navigation ---
SECTIONS = ["Summary", "Findings", "Exposure", "Fixes", "Evidence & reports"]
if "active_section" not in st.session_state:
    st.session_state["active_section"] = "Summary"

# Sync with sidebar radio
current_nav_idx = SECTIONS.index(st.session_state["active_section"]) if st.session_state["active_section"] in SECTIONS else 0

st.sidebar.markdown("---")
st.sidebar.markdown("<div style='font-family:var(--font-mono); font-size:11px; text-transform:uppercase; color:var(--text-subtle); margin-bottom:4px;'>Report Navigation</div>", unsafe_allow_html=True)
nav_selection = st.sidebar.radio(
    "Report Sections",
    SECTIONS,
    index=current_nav_idx,
    label_visibility="collapsed",
    key="nav_radio_selection",
)
st.session_state["active_section"] = nav_selection

# Persistent Copilot Assistant in Sidebar
render_copilot_panel(report, in_sidebar=True)

# Sidebar footer status
st.sidebar.markdown("---")
auth_status_text = "Password Protected" if DASHBOARD_PASSWORD else "Public Access"
st.sidebar.caption(f"Status: {auth_status_text} | Surface Review v2.0")


# --- 8. Empty State Guard ---
if not report or not report.get("findings"):
    st.markdown(
        """
        <div style="border: 1px solid var(--border-hairline); background: var(--bg-surface); padding: 48px 32px; text-align: center; margin: 32px 0;">
            <h2 style="font-family: var(--font-serif); font-size: 24px; margin: 0 0 12px 0;">No assessment report loaded</h2>
            <p style="color: var(--text-muted); max-width: 560px; margin: 0 auto 24px auto; font-size: 14px; line-height: 1.5;">
                Select an existing target from the sidebar, run a scan against localhost, or initiate a passive OSINT assessment on an external domain.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        if st.button("Run instant localhost scan", use_container_width=True, type="primary"):
            with st.spinner("Executing defensive pipeline for localhost..."):
                scan_result = run_scan(build_scan_request("localhost", DEFAULT_PORTS, force_passive=False))
                st.session_state["pending_target"] = scan_result.target
                st.success("Localhost scan complete.")
                _time.sleep(1)
                st.rerun()
    with col_e2:
        if st.button("Run passive OSINT on example.com", use_container_width=True):
            with st.spinner("Gathering passive intelligence for example.com..."):
                scan_result = run_scan(build_scan_request("example.com", DEFAULT_PORTS, force_passive=True))
                st.session_state["pending_target"] = scan_result.target
                st.success("Passive OSINT scan complete.")
                _time.sleep(1)
                st.rerun()
    st.stop()


# --- 9. Load Asset Metadata for Exposure Section ---
assets_data: dict[str, Any] = {}
try:
    assets_data = read_json("discovered_assets.json", target=selected_target)
except Exception:
    try:
        assets_data = read_json("discovered_assets.json")
    except Exception:
        assets_data = {}

target_display = report.get("target") or (selected_target or "localhost")
mode = report.get("mode") or ("active" if is_target_allowed(target_display) or is_domain_verified(target_display) else "passive")
is_active_authorized = is_target_allowed(target_display) or is_domain_verified(target_display)

# --- 10. Document Header ---
render_field_header(target_display, mode, is_active_authorized)


# --- 11. Section Router ---
active_sec = st.session_state["active_section"]

if active_sec == "Summary":
    render_summary_section(report, diff_data=diff_data, history_files=history_files)
elif active_sec == "Findings":
    render_findings_section(report)
elif active_sec == "Exposure":
    render_exposure_section(report, assets_data, theme_mode=theme_choice.lower())
elif active_sec == "Fixes":
    render_fixes_section(report, discovered_ports=assets_data.get("ports", []))
elif active_sec == "Evidence & reports":
    render_evidence_section(report, history_files=history_files, selected_history=selected_history)
