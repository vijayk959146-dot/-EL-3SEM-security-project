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

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#4b5563",
}

st.set_page_config(page_title="AI Attack Surface Correlation", layout="wide", initial_sidebar_state="expanded")

# 1. Optional Password Protection
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()
if DASHBOARD_PASSWORD:
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        st.title("🔒 Security Dashboard Login")
        st.caption("This dashboard is password-protected by the DASHBOARD_PASSWORD environment variable.")
        pwd = st.text_input("Enter Dashboard Password", type="password")
        if st.button("Log In"):
            if pwd == DASHBOARD_PASSWORD:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Incorrect password.")
        st.stop()


def _load_report() -> dict:
    try:
        return read_json("prioritized_report.json")
    except FileNotFoundError:
        return {}


report = _load_report()

# Sidebar: Scan History & Target Selector
st.sidebar.title("🛡️ Project Controls")
history_files = list_run_history()

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
    - **CPE**: Structured identifier for vendor/product/version.
    - **CVSS**: 0–10 score for vulnerability severity.
    - **CISA KEV**: Known Exploited Vulnerabilities in the wild.
    - **EPSS**: Probability (0–100%) of exploitation in 30 days.
    - **SameSite**: Cookie flag mitigating CSRF attacks.
    - **CORS**: Cross-Origin policy controls for API access.
    """)

st.title("AI-Assisted Attack Surface & Vulnerability Correlation")
st.caption("Defensive correlation tool — scans allowlisted targets with passive discovery and threat intelligence.")

if not report:
    st.warning(
        "No prioritized_report.json found yet. From your terminal run: "
        "`python run_pipeline.py --target localhost`"
    )
    st.stop()

findings = report.get("findings") or []
target = report.get("target") or "Unknown"

# Metrics Row
st.subheader("Summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Target Host", target)
c2.metric("Total Findings", len(findings))
c3.metric("AI Prioritization", "Active (Bedrock)" if report.get("used_llm") else "Heuristic Fallback")
c4.metric("Model ID", (report.get("model_id") or "—")[:22])

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
st.write(f"**Executive Summary:** {report.get('summary') or ''}")
top = report.get("top_risks") or []
if top:
    st.markdown("**Top Strategic Risks:**")
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
            prev_report = json.loads((ROOT / "data" / "history" / prev_file).read_text(encoding="utf-8"))
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

# Formatted Table
table_rows = []
for item in findings:
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
st.dataframe(table_rows, use_container_width=True, hide_index=True)

# Detailed Cards
st.subheader("Defensive Remediation Cards")
for item in sorted(findings, key=lambda f: int(f.get("rank") or 0)):
    severity = item.get("severity") or "Info"
    color = SEVERITY_COLORS.get(severity, "#4b5563")
    header = f"#{item.get('rank', '?')} {item.get('title', 'Finding')} [{severity}]"
    
    with st.expander(header):
        st.markdown(
            f"<div style='padding:0.5rem 0.75rem;border-left:5px solid {color};background:#f9fafb;border-radius:4px;'>"
            f"<b>Why It Matters:</b><br>{item.get('why_it_matters', '')}</div>",
            unsafe_allow_html=True,
        )
        st.markdown(f"**Exploitability Context:** `{item.get('exploitability', '')}`")
        st.markdown(f"**Discovery Source:** `{item.get('source', '')}`")
        
        cves = item.get("related_cves") or []
        if cves:
            st.markdown(f"**Related Public CVEs:** `{'`, `'.join(cves)}`")

        action = item.get("suggested_action", "")
        if action:
            st.markdown(
                f"<div style='margin-top:8px;padding:8px 12px;background:#ecfdf5;border:1px solid #a7f3d0;border-radius:4px;'>"
                f"<b style='color:#065f46;'>🛡️ Recommended Defensive Fix:</b><br><code>{action}</code></div>",
                unsafe_allow_html=True,
            )

# Pipeline Notes
notes = report.get("notes") or []
if notes:
    with st.expander("ℹ️ Pipeline Diagnostic Notes"):
        for note in notes:
            st.write(f"- {note}")

