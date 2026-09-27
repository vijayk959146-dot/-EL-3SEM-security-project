"""Streamlit dashboard for the prioritized report. Run from the repo root."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from storage import read_json

SEVERITY_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#b91c1c",
    "Medium": "#c2410c",
    "Low": "#a16207",
    "Info": "#334155",
}


def _load_report() -> dict:
    try:
        return read_json("prioritized_report.json")
    except FileNotFoundError:
        return {}


st.set_page_config(page_title="Attack Surface Correlation", layout="wide")
st.title("AI-Assisted Attack Surface & Vulnerability Correlation")
st.caption("Lab use only — scans hosts listed in targets.allowlist (default: localhost).")

report = _load_report()
if not report:
    st.warning(
        "No prioritized_report.json yet. From the repo root run: "
        "`python run_pipeline.py --target localhost`"
    )
    st.stop()

findings = report.get("findings") or []
st.subheader("Summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Target", report.get("target") or "—")
c2.metric("Findings", len(findings))
c3.metric("LLM used", "Yes" if report.get("used_llm") else "No (fallback)")
c4.metric("Model", (report.get("model_id") or "—")[:28])

st.write(report.get("summary") or "")
top = report.get("top_risks") or []
if top:
    st.markdown("**Top risks**")
    for i, risk in enumerate(top, start=1):
        st.write(f"{i}. {risk}")

st.subheader("Ranked findings")
rows = []
for item in findings:
    rows.append(
        {
            "Rank": item.get("rank"),
            "Severity": item.get("severity"),
            "Title": item.get("title"),
            "Exploitability": item.get("exploitability"),
            "CVEs": ", ".join(item.get("related_cves") or []),
        }
    )
st.dataframe(rows, use_container_width=True, hide_index=True)

for item in sorted(findings, key=lambda f: int(f.get("rank") or 0)):
    severity = item.get("severity") or "Info"
    color = SEVERITY_COLORS.get(severity, "#334155")
    header = f"{item.get('rank', '?')}. {item.get('title', 'Finding')} — {severity}"
    with st.expander(header):
        st.markdown(
            f"<div style='padding:0.25rem 0.5rem;border-left:4px solid {color}'>"
            f"<b>Why it matters</b><br>{item.get('why_it_matters', '')}</div>",
            unsafe_allow_html=True,
        )
        st.markdown(f"**Suggested action (defensive):** {item.get('suggested_action', '')}")
        st.markdown(f"**Source:** {item.get('source', '')}")
        cves = item.get("related_cves") or []
        if cves:
            st.markdown("**Related public CVEs:** " + ", ".join(cves))

notes = report.get("notes") or []
if notes:
    with st.expander("Pipeline notes"):
        for note in notes:
            st.write(f"- {note}")
