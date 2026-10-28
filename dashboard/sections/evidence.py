"""
Evidence & Reports Section: Regulatory compliance, MITRE ATT&CK alignment,
historical remediation diffs, and SIEM / Webhook exports.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any
import streamlit as st
from dashboard.components import esc
from correlation.compliance import map_compliance
from correlation.mitre_attack import map_findings_to_mitre
from correlation.siem_export import generate_cef_export, generate_ecs_export, send_webhook_alert
from storage import diff_reports, generate_csv_report, generate_html_report


def render_evidence_section(
    report: dict[str, Any],
    history_files: list[Path] | None = None,
    selected_history: Path | None = None,
) -> None:
    """Render compliance tables, MITRE tactics, history diffs, and exports."""
    target = report.get("target") or "Target"
    findings = report.get("findings") or []

    ev_tab_comp, ev_tab_mitre, ev_tab_diff, ev_tab_export = st.tabs(
        ["Regulatory Compliance", "MITRE ATT&CK Matrix", "Historical Drift", "Reports & SIEM Export"]
    )

    # 1. Regulatory Compliance (OWASP & NIST CSF)
    with ev_tab_comp:
        st.markdown("#### Industry Standards & Regulatory Alignment")
        st.caption("Direct evaluation against OWASP Top 10 (2021) categories and NIST Cybersecurity Framework (CSF v2.0).")

        comp_data = map_compliance(findings)
        cat_summary = comp_data.get("categories", {})

        st.markdown(
            f"""
            <div style="display:flex; justify-content:space-between; align-items:center; border:1px solid var(--border-hairline); padding:16px 20px; background:var(--bg-surface); margin-bottom:20px;">
                <div>
                    <div style="font-family:var(--font-mono); font-size:11px; text-transform:uppercase; color:var(--text-muted);">Overall Security Grade</div>
                    <div style="font-size:28px; font-weight:700; font-family:var(--font-serif);">{comp_data['grade']} &mdash; {comp_data['posture']}</div>
                </div>
                <div style="text-align:right;">
                    <div style="font-family:var(--font-mono); font-size:11px; text-transform:uppercase; color:var(--text-muted);">Compliance Score</div>
                    <div style="font-size:24px; font-family:var(--font-mono); font-weight:600;" class="tabular-nums">{comp_data['score']}%</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Plain Table with Text Marks
        table_rows = []
        for cat_id, details in cat_summary.items():
            gaps = details.get("findings_count", 0)
            if gaps == 0:
                mark = '<span class="mark-tag mark-tag-pass">PASS</span>'
                summary_text = "Baseline controls verified; zero active exposures."
            else:
                mark = f'<span class="mark-tag mark-tag-gap">GAP ({gaps})</span>'
                summary_text = f"{gaps} correlated finding(s) require remediation."

            table_rows.append(
                f"""
                <tr>
                    <td class="font-mono">{esc(cat_id)}</td>
                    <td style="font-weight:600;">{esc(details.get('name', ''))}</td>
                    <td>{mark}</td>
                    <td>{esc(details.get('nist_ref', 'NIST CSF PR.DS'))}</td>
                    <td style="font-size:12px; color:var(--text-muted);">{esc(summary_text)}</td>
                </tr>
                """
            )

        st.markdown(
            f"""
            <table class="field-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Standard Category</th>
                        <th>Status</th>
                        <th>NIST Alignment</th>
                        <th>Review Summary</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(table_rows)}
                </tbody>
            </table>
            """,
            unsafe_allow_html=True,
        )

    # 2. MITRE ATT&CK Matrix Alignment
    with ev_tab_mitre:
        st.markdown("#### MITRE ATT&CK Enterprise Mapping")
        st.caption("Discovered vulnerabilities mapped directly to adversary tactics and techniques.")

        mitre_data = map_findings_to_mitre(findings)
        tactics = mitre_data.get("tactics", {})

        if not tactics:
            st.info("No findings mapped to enterprise threat tactics in current assessment scope.")
        else:
            mitre_rows = []
            for t_name, t_info in sorted(tactics.items()):
                t_count = t_info.get("count", 0)
                techs = t_info.get("techniques", [])
                tech_str = ", ".join(f"{t['id']} {t['name']}" for t in techs)

                mitre_rows.append(
                    f"""
                    <tr>
                        <td style="font-weight:600;">{esc(t_name)}</td>
                        <td class="tabular-nums font-mono">{t_count}</td>
                        <td class="font-mono" style="font-size:12px;">{esc(tech_str or 'General Exposure')}</td>
                    </tr>
                    """
                )

            st.markdown(
                f"""
                <table class="field-table">
                    <thead>
                        <tr>
                            <th>Adversary Tactic</th>
                            <th>Correlated Exposures</th>
                            <th>Mapped Techniques</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(mitre_rows)}
                    </tbody>
                </table>
                """,
                unsafe_allow_html=True,
            )

    # 3. Historical Drift & Diff
    with ev_tab_diff:
        st.markdown("#### Historical Drift & Remediation Regression")
        st.caption("Compare the active report against a previous baseline snapshot to verify resolved issues.")

        if history_files and len(history_files) > 1:
            prev_options = [f.name for f in history_files if not (selected_history and f.name == selected_history.name)]
            comp_file = st.selectbox("Select Baseline Snapshot to Compare:", prev_options, key="ev_diff_baseline_sel")

            if comp_file:
                comp_path = next((f for f in history_files if f.name == comp_file), None)
                if comp_path:
                    try:
                        baseline_report = json.loads(comp_path.read_text(encoding="utf-8"))
                        diff = diff_reports(report, baseline_report)

                        d1, d2, d3 = st.columns(3)
                        with d1:
                            st.metric("New Vulnerabilities", len(diff["new"]), delta=f"+{len(diff['new'])}" if diff["new"] else "0", delta_color="inverse")
                        with d2:
                            st.metric("Remediated Issues", len(diff["resolved"]), delta=f"-{len(diff['resolved'])}" if diff["resolved"] else "0", delta_color="normal")
                        with d3:
                            st.metric("Persisting Issues", len(diff["unchanged"]))

                        diff_t1, diff_t2, diff_t3 = st.tabs(["New Issues", "Remediated Issues", "Persisting Issues"])
                        with diff_t1:
                            if diff["new"]:
                                for item in diff["new"]:
                                    st.error(f"[NEW] {item.get('title')} ({item.get('severity')}) &mdash; {item.get('exploitability')}")
                            else:
                                st.success("No newly introduced vulnerabilities detected since baseline.")
                        with diff_t2:
                            if diff["resolved"]:
                                for item in diff["resolved"]:
                                    st.success(f"[RESOLVED] {item.get('title')} ({item.get('severity')})")
                            else:
                                st.info("No prior findings have been marked resolved.")
                        with diff_t3:
                            if diff["unchanged"]:
                                for item in diff["unchanged"]:
                                    st.warning(f"[PERSISTING] {item.get('title')} ({item.get('severity')})")
                            else:
                                st.info("Zero persisting findings.")
                    except Exception as ex:
                        st.error(f"Failed to calculate report diff: {ex}")
        else:
            st.info("Execute additional assessments over time to populate historical diff comparisons.")

    # 4. Exports & SIEM Dispatch
    with ev_tab_export:
        st.markdown("#### Document Exports & SIEM Integration")
        st.caption("Generate executive briefing documents or stream events into security operations log pipelines.")

        # Downloads row
        c_exp1, c_exp2, c_exp3 = st.columns(3)
        with c_exp1:
            html_bytes = generate_html_report(report)
            st.download_button(
                "Download HTML Briefing",
                data=html_bytes,
                file_name=f"surface_review_{target}.html",
                mime="text/html",
                use_container_width=True,
                type="primary",
            )
        with c_exp2:
            csv_bytes = generate_csv_report(report)
            st.download_button(
                "Download CSV Findings Matrix",
                data=csv_bytes,
                file_name=f"findings_{target}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with c_exp3:
            raw_json_str = json.dumps(report, indent=2)
            st.download_button(
                "Download Raw JSON Report",
                data=raw_json_str,
                file_name=f"report_{target}.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown("---")
        st.markdown("##### SIEM Log Formats & Webhooks")
        s_col1, s_col2 = st.columns(2)

        with s_col1:
            st.markdown("**Common Event Format (CEF) / ArcSight / Splunk**")
            cef_data = generate_cef_export(report)
            st.download_button(
                "Download CEF Format",
                data=cef_data,
                file_name=f"findings_{target}.cef",
                mime="text/plain",
                use_container_width=True,
            )

            st.markdown("**Elastic Common Schema (ECS NDJSON)**")
            ecs_data = generate_ecs_export(report)
            st.download_button(
                "Download ECS Format",
                data=ecs_data,
                file_name=f"findings_{target}.ecs.jsonl",
                mime="application/x-ndjson",
                use_container_width=True,
            )

        with s_col2:
            st.markdown("**Webhook Alert Dispatcher**")
            wh_url = st.text_input("Webhook Endpoint URL", placeholder="https://hooks.slack.com/services/...", key="wh_input_url")
            if st.button("Send Assessment Webhook Alert", use_container_width=True):
                if wh_url:
                    with st.spinner("Dispatching webhook notification..."):
                        ok, msg = send_webhook_alert(wh_url.strip(), report)
                        if ok:
                            st.success(msg)
                        else:
                            st.error(msg)
                else:
                    st.error("Please supply a valid HTTPS webhook URL.")
