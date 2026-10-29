"""
Findings Section: Vulnerability & Exposure Ledger.
Table-like finding inventory with inline expansion, severity badges,
and direct remediation routing.
"""

from __future__ import annotations

import html
from typing import Any
import streamlit as st
from dashboard.components import esc, render_severity_mark, severity_class
from correlation.mitre_attack import map_findings_to_mitre
from correlation.compliance import map_compliance


def render_findings_section(report: dict[str, Any]) -> None:
    """Render the vulnerability and exposure ledger."""
    raw_findings = report.get("findings") or []
    target = report.get("target") or "Target"

    if not raw_findings:
        st.markdown(
            """
            <div style="border:1px solid var(--border-hairline); border-radius:var(--radius-md); padding:32px; text-align:center; background:var(--bg-surface); margin:24px 0;">
                <p style="font-size:16px; font-weight:600; margin-bottom:8px; color:var(--text-ink);">
                    No security exposures identified
                </p>
                <p style="font-size:13px; color:var(--text-muted); margin:0;">
                    Execute an active probe or passive OSINT scan to inspect attack surface exposures.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Compute correlation mappings for finding details
    mitre_data = map_findings_to_mitre(raw_findings)
    mitre_mapping = mitre_data.get("findings_mapping", {})
    comp_data = map_compliance(raw_findings)
    cat_summary = comp_data.get("categories", {})

    st.markdown("### Vulnerability & Exposure Ledger")
    st.caption("Prioritized inventory of confirmed security findings, transport weaknesses, and CVE correlations.")

    # 1. Filters & Sort Controls
    f_col1, f_col2, f_col3, f_col4 = st.columns([3, 2, 2, 2])

    with f_col1:
        search_query = st.text_input(
            "Search",
            placeholder="Search title, CVE, service, or action...",
            label_visibility="collapsed",
            key="ledger_search_input",
        ).strip().lower()

    with f_col2:
        sev_filter = st.multiselect(
            "Filter Severity",
            ["Critical", "High", "Medium", "Low", "Info"],
            default=[],
            placeholder="All Severities",
            label_visibility="collapsed",
            key="ledger_sev_filter",
        )

    with f_col3:
        all_sources = sorted(list({str(f.get("source", "nvd")).lower() for f in raw_findings}))
        source_options = ["All Sources"] + all_sources
        source_choice = st.selectbox(
            "Source",
            source_options,
            label_visibility="collapsed",
            key="ledger_source_sel",
        )

    with f_col4:
        sort_choice = st.selectbox(
            "Sort by",
            ["Rank (Priority)", "Severity (High to Low)", "Exploitability"],
            label_visibility="collapsed",
            key="ledger_sort_sel",
        )

    # 2. Filter Logic
    filtered: list[dict[str, Any]] = []
    for f in raw_findings:
        sev_label = str(f.get("severity", "Info")).capitalize()
        source_name = str(f.get("source", "nvd")).lower()
        title_text = str(f.get("title", "")).lower()
        cves_text = " ".join(f.get("related_cves") or []).lower()
        why_text = str(f.get("why_it_matters", "")).lower()

        if sev_filter and sev_label not in sev_filter:
            continue

        if source_choice != "All Sources" and source_name != source_choice.lower():
            continue

        if search_query:
            query_match = (
                search_query in title_text
                or search_query in cves_text
                or search_query in why_text
                or search_query in source_name
            )
            if not query_match:
                continue

        filtered.append(f)

    # 3. Sort Logic
    sev_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    if sort_choice == "Severity (High to Low)":
        filtered.sort(
            key=lambda x: sev_weights.get(str(x.get("severity", "Info")).capitalize(), 0),
            reverse=True,
        )
    elif sort_choice == "Exploitability":
        filtered.sort(
            key=lambda x: 1 if "kev" in str(x.get("exploitability", "")).lower() else 0,
            reverse=True,
        )
    else:
        filtered.sort(key=lambda x: int(x.get("rank") or 999))

    st.markdown(
        f"<div style='font-size:12px; font-weight:500; color:var(--text-subtle); margin:12px 0 8px 0;'>"
        f"Showing {len(filtered)} of {len(raw_findings)} findings"
        f"</div>",
        unsafe_allow_html=True,
    )

    if not filtered:
        st.markdown(
            """
            <div style="border:1px solid var(--border-hairline); border-radius:var(--radius-md); padding:24px; text-align:center; background:var(--bg-surface);">
                <p style="font-size:14px; color:var(--text-muted); margin:0;">
                    No findings match the selected filter criteria.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # 4. Dense Triage Ledger Rows
    for idx, f in enumerate(filtered):
        rank = f.get("rank", idx + 1)
        sev = str(f.get("severity", "Info")).capitalize()
        title = str(f.get("title", "Untitled finding"))
        cves = f.get("related_cves") or []
        cve_str = ", ".join(cves) if cves else "No CVE"
        exploit = str(f.get("exploitability") or "Standard")
        source = str(f.get("source") or "nvd")
        why = str(f.get("why_it_matters") or "Configuration increases target attack surface exposure.")
        action = str(f.get("suggested_action") or "Apply hardening configuration or security updates.")

        # Finding summary header string for expander
        expander_title = f"#{rank}  [{sev.upper()}]  {title}  ·  {cve_str}  ·  {exploit}"

        with st.expander(expander_title, expanded=False):
            c1, c2 = st.columns([3, 1])
            with c1:
                st.markdown(
                    f"""
                    <div style="font-size:13px; margin-bottom:12px;">
                        <div style="font-weight:600; color:var(--text-ink); margin-bottom:4px;">Threat & Exploit Analysis:</div>
                        <div style="color:var(--text-muted); line-height:1.5;">{esc(why)}</div>
                    </div>
                    <div style="font-size:13px; margin-bottom:14px;">
                        <div style="font-weight:600; color:var(--text-ink); margin-bottom:4px;">Recommended Remediation:</div>
                        <div style="color:var(--text-ink); line-height:1.5; font-weight:500;">{esc(action)}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # CVE Links
                if cves:
                    cve_links = []
                    for c in cves:
                        cve_links.append(f'<a href="https://nvd.nist.gov/vuln/detail/{esc(c)}" target="_blank" style="color:var(--accent); text-decoration:none; font-family:var(--font-mono); font-size:12px; margin-right:8px; font-weight:500;">{esc(c)} &nearr;</a>')
                    st.markdown("<div>" + "".join(cve_links) + "</div>", unsafe_allow_html=True)

                # Regulatory & Threat tags
                tags = []
                m_info = mitre_mapping.get(f.get("id")) or mitre_mapping.get(title)
                if m_info:
                    tags.append(f'<span class="mark-tag font-mono">MITRE: {esc(m_info.get("technique_id"))} {esc(m_info.get("technique_name"))}</span>')
                tags.append(f'<span class="mark-tag font-mono">SOURCE: {esc(source.upper())}</span>')
                tags.append(f'<span class="mark-tag font-mono">EXPLOIT: {esc(exploit.upper())}</span>')

                st.markdown(
                    "<div style='display:flex; gap:6px; flex-wrap:wrap; margin-top:12px;'>"
                    + "".join(tags)
                    + "</div>",
                    unsafe_allow_html=True,
                )

            with c2:
                st.markdown(
                    f"""
                    <div style="border-left:1px solid var(--border-hairline); padding-left:16px;">
                        <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--text-subtle); margin-bottom:6px;">Finding Metadata</div>
                        <div style="font-size:12px; margin-bottom:4px;">Rank: <strong>#{rank}</strong></div>
                        <div style="font-size:12px; margin-bottom:4px;">Severity: <strong>{esc(sev)}</strong></div>
                        <div style="font-size:12px; margin-bottom:12px;">Origin: <strong>{esc(source.upper())}</strong></div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if st.button("Show fix", key=f"btn_ledger_fix_{rank}", use_container_width=True):
                    st.session_state["active_section"] = "Fixes"
                    st.session_state["selected_fix_finding"] = rank
                    st.rerun()
