"""
Summary Section: Field Review Executive Overview.
Includes deterministic verdict, compact figures row (severity stacked bar, mode, date, delta),
and prioritized 'Do These First' action ledger.
"""

from __future__ import annotations

import html
from typing import Any
import streamlit as st
from dashboard.components import esc, generate_verdict_text, render_severity_mark, severity_class


def render_summary_section(
    report: dict[str, Any],
    diff_data: dict[str, Any] | None = None,
    history_files: list[Any] | None = None,
) -> None:
    """Render the executive summary overview."""
    findings = report.get("findings") or []
    target = report.get("target") or "Target"
    mode = str(report.get("mode") or "passive").upper()

    # 1. Deterministic Executive Verdict
    verdict_text = generate_verdict_text(report)
    st.markdown(
        f"""
        <div class="verdict-box">
            <div class="verdict-label">Executive Assessment Verdict</div>
            <p class="verdict-text">{esc(verdict_text)}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Compute Severity Counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        cls = severity_class(f.get("severity", "info"))
        counts[cls] += 1

    total = len(findings)

    # 2. Compact Row of 4 Small Figures
    # A) Stacked bar percentages
    if total > 0:
        crit_pct = (counts["critical"] / total) * 100
        high_pct = (counts["high"] / total) * 100
        med_pct = (counts["medium"] / total) * 100
        low_pct = (counts["low"] / total) * 100
        info_pct = (counts["info"] / total) * 100
    else:
        crit_pct = high_pct = med_pct = low_pct = 0
        info_pct = 100

    stacked_bar_html = f"""
    <div class="stacked-bar-container">
        <div class="stacked-bar-segment" style="width:{crit_pct}%; background:var(--sev-crit);"></div>
        <div class="stacked-bar-segment" style="width:{high_pct}%; background:var(--sev-high);"></div>
        <div class="stacked-bar-segment" style="width:{med_pct}%; background:var(--sev-med);"></div>
        <div class="stacked-bar-segment" style="width:{low_pct}%; background:var(--sev-low);"></div>
        <div class="stacked-bar-segment" style="width:{info_pct}%; background:var(--sev-info);"></div>
    </div>
    """

    # B) Date of run
    date_str = str(report.get("timestamp") or report.get("created_at") or "Current session")
    if "T" in date_str and len(date_str) >= 16:
        try:
            date_str = date_str.replace("T", " ")[:16] + " UTC"
        except Exception:
            pass

    # C) Delta vs previous run
    if diff_data:
        new_cnt = len(diff_data.get("new", []))
        res_cnt = len(diff_data.get("resolved", []))
        delta_str = f"+{new_cnt} new, -{res_cnt} resolved"
        delta_sub = f"{len(diff_data.get('unchanged', []))} persisting"
    elif history_files and len(history_files) > 1:
        delta_str = "Comparison available"
        delta_sub = f"{len(history_files)} snapshots stored"
    else:
        delta_str = "Initial baseline"
        delta_sub = "First logged assessment"

    st.markdown(
        f"""
        <div class="figures-row">
            <div class="figure-cell">
                <div class="figure-label">Findings by Severity</div>
                <div class="figure-val tabular-nums">{total} <span style="font-size:13px;font-weight:400;color:var(--text-muted);">total</span></div>
                {stacked_bar_html}
                <div class="figure-sub tabular-nums">
                    C:{counts['critical']} &middot; H:{counts['high']} &middot; M:{counts['medium']} &middot; L:{counts['low']} &middot; I:{counts['info']}
                </div>
            </div>

            <div class="figure-cell">
                <div class="figure-label">Assessment Mode</div>
                <div class="figure-val" style="font-size:18px;">{esc(mode)}</div>
                <div class="figure-sub">
                    {'Zero-touch passive metadata' if 'PASSIVE' in mode else 'Active authorization confirmed'}
                </div>
            </div>

            <div class="figure-cell">
                <div class="figure-label">Assessment Date</div>
                <div class="figure-val" style="font-size:16px;font-family:var(--font-mono);">{esc(date_str)}</div>
                <div class="figure-sub">Standard report retention</div>
            </div>

            <div class="figure-cell">
                <div class="figure-label">Historical Drift</div>
                <div class="figure-val" style="font-size:16px;">{esc(delta_str)}</div>
                <div class="figure-sub">{esc(delta_sub)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 3. 'Do These First' Action Plan
    st.markdown("### Do these first")
    st.caption("Highest-priority exposures ranked by exploitability and impact.")

    top_3 = findings[:3]
    if not top_3:
        st.info("No actionable findings recorded. Surface conforms to standard configuration.")
        return

    for idx, f in enumerate(top_3):
        rank = f.get("rank", idx + 1)
        title = str(f.get("title", "Untitled finding"))
        sev = str(f.get("severity", "Info"))
        action = str(f.get("suggested_action") or "Review exposure and apply vendor patch.")
        cves = ", ".join(f.get("related_cves") or [])

        sev_mark = render_severity_mark(sev)
        cve_tag = f'<span class="mark-tag font-mono">{esc(cves)}</span>' if cves else ""

        col_act, col_btn = st.columns([5, 1])
        with col_act:
            st.markdown(
                f"""
                <div style="border-bottom: 1px solid var(--border-hairline); padding: 12px 0;">
                    <div style="display:flex; align-items:center; gap: 10px; margin-bottom: 4px;">
                        <span class="font-mono" style="font-size:12px; color:var(--text-muted); font-weight:600;">#{rank}</span>
                        {sev_mark}
                        <strong style="color:var(--text-ink); font-size:15px;">{esc(title)}</strong>
                        {cve_tag}
                    </div>
                    <div style="font-size:13px; color:var(--text-muted); padding-left: 24px;">
                        <span style="font-weight:600; color:var(--accent);">Action:</span> {esc(action)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_btn:
            if st.button("Remediate", key=f"btn_jump_fix_{rank}", use_container_width=True):
                st.session_state["active_section"] = "Fixes"
                st.session_state["selected_fix_finding"] = rank
                st.rerun()
