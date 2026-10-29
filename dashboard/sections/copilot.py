"""
Security Analyst Assistant Component.
Provides on-demand technical Q&A, attack chain explanation, and remediation scripting.
Features both a prominent sidebar popup button and a fixed floating bottom-right popup FAB.
"""

from __future__ import annotations

import os
from typing import Any
import streamlit as st
from ai.copilot import query_copilot
from dashboard.components import esc


def render_copilot_content(report: dict[str, Any], key_suffix: str = "main") -> None:
    """Render the inner interactive chatbot interface."""
    answer_key = f"copilot_answer_{key_suffix}"
    source_key = f"copilot_source_{key_suffix}"
    input_key = f"copilot_input_{key_suffix}"

    if answer_key not in st.session_state:
        st.session_state[answer_key] = ""
    if source_key not in st.session_state:
        st.session_state[source_key] = ""
    if input_key not in st.session_state:
        st.session_state[input_key] = ""

    # Header block
    st.markdown(
        """
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; border-bottom:1px solid var(--border-hairline); padding-bottom:10px;">
            <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-size:20px;">🛡️</span>
                <div>
                    <div style="font-weight:700; font-size:15px; color:var(--text-ink); line-height:1.2;">SecOps AI Copilot</div>
                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">Context-aware defensive analysis & remediation</div>
                </div>
            </div>
            <span class="mark-tag mark-tag-pass" style="font-size:10px; font-weight:700; letter-spacing:0.04em;">● READY</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("Select a quick template or type any technical question about findings:")

    # Quick Prompt Chips (2x2 grid)
    col_p1, col_p2 = st.columns(2)
    trigger_submit = False
    chosen_prompt = None

    with col_p1:
        if st.button("📋 Executive Brief", use_container_width=True, key=f"cp_btn_exec_{key_suffix}"):
            chosen_prompt = "Generate a concise executive risk briefing for engineering leadership."
            trigger_submit = True
        if st.button("🛠️ Verify Script", use_container_width=True, key=f"cp_btn_verify_{key_suffix}"):
            chosen_prompt = "Generate a bash curl script to test and verify these fixes."
            trigger_submit = True

    with col_p2:
        if st.button("⚡ Top Priorities", use_container_width=True, key=f"cp_btn_wins_{key_suffix}"):
            chosen_prompt = "What are the top 3 quick-win fixes providing the highest risk reduction?"
            trigger_submit = True
        if st.button("⛓️ Attack Chains", use_container_width=True, key=f"cp_btn_chains_{key_suffix}"):
            chosen_prompt = "How might an external adversary chain these discovered exposures together?"
            trigger_submit = True

    if chosen_prompt:
        st.session_state[input_key] = chosen_prompt

    query_val = st.text_area(
        "Technical Query:",
        value=st.session_state.get(input_key, ""),
        placeholder="e.g. How do I harden against MIME sniffing on Nginx?",
        key=f"widget_{input_key}",
        height=80,
    )

    # Sync typed value
    st.session_state[input_key] = query_val

    MAX_BEDROCK_QUERIES = int(os.getenv("MAX_BEDROCK_QUERIES_PER_SESSION", "20"))
    current_calls = st.session_state.get("bedrock_query_count", 0)

    col_sub, col_clr = st.columns([3, 1])
    with col_sub:
        submit_clicked = st.button("Ask Copilot", type="primary", use_container_width=True, key=f"cp_btn_sub_{key_suffix}")
    with col_clr:
        if st.button("Clear", use_container_width=True, key=f"cp_btn_clr_{key_suffix}"):
            st.session_state[answer_key] = ""
            st.session_state[input_key] = ""
            st.rerun()

    active_query = chosen_prompt if trigger_submit else (query_val.strip() if submit_clicked else None)

    if active_query:
        if not active_query.strip():
            st.warning("Enter a technical question or select a template above.")
        elif current_calls >= MAX_BEDROCK_QUERIES:
            st.error("Session limit reached for cloud query engine.")
        else:
            st.session_state.bedrock_query_count = current_calls + 1
            with st.spinner("Analyzing target exposures and threat intelligence..."):
                ans = query_copilot(active_query, report)
                st.session_state[answer_key] = ans

                if "Bedrock offline" in ans or "Bedrock unavailable" in ans or "Heuristic" in ans:
                    st.session_state[source_key] = "Deterministic Security Rules Engine"
                else:
                    st.session_state[source_key] = "Amazon Bedrock & Correlation Engine"
                st.rerun()

    # Display Answer
    if st.session_state[answer_key]:
        st.markdown("---")
        st.markdown(
            f"""
            <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--accent); margin-bottom:8px; display:flex; align-items:center; gap:6px;">
                <span>💡</span> {esc(st.session_state[source_key] or 'Security Reasoning Engine')}
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(st.session_state[answer_key])


def render_copilot_panel(report: dict[str, Any], in_sidebar: bool = True) -> None:
    """Render the Copilot as a prominent popup button in the sidebar or inline."""
    container = st.sidebar if in_sidebar else st
    with container.popover("🤖 Ask AI Copilot", help="Open AI Security Analyst Copilot", use_container_width=True):
        render_copilot_content(report, key_suffix="sidebar")


def render_floating_copilot_fab(report: dict[str, Any]) -> None:
    """Render a fixed floating popup button at the bottom-right corner of the screen."""
    with st.popover("🤖 AI Copilot", help="Open AI Security Analyst Copilot", key="floating_copilot_popover"):
        render_copilot_content(report, key_suffix="fab")
