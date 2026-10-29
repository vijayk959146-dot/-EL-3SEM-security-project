"""
Security Analyst Assistant Component.
Provides on-demand technical Q&A, attack chain explanation, and remediation scripting.
"""

from __future__ import annotations

import os
from typing import Any
import streamlit as st
from ai.copilot import query_copilot
from dashboard.components import esc


def render_copilot_panel(report: dict[str, Any], in_sidebar: bool = True) -> None:
    """Render the security analyst Q&A panel."""
    container = st.sidebar if in_sidebar else st

    with container.expander("Security Analyst Query", expanded=False):
        st.caption("Query vulnerability correlations, attack chains, or custom remediation.")

        if "copilot_answer" not in st.session_state:
            st.session_state.copilot_answer = ""
        if "copilot_source" not in st.session_state:
            st.session_state.copilot_source = ""

        # Quick Technical Query Templates
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            if st.button("Executive Brief", use_container_width=True, key="cp_btn_exec"):
                st.session_state.copilot_user_input = "Generate a concise executive risk briefing for engineering leadership."
            if st.button("Verification Script", use_container_width=True, key="cp_btn_verify"):
                st.session_state.copilot_user_input = "Generate a bash curl script to test and verify these fixes."
        with col_p2:
            if st.button("Top Priorities", use_container_width=True, key="cp_btn_wins"):
                st.session_state.copilot_user_input = "What are the top 3 quick-win fixes providing the highest risk reduction?"
            if st.button("Attack Chains", use_container_width=True, key="cp_btn_chains"):
                st.session_state.copilot_user_input = "How might an external adversary chain these discovered exposures together?"

        st.text_area(
            "Query:",
            placeholder="e.g. How do I harden against MIME sniffing on Nginx?",
            key="copilot_user_input",
            height=85,
        )

        MAX_BEDROCK_QUERIES = int(os.getenv("MAX_BEDROCK_QUERIES_PER_SESSION", "20"))
        current_calls = st.session_state.get("bedrock_query_count", 0)

        if st.button("Submit Query", type="primary", use_container_width=True, key="cp_btn_submit"):
            query = str(st.session_state.get("copilot_user_input") or "").strip()
            if not query:
                st.warning("Enter a technical question or select a template first.")
            elif current_calls >= MAX_BEDROCK_QUERIES:
                st.error("Session limit reached for cloud query engine.")
            else:
                st.session_state.bedrock_query_count = current_calls + 1
                with st.spinner("Analyzing attack surface context..."):
                    ans = query_copilot(query, report)
                    st.session_state.copilot_answer = ans
                    
                    if "Bedrock offline" in ans or "Bedrock unavailable" in ans or "Heuristic" in ans:
                        st.session_state.copilot_source = "Deterministic Rules Engine"
                    else:
                        st.session_state.copilot_source = "Knowledge Base & Correlation Engine"

        if st.session_state.copilot_answer:
            st.markdown("---")
            st.markdown(
                f"""
                <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:var(--accent); margin-bottom:6px;">
                    Analysis &bull; {esc(st.session_state.copilot_source or 'Security Rules Engine')}
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(st.session_state.copilot_answer)
