"""
Copilot Assistant Component.
Persistent 'Ask about this report' panel for sidebar or section footer.
Displays model ID and transparency on LLM vs deterministic heuristic generation.
"""

from __future__ import annotations

import os
from typing import Any
import streamlit as st
from ai.copilot import query_copilot
from dashboard.components import esc


def render_copilot_panel(report: dict[str, Any], in_sidebar: bool = True) -> None:
    """Render the persistent report question-answering assistant."""
    container = st.sidebar if in_sidebar else st

    with container.expander("Ask about this report", expanded=False):
        st.caption("Query security findings, attack chains, or remediation guidance.")

        if "copilot_answer" not in st.session_state:
            st.session_state.copilot_answer = ""
        if "copilot_source" not in st.session_state:
            st.session_state.copilot_source = ""

        # Pre-baked Prompts
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            if st.button("Executive Brief", use_container_width=True, key="cp_btn_exec"):
                st.session_state.copilot_user_input = "Generate a concise executive risk briefing for senior leadership."
            if st.button("Verification Script", use_container_width=True, key="cp_btn_verify"):
                st.session_state.copilot_user_input = "Generate a bash curl script to test and verify these fixes."
        with col_p2:
            if st.button("Top Quick Wins", use_container_width=True, key="cp_btn_wins"):
                st.session_state.copilot_user_input = "What are the top 3 quick-win fixes that provide the highest risk reduction?"
            if st.button("Attack Chains", use_container_width=True, key="cp_btn_chains"):
                st.session_state.copilot_user_input = "How might an attacker chain these discovered exposures together?"

        st.text_area(
            "Question:",
            placeholder="e.g. How do I harden against MIME sniffing on Nginx?",
            key="copilot_user_input",
            height=85,
        )

        MAX_BEDROCK_QUERIES = int(os.getenv("MAX_BEDROCK_QUERIES_PER_SESSION", "20"))
        current_calls = st.session_state.get("bedrock_query_count", 0)
        remaining = max(0, MAX_BEDROCK_QUERIES - current_calls)

        st.caption(f"Session allowance: {remaining}/{MAX_BEDROCK_QUERIES} queries remaining.")

        if st.button("Submit Question", type="primary", use_container_width=True, key="cp_btn_submit"):
            query = str(st.session_state.get("copilot_user_input") or "").strip()
            if not query:
                st.warning("Enter a question or select a prompt first.")
            elif current_calls >= MAX_BEDROCK_QUERIES:
                st.error("Session rate limit reached for cloud AI queries.")
            else:
                st.session_state.bedrock_query_count = current_calls + 1
                with st.spinner("Analyzing report context..."):
                    ans = query_copilot(query, report)
                    st.session_state.copilot_answer = ans
                    
                    # Detect if response came from LLM or heuristic fallback
                    used_llm = report.get("used_llm", False)
                    model_id = report.get("model_id") or os.getenv("BEDROCK_MODEL_ID", "amazon.nova-micro-v1:0")
                    if "Bedrock offline" in ans or "Bedrock unavailable" in ans or "Heuristic" in ans:
                        st.session_state.copilot_source = f"Heuristic rules engine (Offline fallback)"
                    else:
                        st.session_state.copilot_source = f"Amazon Bedrock ({model_id})"

        if st.session_state.copilot_answer:
            st.markdown("---")
            st.markdown(
                f"""
                <div style="font-family:var(--font-mono); font-size:11px; text-transform:uppercase; color:var(--text-subtle); margin-bottom:6px;">
                    Source: {esc(st.session_state.copilot_source or 'Rule engine')}
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.markdown(st.session_state.copilot_answer)
