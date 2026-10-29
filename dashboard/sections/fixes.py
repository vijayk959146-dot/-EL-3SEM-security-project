"""
Fixes Section: Remediation Engineering, Edge WAF Shield, and Inline Patch Simulation.
Generates copy-paste configuration files and previews posture improvement.
"""

from __future__ import annotations

import html
from typing import Any
import streamlit as st
from dashboard.components import esc, render_severity_mark
from remediation.code_gen import (
    generate_nginx_hardening,
    generate_apache_hardening,
    generate_caddy_hardening,
    generate_cloudflare_rules,
    generate_node_helmet,
    generate_dns_hardening,
    generate_firewall_rules,
)
from remediation.waf_rules import (
    generate_aws_waf_json,
    generate_cloudflare_waf_rules,
    generate_modsecurity_rules,
)


def render_fixes_section(
    report: dict[str, Any],
    discovered_ports: list[Any] | None = None,
) -> None:
    """Render the remediation and WAF rule generators with inline simulation."""
    target = report.get("target") or "Target"
    findings = report.get("findings") or []

    st.markdown("### Remediation & Protective Controls")
    st.caption("Production server configurations, edge WAF shield rules, and posture impact simulations.")

    if not findings:
        st.info("No active findings requiring remediation.")
        return

    # Check if a specific finding was selected from Triage Ledger
    selected_rank = st.session_state.get("selected_fix_finding")
    matched_finding = None
    if selected_rank:
        matched_finding = next((f for f in findings if f.get("rank") == selected_rank), None)

    # 1. Scope Selector
    if matched_finding:
        st.markdown(
            f"""
            <div style="border:1px solid var(--border-hairline); border-left:4px solid var(--accent); border-radius:var(--radius-md); background:var(--bg-surface); padding:14px 18px; margin-bottom:16px; box-shadow:var(--shadow-sm);">
                <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--accent);">Scoped to Selected Finding</div>
                <div style="font-weight:600; font-size:15px; margin-top:2px; color:var(--text-ink);">#{matched_finding.get('rank')} &mdash; {esc(matched_finding.get('title'))}</div>
                <div style="font-size:13px; color:var(--text-muted); margin-top:4px;">Action: {esc(matched_finding.get('suggested_action'))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Clear finding scope (Show full server remediation)"):
            st.session_state["selected_fix_finding"] = None
            st.rerun()
        scope_findings = [matched_finding]
    else:
        scope_findings = findings

    fix_tab_code, fix_tab_waf, fix_tab_sim = st.tabs(["Server Hardening", "Edge WAF Shield", "Patch Simulation"])

    # TAB 1: Server Hardening Code
    with fix_tab_code:
        st.markdown("#### Web Server & Transport Hardening")
        rem_choice = st.radio(
            "Select Web Server / Infrastructure Format:",
            [
                "Nginx Web Server (`nginx.conf`)",
                "Apache HTTP Server (`.htaccess` / `httpd.conf`)",
                "Caddy Server (`Caddyfile`)",
                "Cloudflare Edge (Workers / Transform Rules)",
                "Node.js / Express (`helmet` Middleware)",
                "DNS Email Security Records (SPF & DMARC)",
                "Linux Firewall (`ufw` & `iptables`)",
            ],
            key="fixes_server_choice_radio",
        )

        exposed_ports: list[int] = []
        for p in (discovered_ports or []):
            if isinstance(p, dict) and str(p.get("port", "")).isdigit():
                exposed_ports.append(int(p["port"]))
            elif isinstance(p, int):
                exposed_ports.append(p)

        if "Nginx" in rem_choice:
            code_text = generate_nginx_hardening(scope_findings, target=target)
            lang = "nginx"
            filename = f"nginx_hardening_{target}.conf"
        elif "Apache" in rem_choice:
            code_text = generate_apache_hardening(scope_findings, target=target)
            lang = "apacheconf"
            filename = f"apache_hardening_{target}.conf"
        elif "Caddy" in rem_choice:
            code_text = generate_caddy_hardening(scope_findings, target=target)
            lang = "caddyfile"
            filename = "Caddyfile"
        elif "Cloudflare" in rem_choice:
            code_text = generate_cloudflare_rules(scope_findings, target=target)
            lang = "javascript"
            filename = f"cloudflare_headers_{target}.js"
        elif "Node" in rem_choice:
            code_text = generate_node_helmet(scope_findings)
            lang = "javascript"
            filename = "security-middleware.js"
        elif "DNS" in rem_choice:
            code_text = generate_dns_hardening(target=target)
            lang = "dns"
            filename = f"dns_security_{target}.zone"
        else:
            code_text = generate_firewall_rules(exposed_ports or None)
            lang = "bash"
            filename = f"firewall_rules_{target}.sh"

        st.code(code_text, language=lang)
        st.download_button(
            label=f"Download {filename}",
            data=code_text,
            file_name=filename,
            mime="text/plain",
            type="primary",
            key="dl_server_fix",
        )

        # Inline "Preview effect of this fix"
        st.markdown("---")
        st.markdown("##### Preview the effect of this fix")
        sim_remaining = [f for f in findings if f not in scope_findings]
        old_score = min(100, sum(30 if str(f.get("severity")).lower() == "critical" else 18 if str(f.get("severity")).lower() == "high" else 8 if str(f.get("severity")).lower() == "medium" else 3 for f in findings))
        new_score = min(100, sum(30 if str(f.get("severity")).lower() == "critical" else 18 if str(f.get("severity")).lower() == "high" else 8 if str(f.get("severity")).lower() == "medium" else 3 for f in sim_remaining))
        drop = old_score - new_score

        st.markdown(
            f"""
            <div style="font-size:14px; color:var(--text-muted); background:var(--bg-subtle); padding:12px 16px; border:1px solid var(--border-hairline); border-radius:var(--radius-md);">
                Applying this configuration resolves <strong>{len(scope_findings)}</strong> finding(s).
                Threat index decreases from <span class="tabular-nums font-mono">{old_score}/100</span> to 
                <span class="tabular-nums font-mono" style="color:var(--accent); font-weight:600;">{new_score}/100</span> 
                (reduction of <span class="tabular-nums font-mono">-{drop}</span> points).
            </div>
            """,
            unsafe_allow_html=True,
        )

    # TAB 2: Edge WAF Shield Rules
    with fix_tab_waf:
        st.markdown("#### Web Application Firewall (WAF) Rule Export")
        st.caption("Deploy ready-to-import firewall rules to block exploit scanners and enforce header protections directly at the network edge.")

        waf_env = st.radio(
            "Select WAF Format:",
            ["AWS WAF (WebACL JSON)", "Cloudflare WAF (Custom Rules Expression)", "ModSecurity / Coraza (.conf)"],
            horizontal=True,
            key="fixes_waf_env_radio",
        )

        if "AWS" in waf_env:
            waf_code = generate_aws_waf_json(scope_findings, target=target)
            waf_lang = "json"
            waf_file = f"aws_waf_shield_{target}.json"
        elif "Cloudflare" in waf_env:
            waf_code = generate_cloudflare_waf_rules(scope_findings, target=target)
            waf_lang = "bash"
            waf_file = f"cloudflare_waf_{target}.txt"
        else:
            waf_code = generate_modsecurity_rules(scope_findings, target=target)
            waf_lang = "apacheconf"
            waf_file = f"modsecurity_{target}.conf"

        st.code(waf_code, language=waf_lang)
        st.download_button(
            label=f"Download {waf_file}",
            data=waf_code,
            file_name=waf_file,
            mime="text/plain",
            type="primary",
            key="dl_waf_fix",
        )

    # TAB 3: Global What-If Patch Simulator
    with fix_tab_sim:
        st.markdown("#### Interactive Threat Reduction Simulator")
        st.caption("Toggle hypothetical patches to see how resolving combinations of exposures improves the target threat posture.")

        if "simulated_patches" not in st.session_state:
            st.session_state.simulated_patches = set()

        # One-click bulk simulation controls
        col_btn_all, col_btn_rst, _ = st.columns([1.5, 1.2, 2])
        with col_btn_all:
            if st.button("⚡ Patch All Issues", use_container_width=True, type="primary"):
                for idx, f in enumerate(findings):
                    st.session_state.simulated_patches.add(f"sim_box_{f.get('rank', idx + 1)}_{idx}")
                st.rerun()
        with col_btn_rst:
            if st.button("↺ Reset All", use_container_width=True):
                st.session_state.simulated_patches.clear()
                st.rerun()

        sim_c1, sim_c2 = st.columns([3, 2])

        with sim_c1:
            st.markdown("**Simulate Applied Patches:**")
            for idx, f in enumerate(findings):
                rank = f.get("rank", idx + 1)
                sev = str(f.get("severity", "Info")).upper()
                title = str(f.get("title", f"Finding #{rank}"))
                cb_key = f"sim_box_{rank}_{idx}"

                is_patched = st.checkbox(
                    f"#{rank} [{sev}] {title}",
                    key=cb_key,
                    value=(cb_key in st.session_state.simulated_patches),
                )
                if is_patched:
                    st.session_state.simulated_patches.add(cb_key)
                else:
                    st.session_state.simulated_patches.discard(cb_key)

        with sim_c2:
            sim_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for idx, f in enumerate(findings):
                cb_key = f"sim_box_{f.get('rank', idx+1)}_{idx}"
                if cb_key not in st.session_state.simulated_patches:
                    s_label = str(f.get("severity", "Info")).capitalize()
                    sim_counts[s_label if s_label in sim_counts else "Info"] += 1

            sim_raw = (
                sim_counts["Critical"] * 30
                + sim_counts["High"] * 18
                + sim_counts["Medium"] * 8
                + sim_counts["Low"] * 3
                + sim_counts["Info"] * 1
            )
            sim_risk = min(100, sim_raw)
            base_risk = min(100, sum(30 if str(f.get("severity")).lower() == "critical" else 18 if str(f.get("severity")).lower() == "high" else 8 if str(f.get("severity")).lower() == "medium" else 3 for f in findings))
            pts_saved = max(0, base_risk - sim_risk)

            st.markdown(
                f"""
                <div style="border:1px solid var(--border-hairline); border-radius:var(--radius-md); background:var(--bg-surface); padding:20px; text-align:center; box-shadow:var(--shadow-sm);">
                    <div style="font-size:11px; font-weight:700; text-transform:uppercase; color:var(--text-muted);">Simulated Threat Index</div>
                    <div style="font-family:var(--font-sans); font-size:36px; font-weight:700; color:var(--text-ink); margin:8px 0;" class="tabular-nums">
                        {sim_risk}/100
                    </div>
                    <div style="font-size:13px; color:var(--accent); font-weight:600;">
                        Index reduced by {pts_saved} points
                    </div>
                    <div style="font-size:12px; color:var(--text-subtle); margin-top:6px;">
                        Baseline: {base_risk} &rarr; Projected: {sim_risk}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
