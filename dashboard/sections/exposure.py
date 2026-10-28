"""
Exposure Section: Architectural topology diagram and OSINT telemetry details.
Flat layered diagram plus DNS/Email, TLS, Certificate Transparency, and Open Ports.
"""

from __future__ import annotations

import html
from typing import Any
import streamlit as st
import streamlit.components.v1 as components
from dashboard.components import esc
from dashboard.attack_graph import render_attack_surface_graph_html


def render_exposure_section(
    report: dict[str, Any],
    assets_data: dict[str, Any],
    theme_mode: str = "light",
) -> None:
    """Render the exposure topology and OSINT telemetry."""
    target = report.get("target") or "Target"
    findings = report.get("findings") or []

    passive_meta = assets_data.get("passive_meta") or {}
    ports = assets_data.get("ports", [])
    subdomains = passive_meta.get("certificate_transparency", [])
    ips = passive_meta.get("dns", {}).get("A", [])

    st.markdown("### Attack Surface Exposure")
    st.caption("Layered mapping of network ingress, resolving endpoints, active services, and discovered exposures.")

    # 1. Flat Layered Exposure Topology Diagram (SVG)
    graph_html = render_attack_surface_graph_html(
        target=target,
        findings=findings,
        ports=ports,
        subdomains=subdomains,
        ips=ips,
        theme_mode=theme_mode,
    )
    # Estimate height
    calc_height = max(380, min(650, 80 + max(len(ips), len(ports), len(findings)) * 44))
    components.html(graph_html, height=calc_height, scrolling=False)

    st.markdown("---")
    st.markdown("### Surface Telemetry & Reconnaissance")
    st.caption("Non-intrusive metadata gathered from public DNS, TLS certificates, and Certificate Transparency logs.")

    # 2. Sub-sections with clean expanders
    # A) DNS & Email Spoofing Defenses
    with st.expander("DNS Records & Email Authentication Defenses", expanded=True):
        dns_data = passive_meta.get("dns", {})
        c_dns1, c_dns2 = st.columns(2)

        with c_dns1:
            st.markdown(
                f"""
                <table class="field-table">
                    <thead><tr><th>Record Type</th><th>Discovered Value</th></tr></thead>
                    <tbody>
                        <tr><td>A (IPv4)</td><td class="font-mono">{esc(', '.join(dns_data.get('A', [])) or 'None')}</td></tr>
                        <tr><td>AAAA (IPv6)</td><td class="font-mono">{esc(', '.join(dns_data.get('AAAA', [])) or 'None')}</td></tr>
                        <tr><td>MX (Mail)</td><td class="font-mono">{esc(', '.join(dns_data.get('MX', [])) or 'None')}</td></tr>
                    </tbody>
                </table>
                """,
                unsafe_allow_html=True,
            )

        with c_dns2:
            spf = dns_data.get("SPF")
            dmarc = dns_data.get("DMARC")
            spf_mark = '<span class="mark-tag mark-tag-pass">PASS</span>' if spf else '<span class="mark-tag mark-tag-gap">GAP (Missing SPF)</span>'
            dmarc_mark = '<span class="mark-tag mark-tag-pass">PASS</span>' if dmarc else '<span class="mark-tag mark-tag-gap">GAP (Missing DMARC)</span>'

            st.markdown(
                f"""
                <table class="field-table">
                    <thead><tr><th>Defense Policy</th><th>Status</th><th>Raw Configuration</th></tr></thead>
                    <tbody>
                        <tr><td>SPF Record</td><td>{spf_mark}</td><td class="font-mono">{esc(spf or 'No policy declared')}</td></tr>
                        <tr><td>DMARC Policy</td><td>{dmarc_mark}</td><td class="font-mono">{esc(dmarc or 'No policy declared')}</td></tr>
                    </tbody>
                </table>
                """,
                unsafe_allow_html=True,
            )

    # B) TLS / SSL Certificate Details
    with st.expander("TLS / SSL Certificate Details", expanded=False):
        tls_data = passive_meta.get("tls", {})
        if tls_data.get("available"):
            days = tls_data.get("days_remaining", 0)
            validity_mark = '<span class="mark-tag mark-tag-pass">VALID</span>' if days > 30 else '<span class="mark-tag mark-tag-gap">EXPIRING</span>'
            self_signed = '<span class="mark-tag mark-tag-gap">UNTRUSTED</span>' if tls_data.get("self_signed") else '<span class="mark-tag mark-tag-pass">CA SIGNED</span>'

            st.markdown(
                f"""
                <table class="field-table">
                    <thead><tr><th>Certificate Attribute</th><th>Configuration Details</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td>Subject Common Name</td><td class="font-mono">{esc(tls_data.get('subject'))}</td><td>&mdash;</td></tr>
                        <tr><td>Issuer Authority</td><td class="font-mono">{esc(tls_data.get('issuer'))}</td><td>{self_signed}</td></tr>
                        <tr><td>TLS Protocol Version</td><td class="font-mono">{esc(tls_data.get('version'))}</td><td>&mdash;</td></tr>
                        <tr><td>Validity Expiration</td><td class="font-mono">{esc(tls_data.get('notAfter'))} ({days} days)</td><td>{validity_mark}</td></tr>
                    </tbody>
                </table>
                """,
                unsafe_allow_html=True,
            )
        else:
            err_msg = tls_data.get("error", "No TLS service reachable on port 443.")
            st.info(f"TLS data unavailable: {err_msg}")

    # C) Certificate Transparency Subdomains
    with st.expander(f"Certificate Transparency Subdomains ({len(subdomains)})", expanded=False):
        if subdomains:
            st.markdown(f"Discovered **{len(subdomains)}** public subdomains indexed in public Certificate Transparency logs (`crt.sh`):")
            st.code("\n".join(subdomains), language="text")
            st.caption("Subdomains from public CT logs are mapped for passive footprinting. Active scans require explicit authorization.")
        else:
            st.info("No subdomains identified in public CT log records.")

    # D) Open Ports & Services
    with st.expander(f"Discovered Open Ports & Services ({len(ports)})", expanded=False):
        if ports:
            port_rows = []
            for p in ports:
                if isinstance(p, dict):
                    port_rows.append({
                        "Port": p.get("port"),
                        "Service": p.get("service", "unknown"),
                        "Product": p.get("product", "-"),
                        "Version": p.get("version", "-"),
                    })
                else:
                    port_rows.append({"Port": p, "Service": "open", "Product": "-", "Version": "-"})
            st.dataframe(port_rows, use_container_width=True)
        else:
            st.info("No active open ports logged (passive scan executed or zero responsive ports).")
