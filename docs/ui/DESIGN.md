# Field Report Design System

## Overview
**Field Report** is an editorial, high-density visual design system crafted for security assessment and attack surface management. It rejects the generic "cyberpunk/neon dark-mode" aesthetics (glassmorphism, cyan glows, radar sweeps, floating pill badges, emoji-saturated headings) in favor of a restrained, typography-first presentation inspired by formal engineering field evaluations and published vulnerability bulletins.

---

## 1. Design Tokens

### 1.1 Color Palette

#### Light Mode (Default)
The default theme reflects warm archival paper, dark ink text, and hairline borders:

| Token | Variable | Value | Semantic Purpose |
|---|---|---|---|
| Background App | `--bg-app` | `#F6F3EC` | Base paper background |
| Surface | `--bg-surface` | `#FFFFFF` | Primary card & panel background |
| Subtle Surface | `--bg-subtle` | `#EFECE4` | Table headers, code blocks, sidebar |
| Hover State | `--bg-hover` | `#E7E3D8` | Row hover & interactive states |
| Primary Ink | `--text-ink` | `#1B1B1B` | High-contrast body & header text |
| Muted Ink | `--text-muted` | `#5C5A55` | Secondary text, captions, table subheadings |
| Subtle Ink | `--text-subtle` | `#8C887F` | Form labels, metadata tags, hints |
| Hairline Rule | `--border-hairline` | `#D9D4C7` | 1px dividers, card borders |
| Strong Rule | `--border-strong` | `#BCB6A6` | Active input borders, buttons |
| Signal Accent | `--accent` | `#D8431F` | Singular vermilion accent for primary callouts |

#### Dark Mode (Charcoal Paper)
A switchable dark variant with equally restrained contrast:

| Token | Variable | Value | Semantic Purpose |
|---|---|---|---|
| Background App | `--bg-app` | `#16171A` | Charcoal matte background |
| Surface | `--bg-surface` | `#1E2024` | Surface cards & panels |
| Subtle Surface | `--bg-subtle` | `#26282E` | Secondary containers |
| Hover State | `--bg-hover` | `#2F323A` | Interactive item hover |
| Primary Ink | `--text-ink` | `#E5E5E5` | Off-white reading text |
| Muted Ink | `--text-muted` | `#A3A3A3` | Dimmed annotations |
| Subtle Ink | `--text-subtle` | `#737373` | Low-priority metadata |
| Hairline Rule | `--border-hairline` | `#2C2D32` | 1px separators |
| Strong Rule | `--border-strong` | `#3F4148` | Input outlines |
| Signal Accent | `--accent` | `#E0532E` | Signal vermilion |

#### Severity Tokens
Severity indicators are presented strictly as small 8px geometric squares alongside lowercase/titlecase text. No glowing or neon fills are permitted:

| Severity | Square Color (Light) | Square Color (Dark) | Token Variable |
|---|---|---|---|
| **Critical** | `#991B1B` (Deep Red) | `#DC2626` | `--sev-crit` |
| **High** | `#C2410C` (Rust Orange) | `#EA580C` | `--sev-high` |
| **Medium** | `#B45309` (Ochre) | `#D97706` | `--sev-med` |
| **Low** | `#2563EB` (Slate Blue) | `#60A5FA` | `--sev-low` |
| **Info** | `#64748B` (Neutral Grey) | `#94A3B8` | `--sev-info` |

---

### 1.2 Typography & Scale

The system utilizes Google Fonts imported via `dashboard/theme.css`:
- **Display Serif**: `Fraunces` (page titles, section headings, executive verdict).
- **Body Sans**: `IBM Plex Sans` (general body text, descriptions, buttons).
- **Monospace**: `IBM Plex Mono` (CVE IDs, IP addresses, ports, hashes, code blocks).

#### Type Scale
```css
--text-xs:   12px;   /* Metadata tags, timestamps, table subtext */
--text-sm:   14px;   /* Body secondary, navigation labels */
--text-base: 16px;   /* Default body copy */
--text-md:   20px;   /* Section subsection headers (h3) */
--text-lg:   28px;   /* Major section titles (h2) */
--text-xl:   40px;   /* Primary report titles (h1) */
```

---

### 1.3 Spacing & Layout
- **Grid Unit**: 8px (`4px`, `8px`, `12px`, `16px`, `24px`, `32px`, `40px`, `48px`).
- **Container**: Max width `1100px` centered on desktop.
- **Radii**: 2px to 4px maximum (`--radius-xs: 2px`, `--radius-sm: 3px`, `--radius-md: 4px`). No rounded pill buttons.
- **Rules**: 1px solid hairline dividers (`--border-hairline`). No box shadows or drop-shadow blurs.

---

## 2. Information Architecture (5-Section Structure)

The dashboard replaces disparate tabs with 5 clearly scoped reporting sections navigated via the sidebar outline:

### 1. Summary
- **Executive Assessment Verdict**: A deterministic 2-to-3 sentence analytical summary derived from findings, severity distribution, and exposure categories without making extra LLM API calls.
- **Compact Figures Row**: 4 key metrics:
  1. Findings count & horizontal severity stacked bar.
  2. Assessment mode (`PASSIVE` vs `ACTIVE (verified)`).
  3. Assessment timestamp.
  4. Historical drift delta vs baseline scan.
- **Do These First**: Top 3 ranked findings with one-line prioritized remediation actions and a direct "Remediate" shortcut to the Fixes section.

### 2. Findings (The Triage Ledger)
- High-density list styled as an engineering ledger with 1px hairline borders.
- Columns: Rank (`#`), Severity (small square + word), Title, Related CVEs (monospace), Exploitability (e.g. `KEV-listed`, `EPSS 0.42`), and Origin.
- Inline expander revealing root-cause explanation, remediation action, direct NVD hyperlinks, regulatory tags, and a "Show fix" button.
- Clean text filter controls: keyword search, severity multiselect, origin filter, and sort selector.

### 3. Exposure
- **Layered Architectural Diagram (SVG)**: Replaces radial physics graphs with a flat left-to-right pipeline:
  `Target` &rarr; `Resolved IPs` &rarr; `Open Services` &rarr; `Discovered Exposures`.
  - Connectors highlight on hover.
  - Clicking any node populates an inline inspector panel.
  - Zero emoji, clean mono labels, capped node counts, and theme-token synchronized.
- **Reconnaissance Telemetry**: Structured tables for DNS/Email spoofing records (SPF/DMARC checks), TLS certificates, Certificate Transparency (`crt.sh`) subdomains, and discovered TCP ports.

### 4. Fixes
- **Server Hardening**: Production configuration generators for Nginx, Apache, Caddy, Cloudflare, Node.js (`helmet`), DNS records, and Linux firewall rules.
- **Preview Effect of This Fix**: Inline simulation calculating exact points dropped from the Threat Index when applying the current fix.
- **Edge WAF Shield**: Formatted rules for AWS WAF (WebACL JSON), Cloudflare WAF expressions, and ModSecurity `.conf`.
- **Patch Simulator**: Interactive toggle simulator modeling cumulative risk reduction.

### 5. Evidence & Reports
- **Regulatory Compliance**: Plain tabular alignment against OWASP Top 10 (2021) and NIST CSF v2.0 with explicit `PASS` and `GAP` tags.
- **MITRE ATT&CK Matrix**: Enterprise adversarial tactics and techniques mapped from findings.
- **Historical Drift**: Snapshot comparison showing new vulnerabilities, remediated issues, and persisting findings.
- **Exports & SIEM Pipelines**: Formatted HTML briefing, CSV matrix, JSON dump, ArcSight/Splunk CEF, Elastic Common Schema (ECS NDJSON), and live webhook dispatcher.

### Persistent Copilot Assistant
Located persistently in the sidebar under "Ask about this report". Features one-click analytical prompts, session rate-limit indicators, and explicit transparency marking whether an answer was generated via Amazon Bedrock LLM or the local heuristic fallback engine.

---

## 3. How to Add a New Section

To add a new section to the Field Report dashboard, follow these steps:

1. **Create the section module in `dashboard/sections/<name>.py`**:
   ```python
   # dashboard/sections/audit_trail.py
   from typing import Any
   import streamlit as st
   from dashboard.components import esc

   def render_audit_trail_section(report: dict[str, Any]) -> None:
       st.markdown("### Audit Trail")
       st.caption("Verification event log and integrity attestations.")
       # Section layout code here
   ```

2. **Export the renderer in `dashboard/sections/__init__.py`**:
   ```python
   from dashboard.sections.audit_trail import render_audit_trail_section
   __all__ = [..., "render_audit_trail_section"]
   ```

3. **Register the section in `dashboard/app.py`**:
   Add the section name to the `SECTIONS` list and router:
   ```python
   SECTIONS = ["Summary", "Findings", "Exposure", "Fixes", "Evidence & reports", "Audit Trail"]
   
   ...
   elif active_sec == "Audit Trail":
       render_audit_trail_section(report)
   ```

4. **Add an automated test in `tests/test_dashboard_state.py`**:
   Ensure `test_navigation_across_all_five_sections` includes the new section in its loop.

---

## 4. Security & Escaping Invariants
All strings sourced from scan outputs, domain queries, HTTP banners, TLS certificates, or LLM responses **must** pass through `dashboard.components.esc()` or `html.escape(..., quote=True)` before being injected into any HTML markup or SVG elements.
