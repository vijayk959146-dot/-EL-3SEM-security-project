# Modern Enterprise SecOps Design System

## Overview
**SecOps Attack Surface Console** is a clean, production-grade cybersecurity and external attack surface management (EASM) visual system. It rejects both generic AI tropes (retro-editorial serif fonts, warm archival paper, and chat-assistant gimmicks) and cheesy neon cyberpunk clichés in favor of the authentic, crisp interface standards used by industry-leading security engineering platforms (e.g., Datadog, Snyk, Wiz, GitHub Advanced Security).

---

## 1. Design Tokens

### 1.1 Color Palette

#### Light Mode (Default: Enterprise Slate)
The default theme delivers high contrast, sharp legibility, and professional telemetry cards:

| Token | Variable | Value | Semantic Purpose |
|---|---|---|---|
| Background App | `--bg-app` | `#F8FAFC` | Clean slate-50 backdrop |
| Surface | `--bg-surface` | `#FFFFFF` | Primary white card & panel background |
| Subtle Surface | `--bg-subtle` | `#F1F5F9` | Slate-100 table headers, code panels, sidebar |
| Hover State | `--bg-hover` | `#E2E8F0` | Slate-200 row hover & interactive states |
| Primary Ink | `--text-ink` | `#0F172A` | Slate-900 high-contrast body & header text |
| Muted Ink | `--text-muted` | `#475569` | Slate-600 secondary text & captions |
| Subtle Ink | `--text-subtle` | `#94A3B8` | Slate-400 metadata tags & hints |
| Hairline Rule | `--border-hairline` | `#E2E8F0` | 1px crisp dividers, card outlines |
| Strong Rule | `--border-strong` | `#CBD5E1` | Active input outlines, button borders |
| Signal Accent | `--accent` | `#2563EB` | Cobalt tech blue for active actions and brand |

#### Dark Mode (Obsidian Console)
A deep console dark theme with balanced contrast:

| Token | Variable | Value | Semantic Purpose |
|---|---|---|---|
| Background App | `--bg-app` | `#0B0F19` | Deep slate-950 backdrop |
| Surface | `--bg-surface` | `#111827` | Surface cards & panels |
| Subtle Surface | `--bg-subtle` | `#1F2937` | Secondary containers |
| Hover State | `--bg-hover` | `#374151` | Interactive item hover |
| Primary Ink | `--text-ink` | `#F9FAFB` | Crisp off-white reading text |
| Muted Ink | `--text-muted` | `#9CA3AF` | Secondary annotations |
| Subtle Ink | `--text-subtle` | `#6B7280` | Low-priority metadata |
| Hairline Rule | `--border-hairline` | `#1F2937` | 1px separators |
| Strong Rule | `--border-strong` | `#374151` | Input outlines |
| Signal Accent | `--accent` | `#3B82F6` | Electric Blue accent |

#### Severity Tokens
Severity indicators are presented as modern status pills with colored indicator dots:

| Severity | Dot & Border Color | Background (Light) | Token Variable |
|---|---|---|---|
| **Critical** | `#DC2626` | `#FEF2F2` | `--sev-crit` |
| **High** | `#EA580C` | `#FFF7ED` | `--sev-high` |
| **Medium** | `#D97706` | `#FFFBEB` | `--sev-med` |
| **Low** | `#2563EB` | `#EFF6FF` | `--sev-low` |
| **Info** | `#64748B` | `#F8FAFC` | `--sev-info` |

---

### 1.2 Typography & Scale

The system utilizes Google Fonts:
- **Primary Sans**: `Inter` (UI copy, headings, cards, navigation).
- **Monospace**: `JetBrains Mono` (CVE IDs, IP addresses, ports, hashes, code blocks).

#### Type Scale
```css
--text-xs:   12px;   /* Metadata tags, timestamps, table subtext */
--text-sm:   13px;   /* Body secondary, navigation labels */
--text-base: 14px;   /* Default body copy */
--text-md:   18px;   /* Section subsection headers (h3) */
--text-lg:   24px;   /* Major section titles (h2) */
--text-xl:   32px;   /* Primary report titles (h1) */
```

---

### 1.3 Spacing & Layout
- **Grid Unit**: 8px base grid (`4px`, `8px`, `12px`, `16px`, `20px`, `28px`, `36px`, `48px`).
- **Container**: Max width `1200px` centered on desktop.
- **Radii**: `--radius-sm: 6px`, `--radius-md: 8px`, `--radius-lg: 12px`, `--radius-pill: 9999px`.
- **Elevation**: Subtle soft drop-shadows (`box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05)`).

---

## 2. Information Architecture (5 Core Sections)

The console organizes telemetry across 5 core security sections:

### 1. Summary
- **Security Posture Overview**: Analytical, plain-English summary of confirmed exposures and immediate priority actions.
- **KPI Metrics Grid**: 4 key telemetry cards:
  1. Total findings with horizontal severity stacked bar.
  2. Exploitation threat count (CISA KEV listed, high EPSS).
  3. Assessment telemetry & mode (`PASSIVE RECON (OSINT)` vs `ACTIVE PROBE (VERIFIED)`).
  4. Historical drift delta vs baseline scan.
- **Priority Remediation Queue**: Top 3 ranked findings with prioritized action statements and a direct "Remediate" button.

### 2. Findings (Vulnerability & Exposure Ledger)
- High-density vulnerability ledger with modern severity pills, CVE tags, and sort/filter controls.
- Search by keyword, filter by severity or origin, sort by rank/severity/exploitability.
- Structured technical details for root-cause impact, suggested patch, direct NVD hyperlinks, and MITRE ATT&CK technique tags.

### 3. Exposure
- **Layered Architecture Pipeline (SVG)**: Left-to-right topological mapping:
  `Target` &rarr; `Resolved IPs` &rarr; `Open Services` &rarr; `Discovered Exposures`.
  - Hover highlights and interactive inspector panel.
- **Surface Telemetry & Reconnaissance**: Structured data tables for DNS/Email spoofing defense (SPF/DMARC checks), TLS certificates, Certificate Transparency (`crt.sh`) subdomains, and discovered TCP ports.

### 4. Fixes
- **Server Hardening**: Production configuration generators for Nginx, Apache, Caddy, Cloudflare, Node.js (`helmet`), DNS records, and Linux firewall rules.
- **Threat Reduction Calculator**: Live simulation calculating exact points dropped from the Threat Index when applying the current fix.
- **Edge WAF Shield**: Formatted rules for AWS WAF (WebACL JSON), Cloudflare WAF expressions, and ModSecurity `.conf`.
- **Interactive Patch Simulator**: Multi-checkbox simulator calculating cumulative risk reduction.

### 5. Evidence & Reports
- **Regulatory Compliance**: Tabular evaluation against OWASP Top 10 (2021) and NIST CSF v2.0 with explicit `PASS` and `GAP` tags.
- **MITRE ATT&CK Matrix**: Enterprise adversarial tactics and techniques mapped from findings.
- **Historical Drift**: Snapshot comparison showing new vulnerabilities, remediated issues, and persisting findings.
- **Enterprise SIEM Exports**: Formatted HTML executive briefing, CSV matrix, JSON dump, ArcSight/Splunk CEF, Elastic Common Schema (ECS NDJSON), and live webhook dispatcher.

---

## 3. Security & Escaping Invariants
All strings sourced from scan outputs, domain queries, HTTP banners, TLS certificates, or queries **must** pass through `dashboard.components.esc()` or `html.escape(..., quote=True)` before being injected into any HTML markup or SVG elements.
