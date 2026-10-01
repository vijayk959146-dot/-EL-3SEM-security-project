# Attack Surface Security Dashboard Guide

## What this project does

This project is a defensive security assessment tool. It collects evidence about a target that you own or are authorized to test, compares the evidence with public vulnerability intelligence, and presents prioritized remediation advice.

It does not exploit vulnerabilities, steal credentials, bypass authentication, or guarantee that a target is vulnerable.

## Two operating modes

### Passive OSINT mode

Use passive mode for a public domain when you only want low-impact, publicly observable information.

It can check:

- HTTP reachability and response status
- Page title and basic response headers
- Missing security headers
- Cookie security flags
- CORS configuration warnings
- Server or framework version disclosure
- TLS certificate availability and basic certificate details
- Certificate expiry and self-signed certificates
- Public DNS A and AAAA records
- Mail exchanger records
- SPF and DMARC records
- Public Certificate Transparency subdomains

Certificate Transparency names are shown for awareness only. They are not scanned automatically.

Run it with:

```bash
python run_pipeline.py --target example.com --passive-only
```

### Authorized active mode

Use active mode only for localhost, a lab, or a domain that you own and have verified.

It can additionally check:

- Reachable TCP ports from the configured port list
- Basic service and product banners
- Service versions when Nmap is available
- Local TLS socket details
- Public CVE matches for detected software and versions
- CISA Known Exploited Vulnerability signals
- EPSS exploitation probability signals

Run a local lab check with:

```bash
python run_pipeline.py --target localhost --ports 80,443,8000,8080
```

The allowlist and domain ownership verification guard active scans. A target that is neither allowlisted nor verified is kept in passive mode.

## What the pipeline does with the results

1. Discovery gathers target evidence.
2. Correlation compares software and configuration evidence with NVD, CISA KEV, and FIRST EPSS data.
3. Prioritization ranks findings using Bedrock when configured, with a transparent heuristic fallback when it is unavailable.
4. Storage writes a report under `data/<target>/`.
5. The Streamlit dashboard reads the report and shows risk summaries, CVEs, evidence, and defensive actions.

## Running the Dashboard

To launch the web interface:

```bash
# On Windows PowerShell / Command Prompt:
py -m streamlit run dashboard/app.py

# Or:
python -m streamlit run dashboard/app.py
```

## What the dashboard shows


- **📋 Ranked Findings & Remediation Cards:** Searchable, severity-filtered vulnerabilities with exploitability context and NVD/CISA KEV links.
- **🛠️ Remediation Sandbox & Code Generator:** Instant drop-in configuration patches for Nginx, Apache, Caddy, Cloudflare Workers, Node.js/Helmet, DNS records (SPF/DMARC), and Linux UFW/iptables firewalls.
- **🕸️ MITRE ATT&CK Threat Matrix:** Visual cyber kill-chain pipeline mapping findings to Reconnaissance, Initial Access, Discovery, Defense Evasion, and Credential Access.
- **⚡ Real-Time "What-If" Patch Simulator:** Interactive patch simulator where selecting remediated items recalculates the Threat Index Score in real-time.
- **🤖 AI SOC Security Copilot:** Interactive conversational AI analyst that answers technical queries, generates CISO briefings, simulates threat actor attack paths, and writes bash verification scripts.
- **📊 Executive Insights & Vectors:** Severity distribution charts, top risk vectors, and configuration/network/CVE exposure breakdown.
- **🌐 OSINT & Attack Surface Recon:** Deep DNS, TLS certificates, Certificate Transparency (`crt.sh`) subdomains, and open port telemetry.
- **🔄 Scan History & Diff Tracking:** Side-by-side comparison with previous scans to track resolved vs. persisting vulnerabilities.
- **📥 SIEM & Webhook Export:** Standalone HTML and CSV briefings, ArcSight/Splunk CEF syslog format, Elastic Common Schema (ECS), and live Webhook alerting for Slack/Discord/Teams.

## Where to find vulnerabilities

Open the **Ranked Findings** table. Each row contains the rank, severity, finding title, exploitability context, related CVEs, and discovery source. Expand a row under **Defensive Remediation Cards** to see why it matters and what to fix.

## What a finding means

A finding is evidence-based guidance, not proof of exploitation. A related CVE means the detected product or version matched a public vulnerability record. Confirm versions and exposure before making production changes.

## Safe testing rule

Use `example.com` only for passive testing. Use active mode only against systems you own or have explicit permission to test.

