# AI-Assisted Attack Surface & Vulnerability Correlation Tool

Academic security project for defensible attack surface discovery, public vulnerability correlation, threat intelligence enrichment (CISA KEV + FIRST EPSS), and AI-driven defensive prioritization.

It is **not** a penetration testing or offensive exploitation tool. It is a strictly **passive correlation + defensive remediation explanation layer**.

---

## 🛡️ Dual Operational Modes & Safety Guardrails

The tool supports checking real-world domains and local labs exclusively through two safe, ethical operational modes:

| Mode | Target Eligibility | Scope & Capabilities | Probing / Scanning Behavior |
| :--- | :--- | :--- | :--- |
| **1. Passive OSINT Mode** *(Default)* | Any public internet domain (e.g. `example.com`) | Safe HTTP root headers (`GET /`), public TLS cert inspection, DNS records (A, AAAA, MX, TXT, SPF, DMARC), Certificate Transparency log enumeration (`crt.sh`), optional Shodan InternetDB cache. | **Zero Port Probing**: Strictly passive. Never runs Nmap, never connects to arbitrary ports, never probes paths. |
| **2. Verified Active Mode** | Localhost / allowlist lab targets (`targets.allowlist`) **OR** domains verified via ownership challenge | Full active pipeline: Nmap service version detection (`-sV`), local TLS socket inspection, port-level CVE correlation. | **Authorized Port Probing**: Allowed only against targets the user explicitly owns or controls. |

---

## 🔑 Domain Ownership Verification (`verification/`)

To authorize active port scanning against a public domain, you must prove administrative control over the domain.

```
┌────────────────────────────────────────────────────────┐
│             Domain Ownership Challenge Flow            │
└────────────────────────────────────────────────────────┘
  1. Generate Challenge Token:
     $ python -m verification start mydomain.com
     ├── Token: e82f9d...a7
     ├── Option A: Add DNS TXT record:
     │             _attacksurface-verify.mydomain.com -> e82f9d...a7
     └── Option B: Host file at:
                   https://mydomain.com/.well-known/attacksurface-verify.txt

  2. Verify Ownership:
     $ python -m verification check mydomain.com
     └── [SUCCESS] Domain verified for 30 days! (Expires in 30 days)
```

### CLI Commands:
- **Start Verification**:
  ```bash
  python -m verification start example.com
  ```
- **Check Verification**:
  ```bash
  python -m verification check example.com
  ```
- Verification state is stored securely in `data/verified_targets.json` with a **30-day time-to-live (TTL)**. Expired entries automatically fail closed and revert to Passive OSINT mode.

---

## 🔒 SSRF & Abuse Defenses (`discovery/safe_fetch.py`)

When interacting with external web endpoints, the tool enforces strict Server-Side Request Forgery (SSRF) and network abuse safeguards:
- **Scheme & Port Restriction**: Only `http://` and `https://` on ports 80 and 443 are allowed for external lookups.
- **Private & Cloud Metadata Blocklist**: Every hostname resolution is checked via `ipaddress`. Any resolution to private (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, or cloud instance metadata endpoints (`169.254.169.254`, `fd00:ec2::254`) is immediately aborted.
- **DNS Rebinding Defense**: Connects directly to pre-validated IP addresses or re-validates DNS resolution prior to HTTP dispatch.
- **Manual Redirect Re-validation**: HTTP redirects are followed manually (capped at 3 hops), with full SSRF and IP validation re-executed on every intermediate hop.
- **Response & Rate Limiting**: Capped at 1 MB response payload and 6.0-second network timeouts per request with per-domain rate limiting.

---

## 📖 Security & Threat Intelligence Concepts (For 3rd Semester Students)

| Concept | Explanation |
| :--- | :--- |
| **SSRF (Server-Side Request Forgery)** | A vulnerability where an attacker tricks a backend server into requesting internal, non-public systems (e.g. AWS metadata). |
| **DNS Rebinding** | An attack that exploits DNS TTL changes to make a public domain resolve to an internal IP like `127.0.0.1`. |
| **Certificate Transparency (CT)** | Public append-only logs recording all issued TLS certificates, allowing discovery of associated subdomains. |
| **SPF & DMARC** | DNS TXT records specifying which mail servers are authorized to send email for a domain, preventing email spoofing. |
| **CPE (Common Platform Enumeration)** | A structured naming scheme (e.g. `cpe:2.3:a:apache:http_server:2.4.49`) used to query NVD for exact version matches. |
| **CVSS (Common Vulnerability Scoring System)** | A 0.0 to 10.0 score reflecting theoretical flaw severity. |
| **CISA KEV (Known Exploited Vulnerabilities)** | A public catalog of vulnerabilities actively weaponized by real-world threat actors in the wild. |
| **EPSS (Exploit Prediction Scoring System)** | A machine-learning probability score (0.0 to 1.0 / 0% to 100%) predicting real-world exploitation in the next 30 days. |
| **SameSite Cookie Attribute** | Flag (`Strict`, `Lax`, `None`) that tells the browser whether to send cookies on cross-origin requests, preventing CSRF attacks. |
| **CORS (Cross-Origin Resource Sharing)** | Header policy controlling domain API access. A wildcard `Access-Control-Allow-Origin: *` allows any website to read sensitive API data. |

---

## 🏗️ Architecture Pipeline

```
          Target Host / Public Domain
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
[Unverified / Public]      [Allowlisted / Verified]
 100% Passive OSINT         Authorized Active Scan
 ├── Safe GET / (Headers)   ├── Nmap / TCP Port Probe
 ├── TLS Cert Parsing       ├── Service Banner -sV
 ├── DNS (SPF/DMARC/MX)     └── Local TLS Socket Audit
 └── CT Logs (crt.sh)
        │                           │
        └─────────────┬─────────────┘
                      ▼
        [2] Correlation & Threat Intelligence
            ├── NVD CVE Matching (CPE & keyword)
            ├── CISA KEV Exploited Catalog lookup
            └── FIRST EPSS Exploit Probability
                      │
                      ▼
        [3] AI Defensive Prioritization
            ├── Amazon Bedrock Converse API (Amazon Nova / Anthropic Claude)
            ├── Strict Prompt Injection Sanitization (<target_data> boundary)
            ├── Mode-aware prompting (never implies active testing on unverified)
            └── Deterministic KEV > EPSS > CVSS fallback
                      │
                      ▼
        [4] Dashboard & Evaluation Suite
            ├── Streamlit Interactive UI with Domain Verification Panel
            ├── Scan History & Diff Analysis (New / Resolved / Unchanged)
            └── CSV & HTML Report Downloads
```

---

## 🚀 Setup & Execution

### 1. Installation
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate | Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env   # On Windows (or cp on Linux/macOS)
```

Configure `.env` with your AWS credentials:
```ini
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=amazon.nova-micro-v1:0
DASHBOARD_PASSWORD=replace_with_a_long_random_password
ALLOW_ANONYMOUS_DASHBOARD=true  # Demo mode; use false with DASHBOARD_PASSWORD for private deployments
```

For Elastic Beanstalk, set `DASHBOARD_PASSWORD` and `ALLOW_ANONYMOUS_DASHBOARD=false`
under the environment properties. The dashboard fails closed when no password is
configured. Anonymous access should only be enabled for a private local demonstration.

### 2. Running Scans

- **Passive OSINT Scan (Any public domain)**:
  ```bash
  python run_pipeline.py --target example.com
  ```
- **Localhost Lab Scan (Active probing authorized)**:
  ```bash
  python run_pipeline.py --target localhost --ports 80,443,3000,8000,8080
  ```
- **Force Passive Mode on Verified Domain**:
  ```bash
  python run_pipeline.py --target verified-site.com --passive-only
  ```

---

## 📊 Evaluation & Testing

```bash
# Run full unit test suite (SSRF, Verification, Diffs, AI Sanitization)
python -m unittest discover -s tests -v

# Run OWASP Juice Shop benchmark evaluation
python tests/validate.py

# Run ranking methodology comparison (CVSS vs KEV/EPSS vs Bedrock AI)
python tests/compare_rankings.py
```

---

## 🖥️ Streamlit Dashboard

For a plain-language explanation of scan modes, checks, reports, and safe testing, see [USER_GUIDE.md](USER_GUIDE.md).

Launch the web UI:
```bash
# On Windows (PowerShell / CMD):
py -m streamlit run dashboard/app.py

# Or with python:
python -m streamlit run dashboard/app.py
```

Includes:
- **Dynamic Mode Badges**: `Local Lab`, `Passive OSINT`, and `Verified Active`.
- **Domain Verification Panel**: Interactive DNS TXT / `.well-known` token generation and validation.
- **Passive OSINT Inspector**: Explore public DNS records, TLS certificates, and Certificate Transparency subdomains.
- **Scan History Diffs**: Track vulnerability remediation over time.
- **Report Exports**: Download findings in CSV and HTML formats.

---

## ⚠️ Honest Limitations & Scope

1. **Domain Control vs Server Ownership**: Ownership verification proves control over a hostname's DNS zone or web document root. It does **not** prove ownership of the shared physical server, cloud hypervisor, or IP address space hosting it.
2. **Passive Mode Scope**: Passive scans strictly see what an ordinary visitor's web browser sees (`GET /`, TLS certificate, and public DNS records). It does not reveal internal endpoints, closed ports, or non-HTTP services.
3. **Certificate Transparency Subdomains**: Subdomains extracted from public Certificate Transparency logs (`crt.sh`) are indexed for organizational awareness only and are **never scanned automatically**. Each subdomain requires separate verification before active probing.
4. **No Exploitation**: The tool does not perform fuzzing, SQL injection, XSS exploitation, brute forcing, or directory brute-forcing.

---

## ⚖️ Ethics and Responsible Use

This tool was designed under ethical AI and defensive security research principles:
- **Authorization by Default**: Active port scanning is prohibited against unauthorized targets.
- **Safe Intelligence Gathering**: Public domain lookups utilize rate-limited, non-intrusive queries.
- **AI Safety & Defense-Only Remediation**: The AI model is instructed to provide only defensive hardening advice (e.g. Nginx configurations, Content-Security-Policy headers) and will never suggest exploitation steps or unauthorized testing.

