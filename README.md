# AI-Assisted Attack Surface & Vulnerability Correlation Tool

Academic security project for defensible attack surface discovery, public vulnerability correlation, threat intelligence enrichment (CISA KEV + FIRST EPSS), and AI-driven defensive prioritization.

It is **not** a penetration testing or offensive exploitation tool. It is a strictly **passive correlation + defensive remediation explanation layer**.

---

## 🛡️ Safety & Guardrails (Strict Allowlist)

- Scans **only** hosts listed in `targets.allowlist` (e.g. `localhost`, `127.0.0.1`, `::1`).
- Default target is local **OWASP Juice Shop** (Docker). Third-party hosts cannot be scanned.
- **Passive checks only**: No exploit payloads, no fuzzing, no brute-forcing, and no attack scripts.
- **Prompt Injection Defense**: Target-derived banners and HTTP headers are sanitized and enclosed in `<target_data>` delimiters with strict LLM system safety rules.
- **Credential Protection**: Credentials come from `.env` or the default AWS IAM role/credential chain and are never committed to git.

---

## 📖 Security & Threat Intelligence Concepts (For 3rd Semester Students)

| Concept | Explanation |
| :--- | :--- |
| **CPE (Common Platform Enumeration)** | A structured naming scheme (e.g. `cpe:2.3:a:apache:http_server:2.4.49`) used to query NVD for exact version matches. |
| **CVSS (Common Vulnerability Scoring System)** | A 0.0 to 10.0 score reflecting theoretical flaw severity. |
| **CISA KEV (Known Exploited Vulnerabilities)** | A public catalog of vulnerabilities actively weaponized by real-world threat actors in the wild. |
| **EPSS (Exploit Prediction Scoring System)** | A machine-learning probability score (0.0 to 1.0 / 0% to 100%) predicting real-world exploitation in the next 30 days. |
| **SameSite Cookie Attribute** | Flag (`Strict`, `Lax`, `None`) that tells the browser whether to send cookies on cross-origin requests, preventing CSRF attacks. |
| **CORS (Cross-Origin Resource Sharing)** | Header policy controlling domain API access. A wildcard `Access-Control-Allow-Origin: *` allows any website to read sensitive API data. |
| **Security Headers (CSP, HSTS, XFO, XCTO)** | Defensive HTTP response configurations that harden the web application against XSS, clickjacking, and MIME sniffing. |

---

## 🏗️ Architecture Pipeline

```
OWASP Juice Shop (Docker on localhost:3000)
        │
        ▼
 [1] Discovery Stage
     ├── Port & Service Scan (Nmap -sV or TCP-connect fallback)
     ├── Passive HTTP Inspection (Title, CSP, HSTS, XFO, XCTO, Referrer-Policy)
     ├── Cookie Flag Hardening (Secure, HttpOnly, SameSite)
     ├── CORS Misconfiguration & Version Disclosure checks
     └── Local TLS Socket Inspection (Protocol version & Certificate analysis)
        │  data/discovered_assets.json
        ▼
 [2] Correlation & Threat Intelligence Stage
     ├── NVD REST API v2 lookup (CPE-based search with keyword fallback & disk cache)
     ├── CISA KEV Catalog matching (Cached for 24 hours)
     └── FIRST EPSS Threat Probability query
        │  data/correlated_findings.json
        ▼
 [3] AI Defensive Prioritization Stage
     ├── Amazon Bedrock model-agnostic Converse API (Amazon Nova / Anthropic Claude)
     ├── Prompt injection sanitization (<target_data> boundary)
     ├── Copy-paste defensive remediation snippets (Nginx / Express Helmet)
     └── Deterministic KEV > EPSS > CVSS heuristic fallback
        │  data/prioritized_report.json & data/history/run_<timestamp>_<target>.json
        ▼
 [4] Interactive Streamlit Dashboard & Evaluation
     ├── Live Metrics & Ranked Finding Cards
     ├── Scan History Diff Viewer (New, Resolved, Unchanged findings)
     ├── CSV & Standalone HTML Report Exports
     └── Benchmark Scoring (Precision, Recall, F1 & Spearman Rank Correlation)
```

---

## 🚀 Setup & Execution

### 1. Prerequisites
- Python 3.10+
- Docker (for OWASP Juice Shop)
- AWS Credentials / IAM Role with Amazon Bedrock permissions

### 2. Start OWASP Juice Shop Lab
```bash
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```

### 3. Installation
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate | Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env   # On Windows
```

Configure `.env` with your AWS credentials:
```ini
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=amazon.nova-micro-v1:0
DASHBOARD_PASSWORD=  # Optional password for Streamlit
```

Verify Bedrock connectivity:
```bash
python verify_access.py
```

---

## 💻 Running Scans

### Single Target Scan
```bash
python run_pipeline.py --target localhost --ports 80,443,3000,8000,8080
```

### Multi-Target Scan
```bash
python run_pipeline.py --targets localhost,127.0.0.1
```

---

## 📊 Evaluation & Validation

### 1. Benchmark Validation (Precision, Recall, F1)
```bash
python tests/validate.py
```
Output:
```
==============================================================
           VALIDATION BENCHMARK EVALUATION TABLE          
==============================================================
Target evaluated: localhost
--------------------------------------------------------------
  True Positives (TP):      5    (Successfully detected)
  False Negatives (FN):     1    (Missed expected checks)
  False Positives (FP):     1    (Spurious findings)
  Total Expected Items:     6   
  Total Report Findings:    3   
--------------------------------------------------------------
  RECALL:                   83.3%
  PRECISION:                83.3%
  F1-SCORE:                 83.3%
==============================================================
```

### 2. Ranking Methodology Comparison (Spearman Rank Correlation)
Compares plain CVSS vs Threat Intelligence (KEV/EPSS) vs AI Bedrock ranking:
```bash
python tests/compare_rankings.py
```

### 3. Unit Tests (Offline Test Suite)
```bash
python -m unittest discover -s tests
```

---

## 🖥️ Streamlit Dashboard

Launch the interactive web UI:
```bash
streamlit run dashboard/app.py
```

Features included:
- **Executive Summary & Threat Metrics**
- **Scan History & Diff Viewer**: Track remediation between runs (**New**, **Resolved**, **Unchanged**).
- **Download Reports**: Export standalone **HTML Reports** and **CSV Spreadsheets**.
- **Password Protection**: Enabled when `DASHBOARD_PASSWORD` is set in `.env`.

---

## ⚠️ Known Limitations & Scope

To maintain ethical defensive principles and prevent accidental damage:
1. **Application-Layer Challenges**: Inherent web application flaws (such as DOM XSS, SQL injection on login forms, and hidden scoreboards) require dynamic payload injection and are intentionally out of scope.
2. **Missing Version Banners**: If Nmap is not installed, the tool uses TCP-connect probing; NVD CVE lookups are limited without product version banners.
3. **Localhost SSL Labs**: SSL Labs requires publicly resolvable domain names. For localhost/Docker, the tool uses direct local Python TLS socket inspection.
