# AI-Assisted Attack Surface & Vulnerability Correlation Tool

Academic EL project. Discovers what is exposed on a **lab target you control**, looks up **public CVE records** (NVD), ranks and explains findings with **Amazon Bedrock (Claude)**, and shows them in **Streamlit**.

It is **not** a replacement for Shodan, Snyk, or Amazon Inspector. It is a small **correlation + explanation** layer.

## Safety

- Scans **only** hosts in `targets.allowlist` (default: `localhost`, `127.0.0.1`, `::1`).
- Default target is local **OWASP Juice Shop** (Docker). Do not add third-party sites.
- No exploit code, payloads, or attack scripts. Nmap banner detection and HTTP header reads only.
- API keys and AWS credentials stay in `.env` / `aws configure`, never in git.

## Architecture

```
Juice Shop (Docker, localhost)
        │
        ▼
 Discovery (Nmap or TCP fallback, HTTP headers, SSL Labs skip on localhost)
        │  data/discovered_assets.json
        ▼
 Correlation (NVD CVE API + config issues)
        │  data/correlated_findings.json
        ▼
 Prioritization (Bedrock Claude, or CVSS heuristic fallback)
        │  data/prioritized_report.json
        ▼
 Streamlit dashboard
        │
        ▼
 Validation vs tests/juice_shop_known.json
```

## Prerequisites

- Python 3.11+
- Docker
- AWS CLI configured (`aws configure`) with permission to invoke **Bedrock Runtime** in your region
- Bedrock **model access** approved for a Claude model
- Optional: [Nmap](https://nmap.org/download.html) on PATH (better banners). Without it, the tool still TCP-probes the configured ports.

## Juice Shop

```bash
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```

Open http://127.0.0.1:3000 in a browser before scanning.

## Setup

```bash
cd ai-attack-surface-tool
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env   # Windows
# Edit .env: AWS_REGION and BEDROCK_MODEL_ID must match the Bedrock console.
```

On some accounts the model ID is an **inference profile** (for example `us.anthropic.claude-3-5-sonnet-20241022-v2:0`). Copy the exact ID from Amazon Bedrock → Model access / inference profiles.

Optional: set `NVD_API_KEY` (https://nvd.nist.gov/developers/request-an-api-key) so NVD is faster. Without a key, lookups sleep ~6s between queries to respect public rate limits.

```bash
python verify_access.py
python tests/test_allowlist.py
```

## Run the pipeline

```bash
python run_pipeline.py --target localhost --ports 80,443,3000,8000,8080
```

Writes:

- `data/discovered_assets.json`
- `data/correlated_findings.json`
- `data/prioritized_report.json`

If Bedrock fails, ranking still runs using CVSS + config heuristics so the demo is not blocked.

## Dashboard

```bash
streamlit run dashboard/app.py
```

## Validation

Edit `tests/juice_shop_known.json` if your mentor wants a different confirmed list.

```bash
python tests/validate.py
```

Recall is scored only on **detectable** items (open HTTP port, missing TLS, missing security headers). Juice Shop *application* challenges (SQLi, XSS, score board) are listed as **out of scope** — this tool does not attack the app, so those are not false negatives.

## Why not Shodan / Snyk / Inspector?

| Tool | What it does | What this project adds |
| --- | --- | --- |
| Shodan | Internet-wide exposure index | We only scan an allowlisted lab host |
| Snyk / CodeQL | Source/dependency flaws | We do not scan a git repo; we join **exposure + public CVEs** |
| Amazon Inspector | AWS workload findings | Not available on this account type; we use **NVD + lab validation** |

## Project layout

```
config.py              allowlist + env
run_pipeline.py        one-command path
verify_access.py       AWS/Bedrock check
discovery/             ports, HTTP headers, TLS
correlation/           NVD + merge
ai/prioritize.py       Bedrock JSON ranking
dashboard/app.py       Streamlit
tests/                 allowlist unit test + validate.py
data/                  generated JSON (gitignored)
```
