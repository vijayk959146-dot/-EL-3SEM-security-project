# What's New: AWS Agent Experience Hackathon Edition

This document delineates the pre-existing attack surface scanner components from the new agentic intelligence, decision patterns, and deployment infrastructure created specifically for the **AWS Agent Experience Hackathon: Strands Decider**.

---

## 1. Existing Before the Hackathon

The underlying passive reconnaissance, correlation, and defensive visualization capabilities were developed prior to the hackathon as an academic 3rd-semester project (see original commits `1dd959e` through `63e069f`):

* **`discovery/`**:
  - `dns_recon.py`, `tls_audit.py`, `headers.py`, `cert_transparency.py`: Passive OSINT discovery methods.
  - `safe_fetch.py`: SSRF prevention, IP validation (blocking loopback/private/cloud metadata `169.254.169.254`), and manual redirect re-validation.
* **`correlation/`**:
  - `nvd.py`, `cisa_kev.py`, `epss.py`: Matching discovered banners against NIST NVD CVEs, CISA Known Exploited Vulnerabilities catalog, and FIRST EPSS exploit probability scores.
  - `compliance.py`: Mapping posture to CIS, OWASP Top 10, and NIST standards.
* **`verification/`**:
  - `verify.py`: Cryptographic domain ownership verification via DNS TXT records or `.well-known/attacksurface-verify.txt` challenge tokens with 30-day TTL.
* **`backend/`**:
  - `backend/service.py`: Orchestration layer defining scan boundaries, request parsing, and `ScanResult` contracts.
* **`ai/`**:
  - `ai/copilot.py`: Initial Amazon Bedrock Converse API integration for defensive remediation summaries.
* **`remediation/`**:
  - `waf_rules.py`, `fix_scripts.py`: Deterministic configuration hardening generators (Nginx, Apache, WAF rules).
* **`dashboard/`**:
  - `dashboard/app.py`: Streamlit-based Cyber SOC HUD interface, D3.js interactive attack graphs, and CSV/HTML report exporters.
* **`storage.py`, `config.py`, `schemas.py`**:
  - File-based persistence, environment configuration, and dataclass schemas.
* **Original Tests**:
  - `tests/test_unit.py`, `tests/test_allowlist.py`, `tests/validate.py`, `tests/compare_rankings.py`.

---

## 2. Built for the Hackathon

The following packages, decision patterns, evaluation suites, and deployment infrastructure were designed and implemented specifically for the **Strands Decider Hackathon** (commits `0663146` through `9fd0a9c`):

* **`agent/` (Strands Agents SDK Integration)**:
  - `agent/core.py`: Implementation of `create_security_agent()` pairing Amazon Bedrock foundation models with the Strands Agents SDK runtime.
  - `agent/tools.py`: Safe, wrapped defensive tools (`passive_scan`, `active_scan`, `correlate`, `explain`) exposed to the agent.
* **`decision_patterns/` (Reusable Architectural Patterns)**:
  - **`decision_patterns/grounded_tool_call/` (#guardrails - Primary Pattern)**:
    * `client.py`: High-performance HTTP client for Strands Decider 2B (`POST /v1/systemone`).
    * `intervention.py`: `GroundedToolCallIntervention` extending Strands SDK `InterventionHandler`.
    * Implements a **Two-Tier Defense**: Tier 1 Deterministic Hard Gate (`is_target_allowed`) always executes first (blocking unauthorized active scans with `Deny` without touching the model); Tier 2 queries Strands Decider 2B with a typed `noul` question to verify the target and ports are grounded in the user's prompt (issuing `Guide` if ungrounded).
    * Strictly fail-closed: Defaults to `Deny` on timeouts or runtime exceptions.
    * Complete drop-in guide in `decision_patterns/grounded_tool_call/README.md`.
  - **`decision_patterns/model_routing/` (#routing - Second Decision Pattern)**:
    * `router.py`: `FindingRouter` leveraging Strands Decider 2B `choice` classification to dynamically route security findings to Static Templates ($0.00 / instant), Amazon Nova Micro (`amazon.nova-micro-v1:0`), or Amazon Nova Pro (`amazon.nova-pro-v1:0`).
    * `benchmark.py`: Comparative benchmark measuring real Amazon Bedrock Converse API token consumption and costs.
* **`evals/` (Guardrail Live Benchmark Suite)**:
  - `evals/eval_guardrail_live.py`: Autonomous evaluation harness running 25 benchmark cases against a live Strands Decider server, strictly aborting if the server is offline.
* **`tests/` (Guardrail Test Suite)**:
  - `tests/guardrail_dataset.py`: 25 curated test cases covering grounded, hallucinated, ambiguous, prompt injection, and hard gate boundary conditions.
  - `tests/test_guardrails.py`: 8 mock unit tests verifying intervention control flow and fail-closed guarantees without requiring live model infrastructure.
* **`deploy/` (Single-Instance EC2 Production Deployment)**:
  - `docker-compose.yml`: Multi-container architecture orchestrating the application, Strands Decider 2B, and Caddy reverse proxy.
  - `deploy/Dockerfile.decider`: Container packaging `strands-decider serve` with CPU inference and persistent Hugging Face cache.
  - `deploy/Caddyfile`: Reverse proxy providing automatic Let's Encrypt TLS and Streamlit-compatible Content Security Policy (CSP) headers.
  - `deploy/terraform/main.tf`: Infrastructure as Code provisioning `t3.xlarge` EC2 instance, security groups with port 8501/8099 closed externally, and least-privilege IAM instance profile scoped to exact Bedrock model ARNs.
  - `deploy/smoke_test.py`: Post-deployment verification script validating Decider `/health`, pointer-head inference, Bedrock Converse, and Dashboard HTTP 200.
  - `DEPLOY.md`: Production deployment guide with step-by-step instructions.
* **Dashboard & Service Enhancements**:
  - `dashboard/app.py`: Integrated Strands agent in SOC Copilot tab, added per-session Bedrock rate limiter (`MAX_BEDROCK_QUERIES_PER_SESSION=20`) to prevent runaway costs on the public demo.
