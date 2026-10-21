# Reusable Decision Pattern: Model Routing with Strands Decider 2B

**Pattern Tag:** `#routing` / `#guardrails`  
**Classification Engine:** Strands Decider 2B (`POST /v1/systemone`)  
**Execution Runtime:** Amazon Bedrock (Nova Micro & Claude 3.5 Sonnet) + Static Hardening Templates  

---

## 1. Problem & Architecture

In vulnerability management and attack-surface analysis, treating every finding with a frontier LLM (e.g., Anthropic Claude 3.5 Sonnet) is economically wasteful and slow:
* **Missing HTTP security headers** (HSTS, CSP, X-Frame-Options) have deterministic, standard configuration snippets. They do not need an LLM.
* **Low/Medium informational CVEs** require basic synthesis that a compact, fast model (like Amazon Nova Micro) handles with high fidelity at a fraction of the cost.
* **Critical / CISA KEV actively exploited vulnerabilities** demand deep contextual reasoning, blast-radius analysis, and multi-CVE correlation that benefit from a frontier model.

The **Strands Decider 2B Model Routing Pattern** classifies each finding in under 15ms using a single pointer-head pass before dispatching execution to the right tier.

```mermaid
flowchart TD
    Finding[Vulnerability Finding] --> Decider{Strands Decider 2B}
    Decider -- template --> T1[Static Template Engine]
    Decider -- small --> T2[Amazon Bedrock: Nova Micro]
    Decider -- large --> T3[Amazon Bedrock: Claude 3.5 Sonnet]
    
    T1 --> Out1[0ms Latency | $0.00 Token Cost]
    T2 --> Out2[Fast Latency | $0.00006 Cost]
    T3 --> Out3[Deep Reasoning | $0.0046 Cost]
```

---

## 2. Decider 2B Typed Question Specification

The router uses a typed **`choice`** question evaluated over finding metadata:

* **Question Type:** `choice`
* **Instructions:**
  ```text
  Which execution tier should explain this security finding?
  ```
* **Option Set & Criteria:**
  * `template`: `"Missing HTTP security headers (CSP, HSTS, X-Frame-Options) or static server tokens with known static configuration fixes."`
  * `small`: `"Low or Medium severity CVE, basic informational findings, or single isolated configuration issues with straightforward fixes."`
  * `large`: `"Critical or High severity CVEs, CISA KEV actively exploited flaws, high EPSS scores (>0.20), or complex multi-step attack risks."`

---

## 3. Real-World Benchmark Results

Ran across a 10-finding benchmark comparing **Baseline (Always Claude 3.5 Sonnet)** vs **Decider-Routed**:

| Metric | Always Large (Claude 3.5 Sonnet) | Strands Decider-Routed | Impact |
| :--- | :--- | :--- | :--- |
| **Total Token Cost** | **$0.04665** | **$0.01431** | **69.3% Cost Reduction** |
| **Tokens Consumed** | 3,550 tokens | 3,358 tokens | 5.4% Fewer Tokens |
| **Workload Split** | 100% Large Model | 20% Template, 50% Small, 30% Large | Optimized Resource Allocation |

*All token counts and latencies are measured from live Amazon Bedrock Converse API invocations.*

---

## 4. Drop-In Code Example

```python
from decision_patterns.model_routing.router import FindingRouter

router = FindingRouter()

finding = {
    "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
    "severity": "Low",
    "exploitability": "Protocol downgrade vulnerability",
    "related_cves": []
}

# 1. Decider picks the best execution tier
tier, confidence = router.route(finding)
print(f"Decider routed to: {tier} (confidence: {confidence:.2f})")

# 2. Execute remediation with chosen tier
result = router.execute_with_tier(finding, tier=tier)
print(f"Cost: ${result.cost_usd:.6f} | Model: {result.model_id}")
```
