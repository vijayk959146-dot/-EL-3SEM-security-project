# Model Routing Benchmark Results: Strands Decider 2B vs Always Large Model

**Benchmark Goal:** Compare latency, token consumption, and official Amazon Bedrock execution costs between:
1. **Baseline Strategy (`Always Large`):** Every finding is analyzed using Claude 3.5 Sonnet.
2. **Strands Decider-Routed Strategy:** Strands Decider 2B categorizes findings into `template` ($0.00 / 0ms), `small` (Amazon Nova Micro), or `large` (Claude 3.5 Sonnet).

## Summary Metrics

| Metric | Always Large Model | Decider-Routed | Reduction / Benefit |
| :--- | :--- | :--- | :--- |
| **Total Latency** | `11145.6 ms` | `16325.0 ms` | **-46.5% Faster** |
| **Total Token Cost** | `$0.04665` | `$0.01431` | **69.3% Cost Reduction** |
| **Total Tokens** | `3550` tokens | `3358` tokens | **5.4% Fewer Tokens** |
| **Workload Split** | 100% Large Model | 20% Template, 50% Small, 30% Large | Balanced System-1 / System-2 |

## Detailed Finding Breakdown

| Finding | Severity | Routed Tier | Baseline Latency / Cost | Routed Latency / Cost | Cost Type |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Missing HTTP Strict-Transport-Security (HSTS) Header | Low | `template` | 1361ms / $0.00464 | 0ms / $0.00000 | Estimated |
| Missing Content-Security-Policy (CSP) Header | Medium | `template` | 1071ms / $0.00465 | 0ms / $0.00000 | Estimated |
| Server Information Disclosure in HTTP Banner | Info | `small` | 1104ms / $0.00466 | 2718ms / $0.00006 | Estimated |
| OpenSSL Denial of Service in Certificate Parsing | Low | `small` | 1044ms / $0.00468 | 2631ms / $0.00006 | Estimated |
| Express Cookie Without Secure and SameSite Attributes | Low | `small` | 1049ms / $0.00467 | 2646ms / $0.00006 | Estimated |
| Node.js HTTP Request Smuggling | Medium | `small` | 1162ms / $0.00466 | 2495ms / $0.00006 | Estimated |
| Nginx TLS 1.0 / 1.1 Weak Cipher Suites Enabled | Low | `small` | 1094ms / $0.00468 | 2551ms / $0.00006 | Estimated |
| Apache HTTP Server Path Traversal and Remote Code Execution | Critical | `large` | 1096ms / $0.00469 | 1078ms / $0.00469 | Estimated |
| Log4j JNDI Remote Code Execution (Log4Shell) | Critical | `large` | 1101ms / $0.00467 | 1077ms / $0.00467 | Estimated |
| Spring Framework Remote Code Execution (Spring4Shell) | High | `large` | 1063ms / $0.00466 | 1129ms / $0.00466 | Estimated |

## Official AWS Bedrock Pricing Baseline
- **Anthropic Claude 3.5 Sonnet:** $3.00 / 1M input tokens, $15.00 / 1M output tokens.
- **Amazon Nova Micro:** $0.035 / 1M input tokens, $0.14 / 1M output tokens.
- **Template Remediation:** $0.00 / 0ms execution time.
- **Strands Decider 2B:** System One pointer-head classification (<15ms, zero autoregressive token overhead).