# Production Deployment Guide: Strands Decider 2B & Security Agent

This guide covers deploying the AI Attack Surface tool, the Strands Agent, and the **Strands Decider 2B server** on a single cheap AWS EC2 instance using **Docker Compose**.

---

## 1. Architecture Overview

```
                                      AWS CLOUD (Single EC2 Instance)
                                +---------------------------------------------------------------+
                                |                                                               |
                                |   Public Internet (Port 443 / 80)                             |
                                |                 │                                             |
                                |                 ▼                                             |
                                |       [ Caddy Reverse Proxy ]                                 |
                                |                 │                                             |
                                |                 ▼ (Port 8501)                                 |
                                |     [ Streamlit Dashboard + Agent ]                           |
                                |                 │                                             |
                                |                 ├──► data/ (Docker Volume: app_data)          |
                                |                 │                                             |
                                |                 │ (Internal Docker Bridge Network)            |
                                |                 ▼ (Port 8099 - CLOSED TO OUTSIDE)             |
                                |       [ Strands Decider 2B Server ]                           |
                                |                 │                                             |
                                |                 └──► ~/.cache/huggingface (Volume: hf_cache)  |
                                |                                                               |
                                +-------------------------------┬-------------------------------+
                                                                │
                                                                │ IAM Instance Profile
                                                                ▼ (bedrock:InvokeModel)
                                                   [ Amazon Bedrock Foundation Models ]
                                                   (Nova Micro & Claude Sonnet 4.5)
```

### Security & Cost Guarantees
* **One Single EC2 Instance:** Both services communicate over an internal Docker Compose bridge network.
* **Port 8099 is Closed Externally:** The Decider server is never exposed to the host network or public internet.
* **Zero Hardcoded Credentials:** The agent authenticates to Amazon Bedrock using an **EC2 IAM Instance Profile**.
* **Protected Dashboard:** Web access is gated by `DASHBOARD_PASSWORD`.
* **Safe Scans:** Defaults to passive OSINT reconnaissance. Active scanning is strictly constrained by `targets.allowlist` and the 30-day domain verification challenge.

---

## 2. Infrastructure Sizing & Cost Estimates

| Tier | EC2 Instance Type | vCPUs | RAM | Accelerator | Hourly Cost (On-Demand) [1] | 24-Hour Demo Cost | Decision Latency | Recommended Use |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CPU (Recommended)** | **`t3.xlarge`** | 4 | 16 GB | None (CPU) | **$0.1664 / hr** | **~$4.00** | measured on the deployed instance: TBD | **Best for judges / demo testing** |
| **Compute CPU** | **`c6i.xlarge`** | 4 | 8 GB | None (CPU) | **$0.1700 / hr** | **~$4.08** | measured on the deployed instance: TBD | Standard CPU option |
| **GPU Option** | **`g4dn.xlarge`** | 4 | 16 GB | 1x NVIDIA T4 (16GB) | **$0.5260 / hr** | **~$12.60** | measured on the deployed instance: TBD | High throughput GPU |

*Sources:*
- [1] AWS EC2 On-Demand Pricing for `us-east-1` (Source: https://aws.amazon.com/ec2/pricing/on-demand/).
- [2] EBS gp3 root storage: $0.08 / GB-month (Source: AWS EBS Pricing). 40 GB = ~$3.20/month (~$0.10/day).
- [3] Bedrock Foundation Models: Amazon Nova Micro input $0.035 / 1M tokens, output $0.14 / 1M tokens; Claude Sonnet 4.5 input $3.00 / 1M tokens, output $15.00 / 1M tokens (Source: https://aws.amazon.com/bedrock/pricing/).

---

## 3. Step-by-Step Deployment Walkthrough

### Step A: Provision EC2 & IAM Role via Terraform

Deploy the infrastructure using Terraform (`deploy/terraform/main.tf`):

```bash
cd deploy/terraform
terraform init
terraform apply -var="admin_ip=$(curl -s http://checkip.amazonaws.com)/32"
```

*Note: Port 8501 is closed in the security group. Only ports 80/443 are public, and SSH is restricted to your admin IP.*

---

### Step B: Connect to the EC2 Instance & Launch Containers

1. **SSH into your EC2 host** (or connect via AWS Systems Manager Session Manager):
   ```bash
   ssh -i your-key.pem ec2-user@<EC2_PUBLIC_IP>
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/ai-attack-surface-tool.git /opt/ai-attack-surface-tool
   cd /opt/ai-attack-surface-tool
   ```

3. **Run the automated setup script**:
   ```bash
   chmod +x deploy/ec2_setup.sh
   ./deploy/ec2_setup.sh
   ```
   *The script automatically installs Docker, Docker Compose, generates a secure random `DASHBOARD_PASSWORD` in `.env`, builds the images, and launches the services.*

4. **Verify running containers**:
   ```bash
   docker compose ps
   ```
   You should see `strands_decider` (healthy), `attack_surface_app` (healthy), and `caddy_proxy` (running).

---

## 4. Run the Production Smoke Test

Once the containers are up, execute the included smoke test script to verify all four layers:

```bash
docker compose exec app python deploy/smoke_test.py
```

Expected output format:
```text
================================================================================
  PRODUCTION SMOKE TEST: STRANDS DECIDER + AGENT DEPLOYMENT
================================================================================
Decider URL:   http://decider:8099
Dashboard URL: http://127.0.0.1:8501

[1/4] Checking Strands Decider 2B Health...
      [PASS] Decider is healthy! Model: strands-decider-2B-qwen3.5-v1-2610, Device: cpu

[2/4] Testing Decider 2B Inference Decision Call...
      [PASS] Decision successful! P(grounded) = 0.9412 (latency: measured on the deployed instance: TBD)

[3/4] Testing Amazon Bedrock (amazon.nova-micro-v1:0 in us-east-1)...
      [PASS] Bedrock Converse responded: 'READY' (latency: measured on the deployed instance: TBD)

[4/4] Checking Dashboard Web Service & Login Page (http://127.0.0.1:8501)...
      [PASS] Dashboard responded with HTTP 200 OK! Shell rendered successfully.

================================================================================
  [+] ALL 4 SMOKE TESTS PASSED! System is fully operational.
================================================================================
```

---

## 5. Reverse Proxy & Domain Configuration Options

### Option A: Direct IP Access (No Domain Configured - Default)
* In `.env`, leave `DOMAIN_NAME=` blank.
* Caddy automatically binds to **Port 80 (HTTP)** and reverse-proxies directly to Streamlit (`app:8501`).
* Access URL: `http://<EC2_PUBLIC_IP>`

### Option B: Custom Domain with Automatic Let's Encrypt HTTPS
* Point an `A` record (e.g. `agent.example.com`) to the EC2 Public IP.
* In `.env`, set:
  ```bash
  DOMAIN_NAME=agent.example.com
  ```
* Restart Caddy: `docker compose restart caddy`.
* Caddy automatically negotiates and renews Let's Encrypt TLS certificates, listening on **Port 443 (HTTPS)** with automatic HTTP -> HTTPS redirection.
* Access URL: `https://agent.example.com`

### Option C: AWS Application Load Balancer (ALB) + ACM Certificate
* If your organization manages certificates in AWS Certificate Manager (ACM):
  1. Create an ALB with an HTTPS listener (port 443) using your ACM certificate.
  2. Create a Target Group pointing to EC2 instance on Port 80 (HTTP).
  3. The ALB terminates TLS and forwards clean HTTP traffic to Caddy/App.

---

## 6. Accessing the Dashboard (Judge Demo)

1. Open your browser and navigate to:
   ```text
   http://<EC2_PUBLIC_IP>
   ```
   *(Or `https://<YOUR_DOMAIN>` if configured)*.

2. Enter the `DASHBOARD_PASSWORD` generated by `ec2_setup.sh` (or set in `.env`).

3. Try entering:
   * **Grounded Scan:** Ask the agent in the Copilot tab to *"Run a passive scan on github.com"*. The Decider verifies grounding and executes immediately.
   * **Hallucinated Target:** Ask the agent to *"Analyze security concepts"* and simulate a tool call against an unmentioned target. The Decider guardrail intercepts the action with `Guide`.
   * **Unauthorized Target:** Try an active scan on `8.8.8.8`. The hard gate allowlist immediately triggers a `Deny`.

---

## 6. Data Persistence & Optional S3 Backup

* By default, all scan history, verified domain records, and cached CVEs are stored in the persistent Docker volume `attack_surface_app_data` (`/app/data`).
* **Optional S3 Sync Upgrade:**
  To sync scan outputs to an S3 bucket automatically after each run:
  ```bash
  # In host cron:
  aws s3 sync /var/lib/docker/volumes/attack_surface_app_data/_data/ s3://my-attack-surface-reports/
  ```

---

## 7. Teardown Instructions (Stop AWS Charges)

When the hackathon demo or judging is complete, terminate the resources immediately to prevent ongoing charges:

### If deployed via Terraform:
```bash
cd deploy/terraform
terraform destroy -auto-approve
```

### If deployed manually via AWS Console:
1. Navigate to **EC2 > Instances** > Select `Strands-Decider-Security-Agent` > **Terminate Instance**.
2. Navigate to **IAM > Roles** > Delete `strands-security-agent-ec2-role`.
3. Navigate to **EC2 > Security Groups** > Delete `strands-agent-sg`.
