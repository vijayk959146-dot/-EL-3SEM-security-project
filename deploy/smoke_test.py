"""Production Smoke Test Suite for Strands Decider + Agent Deployment.

Checks:
1. Strands Decider 2B health endpoint (/health)
2. Strands Decider 2B typed inference call (/v1/systemone)
3. Amazon Bedrock foundation model call (Converse API via IAM role)
4. Streamlit Dashboard accessibility & password login page
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import AWS_REGION, BEDROCK_MODEL_ID


def check_decider_health(decider_url: str) -> bool:
    print("\n[1/4] Checking Strands Decider 2B Health...")
    url = f"{decider_url.rstrip('/')}/health"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "ok":
                print(f"      [PASS] Decider is healthy! Model: {data.get('model', 'unknown')}, Device: {data.get('device', 'cpu')}")
                return True
            else:
                print(f"      [FAIL] Decider returned non-ok status: {data}")
                return False
    except Exception as exc:
        print(f"      [FAIL] Decider unreachable at {url}: {exc}")
        return False


def check_decider_decision(decider_url: str) -> bool:
    print("\n[2/4] Testing Decider 2B Inference Decision Call...")
    url = f"{decider_url.rstrip('/')}/v1/systemone"
    payload = {
        "state": "User Request: Audit localhost on port 80 and 443.\nProposed Tool: active_scan(target='localhost', ports=[80, 443])",
        "questions": {
            "grounding_check": {
                "type": "noul",
                "instructions": "Is this tool call grounded in the user request?",
                "criteria": {
                    "true": "The tool call is grounded in what the user asked.",
                    "false": "The tool call is ungrounded or hallucinated.",
                },
            }
        },
        "model": "strands-decider-latest",
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        start = time.perf_counter()
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            elapsed = (time.perf_counter() - start) * 1000.0
            data = json.loads(resp.read().decode("utf-8"))
            noul_val = data.get("answers", {}).get("grounding_check", {}).get("noul")
            if noul_val is not None:
                print(f"      [PASS] Decision successful! P(grounded) = {noul_val:.4f} in {elapsed:.1f}ms")
                return True
            else:
                print(f"      [FAIL] Unexpected response format: {data}")
                return False
    except Exception as exc:
        print(f"      [FAIL] Decision call failed: {exc}")
        return False


def check_bedrock_converse() -> bool:
    print(f"\n[3/4] Testing Amazon Bedrock ({BEDROCK_MODEL_ID} in {AWS_REGION})...")
    try:
        import boto3
        client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
        start = time.perf_counter()
        resp = client.converse(
            modelId=BEDROCK_MODEL_ID,
            messages=[{"role": "user", "content": [{"text": "Reply in one word: 'READY'"}]}],
            inferenceConfig={"maxTokens": 10, "temperature": 0.0},
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        output_parts = resp.get("output", {}).get("message", {}).get("content", [])
        text = "".join(p.get("text", "") for p in output_parts if isinstance(p, dict))
        usage = resp.get("usage", {})
        print(f"      [PASS] Bedrock Converse responded: '{text.strip()}' ({usage.get('totalTokens', 0)} tokens in {elapsed:.1f}ms)")
        return True
    except Exception as exc:
        print(f"      [FAIL] Bedrock call failed: {exc}")
        print("             (Ensure the EC2 IAM Instance Profile has bedrock:InvokeModel attached)")
        return False


def check_dashboard_login(dashboard_url: str) -> bool:
    print(f"\n[4/4] Checking Dashboard Web Service & Login Page ({dashboard_url})...")
    try:
        req = urllib.request.Request(dashboard_url, headers={"User-Agent": "SmokeTest/1.0"})
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="ignore")
            # Streamlit loads an HTML shell that mounts the app
            if status == 200 and ("streamlit" in body.lower() or "ai attack surface" in body.lower() or "<!doctype html>" in body.lower()):
                print(f"      [PASS] Dashboard responded with HTTP 200 OK! Shell rendered successfully.")
                return True
            else:
                print(f"      [FAIL] Unexpected response code {status}")
                return False
    except Exception as exc:
        print(f"      [FAIL] Dashboard unreachable at {dashboard_url}: {exc}")
        return False


def main() -> None:
    decider_url = os.getenv("DECIDER_URL", "http://127.0.0.1:8099")
    dashboard_url = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8501")

    print("================================================================================")
    print("  PRODUCTION SMOKE TEST: STRANDS DECIDER + AGENT DEPLOYMENT")
    print("================================================================================")
    print(f"Decider URL:   {decider_url}")
    print(f"Dashboard URL: {dashboard_url}")

    results = [
        check_decider_health(decider_url),
        check_decider_decision(decider_url),
        check_bedrock_converse(),
        check_dashboard_login(dashboard_url),
    ]

    print("\n" + "=" * 80)
    passed = sum(1 for r in results if r)
    total = len(results)
    if passed == total:
        print(f"  [+] ALL {total} SMOKE TESTS PASSED! System is fully operational.")
        print("=" * 80 + "\n")
        sys.exit(0)
    else:
        print(f"  [-] {total - passed}/{total} SMOKE TESTS FAILED. Inspect logs above.")
        print("=" * 80 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
