"""Run discovery → NVD correlation → Bedrock (or fallback) ranking."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai.prioritize import prioritize
from config import DEFAULT_PORTS, DEFAULT_TARGET, require_allowed_target
from correlation.correlate import correlate
from discovery.run import discover


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-assisted attack-surface correlation (allowlisted targets only)."
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Host to scan (must be allowlisted)")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Comma-separated TCP ports",
    )
    args = parser.parse_args()
    host = require_allowed_target(args.target)
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    print(f"[1/3] Discovering {host} ports={ports} ...")
    assets = discover(host, ports)
    print(f"      open ports: {len(assets.ports)}  method: {assets.scan_method}")
    if "fallback" in assets.scan_method:
        print("      [NOTE] Nmap binary not found in PATH; used TCP connect fallback scan.")

    print("[2/3] Correlating with NVD ...")
    correlated = correlate(assets.to_dict())
    cve_count = sum(len(a.cves) for a in correlated.assets)
    print(f"      assets: {len(correlated.assets)}  CVE hits: {cve_count}")

    print("[3/3] Prioritizing with Bedrock (fallback if needed) ...")
    report = prioritize(correlated.to_dict())
    print(f"      findings: {len(report.findings)}  llm={report.used_llm}")
    if not report.used_llm:
        fallback_reasons = [n for n in report.notes if "fallback" in n.lower() or "reason" in n.lower()]
        reason_msg = fallback_reasons[-1] if fallback_reasons else "CVSS heuristic ranking"
        print(f"      [NOTE] Bedrock not reached; used CVSS heuristic fallback. ({reason_msg})")

    print("Wrote data/discovered_assets.json, correlated_findings.json, prioritized_report.json")
    print("Dashboard: streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
