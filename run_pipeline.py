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
from storage import save_run_history, write_json


def run_target(host: str, ports: list[int]) -> None:
    """Execute the defensive 3-stage pipeline for a single allowlisted target."""
    print(f"\n=======================================================")
    print(f"[*] Starting Security Pipeline for Target: {host}")
    print(f"=======================================================")

    print(f"[1/3] Discovering {host} ports={ports} ...")
    assets = discover(host, ports)
    print(f"      open ports: {len(assets.ports)}  method: {assets.scan_method}")
    if "fallback" in assets.scan_method:
        print("      [NOTE] Nmap binary not found in PATH; used TCP connect fallback scan.")

    print("[2/3] Correlating with NVD, CISA KEV, and FIRST EPSS ...")
    correlated = correlate(assets.to_dict())
    cve_count = sum(len(a.cves) for a in correlated.assets)
    kev_count = sum(1 for a in correlated.assets for c in a.cves if getattr(c, "kev", False) or (isinstance(c, dict) and c.get("kev")))
    print(f"      assets: {len(correlated.assets)}  CVE hits: {cve_count}  (KEV exploited: {kev_count})")

    print("[3/3] Prioritizing with Bedrock (fallback if needed) ...")
    report = prioritize(correlated.to_dict())
    print(f"      findings: {len(report.findings)}  llm={report.used_llm}")
    if not report.used_llm:
        fallback_reasons = [n for n in report.notes if "fallback" in n.lower() or "reason" in n.lower()]
        reason_msg = fallback_reasons[-1] if fallback_reasons else "CVSS heuristic ranking"
        print(f"      [NOTE] Bedrock not reached; used CVSS heuristic fallback. ({reason_msg})")

    # Save target-specific report and timestamped history
    write_json(f"report_{host.replace(':', '_')}.json", report)
    hist_path = save_run_history(host, report.to_dict())
    print(f"[+] Archived historical run to {hist_path.name}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AI-assisted attack-surface correlation (allowlisted targets only)."
    )
    parser.add_argument("--target", default=None, help="Single host to scan (must be allowlisted)")
    parser.add_argument("--targets", default=None, help="Comma-separated list of hosts to scan (e.g. localhost,127.0.0.1)")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Comma-separated TCP ports",
    )
    args = parser.parse_args()
    
    # Resolve targets list
    target_str = args.targets or args.target or DEFAULT_TARGET
    raw_targets = [t.strip() for t in target_str.split(",") if t.strip()]
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    # Validate all targets against allowlist before scanning
    validated_hosts = [require_allowed_target(t) for t in raw_targets]

    for host in validated_hosts:
        run_target(host, ports)

    print("\n[+] Scan complete. Data written to data/ and data/history/")
    print("[+] Dashboard: streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
