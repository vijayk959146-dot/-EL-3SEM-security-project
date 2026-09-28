"""Run discovery → NVD correlation → Bedrock (or fallback) ranking."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai.prioritize import prioritize
from config import DEFAULT_PORTS, DEFAULT_TARGET, is_target_allowed, require_allowed_target
from correlation.correlate import correlate
from discovery.passive import discover_passive
from discovery.run import discover
from storage import save_run_history, write_json


def run_target(host: str, ports: list[int], force_passive: bool = False) -> None:
    """Execute the defensive pipeline in either Active or Passive mode."""
    # Determine mode: Active requires allowlist or active verification
    can_active = is_target_allowed(host) and not force_passive
    mode_str = "ACTIVE (Port scanning & banner correlation)" if can_active else "PASSIVE OSINT (Read-only headers, DNS, TLS, CT logs)"

    print(f"\n=======================================================")
    print(f"[*] Starting Security Pipeline for Target: {host}")
    print(f"[*] Operational Mode: {mode_str}")
    if not can_active and not force_passive:
        print(f"[*] Note: Target '{host}' is not in targets.allowlist and not verified.")
        print(f"    Running in 100% passive mode. (To authorize active scans: python -m verification start {host})")
    print(f"=======================================================")

    if can_active:
        print(f"[1/3] Discovering {host} ports={ports} ...")
        assets = discover(host, ports)
        print(f"      open ports: {len(assets.ports)}  method: {assets.scan_method}")
        if "fallback" in assets.scan_method:
            print("      [NOTE] Nmap binary not found in PATH; used TCP connect fallback scan.")
    else:
        print(f"[1/3] Gathering passive intelligence for {host} (no port scanning) ...")
        assets = discover_passive(host)
        print(f"      reachable: {assets.http.reachable if assets.http else False}  method: {assets.scan_method}")

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
        description="AI-assisted attack-surface correlation (allowlisted active scans + public passive scans)."
    )
    parser.add_argument("--target", default=None, help="Single host or domain to check")
    parser.add_argument("--targets", default=None, help="Comma-separated list of hosts or domains")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="Comma-separated TCP ports (used for active scans only)",
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Force passive OSINT mode even if target is allowlisted or verified",
    )
    args = parser.parse_args()
    
    # Resolve targets list
    target_str = args.targets or args.target or DEFAULT_TARGET
    raw_targets = [t.strip() for t in target_str.split(",") if t.strip()]
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]

    for host in raw_targets:
        run_target(host, ports, force_passive=args.passive_only)

    print("\n[+] Scan complete. Data written to data/ and data/history/")
    print("[+] Dashboard: streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
