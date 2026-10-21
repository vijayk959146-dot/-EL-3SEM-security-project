"""
Command line interface for domain ownership verification.
Usage:
  python -m verification start <domain>
  python -m verification check <domain>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verification.verify import check_verification, is_domain_verified, start_verification

CAVEAT_MESSAGE = """
[!] IMPORTANT SECURITY CAVEAT:
    Ownership verification proves administrative control over a domain name / web root.
    It does NOT imply ownership or authorization over third-party shared infrastructure,
    cloud multi-tenant load balancers, or intermediate ISPs.
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Domain Ownership Verification for AI Attack Surface & Vulnerability Tool"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    start_parser = subparsers.add_parser("start", help="Generate a verification token and instructions for a domain")
    start_parser.add_argument("domain", help="Domain name to verify (e.g. example.com)")

    check_parser = subparsers.add_parser("check", help="Validate DNS TXT or HTTP .well-known proof for a domain")
    check_parser.add_argument("domain", help="Domain name to check")

    args = parser.parse_args()

    if args.action == "start":
        inst = start_verification(args.domain)
        print("================================================================================")
        print(f"       DOMAIN OWNERSHIP VERIFICATION CHALLENGE: {inst['domain']}                ")
        print("================================================================================")
        print(f"Generated Challenge Token: {inst['token']}\n")
        print("To prove ownership and authorize active scanning, complete EITHER of these two methods:\n")
        print("Option 1: DNS TXT Record (Recommended for root domains)")
        print(f"  Record Host/Name:  {inst['dns_record']}")
        print(f"  Record Type:       TXT")
        print(f"  Record Value:      {inst['dns_value']}\n")
        print("Option 2: Web Server .well-known File (Recommended for web hosts)")
        print(f"  File URL:          {inst['file_url']}")
        print(f"  File Content:      {inst['file_content']}\n")
        print("Once configured, run the verification check:")
        print(f"  python -m verification check {inst['domain']}")
        print(CAVEAT_MESSAGE)

    elif args.action == "check":
        success, message = check_verification(args.domain)
        print("================================================================================")
        print(f"       CHECKING DOMAIN VERIFICATION STATUS: {args.domain}                       ")
        print("================================================================================")
        if success:
            print(f"[+] SUCCESS: {message}")
            print(CAVEAT_MESSAGE)
        else:
            print(f"[-] PENDING/FAILED: {message}")
            print("\nPlease ensure your DNS record or .well-known file is publicly accessible and try again.")


if __name__ == "__main__":
    main()
