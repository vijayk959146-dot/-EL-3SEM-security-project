"""
Compare prioritized_report.json to a curated Juice Shop expectation list.

False negative (FN): an expected *detectable* issue never appears in the report.
False positive (FP): a report finding that does not match any expected keyword
and is not clearly a public CVE record (CVE-... is counted as extra NVD data,
not a false positive — NVD hits are a different signal than Juice Shop challenges).

Application challenges listed under not_detectable_nmap_nvd are documented
limitations, not scored as FN.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from storage import read_json

KNOWN_PATH = Path(__file__).resolve().parent / "juice_shop_known.json"


def _blob(finding: dict) -> str:
    parts = [
        finding.get("title") or "",
        finding.get("why_it_matters") or "",
        finding.get("source") or "",
        " ".join(finding.get("related_cves") or []),
        finding.get("suggested_action") or "",
    ]
    return " ".join(parts).lower()


def _matches(blob: str, keywords: list[str]) -> bool:
    return any(k.lower() in blob for k in keywords)


def evaluate(report: dict, known: dict) -> dict:
    findings = report.get("findings") or []
    blobs = [_blob(f) for f in findings]
    expected = known.get("detectable_by_this_tool") or []

    true_positives = []
    false_negatives = []
    matched_finding_indexes: set[int] = set()

    for item in expected:
        hit = False
        for idx, blob in enumerate(blobs):
            if _matches(blob, item.get("keywords") or []):
                hit = True
                matched_finding_indexes.add(idx)
        if hit:
            true_positives.append(item["id"])
        else:
            false_negatives.append(item["id"])

    false_positives = []
    extra_cves = []
    for idx, finding in enumerate(findings):
        if idx in matched_finding_indexes:
            continue
        cves = finding.get("related_cves") or []
        if cves:
            extra_cves.append(finding.get("title") or cves[0])
            continue
        false_positives.append(finding.get("title") or f"finding-{idx}")

    n_expected = len(expected)
    recall = (len(true_positives) / n_expected) if n_expected else 0.0
    return {
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "extra_nvd_cve_findings": extra_cves,
        "counts": {
            "TP": len(true_positives),
            "FN": len(false_negatives),
            "FP": len(false_positives),
            "expected_detectable": n_expected,
            "report_findings": len(findings),
        },
        "recall_on_detectable": round(recall, 3),
        "limitations": known.get("not_detectable_nmap_nvd") or [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate report against Juice Shop known list")
    parser.add_argument(
        "--known",
        default=str(KNOWN_PATH),
        help="Path to curated JSON (edit this if you confirm a different list)",
    )
    args = parser.parse_args()
    report = read_json("prioritized_report.json")
    known = json.loads(Path(args.known).read_text(encoding="utf-8"))
    result = evaluate(report, known)
    print(json.dumps(result, indent=2))
    counts = result["counts"]
    print(
        f"\nDetectable recall: {result['recall_on_detectable']} "
        f"(TP={counts['TP']} FN={counts['FN']} FP={counts['FP']})"
    )


if __name__ == "__main__":
    main()
