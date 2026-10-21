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
    tp = len(true_positives)
    fn = len(false_negatives)
    fp = len(false_positives)

    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "target": report.get("target") or known.get("target", "Target"),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "extra_nvd_cve_findings": extra_cves,
        "counts": {
            "TP": tp,
            "FN": fn,
            "FP": fp,
            "expected_detectable": n_expected,
            "report_findings": len(findings),
        },
        "metrics": {
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "f1_score": round(f1, 3),
        },
        "limitations": known.get("not_detectable_nmap_nvd") or [],
    }


def print_summary_table(result: dict) -> None:
    counts = result["counts"]
    metrics = result["metrics"]
    print("\n" + "=" * 62)
    print("           VALIDATION BENCHMARK EVALUATION TABLE          ")
    print("=" * 62)
    print(f"Target evaluated: {result.get('target', 'Lab Target')}")
    print("-" * 62)
    print(f"  True Positives (TP):      {counts['TP']:<4} (Successfully detected)")
    print(f"  False Negatives (FN):     {counts['FN']:<4} (Missed expected checks)")
    print(f"  False Positives (FP):     {counts['FP']:<4} (Spurious findings)")
    print(f"  Total Expected Items:     {counts['expected_detectable']:<4}")
    print(f"  Total Report Findings:    {counts['report_findings']:<4}")
    print("-" * 62)
    print(f"  RECALL:                   {metrics['recall']*100:.1f}%")
    print(f"  PRECISION:                {metrics['precision']*100:.1f}%")
    print(f"  F1-SCORE:                 {metrics['f1_score']*100:.1f}%")
    print("=" * 62 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate report against curated known list")
    parser.add_argument(
        "--report",
        default=None,
        help="Path to prioritized_report.json (default: data/prioritized_report.json)",
    )
    parser.add_argument(
        "--known",
        default=str(KNOWN_PATH),
        help="Path to curated JSON (default: tests/juice_shop_known.json)",
    )
    args = parser.parse_args()

    if args.report:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    else:
        report = read_json("prioritized_report.json")

    known = json.loads(Path(args.known).read_text(encoding="utf-8"))
    result = evaluate(report, known)
    print(json.dumps(result, indent=2))
    print_summary_table(result)


if __name__ == "__main__":
    main()
