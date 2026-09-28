from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from config import DATA_DIR

HISTORY_DIR = DATA_DIR / "history"


def write_json(name: str, payload: Any) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / name
    if hasattr(payload, "to_dict"):
        data = payload.to_dict()
    elif hasattr(payload, "__dataclass_fields__"):
        data = asdict(payload)
    else:
        data = payload
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def read_json(name: str) -> dict[str, Any]:
    path = DATA_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Run the previous pipeline stage first.")
    return json.loads(path.read_text(encoding="utf-8"))


def save_run_history(target: str, report_data: dict[str, Any]) -> Path:
    """Save a timestamped copy of a prioritized report under data/history/."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(":", "_").replace("/", "_")
    filename = f"run_{timestamp}_{safe_target}.json"
    path = HISTORY_DIR / filename
    path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    return path


def list_run_history() -> list[Path]:
    """List archived historical scan reports sorted from newest to oldest."""
    if not HISTORY_DIR.exists():
        return []
    files = list(HISTORY_DIR.glob("run_*.json"))
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def diff_reports(current_report: dict[str, Any], previous_report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """
    Compare current findings against previous findings.
    Returns: {'new': [...], 'resolved': [...], 'unchanged': [...]}
    """
    def _finding_key(f: dict[str, Any]) -> str:
        title = (f.get("title") or "").strip().lower()
        cves = ",".join(sorted(f.get("related_cves") or []))
        return f"{title}|{cves}"

    curr_findings = current_report.get("findings") or []
    prev_findings = previous_report.get("findings") or []

    curr_map = {_finding_key(f): f for f in curr_findings}
    prev_map = {_finding_key(f): f for f in prev_findings}

    new_items = [f for k, f in curr_map.items() if k not in prev_map]
    resolved_items = [f for k, f in prev_map.items() if k not in curr_map]
    unchanged_items = [f for k, f in curr_map.items() if k in prev_map]

    return {
        "new": new_items,
        "resolved": resolved_items,
        "unchanged": unchanged_items,
    }


def generate_csv_report(report: dict[str, Any]) -> str:
    """Generate a clean CSV representation of report findings."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Rank", "Severity", "Title", "Exploitability", "CVEs", "Source", "Why It Matters", "Suggested Defensive Action"])
    for f in report.get("findings") or []:
        writer.writerow([
            f.get("rank", ""),
            f.get("severity", ""),
            f.get("title", ""),
            f.get("exploitability", ""),
            ", ".join(f.get("related_cves") or []),
            f.get("source", ""),
            f.get("why_it_matters", ""),
            f.get("suggested_action", ""),
        ])
    return output.getvalue()


def generate_html_report(report: dict[str, Any]) -> str:
    """Generate a standalone, beautifully styled HTML security report."""
    target = report.get("target") or "Unknown"
    summary = report.get("summary") or "No summary available."
    model = report.get("model_id") or "Heuristic"
    used_llm = "Yes" if report.get("used_llm") else "No (Fallback)"
    findings = report.get("findings") or []
    top_risks = report.get("top_risks") or []
    notes = report.get("notes") or []

    findings_html = ""
    for f in findings:
        sev = f.get("severity", "Info")
        sev_color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#4b5563",
        }.get(sev, "#4b5563")

        cves = ", ".join(f.get("related_cves") or [])
        cve_badge = f'<span style="background:#fee2e2;color:#991b1b;padding:2px 6px;border-radius:4px;font-size:12px;">{cves}</span>' if cves else ''

        findings_html += f"""
        <div style="border:1px solid #e5e7eb;border-left:5px solid {sev_color};background:#ffffff;border-radius:6px;padding:16px;margin-bottom:14px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3 style="margin:0;font-size:16px;color:#111827;">#{f.get('rank')} {f.get('title')}</h3>
                <span style="background:{sev_color};color:#ffffff;padding:3px 8px;border-radius:12px;font-size:12px;font-weight:bold;">{sev}</span>
            </div>
            <div style="margin-top:8px;font-size:13px;color:#4b5563;">
                <b>Exploitability:</b> {f.get('exploitability', '')} {cve_badge}
            </div>
            <p style="margin:8px 0;font-size:14px;color:#374151;">{f.get('why_it_matters', '')}</p>
            <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px;padding:10px;font-size:13px;margin-top:8px;">
                <b style="color:#065f46;">🛡️ Suggested Defensive Action:</b><br>
                <code>{f.get('suggested_action', '')}</code>
            </div>
        </div>
        """

    top_risks_html = "".join(f"<li>{r}</li>" for r in top_risks)
    notes_html = "".join(f"<li>{n}</li>" for n in notes)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f4f6; margin: 0; padding: 24px; color: #1f2937; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; padding: 32px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        h1 {{ margin-top: 0; color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 12px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
        .meta-card {{ background: #f9fafb; border: 1px solid #e5e7eb; padding: 12px; border-radius: 6px; }}
        .meta-label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; font-weight: bold; }}
        .meta-value {{ font-size: 16px; font-weight: bold; color: #111827; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>AI-Assisted Attack Surface & Vulnerability Report</h1>
        <div class="meta-grid">
            <div class="meta-card"><div class="meta-label">Target</div><div class="meta-value">{target}</div></div>
            <div class="meta-card"><div class="meta-label">Total Findings</div><div class="meta-value">{len(findings)}</div></div>
            <div class="meta-card"><div class="meta-label">LLM Prioritized</div><div class="meta-value">{used_llm}</div></div>
            <div class="meta-card"><div class="meta-label">AI Model</div><div class="meta-value">{model[:18]}</div></div>
        </div>
        <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:16px;margin:20px 0;">
            <h3 style="margin-top:0;color:#1e40af;">Executive Summary</h3>
            <p style="margin-bottom:0;color:#1e3a8a;">{summary}</p>
        </div>
        {"<h3>Top Risks</h3><ul>" + top_risks_html + "</ul>" if top_risks else ""}
        <h2>Prioritized Defensive Findings</h2>
        {findings_html}
        {"<h3>Pipeline Notes</h3><ul>" + notes_html + "</ul>" if notes else ""}
        <div style="text-align:center;font-size:12px;color:#9ca3af;margin-top:32px;border-top:1px solid #e5e7eb;padding-top:16px;">
            Generated by AI-Assisted Attack Surface & Vulnerability Correlation Tool
        </div>
    </div>
</body>
</html>"""
