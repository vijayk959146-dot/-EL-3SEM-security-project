from __future__ import annotations

import csv
import html
import io
import json
import re
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from config import DATA_DIR

# Characters unsafe for directory names on Windows and Unix
_UNSAFE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def target_data_dir(target: str) -> Path:
    """Return the per-target data directory: data/<safe_target>/.

    The target name is sanitised so it is safe as a directory component on
    both Windows and Unix without altering its readability.
    """
    safe = _UNSAFE_CHARS.sub("_", target).strip("._") or "unknown"
    d = DATA_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d

HISTORY_DIR = DATA_DIR / "history"


def write_json(name: str, payload: Any, target: str | None = None) -> Path:
    """Serialise *payload* to JSON.

    If *target* is given the file is written inside ``data/<target>/``;
    otherwise it falls back to the legacy flat ``data/`` location so that
    the dashboard can still read single-target runs without changes.
    """
    base = target_data_dir(target) if target else DATA_DIR
    base.mkdir(parents=True, exist_ok=True)
    path = base / name
    if hasattr(payload, "to_dict"):
        data = payload.to_dict()
    elif hasattr(payload, "__dataclass_fields__"):
        data = asdict(payload)
    else:
        data = payload
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def read_json(name: str, target: str | None = None) -> dict[str, Any]:
    """Read a JSON file from the per-target or legacy flat data directory."""
    # Prefer per-target path when caller supplies a target
    if target:
        path = target_data_dir(target) / name
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    # Fallback to legacy flat location
    path = DATA_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Run the previous pipeline stage first.")
    return json.loads(path.read_text(encoding="utf-8"))


def save_run_history(target: str, report_data: dict[str, Any]) -> Path:
    """Save a timestamped copy of a prioritized report under data/<target>/history/."""
    history_dir = target_data_dir(target) / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"run_{timestamp}.json"
    path = history_dir / filename
    path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    return path


def list_run_history(target: str | None = None) -> list[Path]:
    """List archived historical scan reports sorted from newest to oldest.

    When *target* is supplied, only that target's history is returned.
    Otherwise the legacy flat ``data/history/`` directory is scanned for
    backwards compatibility.
    """
    if target:
        history_dir = target_data_dir(target) / "history"
    else:
        history_dir = HISTORY_DIR
    if not history_dir.exists():
        return []
    files = list(history_dir.glob("run_*.json"))
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


def _sanitize_csv_cell(val: Any) -> str:
    """
    Prevent CSV formula injection (CSV Injection / DDE).
    If a cell starts with =, +, -, @, tab (\\t), or carriage return (\\r), prefix with a single quote.
    """
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def generate_csv_report(report: dict[str, Any]) -> str:
    """Generate a clean CSV representation of report findings protected against formula injection."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Rank", "Severity", "Title", "Exploitability", "CVEs", "Source", "Why It Matters", "Suggested Defensive Action"
    ])
    for f in report.get("findings") or []:
        cves_str = ", ".join(f.get("related_cves") or [])
        writer.writerow([
            _sanitize_csv_cell(f.get("rank", "")),
            _sanitize_csv_cell(f.get("severity", "")),
            _sanitize_csv_cell(f.get("title", "")),
            _sanitize_csv_cell(f.get("exploitability", "")),
            _sanitize_csv_cell(cves_str),
            _sanitize_csv_cell(f.get("source", "")),
            _sanitize_csv_cell(f.get("why_it_matters", "")),
            _sanitize_csv_cell(f.get("suggested_action", "")),
        ])
    return output.getvalue()


def generate_html_report(report: dict[str, Any]) -> str:
    """
    Generate a standalone, beautifully styled HTML security report.
    All dynamic variables are rigorously HTML-escaped to prevent Cross-Site Scripting (XSS).
    """
    target = html.escape(str(report.get("target") or "Unknown"), quote=True)
    summary = html.escape(str(report.get("summary") or "No summary available."), quote=True)
    model = html.escape(str(report.get("model_id") or "Heuristic"), quote=True)
    used_llm = "Yes" if report.get("used_llm") else "No (Fallback)"
    findings = report.get("findings") or []
    top_risks = report.get("top_risks") or []
    notes = report.get("notes") or []

    findings_html = ""
    for f in findings:
        raw_sev = str(f.get("severity") or "Info")
        sev_color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#4b5563",
        }.get(raw_sev, "#4b5563")

        esc_rank = html.escape(str(f.get("rank", "")), quote=True)
        esc_title = html.escape(str(f.get("title", "")), quote=True)
        esc_sev = html.escape(raw_sev, quote=True)
        esc_exploit = html.escape(str(f.get("exploitability", "")), quote=True)
        esc_why = html.escape(str(f.get("why_it_matters", "")), quote=True)
        esc_action = html.escape(str(f.get("suggested_action", "")), quote=True)

        cves_list = f.get("related_cves") or []
        esc_cves = ", ".join(html.escape(str(c), quote=True) for c in cves_list)
        cve_badge = f'<span style="background:#fee2e2;color:#991b1b;padding:2px 6px;border-radius:4px;font-size:12px;">{esc_cves}</span>' if esc_cves else ''

        findings_html += f"""
        <div style="border:1px solid #e5e7eb;border-left:5px solid {sev_color};background:#ffffff;border-radius:6px;padding:16px;margin-bottom:14px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3 style="margin:0;font-size:16px;color:#111827;">#{esc_rank} {esc_title}</h3>
                <span style="background:{sev_color};color:#ffffff;padding:3px 8px;border-radius:12px;font-size:12px;font-weight:bold;">{esc_sev}</span>
            </div>
            <div style="margin-top:8px;font-size:13px;color:#4b5563;">
                <b>Exploitability:</b> {esc_exploit} {cve_badge}
            </div>
            <p style="margin:8px 0;font-size:14px;color:#374151;">{esc_why}</p>
            <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px;padding:10px;font-size:13px;margin-top:8px;">
                <b style="color:#065f46;">🛡️ Suggested Defensive Action:</b><br>
                <code>{esc_action}</code>
            </div>
        </div>
        """

    top_risks_html = "".join(f"<li>{html.escape(str(r), quote=True)}</li>" for r in top_risks)
    notes_html = "".join(f"<li>{html.escape(str(n), quote=True)}</li>" for n in notes)

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
        <h1>🛡️ Security Assessment Report</h1>
        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Target</div>
                <div class="meta-value">{target}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Total Findings</div>
                <div class="meta-value">{len(findings)}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">AI Prioritization</div>
                <div class="meta-value">{used_llm}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Model</div>
                <div class="meta-value">{model}</div>
            </div>
        </div>

        <h2>Executive Summary</h2>
        <p style="font-size:15px;line-height:1.5;color:#374151;">{summary}</p>

        {f'<h3>Top Strategic Risks</h3><ul>{top_risks_html}</ul>' if top_risks_html else ''}

        <h2>Detailed Defensive Findings</h2>
        {findings_html if findings_html else '<p style="color:#6b7280;">No high-priority findings detected.</p>'}

        {f'<h3>Diagnostic Notes</h3><ul>{notes_html}</ul>' if notes_html else ''}
        <div style="text-align:center;font-size:12px;color:#9ca3af;margin-top:32px;border-top:1px solid #e5e7eb;padding-top:16px;">
            Generated by AI-Assisted Attack Surface & Vulnerability Correlation Tool
        </div>
    </div>
</body>
</html>
"""
