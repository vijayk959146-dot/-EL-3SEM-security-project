"""
Ask Amazon Bedrock (Claude) to rank findings and explain them in plain language.

If Bedrock is unavailable, we fall back to a local ranking using CVSS scores
so the dashboard still works for a demo.
"""

from __future__ import annotations

import json
import re
from typing import Any

from config import AWS_REGION, BEDROCK_MODEL_ID
from schemas import PrioritizedFinding, PrioritizedReport
from storage import read_json, write_json

SYSTEM_RULES = """You are a defensive security explainer for a college lab.
You receive correlated attack-surface + public CVE data for a target the user owns.
Rank findings by real-world exploitability AND impact (exposed service + known CVE
or missing security control beats a theoretical low-score issue).
Do NOT provide exploit steps, payloads, or attack instructions.
Return ONLY valid JSON matching this schema:
{
  "summary": "two sentences for a non-technical reader",
  "top_risks": ["short phrase", "short phrase", "short phrase"],
  "findings": [
    {
      "rank": 1,
      "title": "short title",
      "severity": "Critical|High|Medium|Low|Info",
      "exploitability": "one short phrase",
      "why_it_matters": "plain language, no jargon if possible",
      "suggested_action": "defensive fix only",
      "related_cves": ["CVE-YYYY-NNNN"],
      "source": "port/service or config check"
    }
  ]
}
"""


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _invoke_bedrock(user_payload: str) -> str:
    import boto3

    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4000,
        "temperature": 0.2,
        "system": SYSTEM_RULES,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": user_payload}],
            }
        ],
    }
    response = client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(body),
    )
    raw = json.loads(response["body"].read())
    parts = raw.get("content") or []
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text")


def _parse_llm_json(text: str) -> dict[str, Any]:
    cleaned = _strip_fences(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _heuristic_report(correlated: dict) -> PrioritizedReport:
    """Deterministic ranking when Bedrock cannot be called."""
    findings: list[PrioritizedFinding] = []
    rank = 1
    for asset in correlated.get("assets") or []:
        for cve in asset.get("cves") or []:
            score = cve.get("cvss_score") or 0
            severity = cve.get("severity") or "Medium"
            findings.append(
                PrioritizedFinding(
                    rank=rank,
                    title=f"{cve.get('cve_id')} on {asset.get('service') or 'service'}",
                    severity=severity,
                    exploitability=f"Public CVE, CVSS {score}",
                    why_it_matters=(cve.get("description") or "Known public vulnerability.")[:400],
                    suggested_action="Patch or upgrade the affected software if you run it; restrict the port if unused.",
                    related_cves=[cve.get("cve_id")] if cve.get("cve_id") else [],
                    source=asset.get("exposure") or "",
                )
            )
            rank += 1
        for issue in asset.get("config_issues") or []:
            findings.append(
                PrioritizedFinding(
                    rank=rank,
                    title=issue[:80],
                    severity="Medium",
                    exploitability="Depends on network reachability of this lab service.",
                    why_it_matters=issue,
                    suggested_action="Enable HTTPS in production and set standard security headers.",
                    related_cves=[],
                    source="config-check",
                )
            )
            rank += 1

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 5))
    for i, item in enumerate(findings, start=1):
        item.rank = i

    top = [f.title for f in findings[:3]]
    return PrioritizedReport(
        target=correlated.get("target", ""),
        summary="Automated ranking without an LLM (Bedrock fallback). Review CVEs and missing HTTP security controls on the lab target.",
        top_risks=top,
        findings=findings,
        model_id="heuristic-fallback",
        used_llm=False,
        notes=["Bedrock was not used; results are CVSS/config heuristics."],
    )


def _from_llm_dict(correlated: dict, data: dict, used_llm: bool, note: str = "") -> PrioritizedReport:
    findings = []
    for raw in data.get("findings") or []:
        findings.append(
            PrioritizedFinding(
                rank=int(raw.get("rank") or 0),
                title=str(raw.get("title") or ""),
                severity=str(raw.get("severity") or "Info"),
                exploitability=str(raw.get("exploitability") or ""),
                why_it_matters=str(raw.get("why_it_matters") or ""),
                suggested_action=str(raw.get("suggested_action") or ""),
                related_cves=list(raw.get("related_cves") or []),
                source=str(raw.get("source") or ""),
            )
        )
    notes = [note] if note else []
    return PrioritizedReport(
        target=correlated.get("target", ""),
        summary=str(data.get("summary") or ""),
        top_risks=list(data.get("top_risks") or [])[:3],
        findings=findings,
        model_id=BEDROCK_MODEL_ID if used_llm else "heuristic-fallback",
        used_llm=used_llm,
        notes=notes,
    )


def prioritize(correlated: dict | None = None) -> PrioritizedReport:
    correlated = correlated or read_json("correlated_findings.json")
    compact = json.dumps(correlated, indent=2)[:18000]
    user_msg = (
        "Rank and explain these correlated findings for a local OWASP Juice Shop lab.\n"
        + compact
    )
    try:
        text = _invoke_bedrock(user_msg)
        try:
            parsed = _parse_llm_json(text)
        except json.JSONDecodeError:
            text = _invoke_bedrock(user_msg + "\n\nYour last reply was not valid JSON. Reply with JSON only.")
            parsed = _parse_llm_json(text)
        report = _from_llm_dict(correlated, parsed, used_llm=True)
    except Exception as exc:
        report = _heuristic_report(correlated)
        report.notes.append(f"Bedrock fallback reason: {exc.__class__.__name__}: {exc}")

    write_json("prioritized_report.json", report)
    return report
