"""
Look up publicly known CVEs on the NVD (National Vulnerability Database).

We send *product + version strings from banners*, never payloads. NVD returns
JSON records. We keep a short description and the CVSS score when present.
"""

from __future__ import annotations

import time

import requests

from config import NVD_API_KEY
from schemas import CveRecord

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "ai-attack-surface-tool/1.0 (academic EL project)"


def _cvss_from_metrics(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        data = items[0]
        cvss = data.get("cvssData") or {}
        score = cvss.get("baseScore")
        severity = (data.get("baseSeverity") or cvss.get("baseSeverity") or "").title()
        if score is not None:
            return float(score), severity or _severity_from_score(float(score))
    return None, "Unknown"


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def _query_nvd(keyword: str, limit: int = 5) -> list[CveRecord]:
    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    params = {"keywordSearch": keyword, "resultsPerPage": limit}
    response = requests.get(NVD_URL, headers=headers, params=params, timeout=30)
    if response.status_code == 429:
        time.sleep(8)
        response = requests.get(NVD_URL, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    payload = response.json()
    records: list[CveRecord] = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or ""
        descriptions = cve.get("descriptions") or []
        english = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        score, severity = _cvss_from_metrics(cve.get("metrics") or {})
        records.append(
            CveRecord(
                cve_id=cve_id,
                description=(english or "")[:500],
                cvss_score=score,
                severity=severity,
                source_query=keyword,
            )
        )
    return records


def lookup_cves(product: str, version: str = "") -> list[CveRecord]:
    product = (product or "").strip()
    version = (version or "").strip()
    if not product:
        return []
    keyword = f"{product} {version}".strip()
    try:
        results = _query_nvd(keyword)
    except requests.RequestException:
        if version:
            try:
                results = _query_nvd(product)
            except requests.RequestException:
                return []
        else:
            return []
    time.sleep(0.7 if NVD_API_KEY else 6.0)
    return results
