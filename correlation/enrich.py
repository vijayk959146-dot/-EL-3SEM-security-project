"""
Real-world exploitability enrichment via CISA KEV and FIRST EPSS.

Security terms explained for 3rd semester students:
- CISA KEV (Known Exploited Vulnerabilities): A catalog published by the US Cybersecurity &
  Infrastructure Security Agency listing vulnerabilities actively weaponized and exploited
  by real-world threat actors in the wild.
- EPSS (Exploit Prediction Scoring System): A data-driven model by FIRST.org that outputs a
  probability score between 0.0 and 1.0 (0% to 100%) predicting whether a CVE will be exploited
  in the next 30 days based on dark web activity, honeypot signals, and threat intel.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from config import DATA_DIR
from schemas import CveRecord

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = DATA_DIR / "cache"
KEV_CACHE_FILE = CACHE_DIR / "kev_catalog.json"
EPSS_CACHE_DIR = CACHE_DIR / "epss"

KEV_CACHE_TTL_SECONDS = 86400  # 24 hours


def _load_cisa_kev_catalog() -> set[str]:
    """
    Fetch and cache the CISA KEV catalog for 24 hours.
    Returns a set of CVE IDs (e.g. {'CVE-2021-44228', 'CVE-2023-38606'}).
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()

    # Check if cached catalog is still fresh (< 24 hours)
    if KEV_CACHE_FILE.exists():
        try:
            mtime = KEV_CACHE_FILE.stat().st_mtime
            if now - mtime < KEV_CACHE_TTL_SECONDS:
                data = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
                return set(data.get("cve_ids") or [])
        except (json.JSONDecodeError, OSError):
            pass

    # Fetch from CISA with strict timeout
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities") or []
        cve_ids = [v.get("cveID") for v in vulnerabilities if v.get("cveID")]
        
        # Save cache
        KEV_CACHE_FILE.write_text(
            json.dumps({"updated_at": now, "count": len(cve_ids), "cve_ids": cve_ids}),
            encoding="utf-8",
        )
        return set(cve_ids)
    except Exception as exc:
        # Graceful fallback: return empty set or stale cache if network unavailable
        if KEV_CACHE_FILE.exists():
            try:
                data = json.loads(KEV_CACHE_FILE.read_text(encoding="utf-8"))
                return set(data.get("cve_ids") or [])
            except Exception:
                pass
        return set()


def _get_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Query the FIRST EPSS API for a batch of CVEs.
    Returns a mapping of {cve_id: epss_score}.
    """
    if not cve_ids:
        return {}

    EPSS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    results: dict[str, float] = {}
    missing_cves: list[str] = []

    # Check local cache first
    for cve_id in cve_ids:
        cache_file = EPSS_CACHE_DIR / f"{cve_id}.json"
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                results[cve_id] = float(cached["epss"])
                continue
            except (json.JSONDecodeError, KeyError, ValueError, OSError):
                pass
        missing_cves.append(cve_id)

    if not missing_cves:
        return results

    # Query EPSS API for uncached CVEs in comma-separated chunks
    chunk_size = 50
    for i in range(0, len(missing_cves), chunk_size):
        chunk = missing_cves[i : i + chunk_size]
        query_param = ",".join(chunk)
        try:
            response = requests.get(
                EPSS_API_URL,
                params={"cve": query_param},
                timeout=15,
            )
            response.raise_for_status()
            data = response.json().get("data") or []
            for item in data:
                cid = item.get("cve")
                score_str = item.get("epss")
                if cid and score_str is not None:
                    score = float(score_str)
                    results[cid] = score
                    # Cache on disk
                    cache_file = EPSS_CACHE_DIR / f"{cid}.json"
                    try:
                        cache_file.write_text(json.dumps({"cve": cid, "epss": score}), encoding="utf-8")
                    except OSError:
                        pass
        except Exception:
            # Network or API failure: fail gracefully, leave scores as None
            pass

    return results


def enrich_cves(cves: list[CveRecord], notes: list[str] | None = None) -> list[CveRecord]:
    """
    Enrich a list of CveRecords in-place with CISA KEV exploit status and EPSS scores.
    """
    if not cves:
        return cves

    cve_ids = [c.cve_id for c in cves if c.cve_id]
    if not cve_ids:
        return cves

    # 1. Enrich with CISA KEV
    try:
        kev_set = _load_cisa_kev_catalog()
        for record in cves:
            if record.cve_id in kev_set:
                record.kev = True
    except Exception as exc:
        if notes is not None:
            notes.append(f"CISA KEV check skipped: {exc.__class__.__name__}")

    # 2. Enrich with EPSS scores
    try:
        epss_map = _get_epss_scores(cve_ids)
        for record in cves:
            if record.cve_id in epss_map:
                record.epss = epss_map[record.cve_id]
    except Exception as exc:
        if notes is not None:
            notes.append(f"EPSS score check skipped: {exc.__class__.__name__}")

    return cves
