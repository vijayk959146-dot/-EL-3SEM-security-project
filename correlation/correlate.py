"""Merge discovery JSON with NVD matches into one correlated findings file."""

from __future__ import annotations

from correlation.nvd_lookup import lookup_cves
from schemas import CorrelatedAsset, CorrelatedFindings, CveRecord
from storage import read_json, write_json


def _load_discovered() -> dict:
    return read_json("discovered_assets.json")


def _config_issues(discovered: dict) -> list[str]:
    issues: list[str] = []
    for raw in discovered.get("ports") or []:
        port = raw.get("port")
        if raw.get("state") == "open" and port in {80, 443, 3000, 8000, 8080}:
            issues.append(f"Open TCP/{port} web service on the lab host.")
    http = discovered.get("http") or {}
    if http.get("reachable") and not http.get("uses_tls"):
        issues.append("Service is reachable over HTTP without TLS encryption.")
    for header in http.get("missing_security_headers") or []:
        issues.append(f"Missing security header: {header}")
    tls = discovered.get("tls") or {}
    if not tls.get("skipped") and tls.get("grade") in {"C", "D", "E", "F", "T"}:
        issues.append(f"Weak TLS grade from SSL Labs: {tls.get('grade')}")
    return issues


def correlate(discovered: dict | None = None) -> CorrelatedFindings:
    discovered = discovered or _load_discovered()
    target = discovered.get("target", "")
    shared_issues = _config_issues(discovered)
    assets: list[CorrelatedAsset] = []
    seen_queries: dict[str, list[CveRecord]] = {}

    ports: list[dict] = discovered.get("ports") or []
    if not ports:
        assets.append(
            CorrelatedAsset(
                target=target,
                port=None,
                service="none",
                product="",
                version="",
                exposure="No open ports found on the scanned set.",
                cves=[],
                config_issues=shared_issues,
            )
        )
    for raw in ports:
        product = raw.get("product") or raw.get("service") or ""
        version = raw.get("version") or ""
        query_key = f"{product}|{version}"
        if query_key not in seen_queries:
            seen_queries[query_key] = lookup_cves(product, version) if product and product != "unknown" else []
        cves = seen_queries[query_key]
        port = raw.get("port")
        exposure = (
            f"Open {raw.get('protocol', 'tcp')}/{port} "
            f"service={raw.get('service') or 'unknown'} "
            f"product={product or 'n/a'} version={version or 'n/a'}"
        )
        assets.append(
            CorrelatedAsset(
                target=target,
                port=port,
                service=raw.get("service") or "",
                product=product,
                version=version,
                exposure=exposure,
                cves=cves,
                config_issues=shared_issues if port in {80, 443, 3000, 8000, 8080} else [],
            )
        )

    if shared_issues and not any(a.config_issues for a in assets):
        assets.append(
            CorrelatedAsset(
                target=target,
                port=None,
                service="http-config",
                product="",
                version="",
                exposure="HTTP configuration checks",
                cves=[],
                config_issues=shared_issues,
            )
        )

    result = CorrelatedFindings(
        target=target,
        assets=assets,
        notes=list(discovered.get("notes") or []),
    )
    write_json("correlated_findings.json", result)
    return result
