"""NVD CWE -> example-CVE enrichment.

Owned by branch ``foundation/enrichment``.

``enrich_findings`` groups findings by ``cwe_id``, asks NVD for CVEs tagged with
that CWE, and writes up to three illustrative CVE ids onto every finding in the
group. It is best-effort: it never raises, records every failure on the
``ErrorCollector`` (stage ``"enrich"``), and is a no-op when the scan is offline
or NVD enrichment is disabled. Results are cached on disk with a TTL so repeat
scans are fast and keep working without network.
"""
from __future__ import annotations

import time

import httpx

from ..config import ScanConfig
from ..models import ErrorCollector, Finding
from .cache import DEFAULT_CACHE_DIR, Cache

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 5
MAX_CVES_PER_FINDING = 3


def _cache_dir() -> str:
    """Directory for the enrichment cache. Patched in tests."""
    return str(DEFAULT_CACHE_DIR)


def _fetch_cves_for_cwe(cwe_id: str, timeout: float) -> list[str]:
    """Return CVE ids tagged with ``cwe_id`` from NVD (network call)."""
    response = httpx.get(
        NVD_API_URL,
        params={"cweId": cwe_id, "resultsPerPage": NVD_RESULTS_PER_PAGE},
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    cve_ids: list[str] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {}) if isinstance(item, dict) else {}
        cve_id = cve.get("id")
        if cve_id and cve_id not in cve_ids:
            cve_ids.append(str(cve_id))
    return cve_ids[:MAX_CVES_PER_FINDING]


def enrich_findings(
    findings: list[Finding], cfg: ScanConfig, errors: ErrorCollector
) -> None:
    """Populate ``findings[*].cve_ids`` in place from NVD. Never raises."""
    if cfg.offline or not cfg.enrich_nvd:
        return

    by_cwe: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.cwe_id:
            by_cwe.setdefault(finding.cwe_id, []).append(finding)
    if not by_cwe:
        return

    cache = Cache(path=_cache_dir(), ttl_hours=cfg.cache_ttl_hours)
    deadline = time.monotonic() + max(cfg.enrich_time_budget, 0.0)
    pending = sorted(by_cwe)

    for index, cwe_id in enumerate(pending):
        if time.monotonic() >= deadline:
            errors.add(
                "enrich",
                "nvd",
                f"time budget ({cfg.enrich_time_budget}s) exhausted; "
                f"{len(pending) - index} CWE group(s) not enriched",
            )
            break

        cache_key = f"cwe:{cwe_id}"
        cached = cache.get(cache_key)
        if isinstance(cached, list):
            cve_ids = [str(c) for c in cached][:MAX_CVES_PER_FINDING]
        else:
            try:
                cve_ids = _fetch_cves_for_cwe(cwe_id, cfg.network_timeout)
            except Exception as exc:  # noqa: BLE001 - enrichment must never raise
                errors.add("enrich", cwe_id, f"NVD lookup failed: {exc}")
                continue
            cache.set(cache_key, cve_ids)

        if cve_ids:
            for finding in by_cwe[cwe_id]:
                finding.cve_ids = list(cve_ids)
