"""OSV.dev batch client for the SCA stage.

Owned by branch ``foundation/sca``. Imports only from ``security_preview.models``,
``security_preview.config``, ``security_preview.contracts`` and this package.

Contract (``contracts.py``)::

    sca.osv_client.query_osv(components, cfg, errors) -> list[DependencyFinding]

* Returns ``[]`` when ``cfg.offline`` (no network at all).
* ``POST https://api.osv.dev/v1/querybatch`` in batches, honouring
  ``cfg.network_timeout`` per request.
* Resolves per-vuln detail from ``GET /v1/vulns/{id}`` (querybatch only returns
  ids), maps OSV severity to :class:`RiskLevel`, and picks the **lowest** fixed
  version offered across the matching advisories.
* Network failures are recorded on ``errors`` (stage ``"sca"``); the partial list
  gathered so far is returned. Never raises.
* The returned list is de-duplicated and deterministically ordered.
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterator

import httpx

from ..config import ScanConfig
from ..models import Component, DependencyFinding, ErrorCollector, RiskLevel

__all__ = ["query_osv"]

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
MAX_BATCH = 1000
_USER_AGENT = "security-preview/0.1 (+https://osv.dev)"

_LABEL_MAP: dict[str, RiskLevel] = {
    "CRITICAL": RiskLevel.CRITICAL,
    "HIGH": RiskLevel.HIGH,
    "MODERATE": RiskLevel.MEDIUM,
    "MEDIUM": RiskLevel.MEDIUM,
    "LOW": RiskLevel.LOW,
    "NONE": RiskLevel.INFO,
    "INFO": RiskLevel.INFO,
}


# --------------------------------------------------------------------------- #
# HTTP seam — monkeypatched wholesale in tests (no live network in CI).        #
# --------------------------------------------------------------------------- #

def _query_batch(payload: dict, timeout: float) -> dict:
    resp = httpx.post(
        OSV_QUERYBATCH_URL,
        json=payload,
        timeout=timeout,
        headers={"user-agent": _USER_AGENT},
    )
    resp.raise_for_status()
    return resp.json()


def _fetch_vuln(vuln_id: str, timeout: float) -> dict:
    resp = httpx.get(
        OSV_VULN_URL + vuln_id,
        timeout=timeout,
        headers={"user-agent": _USER_AGENT},
    )
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------- #
# Severity mapping                                                             #
# --------------------------------------------------------------------------- #

def _bucket(score: float) -> RiskLevel:
    if score >= 9.0:
        return RiskLevel.CRITICAL
    if score >= 7.0:
        return RiskLevel.HIGH
    if score >= 4.0:
        return RiskLevel.MEDIUM
    if score >= 0.1:
        return RiskLevel.LOW
    return RiskLevel.INFO


def _cvss_v3_base_score(vector: str) -> float | None:
    try:
        metrics: dict[str, str] = {}
        for part in vector.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                metrics[key] = value
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope_changed = metrics["S"].upper() == "C"
        if scope_changed:
            pr = {"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
        impact_w = {"H": 0.56, "L": 0.22, "N": 0.0}
        conf = impact_w[metrics["C"]]
        integ = impact_w[metrics["I"]]
        avail = impact_w[metrics["A"]]
        iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        raw = impact + exploitability
        if scope_changed:
            raw *= 1.08
        return math.ceil(min(raw, 10.0) * 10) / 10
    except (KeyError, ValueError, ZeroDivisionError):
        return None


def _cvss_score(score: object) -> float | None:
    if not isinstance(score, str) or not score.strip():
        return None
    text = score.strip()
    try:
        return float(text)
    except ValueError:
        pass
    if text.upper().startswith("CVSS:"):
        return _cvss_v3_base_score(text)
    return None


def _map_severity(detail: dict) -> RiskLevel:
    holders: list[dict] = [detail]
    holders.extend(a for a in (detail.get("affected") or []) if isinstance(a, dict))
    for holder in holders:
        db_specific = holder.get("database_specific") or {}
        label = db_specific.get("severity")
        if isinstance(label, str):
            mapped = _LABEL_MAP.get(label.strip().upper())
            if mapped is not None:
                return mapped
    best: float | None = None
    for entry in detail.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        value = _cvss_score(entry.get("score"))
        if value is not None and (best is None or value > best):
            best = value
    if best is not None:
        return _bucket(best)
    return RiskLevel.MEDIUM


# --------------------------------------------------------------------------- #
# Fixed-version resolution                                                     #
# --------------------------------------------------------------------------- #

def _version_key(version: str) -> list[tuple[int, int, str]]:
    key: list[tuple[int, int, str]] = []
    for token in re.split(r"[.\-+_~]", version.strip().lower()):
        if token.isdigit():
            key.append((0, int(token), ""))
        elif token:
            key.append((1, 0, token))
    return key or [(0, 0, "")]


def _fixed_versions(detail: dict, component: Component) -> list[str]:
    out: list[str] = []
    for affected in detail.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        pkg_name = pkg.get("name")
        if isinstance(pkg_name, str) and pkg_name and pkg_name != component.name:
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                fixed = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(fixed, str) and fixed:
                    out.append(fixed)
    return out


# --------------------------------------------------------------------------- #
# Assembly                                                                     #
# --------------------------------------------------------------------------- #

def _chunk(seq: list[Component], size: int) -> Iterator[list[Component]]:
    for start in range(0, len(seq), size):
        yield seq[start : start + size]


def _build_finding(
    component: Component,
    details: list[tuple[str, dict | None]],
) -> DependencyFinding | None:
    advisory_ids: set[str] = set()
    best_severity = RiskLevel.MEDIUM
    best_rank: int | None = None
    fixed_candidates: list[str] = []
    summary = ""
    summary_rank: int | None = None
    for vuln_id, detail in details:
        advisory_ids.add(vuln_id)
        if not detail:
            continue
        for alias in detail.get("aliases") or []:
            if isinstance(alias, str) and alias:
                advisory_ids.add(alias)
        severity = _map_severity(detail)
        if best_rank is None or severity.rank < best_rank:
            best_rank = severity.rank
            best_severity = severity
        fixed_candidates.extend(_fixed_versions(detail, component))
        text = (detail.get("summary") or detail.get("details") or "").strip()
        if text and (summary_rank is None or severity.rank < summary_rank):
            summary_rank = severity.rank
            summary = text[:300]
    if not advisory_ids:
        return None
    fixed_version: str | None = None
    if fixed_candidates:
        fixed_version = min(set(fixed_candidates), key=_version_key)
    return DependencyFinding(
        ecosystem=component.ecosystem,
        package=component.name,
        version=component.version,
        advisory_ids=sorted(advisory_ids),
        severity=best_severity,
        fixed_version=fixed_version,
        source_manifest=component.source_manifest,
        summary=summary,
    )


def query_osv(
    components: list[Component],
    cfg: ScanConfig,
    errors: ErrorCollector,
) -> list[DependencyFinding]:
    """Query OSV.dev for known vulnerabilities in ``components``; never raises."""
    if cfg.offline or not components:
        return []

    unique = sorted(
        set(components),
        key=lambda c: (c.ecosystem, c.name, c.version, c.source_manifest),
    )
    vuln_cache: dict[str, dict | None] = {}
    findings: list[DependencyFinding] = []

    for batch in _chunk(unique, MAX_BATCH):
        payload = {
            "queries": [
                {
                    "package": {"ecosystem": c.ecosystem, "name": c.name},
                    "version": c.version,
                }
                for c in batch
            ]
        }
        try:
            data = _query_batch(payload, cfg.network_timeout)
        except Exception as exc:  # noqa: BLE001 - contract: record, return partial
            errors.add(
                "sca",
                OSV_QUERYBATCH_URL,
                f"OSV querybatch failed: {type(exc).__name__}: {exc}",
            )
            continue

        results = data.get("results") or []
        for component, result in zip(batch, results):
            raw_vulns = (result or {}).get("vulns") or []
            if not raw_vulns:
                continue
            details: list[tuple[str, dict | None]] = []
            for raw in raw_vulns:
                vuln_id = raw.get("id") if isinstance(raw, dict) else None
                if not vuln_id:
                    continue
                if vuln_id not in vuln_cache:
                    try:
                        vuln_cache[vuln_id] = _fetch_vuln(vuln_id, cfg.network_timeout)
                    except Exception as exc:  # noqa: BLE001 - record, keep partial
                        errors.add(
                            "sca",
                            vuln_id,
                            f"OSV vuln lookup failed: {type(exc).__name__}: {exc}",
                        )
                        vuln_cache[vuln_id] = None
                details.append((vuln_id, vuln_cache[vuln_id]))
            finding = _build_finding(component, details)
            if finding is not None:
                findings.append(finding)

    findings.sort(
        key=lambda f: (
            f.severity.rank,
            f.ecosystem,
            f.package,
            f.version,
            f.source_manifest,
        )
    )
    return findings
