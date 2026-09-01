"""STUB. Owned by branch ``foundation/orchestrator-cli``. Do NOT edit on other branches.

Real implementation sequences: walker.discover -> sast.scan_paths -> confidence
filter -> (sca.collect_components -> sca.query_osv) -> enrich.enrich_findings ->
assemble ScanResult with ``partial = errors.partial``.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .config import ScanConfig
from .models import ScanResult


def scan(path: str, cfg: ScanConfig) -> ScanResult:
    now = datetime.now(timezone.utc)
    return ScanResult(
        target=path,
        started_at=now,
        finished_at=now,
        findings=[],
        dependency_findings=[],
        files_scanned=0,
        dependencies_scanned=0,
        errors=[],
        partial=False,
    )
