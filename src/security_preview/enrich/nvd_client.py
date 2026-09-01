"""STUB. Owned by branch ``foundation/enrichment``. Do NOT edit on other branches."""
from __future__ import annotations

from ..config import ScanConfig
from ..models import ErrorCollector, Finding


def enrich_findings(
    findings: list[Finding], cfg: ScanConfig, errors: ErrorCollector
) -> None:
    return None
