"""STUB. Owned by branch ``foundation/sca``. Do NOT edit on other branches."""
from __future__ import annotations

from ..config import ScanConfig
from ..models import Component, DependencyFinding, ErrorCollector


def query_osv(
    components: list[Component], cfg: ScanConfig, errors: ErrorCollector
) -> list[DependencyFinding]:
    return []
