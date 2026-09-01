"""STUB. Owned by branch ``foundation/sast-engine``. Do NOT edit on other branches."""
from __future__ import annotations

from ..config import ScanConfig
from ..models import ErrorCollector, Finding


def scan_paths(
    root: str, files: list[str], cfg: ScanConfig, errors: ErrorCollector
) -> list[Finding]:
    return []
