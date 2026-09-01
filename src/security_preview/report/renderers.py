"""STUB. Owned by branch ``foundation/report-renderers``. Do NOT edit on other branches."""
from __future__ import annotations

from ..models import ScanResult

FORMATS = ("text", "markdown", "json", "sarif", "html")


def render(result: ScanResult, fmt: str) -> str:
    return ""
