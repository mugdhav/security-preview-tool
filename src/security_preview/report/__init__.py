"""Report rendering for security-preview.

Owned by branch ``foundation/report-renderers``. Public API:

    render(result: ScanResult, fmt: str) -> str
    FORMATS: tuple[str, ...]
"""
from __future__ import annotations

from .renderers import FORMATS, render

__all__ = ["FORMATS", "render"]
