"""Report renderers. Owned by branch ``foundation/report-renderers``.

``render(result, fmt)`` is the single entry point named in ``contracts.py``.
Output is deterministic: an identical :class:`ScanResult` always produces a
byte-identical string, independent of input list ordering.
"""
from __future__ import annotations

import json

from ..models import ScanResult
from .html_report import render_html
from .markdown_report import render_markdown
from .sarif_report import render_sarif
from .text_report import render_text

FORMATS: tuple[str, ...] = ("text", "markdown", "json", "sarif", "html")


def _render_json(result: ScanResult) -> str:
    """Exactly ``result.to_dict()`` content, pretty-printed."""
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render(result: ScanResult, fmt: str) -> str:
    """Render ``result`` as ``fmt`` (one of :data:`FORMATS`).

    Raises :class:`ValueError` for an unknown ``fmt``.
    """
    if fmt == "text":
        return render_text(result)
    if fmt == "markdown":
        return render_markdown(result)
    if fmt == "json":
        return _render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "html":
        return render_html(result)
    raise ValueError(
        f"unknown report format {fmt!r}; expected one of {', '.join(FORMATS)}"
    )
