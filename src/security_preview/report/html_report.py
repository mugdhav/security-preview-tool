"""Self-contained HTML report.

Rendered from ``templates/report.html.j2`` to match the ReportScreen artboard,
with an embedded ``@media print`` block matching ReportPrint. One inline
``<style>``, no ``<script>``, no web fonts, no external resources. Deterministic.
"""
from __future__ import annotations

import functools
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ScanResult
from ._shared import (
    SEVERITY_HEX,
    SEVERITY_ORDER,
    SEVERITY_TINT,
    advisory_url,
    cwe_url,
    rerun_command,
    scanned_line,
    severity_counts,
    snippet_lines,
    sorted_dependency_findings,
    sorted_findings,
)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


@functools.lru_cache(maxsize=1)
def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env


def _context(result: ScanResult) -> dict:
    findings = sorted_findings(result.findings)
    deps = sorted_dependency_findings(result.dependency_findings)

    sev_rows = [
        {
            "level": level,
            "label": level.title(),
            "hex": SEVERITY_HEX[level],
            "count": count,
        }
        for level, count in severity_counts(result)
    ]

    f_rows = []
    for i, f in enumerate(findings):
        f_rows.append(
            {
                "sev_level": f.severity.value,
                "sev_label": f.severity.value.title(),
                "sev_hex": SEVERITY_HEX[f.severity.value],
                "sev_tint": SEVERITY_TINT[f.severity.value],
                "name": f.name,
                "rule_id": f.rule_id,
                "category": f.category,
                "cwe_id": f.cwe_id,
                "cwe_url": cwe_url(f.cwe_id),
                "file_path": f.file_path,
                "line": f.line,
                "confidence": f.confidence.value,
                "snippet": [
                    {"num": num, "text": text, "hit": hit}
                    for num, text, hit in snippet_lines(f)
                ],
                "description": f.description,
                "rem_vuln": f.remediation_vulnerable,
                "rem_secure": f.remediation_secure,
                "cves": [
                    {"id": c, "url": f"https://nvd.nist.gov/vuln/detail/{c}"}
                    for c in f.cve_ids
                ],
                "open": i == 0,
            }
        )

    d_rows = [
        {
            "package": d.package,
            "version": d.version,
            "ecosystem": d.ecosystem,
            "severity": d.severity.value,
            "sev_label": d.severity.value.title(),
            "sev_hex": SEVERITY_HEX[d.severity.value],
            "fixed_version": d.fixed_version,
            "source_manifest": d.source_manifest,
            "summary": d.summary,
            "advisories": [{"id": a, "url": advisory_url(a)} for a in d.advisory_ids],
        }
        for d in deps
    ]

    return {
        "tool_version": result.tool_version,
        "target": result.target,
        "scanned_line": scanned_line(result),
        "partial": result.partial,
        "error_count": len(result.errors),
        "sev_rows": sev_rows,
        "dep_count": len(deps),
        "total_findings": len(findings),
        "files_scanned": result.files_scanned,
        "deps_scanned": result.dependencies_scanned,
        "findings": f_rows,
        "deps": d_rows,
        "errors": [
            {"stage": e.stage, "target": e.target, "message": e.message}
            for e in result.errors
        ],
        "rerun_cmd": rerun_command(result, "html"),
        "severity_order": [s.value for s in SEVERITY_ORDER],
    }


def render_html(result: ScanResult) -> str:
    return _env().get_template("report.html.j2").render(**_context(result))
