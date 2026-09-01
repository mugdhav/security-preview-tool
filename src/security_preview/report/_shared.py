"""Shared helpers for the report renderers.

Everything here is pure and deterministic: the same :class:`ScanResult` always
yields the same intermediate values, independent of dict/list iteration order in
the input.
"""
from __future__ import annotations

from datetime import timezone

from ..models import DependencyFinding, Finding, RiskLevel, ScanResult

# Fixed severity order used by every renderer (CRITICAL first ... INFO last).
SEVERITY_ORDER: tuple[RiskLevel, ...] = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.INFO,
)

# Emoji tokens for the Markdown report (design brief 1.1 / 5.2).
SEVERITY_EMOJI: dict[str, str] = {
    "CRITICAL": "\U0001f534",  # red circle
    "HIGH": "\U0001f7e0",      # orange circle
    "MEDIUM": "\U0001f7e1",    # yellow circle
    "LOW": "\U0001f535",       # blue circle
    "INFO": "⚪",          # white circle
}

# Solid badge hex + row tint, locked in security-preview-plan.md 6.
SEVERITY_HEX: dict[str, str] = {
    "CRITICAL": "#912018",
    "HIGH": "#d92d20",
    "MEDIUM": "#b45309",
    "LOW": "#175cd3",
    "INFO": "#667085",
}
SEVERITY_TINT: dict[str, str] = {
    "CRITICAL": "#fef3f2",
    "HIGH": "#fff4ed",
    "MEDIUM": "#fffaeb",
    "LOW": "#eff4ff",
    "INFO": "#f2f4f7",
}

# SARIF 2.1.0 result levels.
SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    """Stable presentation order: severity, then file, line, rule, name."""
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, f.file_path, f.line, f.rule_id, f.name),
    )


def sorted_dependency_findings(deps: list[DependencyFinding]) -> list[DependencyFinding]:
    """Stable presentation order: severity, package, version, first advisory."""
    return sorted(
        deps,
        key=lambda d: (
            d.severity.rank,
            d.package,
            d.version,
            d.advisory_ids[0] if d.advisory_ids else "",
            d.source_manifest,
        ),
    )


def cwe_url(cwe_id: str | None) -> str | None:
    """MITRE definition URL for a ``CWE-<n>`` id, or ``None``."""
    if not cwe_id:
        return None
    digits = cwe_id.split("-", 1)[-1].strip()
    if not digits.isdigit():
        return None
    return f"https://cwe.mitre.org/data/definitions/{digits}.html"


def advisory_url(advisory_id: str) -> str:
    """Best-effort canonical URL for an OSV / GHSA / CVE advisory id."""
    aid = advisory_id.strip()
    upper = aid.upper()
    if upper.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{upper}"
    if upper.startswith("GHSA-"):
        return f"https://github.com/advisories/{aid}"
    return f"https://osv.dev/vulnerability/{aid}"


def scanned_line(result: ScanResult) -> str:
    """The ``<timestamp> UTC | <duration> | deterministic, non-LLM`` line."""
    ts = result.started_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    dur = result.summary()["duration_seconds"]
    dur_txt = f"{dur:.1f}s" if isinstance(dur, (int, float)) else "n/a"
    return f"{ts} | {dur_txt} | deterministic, non-LLM"


def severity_counts(result: ScanResult) -> list[tuple[str, int]]:
    """``[(level, count), ...]`` in the fixed severity order."""
    by_sev = result.summary()["by_severity"]
    return [(lvl.value, by_sev.get(lvl.value, 0)) for lvl in SEVERITY_ORDER]


def snippet_lines(finding: Finding) -> list[tuple[int | None, str, bool]]:
    """Parse ``code_snippet`` into ``(lineno, text, is_offending)`` rows.

    Recognises an optional ``123|`` or ``123:`` gutter prefix. When no gutter is
    present, line numbers are ``None`` and nothing is marked as the hit line.
    """
    raw = finding.code_snippet.replace("\r\n", "\n").replace("\r", "\n")
    rows: list[tuple[int | None, str, bool]] = []
    for line in raw.split("\n"):
        num: int | None = None
        text = line
        for sep in ("|", ":"):
            head, found, tail = line.partition(sep)
            if found and head.strip().isdigit():
                num = int(head.strip())
                text = tail.removeprefix(" ")
                break
        rows.append((num, text, num is not None and num == finding.line))
    return rows


def rerun_command(result: ScanResult, fmt: str) -> str:
    return f'security-preview scan "{result.target}" --format {fmt}'
