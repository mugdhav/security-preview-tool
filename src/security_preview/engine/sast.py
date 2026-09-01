"""Static analysis pass: run the built-in regex rules over a list of files.

``scan_paths`` is the orchestrator seam. It never raises -- any per-file failure
is recorded on the :class:`ErrorCollector` with ``stage="sast"`` and scanning
continues. Output is deterministic: findings are sorted by
``(file_path, line, rule_id)`` and no wall-clock or RNG is involved.

High-signal rules (SQLi, command injection, deserialization) are matched against
a sliding multi-line window so cross-line string concatenation is caught; the
rest are matched line by line, mirroring the original Security Auditor engine.
Secret values are masked in ``code_snippet`` before the Finding leaves this
module.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..config import ScanConfig
from ..models import ErrorCollector, Finding
from .rules import MATCH_WINDOW, RULES, RULES_BY_EXT, Rule

_CONTEXT_BEFORE = 1
_CONTEXT_AFTER = 1

# ``= "value"`` / ``: 'value'`` -- used to blank out secrets in snippets.
_SECRET_ASSIGN_RE = re.compile(r"""([=:]\s*)(b?['"])([^'"\n]{3,})(['"])""")


def _mask_secret_snippet(snippet: str) -> str:
    def repl(match: re.Match[str]) -> str:
        prefix, open_q, value, close_q = match.groups()
        visible = value[:3]
        return f"{prefix}{open_q}{visible}{'•' * 8}{close_q}"

    return _SECRET_ASSIGN_RE.sub(repl, snippet)


def _snippet(lines: list[str], line_no: int) -> str:
    start = max(0, line_no - 1 - _CONTEXT_BEFORE)
    end = min(len(lines), line_no + _CONTEXT_AFTER)
    return "\n".join(lines[start:end])


def _is_false_positive(rule: Rule, text: str) -> bool:
    return any(fp.search(text) for fp in rule.false_positive_patterns)


def _make_finding(rule: Rule, rel_path: str, line_no: int, lines: list[str]) -> Finding:
    snippet = _snippet(lines, line_no)
    if rule.category == "Secrets":
        snippet = _mask_secret_snippet(snippet)
    return Finding(
        rule_id=rule.rule_id,
        name=rule.name,
        severity=rule.severity,
        confidence=rule.confidence,
        category=rule.category,
        cwe_id=rule.cwe_id,
        file_path=rel_path,
        line=line_no,
        code_snippet=snippet,
        description=rule.description,
        remediation_vulnerable=rule.remediation_vulnerable,
        remediation_secure=rule.remediation_secure,
        cve_ids=[],
    )


def _scan_windowed(rule: Rule, lines: list[str], rel_path: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[int] = set()
    total = len(lines)
    for i in range(total):
        window = "\n".join(lines[i : i + MATCH_WINDOW])
        match = rule.pattern.search(window)
        if not match:
            continue
        line_no = i + window[: match.start()].count("\n") + 1
        if line_no in seen:
            continue
        if _is_false_positive(rule, lines[line_no - 1]):
            continue
        seen.add(line_no)
        out.append(_make_finding(rule, rel_path, line_no, lines))
    return out


def _scan_lines(rule: Rule, lines: list[str], rel_path: str) -> list[Finding]:
    out: list[Finding] = []
    for idx, line in enumerate(lines, start=1):
        if not rule.pattern.search(line):
            continue
        if _is_false_positive(rule, line):
            continue
        out.append(_make_finding(rule, rel_path, idx, lines))
    return out


def _scan_code(code: str, rel_path: str, rules: list[Rule]) -> list[Finding]:
    lines = code.split("\n")
    out: list[Finding] = []
    for rule in rules:
        if rule.windowed:
            out.extend(_scan_windowed(rule, lines, rel_path))
        else:
            out.extend(_scan_lines(rule, lines, rel_path))
    return out


def scan_paths(
    root: str, files: list[str], cfg: ScanConfig, errors: ErrorCollector
) -> list[Finding]:
    """Scan ``files`` and return findings with ``file_path`` relative to ``root``.

    ``cfg`` is accepted for signature stability; confidence filtering is the
    orchestrator's job, not this function's.
    """
    _ = cfg
    root_path = Path(root)
    findings: list[Finding] = []

    for raw in files:
        path = Path(raw)
        rules = RULES_BY_EXT.get(path.suffix.lower())
        if not rules:
            continue
        try:
            code = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            errors.add("sast", str(path), f"could not read file: {exc}")
            continue
        try:
            rel = path.resolve().relative_to(root_path.resolve()).as_posix()
        except ValueError:
            rel = path.name
        try:
            findings.extend(_scan_code(code, rel, rules))
        except re.error as exc:  # pragma: no cover - defensive, patterns are static
            errors.add("sast", str(path), f"rule evaluation failed: {exc}")

    findings.sort(key=lambda f: (f.file_path, f.line, f.rule_id))
    return findings


__all__ = ["RULES", "scan_paths"]
