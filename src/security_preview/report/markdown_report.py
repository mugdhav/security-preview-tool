"""Markdown report (CommonMark + GFM), per design brief 5.2.

No raw HTML, no ``<details>``. Severity is emoji + UPPERCASE word so the meaning
survives with emoji stripped.
"""
from __future__ import annotations

from ..models import Finding, ScanResult
from ._shared import (
    SEVERITY_EMOJI,
    advisory_url,
    cwe_url,
    rerun_command,
    scanned_line,
    severity_counts,
    snippet_lines,
    sorted_dependency_findings,
    sorted_findings,
)

_LANG_BY_EXT = {
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "go": "go",
    "rb": "ruby",
    "java": "java",
    "php": "php",
    "c": "c",
    "cpp": "cpp",
    "cs": "csharp",
    "sh": "bash",
    "yml": "yaml",
    "yaml": "yaml",
    "json": "json",
    "sql": "sql",
}


def _lang(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return _LANG_BY_EXT.get(ext, "")


def _sev(level: str) -> str:
    return f"{SEVERITY_EMOJI[level]} {level}"


def _finding_block(f: Finding) -> list[str]:
    out: list[str] = []
    out.append(f"### {_sev(f.severity.value)} — {f.name} — {f.file_path}:{f.line}")
    out.append("")
    out.append(f.description)
    out.append("")
    out.append(f"**Location:** `{f.file_path}:{f.line}`")
    meta = [f"**Rule:** `{f.rule_id}`", f"**Category:** {f.category}",
            f"**Confidence:** {f.confidence.value}"]
    url = cwe_url(f.cwe_id)
    if f.cwe_id and url:
        meta.append(f"[{f.cwe_id}]({url})")
    elif f.cwe_id:
        meta.append(f.cwe_id)
    out.append(" · ".join(meta))
    out.append("")

    lang = _lang(f.file_path)
    out.append(f"```{lang}".rstrip())
    for _num, text, _hit in snippet_lines(f):
        out.append(text)
    out.append("```")
    out.append(f"> offending line: {f.line}")
    out.append("")

    out.append("**Vulnerable**")
    out.append("")
    out.append(f"```{lang}".rstrip())
    out.append(f.remediation_vulnerable)
    out.append("```")
    out.append("")
    out.append("**Secure**")
    out.append("")
    out.append(f"```{lang}".rstrip())
    out.append(f.remediation_secure)
    out.append("```")
    out.append("")

    if f.cve_ids:
        out.append("Illustrative CVEs:")
        out.append("")
        for cve in f.cve_ids:
            out.append(f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
        out.append("")
    return out


def render_markdown(result: ScanResult) -> str:
    findings = sorted_findings(result.findings)
    deps = sorted_dependency_findings(result.dependency_findings)
    out: list[str] = []

    out.append("# security-preview report")
    out.append("")
    out.append(f"target: `{result.target}`")
    out.append("")
    out.append(f"scanned: {scanned_line(result)}")
    out.append("")

    out.append("## Summary")
    out.append("")
    if result.partial:
        out.append("> [!WARNING]")
        out.append(
            f"> PARTIAL — {len(result.errors)} issue(s) recorded during the scan. "
            "Code findings are"
        )
        out.append("> complete; only some illustrative data is missing. See "
                   "[Skipped / errors](#skipped--errors).")
        out.append("")
    out.append("| Severity | Count |")
    out.append("| --- | --- |")
    for level, count in severity_counts(result):
        out.append(f"| {_sev(level)} | {count} |")
    out.append(f"| Vulnerable dependencies | {len(deps)} |")
    out.append("")
    out.append(
        f"Files scanned: {result.files_scanned} · "
        f"Dependencies checked: {result.dependencies_scanned}"
    )
    out.append("")

    out.append("## Code findings")
    out.append("")
    if not findings:
        out.append("No code findings.")
        out.append("")
    else:
        for f in findings:
            out.extend(_finding_block(f))

    out.append("## Vulnerable dependencies")
    out.append("")
    if not deps:
        out.append("No vulnerable dependencies.")
        out.append("")
    else:
        for d in deps:
            fixed = f"fixed in `{d.fixed_version}`" if d.fixed_version else "no fix available"
            out.append(f"- {_sev(d.severity.value)} — `{d.package} {d.version}` "
                       f"({d.ecosystem}) — {fixed}")
            out.append(f"  {d.summary}")
            if d.advisory_ids:
                links = ", ".join(f"[{a}]({advisory_url(a)})" for a in d.advisory_ids)
                out.append(f"  Advisories: {links}")
            out.append(f"  Source: `{d.source_manifest}`")
        out.append("")

    out.append("## Skipped / errors")
    out.append("")
    if not result.errors:
        out.append("Nothing was skipped; all stages completed.")
        out.append("")
    else:
        out.append("> [!NOTE]")
        out.append(f"> {len(result.errors)} issue(s) recorded. Code findings above are complete.")
        out.append("")
        for e in result.errors:
            out.append(f"- **{e.stage}** — `{e.target}` — {e.message}")
        out.append("")

    out.append("---")
    out.append("")
    out.append(
        f"Generated by security-preview v{result.tool_version} — a deterministic, non-LLM "
        "static scan. Findings are pattern- and dependency-based; treat them as leads, "
        "not proof."
    )
    out.append("")
    out.append(f"Re-run: `{rerun_command(result, 'markdown')}`")

    return "\n".join(out) + "\n"
