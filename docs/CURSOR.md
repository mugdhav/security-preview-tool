# security-preview in Cursor and other AI-coding editors

`security-preview` is a plain CLI, so any editor that can run a shell command or a
task can use it. There is no editor plugin and nothing to configure beyond
installing the package. This guide covers Cursor specifically; the same approach
works in VS Code, Windsurf, Zed, JetBrains, or a bare terminal.

## 1. Install once

From the project root:

```
python scripts/bootstrap.py
```

That builds `.venv/` (preferring `uv`) and installs the `security-preview`
console script. Either activate `.venv` in your integrated terminal, or install
the tool globally so it is always on PATH:

```
uv tool install .        # or: pipx install .
```

Verify:

```
security-preview selftest
```

## 2. Invoke it from the editor

### From the AI chat / agent

Tell the assistant to run the CLI and read the machine-readable output, e.g.:

> Run `security-preview scan . --format json --min-confidence medium` and
> summarise the CRITICAL and HIGH findings with file:line and the secure
> remediation for each.

The assistant runs it in the integrated terminal and works from the JSON. Ask for
`--format markdown --out SECURITY_REPORT.md` when you want a durable report in the
repo.

### As a Cursor / VS Code task

Add `.vscode/tasks.json` (Cursor reads it too):

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "security-preview: scan (markdown)",
      "type": "shell",
      "command": "security-preview scan . --format markdown --out SECURITY_REPORT.md",
      "problemMatcher": []
    },
    {
      "label": "security-preview: scan (SARIF)",
      "type": "shell",
      "command": "security-preview scan . --format sarif --out results.sarif",
      "problemMatcher": []
    },
    {
      "label": "security-preview: scan (offline, SAST only)",
      "type": "shell",
      "command": "security-preview scan . --offline --no-sca --format text",
      "problemMatcher": []
    }
  ]
}
```

Run via the command palette → *Tasks: Run Task*.

### As a rules / instructions entry

Add a short note to `.cursorrules` (or `.cursor/rules/*.mdc`, or your editor's
equivalent) so the agent reaches for the tool at the right moment:

```
When asked for a security review, vulnerability check, or a pre-ship safety pass,
run `security-preview scan <dir> --format json --min-confidence medium`, parse the
JSON, and report the severity summary plus top findings with file:line and the
`remediation_secure` block. It is deterministic and non-LLM. Use `--offline` when
there is no network.
```

## 3. Consume the output

### JSON (`--format json`)

Exactly `ScanResult.to_dict()`. Shape:

```jsonc
{
  "tool_version": "0.1.0",
  "target": "/abs/path",
  "started_at": "2026-09-01T14:22:00+00:00",
  "finished_at": "2026-09-01T14:22:03+00:00",
  "summary": {
    "by_severity": { "CRITICAL": 1, "HIGH": 0, "MEDIUM": 2, "LOW": 0, "INFO": 0 },
    "total_findings": 3,
    "vulnerable_dependencies": 1,
    "files_scanned": 342,
    "dependencies_scanned": 47,
    "duration_seconds": 3.0,
    "partial": false,
    "errors": 0
  },
  "findings": [
    {
      "rule_id": "py.sqli",
      "name": "SQL Injection",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "category": "Injection",
      "cwe_id": "CWE-89",
      "file_path": "api/reports.py",
      "line": 142,
      "code_snippet": "cur.execute(f\"... {owner}\")",
      "description": "User input flows into a SQL string.",
      "remediation_vulnerable": "cur.execute(f\"... {owner}\")",
      "remediation_secure": "cur.execute(\"... %s\", (owner,))",
      "cve_ids": []
    }
  ],
  "dependency_findings": [
    {
      "ecosystem": "PyPI",
      "package": "pyyaml",
      "version": "5.1",
      "advisory_ids": ["CVE-2020-1747"],
      "severity": "CRITICAL",
      "fixed_version": "5.3.1",
      "source_manifest": "requirements.txt",
      "summary": "Arbitrary code execution via full_load."
    }
  ],
  "errors": [],
  "partial": false
}
```

`file_path` is relative to the scan root with posix separators; `line` is
1-based; secret values in `code_snippet` are already masked. When `partial` is
`true`, inspect `errors` (`{stage, target, message}`, `stage` in
`walk|sast|sca|enrich`) — the scan still ran, just with reduced coverage.

Extract findings for a given file (agent tool call, jq, etc.):

```
security-preview scan . --format json \
  | jq '.findings[] | select(.file_path=="api/reports.py") | {line, name, severity, remediation_secure}'
```

### SARIF (`--format sarif`)

SARIF 2.1.0. Point any SARIF viewer at it — the *SARIF Viewer* extension for
VS Code / Cursor renders findings inline in the editor gutter, and GitHub / GitLab
code scanning ingest it directly:

```
security-preview scan . --format sarif --out results.sarif
```

### Markdown / HTML

`--format markdown --out SECURITY_REPORT.md` for a repo-committable report;
`--format html --out security-report.html` for a self-contained page to open in a
browser (inline CSS, no scripts, no network).

## 4. Notes

- Deterministic: identical tree ⇒ identical report. Safe to diff between runs.
- Windows and POSIX path separators are both accepted for `<path>`.
- `--offline` skips all network (OSV + NVD); SAST still completes and the report
  is flagged **PARTIAL**. OSV/NVD responses are cached under
  `~/.security-preview/cache/` for 24 h, so later online runs are fast.
- Exit code: `0` = completed, no CRITICAL findings; `1` = completed with CRITICAL
  findings; `2` = usage/IO error. The report is still emitted on exit `1`, so a
  baseline-diff gate can parse the JSON either way. See `docs/USAGE.md`.
