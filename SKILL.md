---
name: security-preview
description: >-
  Run a deterministic, non-LLM static security scan (SAST + dependency CVE check)
  on a local project directory and produce a vulnerability report with
  remediation. Use for a security review / scan / vuln check, or before shipping.
---

# security-preview

`security-preview` is a deterministic, **non-LLM** static analyzer for a local
project directory. It runs regex + AST pattern rules (SAST) and real dependency
CVE matching (SCA) against `api.osv.dev`, then emits a vulnerability report with
per-finding remediation. Nothing about the analysis is model-driven, so results
are stable and reproducible: the same tree yields the same report.

## When to use this skill

Invoke it whenever the user asks for any of:

- a "security review", "security scan", "vulnerability check", "vuln check",
  "audit this code for security issues";
- "check my dependencies for CVEs" / "is anything I depend on vulnerable";
- a pre-ship / pre-release / pre-commit safety pass on a directory.

Do **not** use it for remote URL scanning, dynamic analysis, or secret rotation —
it only reads files on disk.

## How to run it

The tool ships as a console script (`security-preview`) and an equivalent module
entry point (`python -m security_preview.cli`). If neither is importable yet, run
the bootstrap once — it builds an isolated virtualenv and installs the package:

```
python scripts/bootstrap.py
```

Then run a scan and consume the JSON:

```
security-preview scan "<project-dir>" --format json --min-confidence medium
```

(equivalently `python -m security_preview.cli scan "<project-dir>" --format json
--min-confidence medium`).

Parse the JSON, then present to the user:

1. the `summary.by_severity` table plus `files_scanned` / `dependencies_scanned`;
2. the top findings (CRITICAL and HIGH first) with `file_path:line`, the masked
   `code_snippet`, and the `remediation_secure` block;
3. any vulnerable dependencies from `dependency_findings` (package, advisory ids,
   `fixed_version`);
4. if `partial` is true, warn that the scan was incomplete and list `errors`.

Offer to write the full human-readable report into the project, e.g.
`security-preview scan "<project-dir>" --format markdown --out SECURITY_REPORT.md`
or `--format html --out security-report.html`.

## CLI surface

### `security-preview scan <path> [options]`

Scan a directory and print (or write) a report.

| Flag | Values / default | Meaning |
|---|---|---|
| `<path>` | required | Directory to scan. |
| `--format` | `text` (default), `markdown`, `json`, `sarif`, `html` | Report format. |
| `--offline` | off | Skip **all** network (OSV + NVD). Code findings still complete; the report is marked PARTIAL for the skipped enrichment. Use in CI / air-gapped. |
| `--no-sca` | off | Skip dependency (SCA) scanning; run SAST only. |
| `--min-confidence` | `low`, `medium` (default), `high` | Drop findings below this confidence. |
| `--out` | stdout | Write the report to this file instead of stdout. |

Exit code: `0` when the scan completes with no CRITICAL findings, `1` when it
completes with one or more CRITICAL findings, `2` on a usage / IO error (path
missing, not a directory, bad `--format`). Network / enrichment failures only mark
the report PARTIAL. The report is still emitted on exit `1`, so a new-vs-baseline
CI gate can parse the JSON regardless of the code.

### `security-preview serve [--port N]`

Start the local browser UI on `http://127.0.0.1:<port>` (127.0.0.1 only, random
free port if `--port` is omitted) and open a browser. Paste a folder path, choose
options, click Scan, read the rendered report, download it as md/json/sarif/html.

### `security-preview selftest`

Scan the bundled vulnerable fixtures, assert the known findings and the JSON
schema, and exit non-zero on any mismatch. Run it once after bootstrap and in CI
to confirm the install is healthy.

## Report formats at a glance

- **text** — terminal summary + findings; good for a quick look.
- **markdown** — CommonMark + GFM tables, severity as emoji; drop into a repo or
  a PR description.
- **json** — `ScanResult.to_dict()`; the machine contract this skill parses.
- **sarif** — SARIF 2.1.0; upload to code-scanning dashboards.
- **html** — self-contained single file (inline CSS, no scripts, no web fonts);
  hand to a non-terminal reviewer.

## Optional hook

`.claude/hooks-example.json` in the repo shows a `SessionStart` scan and a
`PreToolUse` guard that blocks `git commit` when a new CRITICAL finding appears.
See `docs/USAGE.md` for installation. Editor integration (Cursor and similar) is
covered in `docs/CURSOR.md`.
