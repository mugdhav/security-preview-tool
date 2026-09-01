# security-preview — Usage

A deterministic, **non-LLM** static security scanner for a local project
directory. It runs regex + AST pattern rules (SAST) and real dependency CVE
matching (SCA, via `api.osv.dev`), then produces a vulnerability report with
per-finding remediation. Same tree in, same report out.

- Nothing leaves your machine except optional CVE lookups (OSV for dependencies,
  NVD for illustrative CVE examples). `--offline` disables even those.
- No source code is uploaded anywhere. No language model is involved.

## Install

### 1. Bootstrap an isolated environment (recommended)

From the repository root:

```
python scripts/bootstrap.py
```

This creates `.venv/` and installs the package in editable mode. It prefers
[`uv`](https://docs.astral.sh/uv/) when it is on your PATH (`uv venv` +
`uv pip install -e .`) and otherwise falls back to the standard library
(`python -m venv .venv` + that venv's `pip install -e .`).

Options:

| Flag | Effect |
|---|---|
| `--dev` | also install the `dev` extra (pytest, pytest-asyncio, ruff, mypy) |
| `--venv PATH` | put the virtualenv somewhere other than `./.venv` |
| `--no-uv` | ignore `uv` even if installed; use `python -m venv` + `pip` |
| `--dry-run` | print the commands without running them |
| `--help` | usage |

Then activate it:

```
source .venv/bin/activate                 # macOS / Linux
.venv\Scripts\activate.bat                 # Windows cmd.exe
.venv\Scripts\Activate.ps1                 # Windows PowerShell
```

Confirm the install:

```
security-preview selftest
```

### 2. Or install directly

```
uv tool install .        # or: pipx install .        or: pip install -e ".[dev]"
```

Both a console script (`security-preview`) and a module entry point
(`python -m security_preview.cli`) are provided; they are equivalent.

## Run a scan

```
security-preview scan <path> [--format text|markdown|json|sarif|html] \
                             [--offline] [--no-sca] \
                             [--min-confidence low|medium|high] [--out FILE]
```

Examples:

```
security-preview scan .                                   # text report to stdout
security-preview scan ./service --format markdown --out SECURITY_REPORT.md
security-preview scan . --format json --min-confidence medium
security-preview scan . --format sarif --out results.sarif
security-preview scan . --offline --no-sca                # SAST only, no network
```

### `scan` flags

| Flag | Values (default) | Meaning |
|---|---|---|
| `<path>` | required | Directory to scan. Must be a directory. |
| `--format` | `text` (default), `markdown`, `json`, `sarif`, `html` | Output format. |
| `--offline` | off | Skip **all** network (OSV + NVD). Code findings still complete; enrichment is skipped and the report is marked **PARTIAL**. For CI / air-gapped runs. |
| `--no-sca` | off | Skip dependency scanning entirely; run SAST rules only. |
| `--min-confidence` | `low`, `medium` (default), `high` | Hide findings whose confidence is below this level. Confidence is independent of severity. |
| `--out` | stdout | Write the report to this path instead of printing it. |

Exit status: `0` whenever a scan completes, **even if it found vulnerabilities**;
non-zero only on a hard error (path does not exist, path is a file, unreadable
root). CI gates should inspect the JSON or SARIF content, not the exit code — see
the hook example below.

## Other subcommands

### `security-preview serve [--port N]`

Starts the local browser UI, bound to `127.0.0.1` only, and opens a browser tab.
If `--port` is omitted a free port is chosen. In the page: paste a folder path
(Windows and POSIX separators both accepted), tick `Offline` / `Scan
dependencies`, pick `Min confidence`, click **Scan**, read the rendered report,
and use `Download ▾` to save it as markdown / json / sarif / html. The UI is
desktop-only and ships no external resources.

### `security-preview selftest`

Scans the bundled vulnerable fixtures, asserts the expected findings and the JSON
schema, and exits non-zero on any mismatch. Run it after bootstrap and in CI to
verify the install is intact.

## Reading the report

Every format carries the same data; pick by audience.

### Summary

- **Severity counts** — CRITICAL, HIGH, MEDIUM, LOW, INFO. Fixed order, always
  shown with colour + icon + word.
- **Files scanned** and **dependencies scanned**.
- A **PARTIAL** banner appears when some work could not finish (network failure,
  oversized file, parse error). The `errors` list says what was skipped and why.
  A partial scan is still a valid scan — the code findings are complete.

### Code findings

Grouped by severity, highest first. Each finding has:

- `rule_id`, `name`, `category` (Injection, Crypto, Secrets, Config, …), and a
  `cwe_id` when applicable;
- `file_path` (relative, posix separators) and `line`;
- a `code_snippet` with the offending line — **secret values are masked**
  (`sk_live_••••…`) before they ever reach a report;
- `confidence` (HIGH / MEDIUM / LOW), independent of severity;
- `description` ("what's wrong"), plus `remediation_vulnerable` and
  `remediation_secure` code blocks;
- `cve_ids` — illustrative example CVEs for the CWE (from NVD enrichment), not a
  claim that your code contains that specific CVE.

### Vulnerable dependencies

A separate section. Each entry: `ecosystem`, `package`, `version`,
`advisory_ids` (OSV / GHSA / CVE), `severity`, `fixed_version` (the lowest
version that resolves it, when known), and `source_manifest` (which lockfile it
came from). These are **real** known-vulnerability matches from OSV, distinct
from the pattern-based code findings.

### Format specifics

| Format | Use it for |
|---|---|
| `text` | quick terminal read |
| `markdown` | CommonMark + GFM tables, severity as emoji; commit into a repo or paste into a PR |
| `json` | automation; exactly `ScanResult.to_dict()` — `summary`, `findings`, `dependency_findings`, `errors`, `partial`, `tool_version` |
| `sarif` | SARIF 2.1.0; upload to a code-scanning dashboard |
| `html` | one self-contained file — inline CSS, no `<script>`, no web fonts, `prefers-color-scheme` aware, print-friendly |

## Offline mode

`--offline` skips every network call:

- no OSV dependency lookups (the Vulnerable Dependencies section will be empty
  even if lockfiles are present);
- no NVD CVE enrichment (`cve_ids` stays empty).

SAST code findings are unaffected and complete normally. The report is marked
**PARTIAL** to make the reduced coverage explicit. Repeat online scans are fast
because OSV/NVD responses are cached on disk for 24 h under
`~/.security-preview/cache/`, and a cached result is still usable offline.

## CI / commit gate

`.claude/hooks-example.json` in the repo root is a ready-to-adapt Claude Code
hooks config with two hooks:

1. **SessionStart** — runs `security-preview scan . --format text
   --min-confidence high` when a Claude Code session starts and feeds the summary
   back as context. Non-blocking; a no-op if the CLI is not installed.
2. **PreToolUse** (`matcher: "Bash"`) — before a Bash command that contains
   `git commit`, runs `security-preview scan . --format json` and compares the
   CRITICAL count to a baseline in `.security-preview/baseline-critical` (a single
   integer; `0` when the file is missing). If the count has grown, the hook exits
   `2`, which **blocks the commit** and shows the reason to Claude.

### Install the hook

Merge the `hooks` object from `.claude/hooks-example.json` into your
`.claude/settings.json` (project-scoped, checked in) or `~/.claude/settings.json`
(user-scoped). Keep any hooks you already have. The `_README` array in that file
is documentation only — it is ignored by Claude Code.

### Set / update the baseline

Adopt the current CRITICAL count as the accepted baseline (e.g. when starting on
a legacy codebase):

```
mkdir -p .security-preview
security-preview scan . --format json \
  | python -c "import json,sys; print(json.load(sys.stdin)['summary']['by_severity']['CRITICAL'])" \
  > .security-preview/baseline-critical
```

Commit `.security-preview/baseline-critical` so the gate is shared. Lower it as
you fix findings; the gate only ever blocks an **increase**.

### Plain (non-Claude) CI

The same idea without hooks — fail the job when CRITICAL findings exceed the
baseline:

```
security-preview scan . --format json --min-confidence medium --out scan.json
python - <<'PY'
import json, sys, pathlib
crit = json.load(open("scan.json"))["summary"]["by_severity"]["CRITICAL"]
base = int(pathlib.Path(".security-preview/baseline-critical").read_text().strip()
           if pathlib.Path(".security-preview/baseline-critical").exists() else "0")
if crit > base:
    sys.exit(f"{crit} CRITICAL findings (baseline {base})")
PY
```

For air-gapped runners add `--offline`.
