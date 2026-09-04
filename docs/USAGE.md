# Vulnascan CLI — `security-preview`

A deterministic, **non-LLM** static security scanner for a local project
directory. It runs regex + AST pattern rules (SAST) and real dependency CVE
matching (SCA, via `api.osv.dev`), then produces a vulnerability report with
per-finding remediation. Same tree in, same report out.

- Nothing leaves your machine except optional CVE lookups (OSV for dependencies,
  NVD for illustrative CVE examples). `--offline` disables even those.
- No source code is uploaded anywhere. No language model is involved.

## What a report looks like

```console
$ security-preview scan ./service --offline --min-confidence high
security-preview report v0.1.0
target:  ./service
scanned: 2026-09-02 20:20 UTC | 0.0s | deterministic, non-LLM

SUMMARY
  CRITICAL  7
  HIGH      2
  MEDIUM    2
  LOW       0
  INFO      0
  DEPS      0  (vulnerable dependencies)
  files scanned: 13 | dependencies checked: 0

CODE FINDINGS (11)

CRITICAL
  [sast.command-injection] Command Injection
    location:   command_injection.py:7
    cwe:        CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
    category:   Injection
    confidence: HIGH
    snippet:
           | def ping(host):
           |     os.system("ping -c 1 " + host)
    what's wrong: User input may be passed to a system shell, allowing arbitrary
                  command execution on the host.
    vulnerable:   os.system(f"ping {user_input}")
    secure:       subprocess.run(["ping", user_input], shell=False)
```

`--format markdown` emits the same data as GFM (a summary table, severity as
emoji, one section per finding) for committing into a repo or pasting into a PR;
`--format html` is one self-contained page. Full breakdown in
[Reading the report](#reading-the-report).

## Install

> For the packaged double-click desktop app (no Python), download from the
> [Releases page](https://github.com/mugdhav/security-preview-tool/releases) —
> see [`DESKTOP.md`](DESKTOP.md).

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

Exit status: `0` when the scan completes with **no CRITICAL findings** (after the
confidence filter); `1` when the scan completes and at least one CRITICAL finding
remains; `2` on a usage / IO error (path missing, path is a file, bad `--format`,
unwritable `--out`). Network or enrichment failures never change the exit code —
they only mark the report **PARTIAL**. The report is still written to stdout / `--out`
on exit `1`, so CI gates that want new-vs-baseline semantics can parse the JSON
regardless of the code — see the hook example below.

## Other subcommands

### `security-preview serve [--port N] [--open|--no-open] [--desktop]`

Starts the local UI, bound to `127.0.0.1` only.

- `--port` defaults to `0` → the OS assigns a free port. The resolved URL is
  printed as `security-preview → http://127.0.0.1:<port>  (Ctrl+C to stop)`.
- `--open` (default) opens that URL in your browser once the server answers
  `GET /healthz`; `--no-open` just prints it.
- `--desktop` opens a **native window** instead of a browser tab and enables the
  **Choose folder…** button (native OS folder picker). Needs `pywebview`
  (`pip install "security-preview[desktop]"`); without it, `serve` falls back to
  the browser.

In the page: click **Choose folder…** (desktop) or paste an absolute folder path
(Windows and POSIX separators both accepted), tick `Offline` / `Scan
dependencies`, pick `Min confidence`, click **Scan**, read the rendered report,
and use `Download ▾` to save it. The UI ships no external resources.

The folder you point at **is** the root for that scan — there is no global
allowed root. `..` tokens and symlink escapes in a typed path are still rejected
with HTTP 400.

For the packaged double-click app (installers, no Python), see
[`DESKTOP.md`](DESKTOP.md).

> **Removed:** the `SECURITY_PREVIEW_ROOT` environment variable no longer exists.
> The scan root now comes from the folder chosen per scan.

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

Markdown (`--format markdown`):

```markdown
# security-preview report

## Summary

| Severity | Count |
| --- | --- |
| 🔴 CRITICAL | 7 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 2 |
| 🔵 LOW | 0 |
| ⚪ INFO | 0 |
| Vulnerable dependencies | 0 |

### 🔴 CRITICAL — Command Injection — command_injection.py:7
...
```

Vulnerable dependencies, `--format text` excerpt (online scan):

```console
VULNERABLE DEPENDENCIES
  MEDIUM    requests 2.25.1 (PyPI)
    advisories: CVE-2023-32681, CVE-2024-35195, CVE-2024-47081, GHSA-9wx4-h78v-vm56, PYSEC-2023-74, …
    fixed in:   2.31.0
    source:     manifests/pip/requirements.txt
    summary:    Requests vulnerable to .netrc credentials leak via malicious URLs
  LOW       @babel/core 7.12.3 (npm)
    advisories: CVE-2026-49356, GHSA-4x5r-pxfx-6jf8
    fixed in:   7.29.6
    source:     manifests/npm/package-lock.json
```

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
