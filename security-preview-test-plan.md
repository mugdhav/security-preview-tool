# security-preview — Test Plan

Date: 2026-09-01
Covers: `v0.1.0-foundation`
Reads with: `security-preview-plan.md` (what the tool does),
`security-preview-design-brief.md` (UI/report spec),
`security-preview-parallel-build-plan.md` (module contracts).

---

## 1. Purpose & scope

Verify the three user-facing surfaces of security-preview behave to spec:

| # | Surface | Entry point | What "working" means |
|---|---------|-------------|----------------------|
| A | **CLI tool** | `security-preview` / `python -m security_preview.cli` | `scan` / `serve` / `selftest` produce correct reports, exit codes, and flag behaviour |
| B | **Browser app** | `security-preview serve` → `http://127.0.0.1:<port>` | FastAPI API + single-window desktop UI match the design brief and confine the scanned path |
| C | **Coding-harness skill** | `SKILL.md` + `.claude/hooks-example.json` | An agent triggers the skill on the right prompts, runs the CLI, and reports findings correctly; the example hooks gate a session / commit |

**In scope:** functional correctness, determinism, offline/degraded-network behaviour, path-confinement security, report-format validity, exit codes, skill trigger behaviour, hook scripts.

**Out of scope:** rule-precision tuning (false-positive/negative rate is a milestone-M7 concern), remote/dynamic scanning, load/soak testing beyond the sanity caps, packaging to PyPI, cross-browser matrix (UI is desktop-Chromium only per brief §3).

---

## 2. Test environment

### 2.1 Matrix

| Axis | Values |
|---|---|
| OS | Windows 11 (primary), macOS or Linux (secondary smoke) |
| Python | 3.10 (floor), 3.13 (primary) |
| Network | online; **offline** (firewall / `--offline`); **degraded** (DNS or TCP blackhole) |
| Install mode | `pip install -e ".[dev]"`; `scripts/bootstrap.py` venv; `python -m security_preview.cli` without install |

### 2.2 Setup

```
python scripts/bootstrap.py          # or: python -m pip install -e ".[dev]"
security-preview selftest            # sanity: must print JSON summary
python -m pytest -q                  # baseline: 139 passed
```

### 2.3 Test data (in-repo)

- `tests/fixtures/vulnerable/` — 13 must-detect samples (SQLi, cmd-injection, deser, XXE, SSRF, path-traversal, weak crypto/hash, hardcoded creds, TLS-verify-off, CORS `*`, debug-mode, XSS).
- `tests/fixtures/safe/` — 10 must-**not**-detect framework idioms (parameterised SQL, arg-vector subprocess, `yaml.safe_load`, `defusedxml`, env-var secrets, bcrypt/Fernet, pinned TLS…).
- `tests/fixtures/manifests/` — one lockfile per ecosystem: pip, poetry, pipenv, npm, yarn, go, ruby, maven.
- `tests/fixtures/golden/` — frozen `text|md|json|sarif|html` renders of `sample_scan_result.json`.
- External real project: `../security_auditor` (larger tree, unpinned `requirements.txt`).

---

## 3. Component A — CLI tool

Legend: **[auto]** already covered by `tests/test_cli.py` / `test_scan.py`; **[manual]** run by hand for this plan; **[both]** automated but re-verify on release.

### 3.1 `scan` — happy path

| ID | Case | Steps | Expected |
|---|---|---|---|
| CLI-01 | Default scan | `security-preview scan tests/fixtures/vulnerable` | Text report to stdout; severity table; ≥1 finding per vulnerable category; exit **1** (CRITICAL present). **[both]** |
| CLI-02 | Each format | `--format text\|markdown\|json\|sarif\|html` against the same dir | Each renders without error; `json` parses; `sarif` validates as SARIF 2.1.0 (`$schema`, `runs[0].tool.driver`, `results[]`); `html` is one file with **no `<script>`**, no `<link>`, no web-font/`@font-face`, ≤1 inline `<style>`; `markdown` has a `## Summary` GFM table. **[both]** |
| CLI-03 | `--out FILE` | `--format markdown --out SECURITY_REPORT.md` | File written UTF-8; stdout empty; content identical to piped render; exit code unchanged. **[both]** |
| CLI-04 | `--out` unwritable | `--out /nonexistent-dir/x.md` (or read-only path) | stderr `error: cannot write …`; exit **2**; nothing partially written. **[auto]** |
| CLI-05 | Safe tree only | `scan tests/fixtures/safe` | 0 findings; exit **0**; report still well-formed (zero-findings state). **[manual]** |
| CLI-06 | Large real tree | `scan ../security_auditor --offline --format json` | Completes < ~30 s; `files_scanned` > 0; valid JSON; `partial` reflects only network (here offline → enrichment skipped, still `partial` per design note). **[manual]** |

### 3.2 `scan` — flags

| ID | Case | Expected |
|---|---|---|
| CLI-10 | `--offline` | No DNS/TCP to `osv.dev` or `services.nvd.nist.gov` (verify with a sniffer / blocked network). SAST findings unchanged. `dependency_findings` empty. Report/JSON marked PARTIAL. Exit code driven only by findings. **[both]** |
| CLI-11 | `--no-sca` | `sca.collect_components` / `query_osv` never invoked (no manifest parsing); SAST-only; `dependencies_scanned == 0`. **[auto]** |
| CLI-12 | `--min-confidence HIGH` | Findings with confidence MEDIUM/LOW dropped; count ≤ default run; `--min-confidence LOW` ≥ default run. **[both]** |
| CLI-13 | `--min-confidence` default | Omitted ⇒ behaves as `MEDIUM` (matches `ScanConfig.defaults()`). **[auto]** |
| CLI-14 | Flag threading | `--offline` sets `cfg.offline=True` **and** suppresses enrichment; `--no-sca` sets `cfg.run_sca=False`. Assert via monkeypatched seams. **[auto]** |
| CLI-15 | Case sensitivity | `--min-confidence high` (lowercase) → argparse `choices` rejects → exit 2 with usage. (Docs say low/medium/high; CLI `choices` are upper. **Known gap — file bug if release wants lowercase accepted.**) **[manual]** |

### 3.3 `scan` — error handling & exit codes

| ID | Case | Expected |
|---|---|---|
| CLI-20 | Path missing | `scan ./does-not-exist` → stderr `not a directory`; exit **2**. **[auto]** |
| CLI-21 | Path is a file | `scan ./README.md` → exit **2**. **[auto]** |
| CLI-22 | Unknown format | `--format xml` → stderr `unknown format 'xml'`; exit **2**; renderer not called. **[auto]** |
| CLI-23 | No CRITICAL | scan a tree whose worst finding is HIGH → exit **0**. **[auto]** |
| CLI-24 | CRITICAL present | exit **1**; report still fully emitted to stdout/`--out`. **[auto]** |
| CLI-25 | Network failure mid-scan (not `--offline`) | Block sockets after start → scan completes; `partial=True`; `errors[]` has `stage="enrich"` (and/or `"sca"`) entries; **exit code still only findings-driven** (0/1), not 2. **[manual]** |
| CLI-26 | No subcommand | `security-preview` with no args → argparse error, exit 2, usage on stderr. **[manual]** |
| CLI-27 | `-h` / `--help` | Top-level and per-subcommand help list all flags; exit 0. **[manual]** |

### 3.4 `selftest`

| ID | Case | Expected |
|---|---|---|
| CLI-30 | Bundled fixtures present | `security-preview selftest` → pretty JSON summary (`by_severity`, `files_scanned`, …); CRITICAL count > 0 ⇒ exit **1**. **[both]** |
| CLI-31 | Fixtures absent (installed wheel) | Falls back to a generated temp project with an `os.system` sink; still prints summary; temp dir cleaned up afterwards. **[manual]** |
| CLI-32 | Determinism | Run 3× → byte-identical JSON except `duration_seconds`. **[manual]** |

### 3.5 `serve` (CLI side only — see §4 for the app)

| ID | Case | Expected |
|---|---|---|
| CLI-40 | Default port | `security-preview serve` (no `--port`) → OS-assigned free port; stdout prints `security-preview → http://127.0.0.1:<port>  (Ctrl+C to stop)`; `GET /` returns HTML 200; `GET /healthz` → `{"ok":true,"mode":"browser"}`. **[auto: bind+URL; manual: real browser]** |
| CLI-41 | `--port N` | Binds the given port; refuses / errors clearly if taken. **[manual]** |
| CLI-42 | Bind scope | `curl http://<LAN-IP>:<port>/` from another host → connection refused (127.0.0.1 only). **[manual]** |
| CLI-43 | Lazy import | `serve`'s `uvicorn` / `server.app` import is inside the handler — `scan`/`selftest` work in an env without `uvicorn` importable. **[manual]** |
| CLI-44 | `--open` / `--no-open` | Default opens the printed URL via `webbrowser.open` after `/healthz` answers; `--no-open` prints only. **[auto]** |
| CLI-45 | `--desktop` | Delegates to `security_preview.desktop.main`; with `pywebview` absent it falls back to the system browser and still serves. **[auto: delegation; manual: real window]** |

---

## 4. Component B — Browser app

### 4.1 API — `POST /api/scan` (TestClient, `scan` monkeypatched where noted)

| ID | Case | Expected |
|---|---|---|
| API-01 | Valid body | `{path, format:"json", offline:true, run_sca:false, min_confidence:"MEDIUM"}` → 200; body validates against `ScanResponse` (mirrors `ScanResult.to_dict()`): `tool_version`, `summary`, `findings[]`, `dependency_findings[]`, `errors[]`, `partial`. **[auto]** |
| API-02 | Missing `path` | 422 (Pydantic). **[auto]** |
| API-03 | Empty `path` | 400 `path must not be empty`. **[auto]** |
| API-04 | Bad `format` | `"xml"` → 422 `format must be one of ('json','md','sarif','html')`. **[auto]** |
| API-05 | Bad `min_confidence` | `"URGENT"` → 422. Lowercase `"medium"` → accepted, normalised to `MEDIUM`. **[auto]** |
| API-06 | `..` traversal | `path:"../secrets"` → 400 `must not contain '..'` (rejected before FS touch). **[auto]** |
| API-07 | Folder is its own root | Absolute `path` to **any** real directory (any drive, outside cwd/home) → 200; that dir is passed to `scan` verbatim. No global allowed root. **[auto]** |
| API-08 | Symlink escape | `path` traverses a symlink that resolves elsewhere (`realpath != abspath`) → 400 `path escapes via a symlink`. **[auto]** |
| API-09 | Path not a directory | `path:"README.md"` → 400 `path is not a directory`. **[auto]** |
| API-10 | Non-existent path | `path` to a missing dir → 400. **[auto]** |
| API-11 | `/healthz` + mode | `GET /healthz` → `{"ok":true,"mode":"browser"}`; `create_app(mode="desktop", folder_picker=…)` → `"desktop"`. **[auto]** |
| API-16 | `POST /api/pick-folder` | browser mode → 404; desktop mode → `{"path": <picked>}` from `folder_picker`, or `{"cancelled": true}` when it returns falsy. Performs no FS writes. **[auto]** |
| API-12 | Scan timeout | `create_app(scan_timeout=0.01)` + real scan → 504 `scan exceeded …s time budget`; server stays responsive after. **[auto]** |
| API-13 | Config threading | `offline:true` ⇒ `enrich_nvd=False` in the `ScanConfig` passed to `scan`; `run_sca` passed through; `follow_symlinks` always False. **[auto]** |
| API-14 | Response shape on partial | Force `scan` to return a partial `ScanResult` → `partial:true`, `errors[]` populated, still 200. **[manual]** |
| API-15 | Concurrency | 5 parallel `POST /api/scan` (small dir) → all 200, no cross-talk / shared-state bleed. **[manual]** |

### 4.2 Static / routing

| ID | Case | Expected |
|---|---|---|
| API-20 | `GET /` | 200, `content-type: text/html`; body is `static/index.html`. **[auto]** |
| API-21 | `GET /static/*` | Same-origin assets served; directory listing not exposed. **[manual]** |
| API-22 | No external resources | `index.html` contains no `http(s)://` `src`/`href` to CDNs/fonts, no `<link rel=stylesheet>` to remote, no `@font-face` remote URL. **[auto]** |
| API-23 | OpenAPI | `GET /docs` / `/openapi.json` render; `/` and `/static` excluded from schema (`include_in_schema=False`). **[manual]** |

### 4.3 UI states (manual / exploratory, against design brief §3 & §1.5)

Run `security-preview serve`, drive in Chromium at desktop width.

| ID | State | Expected (per brief) |
|---|---|---|
| UI-01 | **Empty** | Path field + option checkboxes (offline, scan dependencies) + min-confidence selector + **Scan** button. No results area. |
| UI-02 | **Options filled** | Toggling checkboxes / selector updates intended request; Scan enabled only with a non-empty path. |
| UI-03 | **Scanning** | Progress affordance (files walked / stage SAST → SCA → enrichment); Scan disabled during run; no stacked modals. |
| UI-04 | **Results** | Severity count tiles (fixed order CRITICAL→INFO, colour+icon+word), files/deps scanned, Finding cards grouped by severity, vulnerable-deps group, filter/sort/group/download bar. |
| UI-05 | **Results + Detail** | Clicking a card opens ONE inline panel or right drawer (~496px) with full finding + `remediation_secure`; no client-side router, no second drawer. |
| UI-06 | **Zero findings** | Explicit "no findings" state, not an empty void; summary still shown. |
| UI-07 | **Partial** | Amber PARTIAL banner + the `errors[]` list; findings still shown. |
| UI-08 | **Hard error** | Bad path / 400 / 504 surfaces a readable error, recoverable (can edit path and re-scan). |
| UI-09 | **Download ▾** | Exports json client-side; for md/sarif/html either exports or shows the exact CLI command (per browser-app note). |
| UI-10 | Accessibility smoke | Keyboard-reachable controls, focus visible, colour not the only severity signal (icon+word), contrast ≥ AA. |
| UI-11 | Determinism | Same path + options ⇒ identical rendered findings/order across runs. |
| UI-12 | Path separators | Windows `C:\proj` and POSIX `/proj` both accepted in the field. |
| UI-13 | **Choose folder…** button | Desktop mode (`/healthz` → `mode:"desktop"`): button visible, opens the native folder dialog, fills the field with an absolute path, enables Scan; cancel leaves the field unchanged. Browser mode: button hidden, field stays free-text. |
| UI-14 | Deep link | Opening `/?path=<abs>&autoscan=1` pre-fills the path and starts a scan (used by the desktop `--scan` launch and the Explorer right-click verb). |

### 4.4 Desktop app (packaged) — manual, per `docs/DESKTOP.md`

| ID | Case |
|---|---|
| DESK-01 | Fresh Windows 11 VM, no Python: run the `.msi` → desktop + Start-Menu icon present → double-click → window opens < 5 s → **Choose folder…** → scan → results shown. |
| DESK-02 | Same on macOS (`.app` from `.dmg`) and Linux (AppImage). |
| DESK-03 | **Choose folder…** opens the native dialog; cancel leaves the field unchanged; pick fills an absolute path and enables Scan. |
| DESK-04 | Scan a folder on a **different drive / outside any "root"** → succeeds (no root coupling). |
| DESK-05 | `..`, symlink-to-`/etc`, UNC path typed into the field → still 400. |
| DESK-06 | Close the window mid-scan → process exits, port freed, no orphan `uvicorn`. |
| DESK-07 | Launch twice → defined behaviour (single window focused, or a fresh scan). |
| DESK-08 | Offline machine (no NIC) → app starts, scans with Offline checked, PARTIAL banner shown. |
| DESK-09 | WebView2 missing (Win 10 clean) → installer bootstraps it, or the app falls back to the browser with a clear message. |
| DESK-10 | `security-preview-desktop --scan <folder>` → window opens pre-pointed and scans (Explorer right-click verb). |
| DESK-11 | Uninstaller removes app, shortcuts, and any context-menu keys. |
| DESK-12 | Antivirus / SmartScreen: signed build shows publisher, no hard block; unsigned build documented allow-step works. |
| DESK-13 | `security-preview serve` with `pywebview` **not** installed → browser fallback, `--open` works, `--desktop` degrades gracefully. |
| DESK-14 | `python scripts/build_desktop.py check` passes (launcher smoke: `/healthz` + `/api/pick-folder`). **[auto-capable]** |

---

## 5. Component C — Coding-harness skill

### 5.1 Trigger behaviour (`SKILL.md` frontmatter `description`)

Fresh agent session with the skill installed; observe whether it invokes `security-preview`.

| ID | Prompt | Expected |
|---|---|---|
| SKILL-01 | "Do a security review of this repo" | Skill triggers; runs `security-preview scan . --format json …`. |
| SKILL-02 | "Check my dependencies for CVEs" | Triggers; SCA path exercised (no `--no-sca`). |
| SKILL-03 | "Any vulnerabilities before I ship?" | Triggers (pre-ship phrasing). |
| SKILL-04 | "Audit this code for security issues" | Triggers. |
| SKILL-05 | "Scan https://example.com for vulns" | Does **not** trigger / declines — remote URL is out of scope per SKILL.md. |
| SKILL-06 | "Rotate the leaked API key" | Does not trigger — secret rotation is out of scope. |
| SKILL-07 | Unrelated ("refactor this function") | Does not trigger. |

### 5.2 Execution & reporting

| ID | Case | Expected |
|---|---|---|
| SKILL-10 | Tool not yet installed | Agent runs `python scripts/bootstrap.py` once, then the scan (per "How to run it"). |
| SKILL-11 | Bootstrap — uv present | Creates venv via `uv venv` + `uv pip install -e .`; prints activation hint; exit 0. **[manual]** |
| SKILL-12 | Bootstrap — no uv | Falls back to `python -m venv .venv` + venv pip; cross-platform bin path (`Scripts` vs `bin`). **[manual]** |
| SKILL-13 | Bootstrap idempotent | Re-running doesn't corrupt the venv; `--dry-run` prints commands only. **[manual]** |
| SKILL-14 | Result presentation | Agent reports: `summary.by_severity` + files/deps counts; CRITICAL/HIGH findings with `file_path:line`, masked `code_snippet`, `remediation_secure`; `dependency_findings` (pkg, advisory ids, `fixed_version`); if `partial`, warns + lists `errors`. |
| SKILL-15 | Secret masking | A fixture with a hardcoded secret → agent-surfaced `code_snippet` shows the value masked (never the raw secret). **[both]** |
| SKILL-16 | Offer full report | Agent offers `--format markdown --out SECURITY_REPORT.md` / `--format html`. |
| SKILL-17 | Determinism claim | Two consecutive skill runs on an unchanged tree ⇒ same findings; agent may rely on this. |

### 5.3 Example hooks (`.claude/hooks-example.json`)

| ID | Case | Expected |
|---|---|---|
| HOOK-01 | JSON validity | `python -c "import json;json.load(open('.claude/hooks-example.json'))"` OK; both embedded `python -c` scripts `compile()` clean. **[both]** |
| HOOK-02 | SessionStart, CLI installed | Runs `scan . --format text --min-confidence high`, writes summary to stdout as context, **always exits 0** (even on a repo full of CRITICALs). |
| HOOK-03 | SessionStart, CLI absent | No-op, exit 0, no traceback. |
| HOOK-04 | PreToolUse, non-commit Bash | `ls`, `pytest …` → hook exits 0, does not scan. |
| HOOK-05 | PreToolUse, `git commit`, CRITICAL == baseline | `.security-preview/baseline-critical` holds current count → hook exits 0, commit proceeds. |
| HOOK-06 | PreToolUse, `git commit`, CRITICAL > baseline | New CRITICAL introduced → hook prints the blocking message to stderr, exits **2**, commit blocked. |
| HOOK-07 | PreToolUse, baseline file absent | Treated as baseline 0 → any CRITICAL blocks. |
| HOOK-08 | PreToolUse, CLI absent | Prints "not installed; skipping", exits 0 (fail-open). |
| HOOK-09 | PreToolUse, scan output unparseable | Prints "could not parse … allowing commit", exits 0 (fail-open). |
| HOOK-10 | Baseline adoption command | The `docs/USAGE.md` one-liner writes an integer to `.security-preview/baseline-critical`; subsequent commit passes. |

### 5.4 Docs sanity

| ID | Case | Expected |
|---|---|---|
| DOC-01 | `docs/USAGE.md` flags/exit codes match the CLI | Cross-check every flag & the 0/1/2 exit table against `cli.py`. |
| DOC-02 | `docs/CURSOR.md` task block | The `.vscode/tasks.json` / `.cursorrules` snippets run as written; JSON shape described matches `ScanResult.to_dict()`. |
| DOC-03 | `SKILL.md` CLI surface | Subcommands/flags listed = actual; the sample commands run. |

---

## 6. Cross-cutting test areas

### 6.1 Determinism (design brief §1, plan requirement)
- DET-01: `scan` same tree ×3 → `to_dict()` identical except `started_at`/`finished_at`/`duration_seconds`. **[auto: test_report determinism + manual CLI]**
- DET-02: Finding order stable regardless of filesystem walk order (sort by `file_path,line,rule_id`). **[auto]**
- DET-03: Renderers sort input-order-independently (feed shuffled findings → identical `md/sarif/html/text`). **[auto]**
- DET-04: Golden snapshots in `tests/fixtures/golden/` unchanged (any diff = intentional change or regression). **[auto]**

### 6.2 Offline / degraded network resilience
- NET-01: `--offline` → zero outbound connections (verify with OS firewall log / packet capture). **[manual]**
- NET-02: All sockets blocked, online mode → scan finishes, `partial=True`, `errors[]` populated, **no exception**, SAST findings intact. **[manual, mirrors Phase-2 check]**
- NET-03: NVD reachable, OSV down (and vice-versa) → the reachable half still contributes; the down half → `errors[]`, partial. **[manual]**
- NET-04: Slow endpoint (add latency > `network_timeout`) → request times out, recorded, scan proceeds. **[auto: sca/enrich have timeout tests]**
- NET-05: Cache — first online run populates `~/.security-preview/cache/`; second run within TTL makes no NVD call; past `cache_ttl_hours` it refetches. **[auto: test_cache/test_enrich]**

### 6.3 Security / hardening
- SEC-01: App path confinement — every API-06…10 case above; plus `%2e%2e`, UNC `\\host\share`, `NUL`/`CON` on Windows, deeply nested symlink chains. The picked folder is its own root (D1): confinement blocks *escapes* (`..`, symlink-elsewhere), not scanning a directory that happens to sit outside cwd/home. **[auto + manual]**
- SEC-02: App bound to `127.0.0.1` only (CLI-42) — including the desktop bundle and `serve --desktop`. **[manual]**
- SEC-07: `POST /api/pick-folder` exists only in desktop mode, only opens a dialog, performs no FS writes, returns a path the user explicitly picked (API-16). **[auto]**
- SEC-03: Secret values masked in `code_snippet` everywhere they surface (finding, all 5 renderers, API response, UI). **[both]**
- SEC-04: HTML report / UI ship no `<script>`, no remote resources → safe to open from disk / email. **[auto]**
- SEC-05: `max_files` / `max_file_bytes` caps enforced by the walker; oversized/over-count → `errors.add("walk", …)`, scan still completes. **[auto: test_walker]**
- SEC-06: Scanner never executes scanned code (static only) — review + confirm no `import`/`exec`/`eval` of target files. **[manual review]**

### 6.4 Performance sanity (not load testing)
- PERF-01: `../security_auditor` full scan (offline) completes in a few seconds; note `duration_seconds`. **[manual]**
- PERF-02: A directory at `max_files` (~20k files) completes or caps gracefully without OOM. **[manual]**
- PERF-03: API scan timeout (`_DEFAULT_SCAN_TIMEOUT` 120 s) actually bounds a runaway scan → 504. **[auto]**

### 6.5 Install / packaging
- PKG-01: `pip install -e ".[dev]"` clean on Python 3.10 and 3.13.
- PKG-02: `security-preview` console script on PATH after install; `python -m security_preview.cli` equivalent.
- PKG-03: `report/templates/report.html.j2` is packaged (hatch `packages=["src/security_preview"]`) — `--format html` works from an installed wheel, not just the source tree.
- PKG-04: `import security_preview` exposes the assembled API (`scan` via `security_preview.scan`, `render`, `FORMATS`, models, `ScanConfig`); `from security_preview.scan import scan` works.
- PKG-05: `ruff check .` clean; `mypy src` clean.
- PKG-06: `pip install "security-preview[desktop]"` adds `pywebview`; `security-preview-desktop` console script on PATH; `python -m security_preview` opens the window.
- PKG-07: `briefcase create/build/package <windows|macOS|linux>` produce an installer with a shortcut + icon; `scripts/build_desktop.py portable` produces a one-file `.exe`. Bundled deps pinned; `security-preview scan .` run on the build tree in CI before packaging (dogfood). **[CI: `.github/workflows/desktop-release.yml`]**
- PKG-08: `server/static/index.html` is packaged in the wheel and the frozen bundle — `GET /` works from an installed wheel and from the Briefcase/PyInstaller app, not just the source tree.

---

## 7. Automated-coverage map

| Area | Test module | Collected |
|---|---|---|
| Walker (skip-dirs, caps, symlinks) | `tests/test_walker.py` | 8 defs |
| SAST rules (vulnerable/safe fixtures, masking, multi-line) | `tests/test_sast.py` | 11 defs (parametrised → ~32) |
| SCA parsers (8 ecosystems) + OSV client (mocked HTTP) | `tests/test_sca.py` | 17 |
| NVD enrichment (mocked HTTP, budget, offline) | `tests/test_enrich.py` | 8 |
| On-disk TTL cache | `tests/test_cache.py` | 7 |
| Renderers text/md/json/sarif/html + goldens + determinism | `tests/test_report.py` | 11 |
| Orchestrator sequencing / flag threading / partial | `tests/test_scan.py` | 11 |
| CLI argparse / exit codes / `--out` / selftest / `serve` bind+URL / `--open` / `--desktop` | `tests/test_cli.py` | 16 |
| Server API / validation / path confinement / timeout / `/healthz` / pick-folder | `tests/test_server.py` | 18 |
| Desktop launcher (free port, healthz wait, deep link, browser fallback) | `tests/test_desktop.py` | 6 |
| Scaffold contract sanity | `tests/test_scaffold.py` | 6 |
| **Total** | `pytest -q` | **151 passed** |

**Gaps to close with manual/exploratory testing (this plan):** all UI states (§4.3), real-network behaviour (§6.2), `serve` real browser/window & bind scope (CLI-40…45), the packaged desktop app on real OSes (§4.4 DESK-01…13), bootstrap on real machines (SKILL-11…13), hook behaviour end-to-end in a live agent session (§5.3), skill trigger judgement (§5.1), packaged-wheel checks (PKG-03, PKG-07/08).

---

## 8. Regression / CI gate

Per commit / PR:
```
pip install -e ".[dev]"
ruff check .
mypy src            # advisory
pytest -q           # must stay green (151+)
security-preview selftest
python scripts/build_desktop.py check   # desktop launcher smoke (no network)
```
Per release (`v0.x.y`): the full manual pass of §3.5, §4.3, §4.4, §5, §6.2, §6.5 on the OS matrix; diff the `--format html` output against the `ReportScreen` / `ReportPrint` artboards. The desktop installers are built and smoke-tested by `.github/workflows/desktop-release.yml` on the `v*` tag.

---

## 9. Entry / exit criteria

**Entry:** `pytest -q` green on `main`; `selftest` passes; build installs on the target OS.

**Exit (release-ready):**
- All **[auto]** tests green on Python 3.10 + 3.13.
- Every §3–§5 case with no `[auto]` tag executed; result recorded (pass / fail / blocked).
- Zero open Critical or High defects (see §10).
- `--offline` verified to make zero network connections (NET-01).
- Path-confinement suite (SEC-01) fully green.
- Golden snapshots reviewed; any change sign-off'd.

## 10. Defect severity

| Sev | Definition | Examples |
|---|---|---|
| Critical | Wrong security result, or a safety hole in the tool itself | Missed CRITICAL in a `vulnerable/` fixture; path confinement bypass; secret printed unmasked; scanner executes target code |
| High | Core feature broken | A `--format` errors; `--offline` still hits the network; wrong exit code; API 500 on a valid body; hook blocks/allows the wrong way |
| Medium | Works but off-spec | UI state deviates from brief; non-deterministic ordering; misleading error text; docs contradict CLI (e.g. CLI-15 case) |
| Low | Cosmetic / polish | Wording, spacing, help-text typos |

## 11. Known issues / risks going in

- **CLI-15:** `--min-confidence` argparse `choices` are upper-case (`HIGH/MEDIUM/LOW`); docs say `low/medium/high`. Lowercase input errors out. Decide: accept case-insensitive, or fix the docs.
- **SCA unpinned deps:** `sca.parsers` drops unpinned specs (`pkg>=1.0`), so an all-`>=` `requirements.txt` yields 0 components with no error (documented in `progress/sca.md`). Tests should not assume dep findings from such projects.
- **`selftest` fixture discovery** uses `Path(__file__).parents[2]`; from an installed wheel it falls through to the temp-project path — verify CLI-31.
- **HTML report** contains clickable `<a href>` links to `cwe.mitre.org` — allowed (not a loaded resource); SEC-04 checks only for *loaded* remote resources.
- Rule precision (FP/FN rate) is explicitly **not** gated here — tracked for milestone M7.
