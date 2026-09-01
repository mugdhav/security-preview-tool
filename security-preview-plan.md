# security-preview — Build Plan

Date: 2026-09-01
Companions: `security-preview-design-brief.md` (design handoff), design canvas at
https://claude.ai/code/artifact/90379dde-2cfb-4287-bfc3-058bb240b1ee

## 1. What it is

A **non-LLM** static security scanner for a local project directory, delivered in
three shapes over one shared core.

| Shape | Entry point | Who uses it |
|---|---|---|
| **Browser app** | `security-preview serve` → opens `http://127.0.0.1:PORT` | User pastes a folder path, clicks Scan, reads the rendered report |
| **CLI** | `security-preview scan <path> --format md\|json\|sarif\|html` | User in a terminal; also what CI calls |
| **Skill** | `SKILL.md` + bootstrap script wrapping the CLI | Claude Code / Cursor invoke on demand or via a pre-session hook |

All three call the same `scan(path, ScanConfig)` function and get the same
`ScanResult`. No divergent code paths — this is the structural fix for
investigation bugs #1 and #6.

## 2. Port from Security Auditor (`security_auditor/`)

From `security_checker.py`:
- **`SASTEngine` + the 28 regex rules** (`_load_rules`) — SQLi, command injection,
  XSS, path traversal, hardcoded creds, weak crypto/hashing, insecure
  deserialization, SSRF, XXE, CORS wildcard, debug mode, ReDoS, prototype
  pollution, open redirect, mass assignment, … Keep CWE IDs + remediation blocks.
- **Parallel `scan_directory`** — `ThreadPoolExecutor` fan-out, `skip_dirs`,
  `file_extensions` map.
- **Data model** — `RiskLevel`, `Vulnerability`, `ScanResult` (already carries
  `.errors` and `.summary()`).
- **`NVDClient`** — CWE → example-CVE lookup; keep, harden (§4).
- **Report generators** — text / json / markdown; keep, add SARIF + HTML.
- **Aesthetic** — carry forward `theme.py`: warm neutral ground, terracotta
  accent, system fonts, 8px radius, minimal shadows (see §6, now locked).

**Dropped:** `WebAppScanner` (remote-URL scanning is out of scope), all
Modal/`modal_app.py`/`modal_backend.py` offload code, the Gradio UI, the
`ModalScanResult` dynamic `type()` duck-typing (bug #6 disappears with Modal).

## 3. New capability — real dependency scanning (SCA)

Fixes investigation bug #3.
- **`sca/parsers.py`** — `requirements.txt`, `poetry.lock`, `Pipfile.lock`,
  `package-lock.json`, `yarn.lock`, `go.mod`, `Gemfile.lock`, `pom.xml` →
  `(ecosystem, name, version)`.
- **`sca/osv_client.py`** — `POST https://api.osv.dev/v1/querybatch` (no API key,
  batched). Returns real known-vuln matches → `DependencyFinding` (OSV id,
  CVE/GHSA aliases, fixed version, severity).
- Report gets a distinct **Vulnerable Dependencies** section, separate from code
  findings, with its own accent colour (violet `#6941c6`).

## 4. Hardening the live NVD/OSV path

Investigation bugs #1 and #5.
- **Single `ScanConfig` dataclass** threads every toggle (`enrich_nvd`, `run_sca`,
  `offline`, `min_confidence`, `timeout`, `max_files`, `max_file_bytes`) through
  the one scan entrypoint. No code path can hardcode a flag off (bug #1).
- **Central `ErrorCollector`** — every network/TLS/parse failure appends a
  structured entry to `ScanResult.errors` (`{stage, target, message}`) and sets
  `result.partial = True`. No bare `except: pass` (bug #5). Report and UI show the
  amber **PARTIAL** banner.
- **On-disk TTL cache** at `~/.security-preview/cache/`, keyed by `cwe_id` and
  `pkg@version` (24 h). Repeat scans are fast and work from cache when offline.
- **Explicit timeouts + bounded retries with backoff**; total enrichment
  time-budget so a slow NVD never hangs a scan.
- **`--offline` flag** (and UI checkbox) — skip all lookups; code findings still
  complete. For CI / air-gapped use.
- Enrichment failure never fails the scan.

## 5. Precision pass (investigation bug #2 — regex false positives)

- **Multi-line match window** for high-severity rules (SQLi, command injection,
  deserialization): match against a sliding N-line window, not one line.
- **Optional Python AST pass** (`engine/ast_python.py`, stdlib `ast`, still
  deterministic): for SQLi + command injection, confirm the argument to
  `execute(...)` / `os.system(...)` / `subprocess.*` is an f-string, `%`/`+`
  concat, or `.format()` on a non-literal → promotes confidence to HIGH; a plain
  literal downgrades or suppresses. (Surfaced in the drawer copy: "AST check
  confirmed …".)
- **Framework-idiom allowlist** — expand `false_positive_patterns` for ORM query
  builders, parameterised drivers, escaped templating.
- **`confidence` on every finding** + `--min-confidence` filter. Default list view
  hides LOW confidence (UI slider / select).
- **Golden-file regression tests** so precision fixes can't silently regress.
- **Secret redaction** — mask the matched value in "Hardcoded Credentials"
  snippets (`sk_live_••••…`) before it reaches any report or the browser.

## 6. Design system — LOCKED (from the canvas)

Carried forward from `security_auditor/theme.py`; shipped as swappable tokens.

| Role | Light | Dark |
|---|---|---|
| ground | `#faf9f6` | `#131314` |
| card | `#ffffff` | `#1c1c1e` |
| ink | `#131314` | `#f2f2f0` |
| subdued | `#6b7280` | `#9aa0a6` |
| border | `#e5e7eb` | `#2e2e30` |
| accent (interactive only) | `#d97757` | `#d97757` |
| accent hover | `#cc6944` | — |
| dependency / SCA class | `#6941c6` | — |
| success (zero findings) | `#067647` | — |

**Severity ramp** (solid badge hex + list-row tint), fixed order, always
color + icon + text:

| Level | Hex | Tint | Icon |
|---|---|---|---|
| CRITICAL | `#912018` | `#fef3f2` | filled octagon |
| HIGH | `#d92d20` | `#fff4ed` | filled triangle |
| MEDIUM | `#b45309` | `#fffaeb` | filled diamond |
| LOW | `#175cd3` | `#eff4ff` | filled circle |
| INFO | `#667085` | `#f2f4f7` | outline circle |

- Fonts: **system stack only** — `ui-sans-serif, system-ui, -apple-system,
  "Segoe UI", Roboto, sans-serif`; mono `ui-mono, "Cascadia Code", "SF Mono",
  Menlo, Consolas, monospace`. No web fonts (product constraint; also keeps
  PNG/PDF faithful).
- Type scale 12 / 14 / 16 / 20 / 28. Spacing 4·8·12·16·24·32·48. Radius 6
  (inputs/chips) / 8 (cards). Control height 32. Shadows minimal/none.
- **Confidence** = 3-pip meter + label, independent of severity.
- **Accent ≠ severity**: terracotta appears only on buttons / links / focus, never
  as a severity badge — implementation must not reuse it for HIGH.

## 7. Directory layout

```
security-preview/
  pyproject.toml            # installable; uv / pipx friendly
  SKILL.md
  README.md
  design/                   # the .dc.html canvas sources + seed output (reference)
  data/cwe_top25.json
  src/security_preview/
    config.py               # ScanConfig — single source of truth
    models.py               # RiskLevel, Finding, DependencyFinding, ScanResult, ErrorCollector
    scan.py                 # scan(path, config) -> ScanResult   (the one entrypoint)
    engine/
      sast.py               # ported SASTEngine, hardened
      walker.py             # discovery, .gitignore-aware, symlink-safe, size/count caps
      rules/builtin_rules.py
      ast_python.py
    sca/parsers.py
    sca/osv_client.py
    enrich/nvd_client.py
    enrich/cache.py
    report/
      renderers.py          # text | markdown | json | sarif | html
      templates/
        report.html.j2      # the self-contained HTML report (CLI + skill-HTML)
        report.print.css    # @media print block embedded into report.html.j2
        report.md.j2        # Markdown report
    cli.py                  # scan | serve | selftest
    server/
      app.py                # FastAPI, 127.0.0.1 only, Pydantic-validated /api/scan
      static/index.html     # single-page app UI
  tests/
    fixtures/vulnerable/    # must-detect samples
    fixtures/safe/          # must-NOT-detect samples (FP guard)
    test_sast.py test_sca.py test_report_schema.py test_selftest.py test_offline.py
```

## 8. Design → build mapping

### Report renderer (`report/templates/`, shared by CLI-HTML and skill-HTML)
Build `report.html.j2` to match the **ReportScreen** artboard:
- 820px centred content column on the warm ground; header (wordmark + `v…`,
  target path, timestamp, duration, "deterministic, non-LLM"); **TOC** with
  in-page anchors (`#summary`, `#code`, `#deps`, `#errors`).
- **Summary** — severity count table + files/deps counts; **PARTIAL** amber
  banner rendered only when `result.partial`.
- **Code findings** — grouped by severity desc; first finding rendered
  `<details open>`, rest `<details>` (collapsed row = badge, title, CWE link,
  category tag, `file:line`, caret). Expanded body = dark code snippet with the
  offending line highlighted + secret masked, "What's wrong", Vulnerable/Secure
  remediation blocks, illustrative-CVE chips.
- **Vulnerable dependencies** — table: Package · Advisory (OSV/GHSA/CVE links) ·
  Severity pill · Fixed in · Source manifest.
- **Skipped / errors** — `<ul>` from `ScanResult.errors`.
- **Footer** — disclaimer + re-run command in a mono block.
- **Restrictions baked in:** all CSS in one inline `<style>`; no `<script>` at all
  (skill-HTML parity); no web fonts / no network; `prefers-color-scheme` only, no
  toggle; deterministic (no random ids; timestamp only in header).

`report.print.css` (embedded `@media print`) to match the **ReportPrint** artboard:
- Grayscale-safe severity: `.sev.crit` filled black, `.high` double border,
  `.med` grey fill, `.low` plain, `.info` dotted — each keeps its UPPERCASE word.
- Force every `<details>` open; `break-inside: avoid` on findings; show full link
  URLs (`a::after{content:" (" attr(href) ")"}`); Letter width; tighter margins;
  no dark ink floods.

### Markdown renderer (`report.md.j2`)
Follow brief §5.2 exactly — CommonMark + GFM tables, no HTML/CSS, severity as
`🔴 CRITICAL` etc., stable `#`/`##`/`###` hierarchy, ≤100-col width, inline links.
Ship `tests/fixtures/sample-report.md` as the golden reference.

### Desktop app (`server/static/index.html`)
Match the **Main / Empty / Scanning / Detail / EdgeStates** artboards:
- **Topbar** (46px): `security-preview` mono wordmark, version pill, `127.0.0.1:PORT`
  hint, light/dark toggle.
- **Scan bar** (60px): folder-icon path input (mono), `Offline` +
  `Scan dependencies` checkboxes, `Min confidence` select, terracotta **Scan**.
- **Empty**: centred 640px card — headline, path input, options, full-width Scan,
  one-line "nothing leaves your machine except optional CVE lookups".
- **Scanning**: scan bar dimmed; progress card with bar, file counter, and the
  4-stage pipeline chip row **Discover files → SAST rules → Dependency scan →
  CVE enrichment**, Cancel.
- **Results (Main)**: 6 stat tiles (5 severities + Vuln deps) + meta line; filter
  bar (severity chips, confidence select, Group-by-file, sort select,
  `Download ▾` → md/json/sarif/html); grouped finding rows.
- **Detail**: right-side **drawer, 496px** (not inline) — full finding card rows
  1–10, Copy-path affordance, list behind it dimmed and the source row
  ring-highlighted.
- **Edge states**: Zero findings (green check, still shows counts + "re-scan at
  Low confidence"), Partial (results + amber banner linking to Skipped/Errors),
  Hard error (path field in error state + "not a directory" message).
- **Restrictions baked in:** desktop only (1024–1920, no mobile/tablet), single
  window / no router, no account or marketing surface, vanilla JS only, no
  external resources; every severity + confidence carries icon + label.

### API boundary (`server/app.py`)
`POST /api/scan` — Pydantic request (`path`, `offline`, `run_sca`,
`min_confidence`) and response models validated on both sides; this is the schema
discipline bug #6 lacked. Path confined to the entered root: no traversal above
it, symlinks not followed out of root, file-count + size caps, wall-clock
timeout. `127.0.0.1` bind, random free port, auto-open browser.

## 9. Milestones

1. **M1 Core** — models, `ScanConfig`, `scan()`, ported+hardened `SASTEngine`,
   walker, 28 rules, text/md/json reports, CLI `scan`, central error collector,
   fixture tests.
2. **M2 SCA** — lockfile parsers + OSV batch client + cache + dependency report
   section.
3. **M3 Enrichment hardening** — NVD client + TTL cache + `--offline` +
   partial-failure surfacing.
4. **M4 Report renderers** — `report.html.j2` + `report.print.css` + `report.md.j2`
   from the locked designs; SARIF; `sample-report.md` golden; schema + golden-file
   tests.
5. **M5 Browser app** — FastAPI server + `static/index.html` from the desktop
   artboards; schema-validated `/api/scan`; path sandboxing; downloads.
6. **M6 Skill packaging** — `SKILL.md`, `bootstrap.py`, `selftest`, Claude Code +
   Cursor docs, optional pre-session hook snippet.
7. **M7 Precision** — Python AST pass, framework allowlists, `--min-confidence`,
   golden-file FP-regression suite.

## 10. Testing strategy

- **Dual fixture corpus**: `vulnerable/` (assert detections) **and** `safe/`
  (assert *no* detection — false-positive guard).
- **Golden report snapshots** for md/json/sarif/html; schema-validate json + sarif.
- **`test_offline.py`**: monkeypatch all HTTP to raise → scan still completes,
  `errors` populated, `partial=True`.
- `security-preview selftest` scans `tests/fixtures/vulnerable/`, asserts known
  findings + JSON schema; runs in CI and once at skill bootstrap.

## 11. The skill (`SKILL.md`)

- **Trigger description**: "Run a deterministic, non-LLM static security scan
  (SAST + dependency CVE check) on a local project directory and produce a
  vulnerability report with remediation. Use for a security review / scan / vuln
  check, or before shipping."
- **Body**: run
  `python -m security_preview.cli scan "<dir>" --format json --min-confidence medium`
  (bootstrap builds an isolated venv on first run), parse JSON, present the
  summary table + top findings with `file:line` + remediation, offer to write the
  full Markdown or HTML report into the project.
- **Portability**: SKILL.md + `scripts/bootstrap.py` + pinned package; works in
  `.claude/skills/` (project or user) and, for Cursor, as CLI + a short rules doc.
- **Optional hook**: `settings.json` snippet to run `scan` at session start or
  pre-commit, failing on new CRITICAL findings.

## 12. Open items / risks

- **OSV vs NVD roles**: OSV = real dependency matches; NVD = CWE→example-CVE
  colour. NVD rate limits mitigated by cache + offline fallback.
- **AST pass**: Python only (M7); other languages stay regex + multi-line.
- **Windows paths** in the browser input — normalise both separators, validate.
- **Packaging**: `pyproject.toml` + `bootstrap.py` preferring `uv`; no global
  install required.
- **Edge-state artboards** are consolidated on one canvas frame — split into
  three if the app grows distinct empty/partial/error routes.
