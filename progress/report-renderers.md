# report-renderers

## Status
Done.

## What's done
- `report.renderers.render(result: ScanResult, fmt: str) -> str` matches `contracts.py`
  exactly. `fmt` in `{"text","markdown","json","sarif","html"}`; unknown `fmt`
  (including `""`) raises `ValueError`.
- Public API re-exported from `src/security_preview/report/__init__.py` (`render`, `FORMATS`).
- Modules under `src/security_preview/report/`:
  - `_shared.py` - severity order/emoji/hex/tint tables, deterministic sort helpers,
    CWE/CVE/advisory URL builders, snippet gutter parser, scanned/re-run helpers.
  - `text_report.py` - plain-text terminal report (summary counts + findings grouped
    by severity + deps + errors + footer).
  - `markdown_report.py` - CommonMark + GFM per design-brief 5.2 (emoji + UPPERCASE
    severity, GFM table summary, `> [!WARNING]`/`> [!NOTE]` callouts, inline links,
    no raw HTML, no `<details>`).
  - `sarif_report.py` - SARIF 2.1.0 (`$schema`, `version`, `runs[].tool.driver` with
    `rules[]`, `results[]` each with `ruleId`, `level`, `locations[].physicalLocation`).
    Code findings + dependency findings both emitted as results.
  - `html_report.py` + `templates/report.html.j2` - Jinja2 template matching the
    ReportScreen artboard with an embedded `@media print` block matching ReportPrint.
    One inline `<style>`, no `<script>`, no web fonts, no external resources,
    `prefers-color-scheme` dark, single `<h1>`, skip link, landmark sections, TOC
    anchors (`#summary`, `#code`, `#deps`, `#errors`). First finding `<details open>`,
    rest collapsed.
- Determinism: renderers sort findings (severity rank -> file -> line -> rule -> name)
  and dependencies (severity -> package -> version -> advisory) before rendering, so
  input list order does not affect output. All timestamps derive from
  `result.started_at` (UTC); no wall-clock. Jinja env: autoescape, trim_blocks,
  lstrip_blocks, keep_trailing_newline.
- `json` = `json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"` -
  exactly `to_dict()` content, key/list order preserved (caller-defined).

## Tests
- `tests/test_report.py` - 23 tests green. Full suite `python -m pytest -q` = 29 passed.
- `python -m ruff check src/security_preview/report tests/test_report.py` - clean.
- `tests/fixtures/sample_scan_result.json` - serialized feature-covering `ScanResult`
  (6 findings across all 5 severities incl. `cwe_id=None`; 3 dependency findings incl.
  `fixed_version=None` and GHSA/PYSEC/CVE advisory ids; 3 `ScanError`s; `partial=True`).
  Round-trips through `ScanResult.from_dict`.
- `tests/fixtures/golden/sample-report.{txt,md,json,sarif,html}` - snapshot per format;
  tests assert current render == golden. Regenerate with
  `UPDATE_GOLDEN=1 python -m pytest tests/test_report.py`.

## Contract questions
- None blocking. `render` signature honored exactly.
- SARIF includes `dependency_findings` as extra `results[]` (ruleId
  `sca.<ecosystem>.<package>`, anchored at the manifest, `startLine: 1`). If SCA
  findings should be SARIF-excluded, that is a one-line filter in
  `sarif_report._dependency_results`.
- The `json` renderer does not re-sort findings (kept "exactly to_dict() content").
  `text`/`markdown`/`sarif`/`html` sort for stable presentation.

## Extra dependency needed
None. Uses `jinja2` (already in `pyproject.toml`) + stdlib.

## Notes for the merger
- Only owned paths touched: `src/security_preview/report/**`, `tests/test_report.py`,
  `tests/fixtures/golden/**`, `tests/fixtures/sample_scan_result.json`,
  `progress/report-renderers.md`.
- `report/renderers.py` and `report/__init__.py` replaced the Phase 0 stubs;
  `git merge` takes this branch's versions.
- No imports from other foundation implementation modules - only
  `security_preview.models` and the local `report` package.
- HTML template at `src/security_preview/report/templates/report.html.j2`, loaded via
  `FileSystemLoader(Path(__file__).parent / "templates")`. Confirm packaging ships
  the `.j2` (hatch wheel `packages = ["src/security_preview"]` should cover it).
