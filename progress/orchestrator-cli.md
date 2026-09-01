# orchestrator-cli

## Status
Done.

## What's done
- `src/security_preview/scan.py` — real `scan(path, cfg) -> ScanResult`:
  1. `ErrorCollector()` + `started_at` (UTC via `datetime.now(timezone.utc)`).
  2. `walker.discover(path, cfg, errors)`.
  3. `sast.scan_paths(path, files, cfg, errors)`.
  4. confidence gate: `[f for f in findings if f.confidence.meets(cfg.min_confidence)]`.
  5. if `cfg.run_sca`: `sca.parsers.collect_components(path, errors)` then
     `sca.osv_client.query_osv(components, cfg, errors)` (offline handled inside query_osv);
     else both stay `[]`.
  6. if `cfg.enrich_nvd and not cfg.offline`: `enrich.nvd_client.enrich_findings(findings, cfg, errors)`.
  7. assemble `ScanResult` with `files_scanned=len(files)`,
     `dependencies_scanned=len(components)`, `errors=errors.to_list()`,
     `partial=errors.partial`, `finished_at` = UTC now.
  Seams imported as modules (`walker`, `sast`, `sca_parsers`, `osv_client`,
  `nvd_client`) so they are individually monkeypatchable.
- `src/security_preview/cli.py` — argparse, subcommands `scan` / `serve` / `selftest`:
  - `scan <path> [--format text|markdown|json|sarif|html] [--offline] [--no-sca]
    [--min-confidence HIGH|MEDIUM|LOW] [--out FILE]`. Builds `ScanConfig(offline=,
    run_sca=not --no-sca, min_confidence=)`. `--offline` only sets `cfg.offline`;
    enrich suppression is `scan()`'s job (`enrich_nvd and not offline`), so
    `--offline` => enrich never invoked. Renders via `report.renderers.render`,
    writes `--out` file or stdout (adds trailing newline to stdout only).
  - `serve [--port PORT]` — **lazy** `import uvicorn` + `from .server import app`
    inside the handler; `uvicorn.run(app, host="127.0.0.1", port=port)`.
  - `selftest` — scans `tests/fixtures/vulnerable/` if it exists, else a tiny
    temp project (`os.system('echo ' + user_input)`); runs offline; prints
    `json.dumps(result.summary(), indent=2, sort_keys=True)`; exit 1 if CRITICAL
    count or `partial`, else 0.
- `tests/test_scan.py` (12) + `tests/test_cli.py` (12) — all green today against
  the Phase 0 stubs.

## Exit-code choice (documented)
`scan`: `0` = completed, no CRITICAL findings; `1` = >=1 CRITICAL finding present
(after the confidence gate); `2` = usage / IO error (unknown `--format`, path not
a directory, unwritable `--out`). Enrichment / network failure alone never
changes the exit code (it only sets `result.partial`). `selftest`: `1` on CRITICAL
or partial, else `0`. `serve`: `0`.

## Contract questions
- `render()` is called positionally as `render(result, fmt)`. `--format` is
  validated in the CLI against `("text","markdown","json","sarif","html")` and a
  bad value returns exit 2 without calling `render` — I did not couple to
  `renderers.FORMATS` (kept a local tuple) so a rename there won't break the CLI.
- `scan()` passes the **original `path` string** straight through as
  `ScanResult.target` (no normalisation / abspath). If the merger wants an
  absolute/normalised target, that is a one-line change here.
- `selftest` locates fixtures via `Path(__file__).resolve().parents[2] /
  "tests" / "fixtures" / "vulnerable"`. Fine for a repo checkout; an installed
  wheel would fall through to the temp-project path. Acceptable for the
  foundation; revisit if `selftest` must work from an installed package.
- CLI builds `ScanConfig` with only `offline` / `run_sca` / `min_confidence`;
  every other field keeps its frozen default. No flags for `enrich_nvd`,
  timeouts, caps yet — add later if desired.

## Extra dependency needed
None. Uses stdlib (`argparse`, `json`, `os`, `shutil`, `tempfile`, `pathlib`,
`datetime`) plus `uvicorn` (already in `pyproject.toml`) imported lazily in `serve`.

## Notes for the merger
- Only owned paths touched: `src/security_preview/scan.py`,
  `src/security_preview/cli.py`, `tests/test_scan.py`, `tests/test_cli.py`,
  `progress/orchestrator-cli.md`.
- `scan.py` imports the real seam modules by package path
  (`from .engine import sast, walker`, etc.); once units 1-4 land, no change is
  needed here — the stubs are simply replaced.
- Tests monkeypatch seams on the imported module objects
  (`scan_mod.walker.discover`, `cli.scan_mod.scan`, `cli.renderers.render`), so
  they stay valid against real implementations.
- `python -m pytest tests/test_scan.py tests/test_cli.py -q` -> 24 passed.
  Full `tests/` -> 31 passed. `ruff check` on all four files clean.
