# browser-app — progress

## Status
Done.

## Done
- `src/security_preview/server/app.py` — real implementation:
  - `create_app(allowed_root: str | None = None, scan_timeout: float = 120.0) -> FastAPI`.
    Still callable as `create_app()` per `contracts.py`; the two optional args are
    additive (allowed_root also read from env `SECURITY_PREVIEW_ROOT`, default CWD).
  - `POST /api/scan` — explicit Pydantic models both sides:
    - Request `ScanRequest {path: str, format: "json"|"md"|"sarif"|"html" = "json",
      offline: bool = False, run_sca: bool = True, min_confidence: "HIGH"|"MEDIUM"|"LOW" = "MEDIUM"}`.
      Invalid `format` / `min_confidence` -> 422 (field validators). Missing `path` -> 422.
    - Response `ScanResponse` mirrors `ScanResult.to_dict()` exactly
      (`tool_version, target, started_at, finished_at, summary{…}, findings[FindingModel],
      dependency_findings[DependencyFindingModel], errors[ScanErrorModel], partial`),
      built as `ScanResponse(**result.to_dict())` and declared as FastAPI `response_model`.
  - Builds `ScanConfig(offline, run_sca, enrich_nvd=not offline,
    min_confidence=Confidence(...), follow_symlinks=False)` and calls
    `security_preview.scan.scan` via a module reference (`scan_module.scan`) so tests
    can monkeypatch `security_preview.scan.scan`.
  - Path confinement (`_safe_target_dir`): rejects empty, rejects any `..` segment,
    resolves via `os.path.realpath`, requires the resolved path to equal or be under
    the allowed root (blocks symlink / traversal escape), requires an existing
    directory. Any violation -> HTTP 400. Count/size caps come from `ScanConfig`
    defaults (`max_files`, `max_file_bytes`).
  - Wall-clock timeout: scan runs in a single-worker `ThreadPoolExecutor`;
    `future.result(timeout=scan_timeout)` -> HTTP 504 on overrun.
  - `GET /` -> `FileResponse(static/index.html, media_type="text/html")`.
    `/static/*` mounted via `StaticFiles` for future same-origin assets.
- `src/security_preview/server/__init__.py` — exposes `create_app`, `ScanRequest`, `ScanResponse`.
- `src/security_preview/server/static/index.html` — desktop-only (min-width 1024px)
  single-window vanilla-JS UI, zero external resources (all CSS/JS inline, inline SVG
  icons, system font stack, `prefers-color-scheme` + a light/dark toggle persisted in
  `localStorage`). Implements the Empty / Scanning / Main (stat tiles + filter/sort/
  group/download bar + severity-grouped rows + vulnerable-deps group) / Detail
  (right-side 496px drawer with snippet + remediation + CVE chips + copy-path) /
  EdgeStates (zero-findings, partial amber banner, hard-error) artboards. Calls
  `POST /api/scan`, renders `detail` from `HTTPException.detail` on non-2xx.
- `tests/test_server.py` — 13 tests: contract (`create_app` -> FastAPI), request
  validation (missing path 422, bad min_confidence 422, bad format 422), path
  confinement (`..` 400, outside-root 400, symlink escape 400, missing 400, file 400),
  happy path (valid `ScanResponse`, flags threaded into `ScanConfig`, confined path
  passed to `scan`), UI (`GET /` HTML + title, no external `<script src>` / `<link
  href>` / `@import` / `url(http…)` / remote `<img>` / `cdn` / google fonts).

## Test result
`python -m pytest tests/test_server.py -q` -> 13 passed.
`python -m pytest -q` (whole repo) -> 19 passed.

## Ruff
`python -m ruff check src/security_preview/server tests/test_server.py` -> clean.

## Contract questions
1. `create_app()` is zero-arg in `contracts.py`. I added optional `allowed_root` /
   `scan_timeout` params (still callable with no args) plus env `SECURITY_PREVIEW_ROOT`
   so the sandbox root is injectable in tests and by `cli serve`. If the merger wants a
   strictly zero-arg signature, drop the params and keep only the env var — tests would
   then `monkeypatch.setenv`.
2. The request model has a `format` field (per plan §8 / design "Download ▾"), but the
   foundation response is always the JSON `ScanResponse`; `report.renderers.render` is
   not wired in here. The UI's Download menu therefore only exports JSON client-side and
   shows the CLI command for md/sarif/html. If server-side rendered downloads are
   wanted, add a `GET/POST /api/report?format=` route that calls `renderers.render`.
3. Timeout overrun currently returns HTTP 504. If a 400 is preferred (design lumps
   "timeout" under hard error), change the status in `api_scan`.
4. `scan.scan` is invoked as `scan_module.scan(...)` where
   `scan_module = security_preview.scan`. Monkeypatching `security_preview.scan.scan`
   works; monkeypatching a name on `security_preview.server.app` does not (there is no
   such name). Adjust if the merger's integration tests assume otherwise.

## Extra dependency needed
None. Uses `fastapi`, `pydantic`, stdlib only. (`uvicorn` is only needed by the
`cli serve` entrypoint, which this unit does not own.)

## Notes for merger
- Only owned paths changed: `src/security_preview/server/**` and `tests/test_server.py`.
- `server/static/` is a new directory; ensure the wheel packaging picks up
  `security_preview/server/static/index.html` (hatch `packages = ["src/security_preview"]`
  includes it as package data since it lives under the package tree).
- When the real `scan.scan` lands, no change needed here — the seam is the module
  attribute `security_preview.scan.scan`.
- UI expects the exact `ScanResult.to_dict()` shape (severity/confidence as UPPERCASE
  strings, `summary.by_severity` keyed by RiskLevel value, posix `file_path`).
