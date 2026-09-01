"""Local browser / desktop app for security-preview. Owned by branch ``foundation/browser-app``.

``create_app()`` returns a FastAPI application meant to be served on
``127.0.0.1`` only. It exposes:

* ``GET  /``              -> the single-window desktop UI (``static/index.html``)
* ``GET  /static/*``      -> same-origin static assets
* ``GET  /healthz``       -> ``{"ok": true, "mode": "browser"|"desktop"}``
* ``POST /api/pick-folder`` -> native folder dialog (desktop mode only; 404 in
                              browser mode)
* ``POST /api/scan``      -> run a scan, validated Pydantic request/response models

Path confinement: the folder handed to ``POST /api/scan`` **is** the root for
that request. ``..`` tokens and symlink escapes are rejected with HTTP 400 and a
wall-clock timeout guards the scan. There is no global allowed root and no
``SECURITY_PREVIEW_ROOT`` environment variable; relative paths typed into the
browser free-text field resolve under ``allowed_root`` (default: the user's home
directory) purely as a convenience.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from security_preview import scan as scan_module
from security_preview.config import ScanConfig
from security_preview.models import Confidence

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_INDEX_HTML = _STATIC_DIR / "index.html"

_VALID_FORMATS = ("json", "md", "sarif", "html")
_DEFAULT_SCAN_TIMEOUT = 120.0
_VALID_MODES = ("browser", "desktop")


# --------------------------------------------------------------------------- #
# Request / response models
# --------------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    """Body for ``POST /api/scan``."""

    path: str = Field(..., min_length=1, description="Absolute path to a directory to scan.")
    format: str = "json"
    offline: bool = False
    run_sca: bool = True
    min_confidence: str = "MEDIUM"

    @field_validator("format")
    @classmethod
    def _check_format(cls, v: str) -> str:
        if v not in _VALID_FORMATS:
            raise ValueError(f"format must be one of {_VALID_FORMATS}")
        return v

    @field_validator("min_confidence")
    @classmethod
    def _check_min_confidence(cls, v: str) -> str:
        try:
            Confidence(v.upper())
        except ValueError as exc:  # pragma: no cover - message only
            raise ValueError("min_confidence must be HIGH, MEDIUM or LOW") from exc
        return v.upper()


class SummaryModel(BaseModel):
    target: str
    by_severity: dict[str, int]
    total_findings: int
    vulnerable_dependencies: int
    files_scanned: int
    dependencies_scanned: int
    duration_seconds: float | None
    partial: bool
    errors: int


class FindingModel(BaseModel):
    rule_id: str
    name: str
    severity: str
    confidence: str
    category: str
    cwe_id: str | None
    file_path: str
    line: int
    code_snippet: str
    description: str
    remediation_vulnerable: str
    remediation_secure: str
    cve_ids: list[str]


class DependencyFindingModel(BaseModel):
    ecosystem: str
    package: str
    version: str
    advisory_ids: list[str]
    severity: str
    fixed_version: str | None
    source_manifest: str
    summary: str


class ScanErrorModel(BaseModel):
    stage: str
    target: str
    message: str


class ScanResponse(BaseModel):
    """Mirrors ``ScanResult.to_dict()`` with an explicit, validated schema."""

    tool_version: str
    target: str
    started_at: str
    finished_at: str | None
    summary: SummaryModel
    findings: list[FindingModel]
    dependency_findings: list[DependencyFindingModel]
    errors: list[ScanErrorModel]
    partial: bool


# --------------------------------------------------------------------------- #
# Path confinement
# --------------------------------------------------------------------------- #
def _soft_root(allowed_root: str | None) -> Path:
    """Base for resolving *relative* free-text paths. Not a security boundary."""
    raw = allowed_root or str(Path.home())
    return Path(os.path.realpath(raw))


def _safe_target_dir(raw_path: str, soft_root: Path) -> Path:
    """Return an existing directory for ``raw_path`` or raise HTTP 400.

    The picked folder is its own root: we only reject paths that try to *escape*
    what the user actually pointed at -- ``..`` tokens and any symlink in the
    path that resolves somewhere else.
    """
    candidate = (raw_path or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="path must not be empty")

    # Reject explicit traversal tokens before any filesystem resolution.
    parts = candidate.replace("\\", "/").split("/")
    if ".." in parts:
        raise HTTPException(status_code=400, detail="path must not contain '..'")

    p = Path(candidate)
    if not p.is_absolute():
        p = soft_root / p

    lexical = Path(os.path.abspath(p))
    real = Path(os.path.realpath(p))

    # A symlink anywhere in the path resolves elsewhere -> reject the escape.
    if real != lexical:
        raise HTTPException(status_code=400, detail="path escapes via a symlink")

    if not real.is_dir():
        raise HTTPException(status_code=400, detail="path is not a directory")

    return real


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def create_app(
    allowed_root: str | None = None,
    scan_timeout: float = _DEFAULT_SCAN_TIMEOUT,
    *,
    mode: str = "browser",
    folder_picker: Callable[[], str | None] | None = None,
) -> FastAPI:
    """Build the FastAPI app. Serve it bound to ``127.0.0.1`` only.

    ``mode="desktop"`` enables ``POST /api/pick-folder``, which drives the native
    OS folder dialog through ``folder_picker`` (supplied by
    :mod:`security_preview.desktop`). In ``browser`` mode that route returns 404
    and the UI keeps its free-text path field.
    """
    if mode not in _VALID_MODES:  # pragma: no cover - guard
        raise ValueError(f"mode must be one of {_VALID_MODES}")

    app = FastAPI(title="security-preview", version="0.1.0")
    soft_root = _soft_root(allowed_root)

    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        if not _INDEX_HTML.is_file():  # pragma: no cover - packaging guard
            raise HTTPException(status_code=404, detail="UI not found")
        return FileResponse(str(_INDEX_HTML), media_type="text/html")

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"ok": True, "mode": mode, "version": app.version}

    @app.post("/api/pick-folder", include_in_schema=False)
    def pick_folder() -> dict:
        if mode != "desktop" or folder_picker is None:
            raise HTTPException(status_code=404, detail="folder picker is desktop-mode only")
        chosen = folder_picker()
        if not chosen:
            return {"cancelled": True}
        return {"path": str(chosen)}

    @app.post("/api/scan", response_model=ScanResponse)
    def api_scan(req: ScanRequest) -> ScanResponse:
        target = _safe_target_dir(req.path, soft_root)

        cfg = ScanConfig(
            offline=req.offline,
            run_sca=req.run_sca,
            enrich_nvd=not req.offline,
            min_confidence=Confidence(req.min_confidence),
            follow_symlinks=False,
        )

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(scan_module.scan, str(target), cfg)
            try:
                result = future.result(timeout=scan_timeout)
            except FuturesTimeoutError as exc:
                raise HTTPException(
                    status_code=504, detail=f"scan exceeded {scan_timeout:.0f}s time budget"
                ) from exc

        return ScanResponse(**result.to_dict())

    return app
