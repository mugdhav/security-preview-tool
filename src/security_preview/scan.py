"""The one scan entrypoint. Owned by branch ``foundation/orchestrator-cli``.

``scan(path, cfg)`` sequences the foundation seams in a fixed order and assembles
a :class:`~security_preview.models.ScanResult`. Every stage receives the shared
:class:`~security_preview.models.ErrorCollector`; a non-empty collector marks the
result ``partial``.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .config import ScanConfig
from .engine import sast, walker
from .enrich import nvd_client
from .models import ErrorCollector, ScanResult
from .sca import osv_client
from .sca import parsers as sca_parsers

__all__ = ["scan"]


def scan(path: str, cfg: ScanConfig) -> ScanResult:
    """Run discovery, SAST, optional SCA and optional NVD enrichment over ``path``."""
    errors = ErrorCollector()
    started_at = datetime.now(timezone.utc)

    # 1. Discover candidate files (skip-dirs, size/count caps, symlink policy).
    files = walker.discover(path, cfg, errors)

    # 2. Run the static analysis rules.
    findings = sast.scan_paths(path, files, cfg, errors)

    # 3. Confidence gate — the orchestrator owns this, not the engine.
    findings = [f for f in findings if f.confidence.meets(cfg.min_confidence)]

    # 4. Dependency scanning (SCA). ``query_osv`` itself honours ``cfg.offline``.
    components: list = []
    dependency_findings: list = []
    if cfg.run_sca:
        components = sca_parsers.collect_components(path, errors)
        dependency_findings = osv_client.query_osv(components, cfg, errors)

    # 5. NVD enrichment — mutates findings in place; never raises.
    if cfg.enrich_nvd and not cfg.offline:
        nvd_client.enrich_findings(findings, cfg, errors)

    finished_at = datetime.now(timezone.utc)
    return ScanResult(
        target=path,
        started_at=started_at,
        finished_at=finished_at,
        findings=findings,
        dependency_findings=dependency_findings,
        files_scanned=len(files),
        dependencies_scanned=len(components),
        errors=errors.to_list(),
        partial=errors.partial,
    )
