"""Scan configuration. FROZEN in Phase 0 — a single source of truth for every
toggle so no code path can silently ignore one.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Confidence


@dataclass(frozen=True)
class ScanConfig:
    offline: bool = False              # skip ALL network (NVD + OSV)
    run_sca: bool = True
    enrich_nvd: bool = True
    min_confidence: Confidence = Confidence.MEDIUM
    max_files: int = 20_000
    max_file_bytes: int = 2_000_000
    follow_symlinks: bool = False
    network_timeout: float = 8.0       # per request, seconds
    enrich_time_budget: float = 30.0   # whole NVD phase, seconds
    cache_ttl_hours: int = 24

    @classmethod
    def defaults(cls) -> ScanConfig:
        return cls()
