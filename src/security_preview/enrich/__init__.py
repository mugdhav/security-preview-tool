"""Enrichment package: NVD CWE -> example-CVE lookup with an on-disk TTL cache.

Owned by branch ``foundation/enrichment``.
"""
from __future__ import annotations

from .cache import DEFAULT_CACHE_DIR, Cache
from .nvd_client import enrich_findings

__all__ = ["DEFAULT_CACHE_DIR", "Cache", "enrich_findings"]
