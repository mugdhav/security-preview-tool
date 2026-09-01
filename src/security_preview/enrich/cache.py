"""STUB. Owned by branch ``foundation/enrichment``. Do NOT edit on other branches.

Real implementation: on-disk TTL cache under ``~/.security-preview/cache/`` keyed
by ``cwe_id`` and ``pkg@version``, honoring ``ScanConfig.cache_ttl_hours``.
"""
from __future__ import annotations

from typing import Any


class Cache:
    def __init__(self, path: str | None = None, ttl_hours: int = 24) -> None:
        self._d: dict[str, Any] = {}

    def get(self, key: str) -> Any | None:
        return self._d.get(key)

    def set(self, key: str, value: Any) -> None:
        self._d[key] = value
