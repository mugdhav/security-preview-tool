"""On-disk TTL cache for enrichment lookups.

Owned by branch ``foundation/enrichment``.

Stores one JSON file per key under a cache directory (default
``~/.security-preview/cache/``). Each file holds::

    {"stored_at": <unix seconds, float>, "value": <json-serialisable>}

Entries older than ``ttl_hours`` are treated as absent. The cache is keyed by
opaque strings; enrichment uses ``cwe:<CWE-ID>`` and callers may also use
``pkg@version`` style keys. The directory is configurable so tests can point it
at a temp path, and the clock is injectable so TTL/expiry can be tested without
sleeping.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path.home() / ".security-preview" / "cache"


class Cache:
    """Minimal persistent key/value store with per-entry TTL."""

    def __init__(
        self,
        path: str | Path | None = None,
        ttl_hours: int = 24,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._dir = Path(path) if path is not None else DEFAULT_CACHE_DIR
        self._ttl_seconds = float(ttl_hours) * 3600.0
        self._clock = clock
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    @property
    def path(self) -> Path:
        """The directory backing this cache."""
        return self._dir

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self._dir / f"{digest}.json"

    def get(self, key: str) -> Any | None:
        """Return the stored value for ``key``, or ``None`` if missing/expired/corrupt."""
        target = self._path_for(key)
        try:
            raw = target.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return None
        try:
            payload = json.loads(raw)
            stored_at = float(payload["stored_at"])
            value = payload["value"]
        except (ValueError, TypeError, KeyError):
            return None
        if self._ttl_seconds >= 0 and (self._clock() - stored_at) > self._ttl_seconds:
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Persist ``value`` under ``key`` with the current timestamp."""
        target = self._path_for(key)
        payload = {"stored_at": self._clock(), "value": value}
        tmp = target.with_name(target.name + ".tmp")
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            tmp.replace(target)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass
