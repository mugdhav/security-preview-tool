"""Tests for the on-disk TTL cache (``security_preview.enrich.cache``)."""
from __future__ import annotations

import json

from security_preview.enrich.cache import DEFAULT_CACHE_DIR, Cache


def test_set_then_get_roundtrip(tmp_path):
    cache = Cache(path=tmp_path, ttl_hours=24)
    cache.set("cwe:CWE-89", ["CVE-2024-0001", "CVE-2024-0002"])
    assert cache.get("cwe:CWE-89") == ["CVE-2024-0001", "CVE-2024-0002"]


def test_get_missing_key_returns_none(tmp_path):
    cache = Cache(path=tmp_path, ttl_hours=24)
    assert cache.get("cwe:CWE-999") is None


def test_cache_hit_persists_across_instances(tmp_path):
    Cache(path=tmp_path, ttl_hours=24).set("pkg@1.0", {"vulns": 2})
    # A fresh instance pointed at the same directory still sees the entry.
    assert Cache(path=tmp_path, ttl_hours=24).get("pkg@1.0") == {"vulns": 2}


def test_entry_expires_after_ttl(tmp_path):
    now = [1_000_000.0]
    cache = Cache(path=tmp_path, ttl_hours=1, clock=lambda: now[0])
    cache.set("cwe:CWE-79", ["CVE-2024-1111"])

    # Still fresh 59 minutes later.
    now[0] += 59 * 60
    assert cache.get("cwe:CWE-79") == ["CVE-2024-1111"]

    # Expired just past the 1 hour TTL.
    now[0] += 2 * 60
    assert cache.get("cwe:CWE-79") is None


def test_corrupt_file_is_treated_as_miss(tmp_path):
    cache = Cache(path=tmp_path, ttl_hours=24)
    cache.set("cwe:CWE-22", ["CVE-2024-2222"])
    # Corrupt the backing file on disk.
    backing = next(p for p in tmp_path.iterdir() if p.suffix == ".json")
    backing.write_text("{not json", encoding="utf-8")
    assert cache.get("cwe:CWE-22") is None


def test_on_disk_format_is_json_with_timestamp(tmp_path):
    cache = Cache(path=tmp_path, ttl_hours=24, clock=lambda: 42.0)
    cache.set("k", [1, 2, 3])
    backing = next(p for p in tmp_path.iterdir() if p.suffix == ".json")
    payload = json.loads(backing.read_text(encoding="utf-8"))
    assert payload == {"stored_at": 42.0, "value": [1, 2, 3]}


def test_default_cache_dir_under_home():
    assert DEFAULT_CACHE_DIR.parts[-2:] == (".security-preview", "cache")
