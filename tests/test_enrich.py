"""Tests for NVD enrichment (``security_preview.enrich.nvd_client``).

The HTTP layer is always monkeypatched - no live NVD calls in CI.
"""
from __future__ import annotations

import dataclasses

import pytest

from security_preview.config import ScanConfig
from security_preview.enrich import nvd_client
from security_preview.models import ErrorCollector


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def _nvd_payload(*cve_ids: str) -> dict:
    return {"vulnerabilities": [{"cve": {"id": cid}} for cid in cve_ids]}


@pytest.fixture
def cfg() -> ScanConfig:
    return ScanConfig(cache_ttl_hours=24)


@pytest.fixture(autouse=True)
def _cache_in_tmp(tmp_path, monkeypatch):
    """Point the enrichment cache at a throwaway directory."""
    monkeypatch.setattr(nvd_client, "_cache_dir", lambda: str(tmp_path / "cache"))
    return tmp_path


def test_enrich_writes_top_three_cves_and_groups_by_cwe(cfg, make_finding, monkeypatch):
    calls: list[str] = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cweId"])
        return FakeResponse(
            _nvd_payload("CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5")
        )

    monkeypatch.setattr(nvd_client.httpx, "get", fake_get)

    f1 = make_finding(cwe_id="CWE-89", cve_ids=[])
    f2 = make_finding(cwe_id="CWE-89", cve_ids=[])
    f3 = make_finding(cwe_id="CWE-79", cve_ids=[])
    errors = ErrorCollector()

    result = nvd_client.enrich_findings([f1, f2, f3], cfg, errors)

    assert result is None
    assert f1.cve_ids == ["CVE-1", "CVE-2", "CVE-3"]
    assert f2.cve_ids == ["CVE-1", "CVE-2", "CVE-3"]
    assert f3.cve_ids == ["CVE-1", "CVE-2", "CVE-3"]
    # One request per distinct CWE, not per finding.
    assert sorted(calls) == ["CWE-79", "CWE-89"]
    assert errors.to_list() == []


def test_second_run_is_served_from_cache(cfg, make_finding, monkeypatch):
    calls: list[str] = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cweId"])
        return FakeResponse(_nvd_payload("CVE-100", "CVE-200"))

    monkeypatch.setattr(nvd_client.httpx, "get", fake_get)

    first = make_finding(cwe_id="CWE-502", cve_ids=[])
    nvd_client.enrich_findings([first], cfg, ErrorCollector())
    assert calls == ["CWE-502"]
    assert first.cve_ids == ["CVE-100", "CVE-200"]

    # Second run: same CWE, cache hit, no new HTTP call.
    second = make_finding(cwe_id="CWE-502", cve_ids=[])
    nvd_client.enrich_findings([second], cfg, ErrorCollector())
    assert calls == ["CWE-502"]
    assert second.cve_ids == ["CVE-100", "CVE-200"]


def test_expired_cache_entry_triggers_refetch(make_finding, monkeypatch):
    calls: list[str] = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params["cweId"])
        return FakeResponse(_nvd_payload("CVE-A"))

    monkeypatch.setattr(nvd_client.httpx, "get", fake_get)

    short_ttl = ScanConfig(cache_ttl_hours=0)
    nvd_client.enrich_findings([make_finding(cwe_id="CWE-77", cve_ids=[])], short_ttl, ErrorCollector())
    nvd_client.enrich_findings([make_finding(cwe_id="CWE-77", cve_ids=[])], short_ttl, ErrorCollector())
    # ttl_hours=0 => the stored entry is always stale => a second fetch happens.
    assert calls == ["CWE-77", "CWE-77"]


def test_all_requests_fail_leaves_findings_unchanged_and_records_errors(
    cfg, make_finding, monkeypatch
):
    def boom(url, params=None, timeout=None):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(nvd_client.httpx, "get", boom)

    f1 = make_finding(cwe_id="CWE-89", cve_ids=[])
    f2 = make_finding(cwe_id="CWE-78", cve_ids=[])
    errors = ErrorCollector()

    nvd_client.enrich_findings([f1, f2], cfg, errors)

    assert f1.cve_ids == []
    assert f2.cve_ids == []
    recorded = errors.to_list()
    assert {e.target for e in recorded} == {"CWE-78", "CWE-89"}
    assert all(e.stage == "enrich" for e in recorded)


def test_offline_is_a_noop(cfg, make_finding, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no HTTP call expected when offline")

    monkeypatch.setattr(nvd_client.httpx, "get", boom)

    finding = make_finding(cwe_id="CWE-89", cve_ids=[])
    errors = ErrorCollector()

    nvd_client.enrich_findings([finding], dataclasses.replace(cfg, offline=True), errors)

    assert finding.cve_ids == []
    assert errors.to_list() == []


def test_enrich_nvd_disabled_is_a_noop(cfg, make_finding, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no HTTP call expected when enrich_nvd is False")

    monkeypatch.setattr(nvd_client.httpx, "get", boom)

    finding = make_finding(cwe_id="CWE-89", cve_ids=[])
    errors = ErrorCollector()

    nvd_client.enrich_findings([finding], dataclasses.replace(cfg, enrich_nvd=False), errors)

    assert finding.cve_ids == []
    assert errors.to_list() == []


def test_findings_without_cwe_are_skipped(cfg, make_finding, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no HTTP call expected with no CWE ids")

    monkeypatch.setattr(nvd_client.httpx, "get", boom)

    finding = make_finding(cwe_id=None, cve_ids=[])
    errors = ErrorCollector()

    nvd_client.enrich_findings([finding], cfg, errors)

    assert finding.cve_ids == []
    assert errors.to_list() == []


def test_exhausted_time_budget_records_error_and_stops(cfg, make_finding, monkeypatch):
    monkeypatch.setattr(nvd_client.time, "monotonic", lambda: 10_000.0)

    def unexpected(*a, **k):
        raise AssertionError("time budget exhausted before any HTTP call")

    monkeypatch.setattr(nvd_client.httpx, "get", unexpected)

    finding = make_finding(cwe_id="CWE-89", cve_ids=[])
    errors = ErrorCollector()

    nvd_client.enrich_findings([finding], dataclasses.replace(cfg, enrich_time_budget=0.0), errors)

    assert finding.cve_ids == []
    recorded = errors.to_list()
    assert len(recorded) == 1
    assert recorded[0].stage == "enrich"
    assert "time budget" in recorded[0].message
