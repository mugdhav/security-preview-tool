"""Tests for the ``foundation/sca`` unit: manifest parsers + OSV batch client.

No live network: the HTTP seam in ``osv_client`` is monkeypatched.
"""
from __future__ import annotations

from pathlib import Path

import httpx

from security_preview.config import ScanConfig
from security_preview.models import Component, ErrorCollector, RiskLevel
from security_preview.sca import collect_components, osv_client, query_osv

FIXTURES = Path(__file__).parent / "fixtures" / "manifests"


def _components(subdir: str) -> tuple[list[Component], ErrorCollector]:
    errors = ErrorCollector()
    comps = collect_components(str(FIXTURES / subdir), errors)
    return comps, errors


def _as_tuples(comps: list[Component]) -> set[tuple[str, str, str]]:
    return {(c.ecosystem, c.name, c.version) for c in comps}


# --------------------------------------------------------------------------- #
# Parsers                                                                      #
# --------------------------------------------------------------------------- #

def test_requirements_txt():
    comps, errors = _components("pip")
    assert not errors.to_list()
    assert _as_tuples(comps) == {
        ("PyPI", "requests", "2.25.1"),
        ("PyPI", "Flask", "2.0.1"),
        ("PyPI", "PyYAML", "5.1"),
        ("PyPI", "urllib3", "1.26.5"),
        ("PyPI", "package-with-extra", "1.4.0"),
    }
    assert all(c.source_manifest == "requirements.txt" for c in comps)


def test_poetry_lock():
    comps, errors = _components("poetry")
    assert not errors.to_list()
    assert _as_tuples(comps) == {
        ("PyPI", "certifi", "2024.2.2"),
        ("PyPI", "requests", "2.31.0"),
    }
    assert all(c.source_manifest == "poetry.lock" for c in comps)


def test_pipfile_lock():
    comps, errors = _components("pipenv")
    assert not errors.to_list()
    assert _as_tuples(comps) == {
        ("PyPI", "jinja2", "3.1.2"),
        ("PyPI", "pytest", "8.1.1"),
    }


def test_package_lock_json():
    comps, errors = _components("npm")
    assert not errors.to_list()
    assert _as_tuples(comps) == {
        ("npm", "lodash", "4.17.20"),
        ("npm", "@babel/core", "7.12.3"),
        ("npm", "semver", "6.3.0"),
    }


def test_yarn_lock():
    comps, errors = _components("yarn")
    assert not errors.to_list()
    assert _as_tuples(comps) == {
        ("npm", "@babel/core", "7.14.0"),
        ("npm", "lodash", "4.17.21"),
        ("npm", "minimist", "1.2.6"),
    }


def test_go_mod():
    comps, errors = _components("go")
    assert not errors.to_list()
    assert _as_tuples(comps) == {
        ("Go", "github.com/gin-gonic/gin", "v1.7.0"),
        ("Go", "golang.org/x/crypto", "v0.0.0-20210817164053-32db794688a5"),
        ("Go", "github.com/dgrijalva/jwt-go", "v3.2.0"),
        ("Go", "github.com/stretchr/testify", "v1.8.4"),
    }


def test_gemfile_lock():
    comps, errors = _components("ruby")
    assert not errors.to_list()
    assert _as_tuples(comps) == {
        ("RubyGems", "actionpack", "6.0.3.2"),
        ("RubyGems", "nokogiri", "1.10.9"),
        ("RubyGems", "rack", "2.2.3"),
    }


def test_pom_xml():
    comps, errors = _components("maven")
    assert not errors.to_list()
    # log4j-core has a ${property} version -> skipped.
    assert _as_tuples(comps) == {
        ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.10"),
        ("Maven", "org.springframework:spring-core", "5.2.0.RELEASE"),
    }


def test_collect_walks_whole_tree_and_is_deterministic():
    errors = ErrorCollector()
    comps = collect_components(str(FIXTURES), errors)
    assert not errors.to_list()
    # Every ecosystem represented.
    assert {c.ecosystem for c in comps} == {"PyPI", "npm", "Go", "Maven", "RubyGems"}
    # source_manifest is posix-relative to the scan root.
    assert all("\\" not in c.source_manifest for c in comps)
    assert any(c.source_manifest == "npm/package-lock.json" for c in comps)
    # Deterministic ordering.
    assert comps == collect_components(str(FIXTURES), ErrorCollector())
    assert comps == sorted(
        comps, key=lambda c: (c.source_manifest, c.ecosystem, c.name, c.version)
    )


def test_parse_failure_is_recorded_not_raised(write_project):
    root = write_project(
        {
            "poetry.lock": "this is [[ not valid toml",
            "pom.xml": "<project><dependencies><dependency></project>",
            "requirements.txt": "goodpkg==1.0.0\n",
        }
    )
    errors = ErrorCollector()
    comps = collect_components(root, errors)
    # The one valid manifest still yields its component.
    assert ("PyPI", "goodpkg", "1.0.0") in _as_tuples(comps)
    recorded = {e.target for e in errors.to_list()}
    assert recorded == {"poetry.lock", "pom.xml"}
    assert all(e.stage == "sca" for e in errors.to_list())
    assert errors.partial


# --------------------------------------------------------------------------- #
# OSV client                                                                   #
# --------------------------------------------------------------------------- #

PYYAML = Component("PyPI", "pyyaml", "5.1", "requirements.txt")
LODASH = Component("npm", "lodash", "4.17.15", "package-lock.json")


def _batch_response(*vuln_id_lists: list[str]) -> dict:
    return {
        "results": [
            {"vulns": [{"id": vid} for vid in ids]} if ids else {}
            for ids in vuln_id_lists
        ]
    }


def test_offline_short_circuits(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("network must not be touched when offline")

    monkeypatch.setattr(osv_client, "_query_batch", _boom)
    monkeypatch.setattr(osv_client, "_fetch_vuln", _boom)

    errors = ErrorCollector()
    assert query_osv([PYYAML], ScanConfig(offline=True), errors) == []
    assert not errors.to_list()


def test_empty_components_returns_empty():
    assert query_osv([], ScanConfig(), ErrorCollector()) == []


def test_severity_mapping_and_lowest_fixed_version(monkeypatch):
    vulns = {
        "GHSA-1111": {
            "id": "GHSA-1111",
            "summary": "Arbitrary code execution in yaml.load",
            "aliases": ["CVE-2020-1747"],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pyyaml"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "5.3.1"}],
                        }
                    ],
                }
            ],
        },
        "GHSA-2222": {
            "id": "GHSA-2222",
            "summary": "Lower severity issue",
            "aliases": ["CVE-2019-2222"],
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"}
            ],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "pyyaml"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "5.2"}]}],
                }
            ],
        },
    }
    monkeypatch.setattr(
        osv_client, "_query_batch", lambda *_a, **_k: _batch_response(["GHSA-1111", "GHSA-2222"])
    )
    monkeypatch.setattr(osv_client, "_fetch_vuln", lambda vid, _t: vulns[vid])

    errors = ErrorCollector()
    findings = query_osv([PYYAML], ScanConfig(), errors)

    assert not errors.to_list()
    assert len(findings) == 1
    f = findings[0]
    assert f.ecosystem == "PyPI"
    assert f.package == "pyyaml"
    assert f.version == "5.1"
    assert f.source_manifest == "requirements.txt"
    # Highest severity across the two advisories wins.
    assert f.severity is RiskLevel.HIGH
    # Lowest fixed version across all matching advisories.
    assert f.fixed_version == "5.2"
    # Advisory ids deduped + sorted (ids + aliases).
    assert f.advisory_ids == ["CVE-2019-2222", "CVE-2020-1747", "GHSA-1111", "GHSA-2222"]
    assert "yaml.load" in f.summary


def test_cvss_vector_maps_to_critical(monkeypatch):
    detail = {
        "id": "OSV-CRIT",
        "summary": "Critical RCE",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.17.21"}]}],
            }
        ],
    }
    monkeypatch.setattr(osv_client, "_query_batch", lambda *_a, **_k: _batch_response(["OSV-CRIT"]))
    monkeypatch.setattr(osv_client, "_fetch_vuln", lambda *_a, **_k: detail)

    findings = query_osv([LODASH], ScanConfig(), ErrorCollector())
    assert [f.severity for f in findings] == [RiskLevel.CRITICAL]
    assert findings[0].fixed_version == "4.17.21"


def test_querybatch_network_failure_records_error_and_returns_partial(monkeypatch):
    def _fail(*_a, **_k):
        raise httpx.ConnectError("name resolution failed")

    monkeypatch.setattr(osv_client, "_query_batch", _fail)
    monkeypatch.setattr(osv_client, "_fetch_vuln", _fail)

    errors = ErrorCollector()
    findings = query_osv([PYYAML, LODASH], ScanConfig(), errors)

    assert findings == []
    recorded = errors.to_list()
    assert recorded and all(e.stage == "sca" for e in recorded)
    assert osv_client.OSV_QUERYBATCH_URL in {e.target for e in recorded}
    assert errors.partial


def test_vuln_detail_failure_still_yields_partial_finding(monkeypatch):
    monkeypatch.setattr(
        osv_client, "_query_batch", lambda *_a, **_k: _batch_response(["GHSA-DOWN"])
    )

    def _fail(*_a, **_k):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(osv_client, "_fetch_vuln", _fail)

    errors = ErrorCollector()
    findings = query_osv([PYYAML], ScanConfig(), errors)

    assert len(findings) == 1
    f = findings[0]
    assert f.advisory_ids == ["GHSA-DOWN"]
    assert f.fixed_version is None
    assert f.severity is RiskLevel.MEDIUM  # default when detail is unavailable
    assert {e.target for e in errors.to_list()} == {"GHSA-DOWN"}
    assert errors.partial


def test_results_are_deterministically_ordered(monkeypatch):
    comps = [
        Component("npm", "lodash", "4.17.15", "package-lock.json"),
        Component("PyPI", "pyyaml", "5.1", "requirements.txt"),
    ]
    detail_by_pkg = {
        "lodash": {
            "id": "OSV-L",
            "summary": "npm issue",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"name": "lodash"}, "ranges": [
                {"events": [{"fixed": "4.17.21"}]}]}],
        },
        "pyyaml": {
            "id": "OSV-P",
            "summary": "pypi issue",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"name": "pyyaml"}, "ranges": [
                {"events": [{"fixed": "5.4"}]}]}],
        },
    }

    def _batch(payload, _t):
        return {
            "results": [
                {"vulns": [{"id": "OSV-" + q["package"]["name"][0].upper()}]}
                for q in payload["queries"]
            ]
        }

    id_to_pkg = {"OSV-L": "lodash", "OSV-P": "pyyaml"}
    monkeypatch.setattr(osv_client, "_query_batch", _batch)
    monkeypatch.setattr(osv_client, "_fetch_vuln", lambda vid, _t: detail_by_pkg[id_to_pkg[vid]])

    findings_a = query_osv(list(comps), ScanConfig(), ErrorCollector())
    findings_b = query_osv(list(reversed(comps)), ScanConfig(), ErrorCollector())
    assert [f.package for f in findings_a] == [f.package for f in findings_b]
