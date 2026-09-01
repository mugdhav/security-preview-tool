"""Orchestrator wiring tests for ``security_preview.scan.scan``.

All foundation seams are monkeypatched so these pass today against the Phase 0
stubs and keep passing once the real modules land.
"""
from __future__ import annotations

import security_preview.scan as scan_mod
from security_preview.config import ScanConfig
from security_preview.models import Confidence, RiskLevel, ScanResult


def _patch_seams(monkeypatch, *, files=None, findings=None, components=None, deps=None, record=None):
    files = [] if files is None else files
    findings = [] if findings is None else findings
    components = [] if components is None else components
    deps = [] if deps is None else deps

    def _rec(name, ret):
        if record is not None:
            record.append(name)
        return ret

    monkeypatch.setattr(scan_mod.walker, "discover", lambda *a: _rec("discover", list(files)))
    monkeypatch.setattr(scan_mod.sast, "scan_paths", lambda *a: _rec("scan_paths", list(findings)))
    monkeypatch.setattr(
        scan_mod.sca_parsers,
        "collect_components",
        lambda *a: _rec("collect_components", list(components)),
    )
    monkeypatch.setattr(
        scan_mod.osv_client, "query_osv", lambda *a: _rec("query_osv", list(deps))
    )
    monkeypatch.setattr(
        scan_mod.nvd_client, "enrich_findings", lambda *a: _rec("enrich_findings", None)
    )


def test_scan_runs_against_stubs(tmp_path):
    result = scan_mod.scan(str(tmp_path), ScanConfig.defaults())
    assert isinstance(result, ScanResult)
    assert result.findings == []
    assert result.dependency_findings == []
    assert result.files_scanned == 0
    assert result.dependencies_scanned == 0
    assert result.partial is False


def test_stage_order(monkeypatch, tmp_path):
    calls: list[str] = []
    _patch_seams(monkeypatch, files=["a.py", "b.py"], record=calls)
    scan_mod.scan(str(tmp_path), ScanConfig.defaults())
    assert calls == [
        "discover",
        "scan_paths",
        "collect_components",
        "query_osv",
        "enrich_findings",
    ]


def test_files_and_dependencies_counts(monkeypatch, tmp_path):
    from security_preview.models import Component

    comps = [
        Component(ecosystem="PyPI", name="a", version="1", source_manifest="requirements.txt"),
        Component(ecosystem="PyPI", name="b", version="2", source_manifest="requirements.txt"),
    ]
    _patch_seams(monkeypatch, files=["x.py", "y.py", "z.py"], components=comps)
    result = scan_mod.scan(str(tmp_path), ScanConfig.defaults())
    assert result.files_scanned == 3
    assert result.dependencies_scanned == 2


def test_min_confidence_filter(monkeypatch, tmp_path, make_finding):
    findings = [
        make_finding(confidence=Confidence.HIGH),
        make_finding(confidence=Confidence.MEDIUM),
        make_finding(confidence=Confidence.LOW),
    ]
    _patch_seams(monkeypatch, findings=findings)
    result = scan_mod.scan(
        str(tmp_path), ScanConfig(min_confidence=Confidence.MEDIUM, run_sca=False, enrich_nvd=False)
    )
    assert {f.confidence for f in result.findings} == {Confidence.HIGH, Confidence.MEDIUM}

    _patch_seams(monkeypatch, findings=findings)
    result = scan_mod.scan(
        str(tmp_path), ScanConfig(min_confidence=Confidence.LOW, run_sca=False, enrich_nvd=False)
    )
    assert len(result.findings) == 3


def test_no_sca_skips_sca_seams(monkeypatch, tmp_path):
    calls: list[str] = []
    _patch_seams(monkeypatch, record=calls)
    result = scan_mod.scan(str(tmp_path), ScanConfig(run_sca=False))
    assert "collect_components" not in calls
    assert "query_osv" not in calls
    assert result.dependencies_scanned == 0
    assert result.dependency_findings == []


def test_offline_skips_enrich(monkeypatch, tmp_path):
    calls: list[str] = []
    _patch_seams(monkeypatch, record=calls)
    scan_mod.scan(str(tmp_path), ScanConfig(offline=True))
    assert "enrich_findings" not in calls
    # SCA still runs when offline (query_osv handles offline itself).
    assert "query_osv" in calls


def test_enrich_nvd_false_skips_enrich(monkeypatch, tmp_path):
    calls: list[str] = []
    _patch_seams(monkeypatch, record=calls)
    scan_mod.scan(str(tmp_path), ScanConfig(enrich_nvd=False))
    assert "enrich_findings" not in calls


def test_partial_true_when_a_stage_records_errors(monkeypatch, tmp_path):
    def discover(root, cfg, errors):
        errors.add("walk", "somefile", "permission denied")
        return []

    monkeypatch.setattr(scan_mod.walker, "discover", discover)
    monkeypatch.setattr(scan_mod.sast, "scan_paths", lambda *a: [])
    result = scan_mod.scan(str(tmp_path), ScanConfig(run_sca=False, enrich_nvd=False))
    assert result.partial is True
    assert len(result.errors) == 1
    assert result.errors[0].stage == "walk"


def test_timestamps_are_utc_and_ordered(monkeypatch, tmp_path):
    _patch_seams(monkeypatch)
    result = scan_mod.scan(str(tmp_path), ScanConfig.defaults())
    assert result.started_at.utcoffset() is not None
    assert result.finished_at is not None
    assert result.finished_at >= result.started_at
    assert result.target == str(tmp_path)


def test_dependency_findings_passed_through(monkeypatch, tmp_path, make_dependency_finding):
    deps = [make_dependency_finding()]
    _patch_seams(monkeypatch, deps=deps)
    result = scan_mod.scan(str(tmp_path), ScanConfig.defaults())
    assert result.dependency_findings == deps


def test_critical_findings_survive_default_confidence_gate(monkeypatch, tmp_path, make_finding):
    findings = [make_finding(severity=RiskLevel.CRITICAL, confidence=Confidence.HIGH)]
    _patch_seams(monkeypatch, findings=findings)
    result = scan_mod.scan(str(tmp_path), ScanConfig.defaults())
    assert len(result.findings) == 1
