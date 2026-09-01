"""CLI tests for ``security_preview.cli.main``.

``scan_mod.scan`` and ``renderers.render`` are monkeypatched; these pass today
against the Phase 0 stubs.
"""
from __future__ import annotations

import json

import pytest

import security_preview.scan as scan_mod
from security_preview import cli
from security_preview.models import Confidence, RiskLevel


# --------------------------------------------------------------------------- #
# argument / config threading
# --------------------------------------------------------------------------- #
def test_scan_defaults_build_expected_config(monkeypatch, tmp_path, make_scan_result):
    seen = {}

    def fake_scan(path, cfg):
        seen["path"] = path
        seen["cfg"] = cfg
        return make_scan_result(findings=[])

    monkeypatch.setattr(cli.scan_mod, "scan", fake_scan)
    monkeypatch.setattr(cli.renderers, "render", lambda result, fmt: "")
    rc = cli.main(["scan", str(tmp_path)])
    assert rc == 0
    cfg = seen["cfg"]
    assert seen["path"] == str(tmp_path)
    assert cfg.offline is False
    assert cfg.run_sca is True
    assert cfg.min_confidence is Confidence.MEDIUM


def test_offline_flag_sets_config_and_blocks_enrich(monkeypatch, tmp_path):
    calls: list[str] = []
    monkeypatch.setattr(scan_mod.walker, "discover", lambda *a: [])
    monkeypatch.setattr(scan_mod.sast, "scan_paths", lambda *a: [])
    monkeypatch.setattr(
        scan_mod.sca_parsers, "collect_components", lambda *a: calls.append("cc") or []
    )
    monkeypatch.setattr(scan_mod.osv_client, "query_osv", lambda *a: calls.append("osv") or [])
    monkeypatch.setattr(
        scan_mod.nvd_client, "enrich_findings", lambda *a: calls.append("enrich")
    )
    seen = {}

    def fake_render(result, fmt):
        seen["result"] = result
        return ""

    monkeypatch.setattr(cli.renderers, "render", fake_render)
    rc = cli.main(["scan", str(tmp_path), "--offline"])
    assert rc == 0
    assert "enrich" not in calls


def test_no_sca_flag_skips_sca_seams(monkeypatch, tmp_path):
    calls: list[str] = []
    monkeypatch.setattr(scan_mod.walker, "discover", lambda *a: [])
    monkeypatch.setattr(scan_mod.sast, "scan_paths", lambda *a: [])
    monkeypatch.setattr(
        scan_mod.sca_parsers, "collect_components", lambda *a: calls.append("cc") or []
    )
    monkeypatch.setattr(scan_mod.osv_client, "query_osv", lambda *a: calls.append("osv") or [])
    monkeypatch.setattr(cli.renderers, "render", lambda result, fmt: "")
    cli.main(["scan", str(tmp_path), "--no-sca"])
    assert calls == []


def test_min_confidence_flag_filters_findings(monkeypatch, tmp_path, make_finding):
    monkeypatch.setattr(scan_mod.walker, "discover", lambda *a: [])
    monkeypatch.setattr(
        scan_mod.sast,
        "scan_paths",
        lambda *a: [
            make_finding(confidence=Confidence.HIGH),
            make_finding(confidence=Confidence.LOW),
        ],
    )
    seen = {}

    def fake_render(result, fmt):
        seen["result"] = result
        return ""

    monkeypatch.setattr(cli.renderers, "render", fake_render)
    cli.main(["scan", str(tmp_path), "--no-sca", "--min-confidence", "HIGH"])
    findings = seen["result"].findings
    assert len(findings) == 1
    assert findings[0].confidence is Confidence.HIGH


def test_format_is_passed_to_renderer(monkeypatch, tmp_path, make_scan_result):
    seen = {}
    monkeypatch.setattr(cli.scan_mod, "scan", lambda path, cfg: make_scan_result(findings=[]))
    monkeypatch.setattr(
        cli.renderers, "render", lambda result, fmt: seen.setdefault("fmt", fmt) or ""
    )
    cli.main(["scan", str(tmp_path), "--format", "json"])
    assert seen["fmt"] == "json"


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #
def test_writes_to_stdout_by_default(monkeypatch, tmp_path, capsys, make_scan_result):
    monkeypatch.setattr(cli.scan_mod, "scan", lambda path, cfg: make_scan_result(findings=[]))
    monkeypatch.setattr(cli.renderers, "render", lambda result, fmt: "HELLO-STDOUT")
    cli.main(["scan", str(tmp_path)])
    assert "HELLO-STDOUT" in capsys.readouterr().out


def test_out_writes_file(monkeypatch, tmp_path, make_scan_result):
    monkeypatch.setattr(cli.scan_mod, "scan", lambda path, cfg: make_scan_result(findings=[]))
    monkeypatch.setattr(cli.renderers, "render", lambda result, fmt: "REPORT-BODY")
    out = tmp_path / "sub" / "report.txt"
    out.parent.mkdir()
    rc = cli.main(["scan", str(tmp_path), "--out", str(out)])
    assert rc == 0
    assert out.read_text(encoding="utf-8") == "REPORT-BODY"


# --------------------------------------------------------------------------- #
# exit codes
# --------------------------------------------------------------------------- #
def test_exit_code_1_on_critical_finding(monkeypatch, tmp_path, make_scan_result, make_finding):
    monkeypatch.setattr(
        cli.scan_mod,
        "scan",
        lambda path, cfg: make_scan_result(findings=[make_finding(severity=RiskLevel.CRITICAL)]),
    )
    monkeypatch.setattr(cli.renderers, "render", lambda result, fmt: "")
    assert cli.main(["scan", str(tmp_path)]) == 1


def test_exit_code_0_without_critical_finding(
    monkeypatch, tmp_path, make_scan_result, make_finding
):
    monkeypatch.setattr(
        cli.scan_mod,
        "scan",
        lambda path, cfg: make_scan_result(findings=[make_finding(severity=RiskLevel.HIGH)]),
    )
    monkeypatch.setattr(cli.renderers, "render", lambda result, fmt: "")
    assert cli.main(["scan", str(tmp_path)]) == 0


def test_unknown_format_errors_cleanly(tmp_path, capsys):
    rc = cli.main(["scan", str(tmp_path), "--format", "bogus"])
    assert rc == 2
    assert "bogus" in capsys.readouterr().err


def test_missing_directory_errors_cleanly(tmp_path, capsys):
    missing = tmp_path / "nope"
    rc = cli.main(["scan", str(missing)])
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err.lower()


def test_no_subcommand_exits_nonzero():
    with pytest.raises(SystemExit):
        cli.main([])


# --------------------------------------------------------------------------- #
# serve / selftest
# --------------------------------------------------------------------------- #
def test_serve_lazy_imports_and_runs_uvicorn(monkeypatch):
    import uvicorn

    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    rc = cli.main(["serve", "--port", "9191"])
    assert rc == 0
    assert seen["host"] == "127.0.0.1"
    assert seen["port"] == 9191


def test_selftest_prints_json_summary_and_exits_int(capsys):
    rc = cli.main(["selftest"])
    assert rc in (0, 1)
    payload = json.loads(capsys.readouterr().out)
    assert "by_severity" in payload
    assert "files_scanned" in payload
