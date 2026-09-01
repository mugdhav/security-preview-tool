"""Tests for the security-preview browser app (branch ``foundation/browser-app``)."""
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import security_preview.scan as scan_mod
from security_preview.models import ScanResult
from security_preview.server.app import ScanResponse, create_app


@pytest.fixture
def fixture_result(make_scan_result):
    """A concrete ScanResult the monkeypatched ``scan.scan`` returns."""
    return make_scan_result(
        target="REPLACED_AT_RUNTIME",
        started_at=datetime(2026, 9, 1, 14, 22, tzinfo=timezone.utc),
        finished_at=datetime(2026, 9, 1, 14, 22, 3, tzinfo=timezone.utc),
    )


@pytest.fixture
def client(tmp_path, monkeypatch, fixture_result):
    calls: dict = {}

    def fake_scan(path: str, cfg) -> ScanResult:
        calls["path"] = path
        calls["cfg"] = cfg
        return fixture_result

    monkeypatch.setattr(scan_mod, "scan", fake_scan)
    app = create_app(allowed_root=str(tmp_path))
    c = TestClient(app)
    c.calls = calls  # type: ignore[attr-defined]
    c.root = tmp_path  # type: ignore[attr-defined]
    return c


# --------------------------------------------------------------------------- #
# Contract
# --------------------------------------------------------------------------- #
def test_create_app_returns_fastapi():
    from fastapi import FastAPI

    assert isinstance(create_app(), FastAPI)


# --------------------------------------------------------------------------- #
# Request validation
# --------------------------------------------------------------------------- #
def test_missing_path_is_422(client):
    r = client.post("/api/scan", json={"offline": True})
    assert r.status_code == 422


def test_bad_min_confidence_is_422(client):
    r = client.post("/api/scan", json={"path": str(client.root), "min_confidence": "SORTA"})
    assert r.status_code == 422


def test_bad_format_is_422(client):
    r = client.post("/api/scan", json={"path": str(client.root), "format": "pdf"})
    assert r.status_code == 422


# --------------------------------------------------------------------------- #
# Path confinement
# --------------------------------------------------------------------------- #
def test_dotdot_traversal_rejected(client):
    r = client.post("/api/scan", json={"path": str(client.root / ".." / "etc")})
    assert r.status_code == 400


def test_path_outside_root_rejected(client, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    r = client.post("/api/scan", json={"path": str(outside)})
    assert r.status_code == 400


def test_symlink_escape_rejected(client, tmp_path_factory):
    outside = tmp_path_factory.mktemp("target_outside")
    link = client.root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")
    r = client.post("/api/scan", json={"path": str(link)})
    assert r.status_code == 400


def test_nonexistent_path_rejected(client):
    r = client.post("/api/scan", json={"path": str(client.root / "does-not-exist")})
    assert r.status_code == 400


def test_file_path_rejected(client):
    f = client.root / "a_file.txt"
    f.write_text("hi", encoding="utf-8")
    r = client.post("/api/scan", json={"path": str(f)})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_happy_path_returns_valid_response_model(client):
    sub = client.root / "proj"
    sub.mkdir()
    r = client.post(
        "/api/scan",
        json={"path": str(sub), "offline": True, "run_sca": False, "min_confidence": "LOW"},
    )
    assert r.status_code == 200
    payload = r.json()
    # Response validates against the explicit Pydantic model.
    model = ScanResponse.model_validate(payload)
    assert model.tool_version == "0.1.0"
    assert model.summary.total_findings == len(model.findings)
    assert "by_severity" in payload["summary"]

    # Flags were threaded into ScanConfig.
    cfg = client.calls["cfg"]
    assert cfg.offline is True
    assert cfg.run_sca is False
    assert cfg.enrich_nvd is False
    assert cfg.min_confidence.value == "LOW"
    assert client.calls["path"] == str(sub)


def test_scan_called_with_confined_realpath(client):
    sub = client.root / "nested"
    sub.mkdir()
    r = client.post("/api/scan", json={"path": str(sub)})
    assert r.status_code == 200
    assert client.calls["path"] == str(sub)


# --------------------------------------------------------------------------- #
# UI
# --------------------------------------------------------------------------- #
def test_index_served_as_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "<title>security-preview</title>" in r.text


def test_index_has_no_external_resource_refs(client):
    html = client.get("/").text
    # No external scripts / stylesheets / fonts / images / fetches.
    assert not re.search(r"<script[^>]+src=", html, re.IGNORECASE)
    assert not re.search(r"<link[^>]+href=", html, re.IGNORECASE)
    assert not re.search(r"@import", html, re.IGNORECASE)
    assert not re.search(r"url\(\s*['\"]?https?:", html, re.IGNORECASE)
    assert not re.search(r"<img[^>]+src=\s*['\"]https?:", html, re.IGNORECASE)
    assert "cdn" not in html.lower()
    assert "fonts.googleapis" not in html
