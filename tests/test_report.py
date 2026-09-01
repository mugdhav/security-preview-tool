"""Tests for ``security_preview.report``.

Golden files live in ``tests/fixtures/golden/``. Regenerate them with::

    UPDATE_GOLDEN=1 python -m pytest tests/test_report.py

``tests/fixtures/sample_scan_result.json`` is the serialized input every golden
is rendered from; it round-trips through ``ScanResult.from_dict``.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from security_preview.models import (
    Confidence,
    DependencyFinding,
    Finding,
    RiskLevel,
    ScanError,
    ScanResult,
)
from security_preview.report import FORMATS, render
from security_preview.report.renderers import _render_json

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN = FIXTURES / "golden"
SAMPLE_JSON = FIXTURES / "sample_scan_result.json"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"

GOLDEN_NAME = {
    "text": "sample-report.txt",
    "markdown": "sample-report.md",
    "json": "sample-report.json",
    # ``*.sarif`` is git-ignored repo-wide; keep the golden under a tracked name.
    "sarif": "sample-report.sarif.json",
    "html": "sample-report.html",
}


def build_sample_result() -> ScanResult:
    """A deterministic, feature-covering scan result (multi-severity, deps, errors)."""
    started = datetime(2026, 9, 1, 14, 22, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 9, 1, 14, 22, 3, 100000, tzinfo=timezone.utc)
    findings = [
        Finding(
            rule_id="py.sqli",
            name="SQL Injection",
            severity=RiskLevel.CRITICAL,
            confidence=Confidence.HIGH,
            category="Injection",
            cwe_id="CWE-89",
            file_path="api/reports.py",
            line=142,
            code_snippet=(
                '141| owner = request.args["user"]\n'
                "142| cur.execute(f\"SELECT * FROM reports WHERE owner = '{owner}'\")\n"
                "143| rows = cur.fetchall()"
            ),
            description="Request-controlled `owner` is interpolated into the SQL string.",
            remediation_vulnerable="cur.execute(f\"... owner = '{owner}'\")",
            remediation_secure='cur.execute("... owner = %s", (owner,))',
            cve_ids=["CVE-2019-19844", "CVE-2021-23336"],
        ),
        Finding(
            rule_id="js.command_injection",
            name="Command Injection",
            severity=RiskLevel.CRITICAL,
            confidence=Confidence.MEDIUM,
            category="Injection",
            cwe_id="CWE-78",
            file_path="worker/convert.js",
            line=88,
            code_snippet='88| exec("ffmpeg -i " + src + " out.mp4")',
            description="Untrusted `src` is concatenated into a shell command.",
            remediation_vulnerable='exec("ffmpeg -i " + src + " out.mp4")',
            remediation_secure='execFile("ffmpeg", ["-i", src, "out.mp4"])',
            cve_ids=[],
        ),
        Finding(
            rule_id="py.hardcoded_secret",
            name="Hardcoded Credentials",
            severity=RiskLevel.HIGH,
            confidence=Confidence.HIGH,
            category="Secrets",
            cwe_id="CWE-798",
            file_path="config/settings.py",
            line=12,
            code_snippet='12| STRIPE_KEY = "sk_live_abcd" + "••••"',
            description="A live API key is committed to source control.",
            remediation_vulnerable='STRIPE_KEY = "sk_live_********"',
            remediation_secure='STRIPE_KEY = os.environ["STRIPE_KEY"]',
            cve_ids=[],
        ),
        Finding(
            rule_id="py.weak_hash",
            name="Weak Password Hashing",
            severity=RiskLevel.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="Crypto",
            cwe_id="CWE-328",
            file_path="auth/users.py",
            line=57,
            code_snippet="57| digest = hashlib.md5(password.encode()).hexdigest()",
            description="MD5 is unsuitable for password storage.",
            remediation_vulnerable="hashlib.md5(password.encode()).hexdigest()",
            remediation_secure="bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
            cve_ids=[],
        ),
        Finding(
            rule_id="py.open_redirect",
            name="Open Redirect",
            severity=RiskLevel.LOW,
            confidence=Confidence.LOW,
            category="Config",
            cwe_id=None,
            file_path="web/views.py",
            line=203,
            code_snippet='203| return redirect(request.args["next"])',
            description="User-supplied `next` is used as a redirect target unchecked.",
            remediation_vulnerable='return redirect(request.args["next"])',
            remediation_secure="return redirect(url_for(safe_endpoint(request.args)))",
            cve_ids=[],
        ),
        Finding(
            rule_id="generic.todo_security",
            name="Security TODO Marker",
            severity=RiskLevel.INFO,
            confidence=Confidence.LOW,
            category="Hygiene",
            cwe_id=None,
            file_path="core/auth.py",
            line=9,
            code_snippet="9| # TODO: security - re-enable CSRF checks before launch",
            description="A security-relevant TODO remains in the codebase.",
            remediation_vulnerable="# TODO: security - re-enable CSRF checks",
            remediation_secure="Track the TODO in an issue and enable CSRF protection.",
            cve_ids=[],
        ),
    ]
    deps = [
        DependencyFinding(
            ecosystem="npm",
            package="lodash",
            version="4.17.11",
            advisory_ids=["CVE-2019-10744", "GHSA-jf85-cpcp-j695"],
            severity=RiskLevel.CRITICAL,
            fixed_version="4.17.12",
            source_manifest="package-lock.json",
            summary="Prototype pollution in defaultsDeep.",
        ),
        DependencyFinding(
            ecosystem="PyPI",
            package="pyyaml",
            version="5.1",
            advisory_ids=["CVE-2020-1747"],
            severity=RiskLevel.CRITICAL,
            fixed_version="5.3.1",
            source_manifest="requirements.txt",
            summary="Arbitrary code execution via full_load.",
        ),
        DependencyFinding(
            ecosystem="PyPI",
            package="requests",
            version="2.19.1",
            advisory_ids=["PYSEC-2018-28"],
            severity=RiskLevel.HIGH,
            fixed_version=None,
            source_manifest="requirements.txt",
            summary="Credential leak on cross-origin redirect.",
        ),
    ]
    errors = [
        ScanError(
            stage="walk",
            target="assets/vendor.min.js",
            message="exceeded the 2 MB size cap; file skipped",
        ),
        ScanError(
            stage="enrich",
            target="services.nvd.nist.gov",
            message="connection timeout after 3 retries; 12 of 40 CWE lookups failed",
        ),
        ScanError(
            stage="sca",
            target="pom.xml",
            message="malformed XML at line 44; Java dependencies not checked",
        ),
    ]
    return ScanResult(
        target="/work/payments-api",
        started_at=started,
        finished_at=finished,
        findings=findings,
        dependency_findings=deps,
        files_scanned=342,
        dependencies_scanned=47,
        errors=errors,
        partial=True,
    )


@pytest.fixture(scope="module")
def sample_result() -> ScanResult:
    if UPDATE or not SAMPLE_JSON.exists():
        SAMPLE_JSON.parent.mkdir(parents=True, exist_ok=True)
        SAMPLE_JSON.write_bytes(
            (json.dumps(build_sample_result().to_dict(), indent=2) + "\n").encode("utf-8")
        )
    data = json.loads(SAMPLE_JSON.read_text(encoding="utf-8"))
    return ScanResult.from_dict(data)


def _golden(fmt: str, rendered: str) -> str:
    path = GOLDEN / GOLDEN_NAME[fmt]
    if UPDATE or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(rendered.encode("utf-8"))
    return path.read_bytes().decode("utf-8")


def test_sample_json_roundtrips(sample_result: ScanResult):
    again = ScanResult.from_dict(json.loads(SAMPLE_JSON.read_text(encoding="utf-8")))
    assert again.to_dict() == sample_result.to_dict()


@pytest.mark.parametrize("fmt", FORMATS)
def test_render_matches_golden(sample_result: ScanResult, fmt: str):
    rendered = render(sample_result, fmt)
    assert rendered == _golden(fmt, rendered)


@pytest.mark.parametrize("fmt", FORMATS)
def test_render_is_deterministic(sample_result: ScanResult, fmt: str):
    assert render(sample_result, fmt) == render(sample_result, fmt)


@pytest.mark.parametrize("fmt", FORMATS)
def test_render_independent_of_input_order(sample_result: ScanResult, fmt: str):
    shuffled = ScanResult.from_dict(sample_result.to_dict())
    shuffled.findings = list(reversed(shuffled.findings))
    shuffled.dependency_findings = list(reversed(shuffled.dependency_findings))
    if fmt == "json":
        # json mirrors to_dict content exactly, so order is caller-defined.
        return
    assert render(shuffled, fmt) == render(sample_result, fmt)


def test_unknown_format_raises(sample_result: ScanResult):
    with pytest.raises(ValueError):
        render(sample_result, "pdf")
    with pytest.raises(ValueError):
        render(sample_result, "")


def test_json_is_exactly_to_dict(sample_result: ScanResult):
    assert json.loads(render(sample_result, "json")) == sample_result.to_dict()
    assert render(sample_result, "json") == _render_json(sample_result)


def test_text_report_shape(sample_result: ScanResult):
    out = render(sample_result, "text")
    assert out.startswith("security-preview report v0.1.0")
    assert out.endswith("\n")
    assert "CODE FINDINGS (6)" in out
    assert "PARTIAL" in out
    assert "VULNERABLE DEPENDENCIES (3)" in out


def test_markdown_report_shape(sample_result: ScanResult):
    out = render(sample_result, "markdown")
    assert out.startswith("# security-preview report\n")
    assert "## Summary" in out
    assert "## Code findings" in out
    assert "## Vulnerable dependencies" in out
    assert "## Skipped / errors" in out
    assert "\U0001f534 CRITICAL" in out
    assert "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)" in out
    assert "> [!WARNING]" in out
    assert "<style>" not in out and "<details>" not in out


def test_html_report_shape(sample_result: ScanResult):
    out = render(sample_result, "html")
    assert out.startswith("<!doctype html>")
    assert out.count("<h1") == 1
    assert "<script" not in out
    assert "@media print" in out
    assert "prefers-color-scheme" in out
    assert "https://fonts.googleapis.com" not in out
    assert 'href="http://' not in out  # no external non-https resources
    assert "<details class=\"finding" in out
    assert " open>" in out  # first finding expanded
    assert "cwe.mitre.org/data/definitions/89.html" in out


def test_sarif_structure(sample_result: ScanResult):
    doc = json.loads(render(sample_result, "sarif"))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "security-preview"
    assert driver["version"] == "0.1.0"
    assert len(driver["rules"]) >= 1
    results = run["results"]
    assert len(results) == 6 + 3  # findings + dependency findings
    for r in results:
        assert r["ruleId"]
        assert r["level"] in {"error", "warning", "note"}
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1
    # severity mapping sanity
    sqli = next(r for r in results if r["ruleId"] == "py.sqli")
    assert sqli["level"] == "error"


def test_empty_result_renders(make_scan_result):
    empty = make_scan_result(findings=[], dependency_findings=[])
    for fmt in FORMATS:
        out = render(empty, fmt)
        assert isinstance(out, str) and out
