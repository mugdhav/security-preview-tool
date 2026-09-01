"""Tests for ``security_preview.engine.sast.scan_paths`` and the rule set."""
from __future__ import annotations

from pathlib import Path

import pytest

from security_preview.config import ScanConfig
from security_preview.engine import RULES, discover, scan_paths
from security_preview.models import Confidence, ErrorCollector, RiskLevel

FIXTURES = Path(__file__).parent / "fixtures"
VULN_DIR = FIXTURES / "vulnerable"
SAFE_DIR = FIXTURES / "safe"

CFG = ScanConfig(run_sca=False, enrich_nvd=False)

# fixture filename -> rule_id that MUST fire for it
EXPECTED: dict[str, str] = {
    "sql_injection.py": "sast.sql-injection",
    "command_injection.py": "sast.command-injection",
    "xss.js": "sast.xss",
    "path_traversal.py": "sast.path-traversal",
    "hardcoded_credentials.py": "sast.hardcoded-credentials",
    "weak_hashing.py": "sast.weak-password-hashing",
    "weak_crypto.py": "sast.weak-crypto-algorithm",
    "insecure_deserialization.py": "sast.insecure-deserialization-python",
    "ssrf.py": "sast.ssrf",
    "tls_verification.py": "sast.tls-verification-disabled",
    "debug_mode.py": "sast.debug-mode",
    "cors_wildcard.js": "sast.cors-wildcard",
    "xxe.py": "sast.xxe",
}


def _scan(paths: list[Path]) -> list:
    return scan_paths(str(FIXTURES), [str(p) for p in paths], CFG, ErrorCollector())


def test_rule_set_is_complete_and_well_formed():
    assert len(RULES) == 28
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids)), "duplicate rule_id"
    for r in RULES:
        assert r.rule_id.startswith("sast.")
        assert isinstance(r.severity, RiskLevel)
        assert isinstance(r.confidence, Confidence)
        assert r.cwe_id.startswith("CWE-")
        assert r.category
        assert r.remediation_secure


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_vulnerable_fixture_is_detected(name):
    findings = _scan([VULN_DIR / name])
    assert findings, f"no findings for {name}"
    fired = {f.rule_id for f in findings}
    assert EXPECTED[name] in fired, f"{name}: expected {EXPECTED[name]}, got {fired}"
    for f in findings:
        assert f.file_path == f"vulnerable/{name}"
        assert f.line >= 1


@pytest.mark.parametrize(
    "path", sorted(SAFE_DIR.iterdir()), ids=lambda p: p.name
)
def test_safe_fixture_has_no_findings(path):
    findings = _scan([path])
    assert findings == [], [(f.rule_id, f.line, f.code_snippet) for f in findings]


def test_full_vulnerable_dir_end_to_end():
    files = discover(str(VULN_DIR), CFG, ErrorCollector())
    findings = scan_paths(str(VULN_DIR), files, CFG, ErrorCollector())
    fired = {f.rule_id for f in findings}
    for expected in EXPECTED.values():
        assert expected in fired


def test_findings_sorted_by_path_line_rule():
    files = discover(str(VULN_DIR), CFG, ErrorCollector())
    findings = scan_paths(str(VULN_DIR), files, CFG, ErrorCollector())
    keys = [(f.file_path, f.line, f.rule_id) for f in findings]
    assert keys == sorted(keys)


def test_output_is_deterministic():
    files = discover(str(VULN_DIR), CFG, ErrorCollector())
    a = [f.to_dict() for f in scan_paths(str(VULN_DIR), files, CFG, ErrorCollector())]
    b = [f.to_dict() for f in scan_paths(str(VULN_DIR), files, CFG, ErrorCollector())]
    assert a == b


def test_file_path_is_relative_posix():
    findings = _scan([VULN_DIR / "sql_injection.py"])
    assert all(f.file_path == "vulnerable/sql_injection.py" for f in findings)
    assert all("\\" not in f.file_path for f in findings)


def test_secret_value_is_masked_in_snippet():
    findings = _scan([VULN_DIR / "hardcoded_credentials.py"])
    creds = [f for f in findings if f.rule_id == "sast.hardcoded-credentials"]
    assert creds
    joined = "\n".join(f.code_snippet for f in creds)
    assert "S3cr3tPassw0rd123" not in joined
    assert "sk_live_abcdef0123456789" not in joined
    assert "•" in joined  # bullet mask char


def test_multiline_window_catches_split_concatenation():
    findings = _scan([VULN_DIR / "sql_injection.py"])
    sqli = [f for f in findings if f.rule_id == "sast.sql-injection"]
    # one from the f-string (line 6), one from the multi-line concat (line 11)
    assert len(sqli) >= 2
    assert {f.line for f in sqli} >= {6}


def test_scan_paths_never_raises_on_bad_file(tmp_path):
    missing = tmp_path / "gone.py"
    errors = ErrorCollector()
    out = scan_paths(str(tmp_path), [str(missing)], CFG, errors)
    assert out == []
    assert errors.to_list()[0].stage == "sast"


def test_unknown_extension_is_skipped(tmp_path):
    doc = tmp_path / "notes.md"
    doc.write_text("password = \"MySecretPass123\"\n", encoding="utf-8")
    assert scan_paths(str(tmp_path), [str(doc)], CFG, ErrorCollector()) == []
