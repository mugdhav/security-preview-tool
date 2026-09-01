"""Sanity checks for the Phase 0 scaffold contracts."""

from security_preview import __version__
from security_preview import scan as scan_mod
from security_preview.config import ScanConfig
from security_preview.models import Confidence, RiskLevel, ScanResult


def test_version():
    assert __version__ == "0.1.0"


def test_confidence_ordering():
    assert Confidence.HIGH.meets(Confidence.MEDIUM)
    assert not Confidence.LOW.meets(Confidence.MEDIUM)


def test_risklevel_rank_sorts_critical_first():
    order = sorted(RiskLevel, key=lambda r: r.rank)
    assert order[0] is RiskLevel.CRITICAL and order[-1] is RiskLevel.INFO


def test_scanresult_roundtrips(make_scan_result):
    r = make_scan_result()
    assert ScanResult.from_dict(r.to_dict()).to_dict() == r.to_dict()


def test_scanconfig_defaults():
    c = ScanConfig.defaults()
    assert c.run_sca and c.enrich_nvd and not c.offline
    assert c.min_confidence is Confidence.MEDIUM


def test_scan_stub_returns_valid_result(make_scan_result):
    r = scan_mod.scan("/tmp/x", ScanConfig.defaults())
    assert isinstance(r, ScanResult)
    assert r.to_dict()["summary"]["files_scanned"] == 0
