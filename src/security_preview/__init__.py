"""security-preview: deterministic, non-LLM static security scanner.

Top-level public API, assembled from the foundation subpackages.

The orchestrator entry point stays reachable at its frozen contract path,
``security_preview.scan.scan``; import it with ``from security_preview.scan
import scan`` (re-exporting the callable here would shadow the submodule).
"""
from __future__ import annotations

__version__ = "0.1.0"

from .config import ScanConfig
from .models import (
    Component,
    Confidence,
    DependencyFinding,
    ErrorCollector,
    Finding,
    RiskLevel,
    ScanError,
    ScanResult,
)
from .report import FORMATS, render

__all__ = [
    "FORMATS",
    "Component",
    "Confidence",
    "DependencyFinding",
    "ErrorCollector",
    "Finding",
    "RiskLevel",
    "ScanConfig",
    "ScanError",
    "ScanResult",
    "__version__",
    "render",
]
