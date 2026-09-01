"""Local browser app for security-preview. Owned by branch ``foundation/browser-app``."""
from __future__ import annotations

from .app import ScanRequest, ScanResponse, create_app

__all__ = ["ScanRequest", "ScanResponse", "create_app"]
