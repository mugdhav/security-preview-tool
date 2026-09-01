"""Module entry point.

``python -m security_preview`` (and the Briefcase-packaged desktop bundle) open
the native desktop window. The CLI lives at ``python -m security_preview.cli`` /
the ``security-preview`` console script.
"""
from __future__ import annotations

import sys

from .desktop import main

if __name__ == "__main__":
    sys.exit(main())
