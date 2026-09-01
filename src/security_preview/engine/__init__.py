"""SAST engine: filesystem discovery + regex rule scanning.

Public API (owned by branch ``foundation/sast-engine``):

* :func:`discover` -- walk a project root into a list of scannable file paths.
* :func:`scan_paths` -- run the built-in rules over those files -> ``list[Finding]``.
* :data:`RULES` -- the built-in rule set.
"""
from __future__ import annotations

from .rules import RULES, Rule
from .sast import scan_paths
from .walker import KNOWN_EXTENSIONS, SKIP_DIRS, discover

__all__ = [
    "KNOWN_EXTENSIONS",
    "RULES",
    "SKIP_DIRS",
    "Rule",
    "discover",
    "scan_paths",
]
