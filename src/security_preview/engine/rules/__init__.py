"""SAST rule definitions. Owned by branch ``foundation/sast-engine``."""
from __future__ import annotations

from .builtin_rules import MATCH_WINDOW, RULES, RULES_BY_EXT, Rule

__all__ = ["MATCH_WINDOW", "RULES", "RULES_BY_EXT", "Rule"]
