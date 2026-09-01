"""SCA (Software Composition Analysis) package.

Owned by branch ``foundation/sca``. Public surface:

* :func:`collect_components` - discover & parse manifests/lockfiles under a root.
* :func:`query_osv` - batch-query OSV.dev for known vulnerable dependencies.
"""
from __future__ import annotations

from .osv_client import query_osv
from .parsers import collect_components

__all__ = ["collect_components", "query_osv"]
