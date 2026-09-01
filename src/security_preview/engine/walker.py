"""Filesystem discovery for the SAST engine.

``discover`` walks a project root and returns the absolute paths of source files
worth scanning, applying the skip-dir list, the per-file size cap, the overall
file-count cap and the symlink policy from :class:`ScanConfig`. Skips are never
silent -- each one is recorded on the shared :class:`ErrorCollector` with
``stage="walk"``.
"""
from __future__ import annotations

import os

from ..config import ScanConfig
from ..models import ErrorCollector

# Extensions the rule set knows how to reason about (ported from the auditor's
# ``file_extensions`` map).
KNOWN_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go",
        ".cs", ".c", ".cpp", ".h", ".hpp", ".sql", ".html", ".htm", ".xml",
        ".yml", ".yaml", ".json", ".sh", ".bash",
    }
)

# Directories never worth scanning (dependencies, VCS metadata, build output).
SKIP_DIRS: frozenset[str] = frozenset(
    {
        "node_modules", "venv", ".venv", "env", ".env",
        "__pycache__", ".git", ".svn", ".hg",
        "dist", "build", "target", "vendor",
        ".idea", ".vscode", "coverage", ".tox", ".mypy_cache", ".pytest_cache",
    }
)


def discover(root: str, cfg: ScanConfig, errors: ErrorCollector) -> list[str]:
    """Return absolute paths of scannable files under ``root`` (sorted, stable)."""
    if not os.path.isdir(root):
        errors.add("walk", root, "not a directory")
        return []

    found: list[str] = []
    count_cap_hit = False

    for dirpath, dirnames, filenames in os.walk(root, followlinks=cfg.follow_symlinks):
        kept_dirs = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS:
                continue
            if not cfg.follow_symlinks and os.path.islink(os.path.join(dirpath, d)):
                errors.add("walk", os.path.join(dirpath, d), "skipped symlinked directory")
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in KNOWN_EXTENSIONS:
                continue
            if not cfg.follow_symlinks and os.path.islink(full):
                errors.add("walk", full, "skipped symlinked file")
                continue
            try:
                size = os.path.getsize(full)
            except OSError as exc:
                errors.add("walk", full, f"could not stat file: {exc}")
                continue
            if size > cfg.max_file_bytes:
                errors.add(
                    "walk",
                    full,
                    f"skipped oversized file: {size} bytes > max_file_bytes "
                    f"({cfg.max_file_bytes})",
                )
                continue
            if len(found) >= cfg.max_files:
                count_cap_hit = True
                break
            found.append(os.path.abspath(full))

        if count_cap_hit:
            break

    if count_cap_hit:
        errors.add(
            "walk",
            root,
            f"file-count cap reached: stopped after max_files ({cfg.max_files})",
        )

    found.sort()
    return found


__all__ = ["KNOWN_EXTENSIONS", "SKIP_DIRS", "discover"]
