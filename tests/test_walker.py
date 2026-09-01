"""Tests for ``security_preview.engine.walker.discover``."""
from __future__ import annotations

import os

import pytest

from security_preview.config import ScanConfig
from security_preview.engine.walker import discover
from security_preview.models import ErrorCollector


def _cfg(**over) -> ScanConfig:
    base = {"run_sca": False, "enrich_nvd": False}
    base.update(over)
    return ScanConfig(**base)


def test_discover_returns_absolute_sorted_paths(write_project):
    root = write_project(
        {
            "b/second.py": "x = 1\n",
            "a/first.py": "x = 1\n",
            "readme.txt": "not source\n",
        }
    )
    errors = ErrorCollector()
    found = discover(root, _cfg(), errors)

    assert found == sorted(found)
    assert all(os.path.isabs(p) for p in found)
    assert [os.path.basename(p) for p in found] == ["first.py", "second.py"]
    assert errors.to_list() == []


def test_discover_skips_known_dirs(write_project):
    root = write_project(
        {
            "app.py": "x = 1\n",
            "node_modules/pkg/index.js": "y = 2\n",
            ".git/hooks/pre-commit.sh": "echo hi\n",
            "__pycache__/app.cpython-311.pyc": "junk\n",
        }
    )
    found = discover(root, _cfg(), ErrorCollector())
    assert [os.path.basename(p) for p in found] == ["app.py"]


def test_discover_ignores_unknown_extensions(write_project):
    root = write_project({"keep.py": "1\n", "skip.md": "# doc\n", "data.csv": "a,b\n"})
    found = discover(root, _cfg(), ErrorCollector())
    assert [os.path.basename(p) for p in found] == ["keep.py"]


def test_discover_size_cap_records_error(write_project):
    root = write_project(
        {
            "small.py": "x = 1\n",
            "huge.py": "# " + "A" * 5000 + "\n",
        }
    )
    errors = ErrorCollector()
    found = discover(root, _cfg(max_file_bytes=1000), errors)

    assert [os.path.basename(p) for p in found] == ["small.py"]
    recorded = errors.to_list()
    assert len(recorded) == 1
    assert recorded[0].stage == "walk"
    assert recorded[0].target.endswith("huge.py")
    assert "oversized" in recorded[0].message
    assert errors.partial is True


def test_discover_count_cap_records_error(write_project):
    root = write_project({f"m{i}.py": "x = 1\n" for i in range(6)})
    errors = ErrorCollector()
    found = discover(root, _cfg(max_files=3), errors)

    assert len(found) == 3
    recorded = errors.to_list()
    assert any(e.stage == "walk" and "cap" in e.message for e in recorded)


def test_discover_not_a_directory_records_error(tmp_path):
    missing = str(tmp_path / "nope")
    errors = ErrorCollector()
    assert discover(missing, _cfg(), errors) == []
    assert errors.to_list()[0].message == "not a directory"


def test_discover_deterministic(write_project):
    files = {f"pkg/mod{i}.py": "x = 1\n" for i in range(20)}
    root = write_project(files)
    a = discover(root, _cfg(), ErrorCollector())
    b = discover(root, _cfg(), ErrorCollector())
    assert a == b


def test_discover_skips_symlinks_by_default(write_project, tmp_path):
    root = write_project({"real.py": "x = 1\n"})
    link = os.path.join(root, "link.py")
    try:
        os.symlink(os.path.join(root, "real.py"), link)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks not supported in this environment")

    errors = ErrorCollector()
    found = discover(root, _cfg(follow_symlinks=False), errors)
    assert [os.path.basename(p) for p in found] == ["real.py"]
    assert any("symlink" in e.message for e in errors.to_list())
