"""Manifest / lockfile discovery and parsing for the SCA stage.

Owned by branch ``foundation/sca``. Imports only from ``security_preview.models``,
``security_preview.config``, ``security_preview.contracts`` and this package.

Contract (``contracts.py``)::

    sca.parsers.collect_components(root: str, errors: ErrorCollector) -> list[Component]

Discovers and parses every supported manifest/lockfile under ``root``. Parse
failures are recorded via ``errors.add("sca", target, message)`` and never raised.
``Component.source_manifest`` is a path relative to ``root`` with posix separators.
The returned list is de-duplicated and deterministically ordered.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path

import tomllib

from ..models import Component, ErrorCollector

__all__ = ["collect_components"]

# Directories never worth walking into for manifests.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        "vendor",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".gradle",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "target",
        ".eggs",
        "site-packages",
    }
)

Pairs = list[tuple[str, str]]


# --------------------------------------------------------------------------- #
# Individual parsers.  Each takes the file text and returns (name, version)    #
# pairs.  Ecosystem is attached by ``collect_components``.                     #
# --------------------------------------------------------------------------- #

_REQ_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(?:\[[^\]]*\])?\s*"
    r"==\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._!+-]*)"
)


def _parse_requirements(text: str) -> Pairs:
    out: Pairs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # Drop inline comments and environment markers.
        line = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
        line = line.split(";", 1)[0].strip()
        if not line:
            continue
        m = _REQ_RE.match(line)
        if m:
            out.append((m.group("name"), m.group("version")))
    return out


def _parse_poetry_lock(text: str) -> Pairs:
    data = tomllib.loads(text)
    out: Pairs = []
    for pkg in data.get("package", []) or []:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if isinstance(name, str) and isinstance(version, str):
            out.append((name, version))
    return out


def _parse_pipfile_lock(text: str) -> Pairs:
    data = json.loads(text)
    out: Pairs = []
    for section in ("default", "develop"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str) and version.startswith("=="):
                out.append((name, version[2:].strip()))
    return out


def _parse_package_lock(text: str) -> Pairs:
    data = json.loads(text)
    out: Pairs = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        # npm lockfile v2 / v3
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict):
                continue
            if "node_modules/" not in key:
                continue
            name = key.split("node_modules/")[-1]
            version = meta.get("version")
            if name and isinstance(version, str):
                out.append((name, version))
        return out
    # npm lockfile v1
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        stack: list[dict] = [deps]
        while stack:
            current = stack.pop()
            for name, meta in current.items():
                if not isinstance(meta, dict):
                    continue
                version = meta.get("version")
                if isinstance(version, str):
                    out.append((name, version))
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    stack.append(nested)
    return out


_YARN_VERSION_RE = re.compile(r'version:?\s+"?(?P<version>[^"\s]+)"?')


def _yarn_name(spec: str) -> str:
    spec = spec.strip().strip('"').strip("'")
    if spec.startswith("@"):
        idx = spec.find("@", 1)
    else:
        idx = spec.find("@")
    return spec[:idx] if idx > 0 else spec


def _parse_yarn_lock(text: str) -> Pairs:
    out: Pairs = []
    current: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace() and raw.rstrip().endswith(":"):
            header = raw.rstrip()[:-1]
            first = header.split(",")[0]
            current = _yarn_name(first)
            continue
        if current is not None:
            m = _YARN_VERSION_RE.match(raw.strip())
            if m:
                out.append((current, m.group("version")))
                current = None
    return out


def _go_dep(fragment: str) -> tuple[str, str] | None:
    fragment = fragment.split("//", 1)[0].strip()
    fragment = fragment.strip("()").strip()
    parts = fragment.split()
    if len(parts) < 2:
        return None
    name, version = parts[0], parts[1]
    version = version.removesuffix("+incompatible")
    if not name or not version:
        return None
    return name, version


def _parse_go_mod(text: str) -> Pairs:
    out: Pairs = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if in_block:
            if line.startswith(")"):
                in_block = False
                continue
            dep = _go_dep(line)
            if dep:
                out.append(dep)
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if line.startswith("require "):
            dep = _go_dep(line[len("require ") :])
            if dep:
                out.append(dep)
    return out


_GEM_SPEC_RE = re.compile(r"^ {4}(?P<name>[A-Za-z0-9._-]+) \((?P<version>[^()]+)\)\s*$")


def _parse_gemfile_lock(text: str) -> Pairs:
    out: Pairs = []
    in_specs = False
    for raw in text.splitlines():
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if raw.strip() and not raw[0].isspace():
                in_specs = False
                continue
            m = _GEM_SPEC_RE.match(raw)
            if m:
                out.append((m.group("name"), m.group("version").strip()))
    return out


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_pom_xml(text: str) -> Pairs:
    root = ET.fromstring(text)
    out: Pairs = []
    for dep in root.iter():
        if _local_name(dep.tag) != "dependency":
            continue
        fields: dict[str, str] = {}
        for child in dep:
            fields[_local_name(child.tag)] = (child.text or "").strip()
        group_id = fields.get("groupId", "")
        artifact_id = fields.get("artifactId", "")
        version = fields.get("version", "")
        if not (group_id and artifact_id and version):
            continue
        if version.startswith("${"):
            continue
        out.append((f"{group_id}:{artifact_id}", version))
    return out


# --------------------------------------------------------------------------- #
# Discovery                                                                    #
# --------------------------------------------------------------------------- #

_EXACT: dict[str, tuple] = {
    "requirements.txt": (_parse_requirements, "PyPI"),
    "poetry.lock": (_parse_poetry_lock, "PyPI"),
    "Pipfile.lock": (_parse_pipfile_lock, "PyPI"),
    "package-lock.json": (_parse_package_lock, "npm"),
    "yarn.lock": (_parse_yarn_lock, "npm"),
    "go.mod": (_parse_go_mod, "Go"),
    "Gemfile.lock": (_parse_gemfile_lock, "RubyGems"),
    "pom.xml": (_parse_pom_xml, "Maven"),
}

_REQUIREMENTS_NAME_RE = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)


def _match_manifest(filename: str) -> tuple | None:
    if filename in _EXACT:
        return _EXACT[filename]
    if _REQUIREMENTS_NAME_RE.match(filename):
        return (_parse_requirements, "PyPI")
    return None


def _iter_manifest_files(root: Path) -> Iterable[tuple[Path, tuple]]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            spec = _match_manifest(filename)
            if spec is not None:
                yield Path(dirpath) / filename, spec


def collect_components(root: str, errors: ErrorCollector) -> list[Component]:
    """Discover and parse manifests under ``root``; never raises."""
    root_path = Path(root)
    seen: dict[Component, None] = {}
    for file_path, (parser, ecosystem) in _iter_manifest_files(root_path):
        try:
            rel = file_path.relative_to(root_path).as_posix()
        except ValueError:
            rel = file_path.as_posix()
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
            pairs = parser(text)
        except Exception as exc:  # noqa: BLE001 - contract: record, never raise
            errors.add("sca", rel, f"{type(exc).__name__}: {exc}")
            continue
        for name, version in pairs:
            name = (name or "").strip()
            version = (version or "").strip()
            if not name or not version:
                continue
            component = Component(
                ecosystem=ecosystem,
                name=name,
                version=version,
                source_manifest=rel,
            )
            seen.setdefault(component, None)
    return sorted(
        seen,
        key=lambda c: (c.source_manifest, c.ecosystem, c.name, c.version),
    )
