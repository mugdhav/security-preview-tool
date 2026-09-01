# security-preview — Parallel Foundation Build Plan

Date: 2026-09-01
Reads with: `security-preview-plan.md` (what to build), `security-preview-design-brief.md` (UI/report).

## How this works

1. **Phase 0** lands a shared scaffold on `main` — the data model, config, contracts,
   test fixtures, and a tiny **stub** for every module. Nothing in Phase 0 changes
   after it merges.
2. **Phase 1** — you open one Claude Code session per work unit below, each on its
   own `foundation/<area>` branch cut from `main`. Each session **only edits the
   files it owns** and codes against the frozen contracts. Because every non-owned
   file stays byte-identical to `main`, the branches do not conflict.
3. **Phase 2** — I fetch every branch, test each in isolation, merge them in
   dependency order, wire the orchestrator to the real modules, and run the full
   foundation check.

### Why there is no friction

| Collision risk | Why it can't happen |
|---|---|
| Two branches edit the same file | Ownership is disjoint (table below). A session touching a non-owned file is a plan violation, caught at review. |
| `models.py` / `config.py` / `contracts.py` drift | Frozen in Phase 0. Sessions import them, never edit them. A missing field → raise it in `progress/<area>.md`, I add it at merge. |
| `pyproject.toml` dependency edits | Phase 0 pre-declares every dependency all seven units need. Frozen. Need an unlisted dep → note it in `progress/<area>.md`. |
| `src/security_preview/__init__.py` exports | Frozen (version only). Expose your API from *your own* subpackage `__init__.py`. I assemble the top-level API at merge. |
| `tests/conftest.py` | Frozen; provides shared fixtures. Add your own `tests/test_<area>.py`. |
| Stub vs real implementation of a non-owned module | The stub sits on `main`. Only the owning branch replaces it. Every other branch keeps the merge-base version → `git merge` takes the real one with no conflict. |
| Git status / progress notes | Each session writes only `progress/<its-own-area>.md`. |

---

## Phase 0 — shared scaffold (must be on `main` before any session starts)

Additive only. One commit. After this, `main` HEAD is the branch point for all seven sessions.

### File tree created

```
pyproject.toml                              FROZEN
README.md                                   FROZEN
.gitattributes                              FROZEN  (* text=auto eol=lf)
src/security_preview/__init__.py            FROZEN  (__version__ only)
src/security_preview/models.py              FROZEN  (the data contract)
src/security_preview/config.py              FROZEN  (ScanConfig)
src/security_preview/contracts.py           FROZEN  (Protocols + call notes)
src/security_preview/scan.py                stub → foundation/orchestrator-cli
src/security_preview/cli.py                 stub → foundation/orchestrator-cli
src/security_preview/engine/__init__.py     stub → foundation/sast-engine
src/security_preview/engine/sast.py         stub → foundation/sast-engine
src/security_preview/engine/walker.py       stub → foundation/sast-engine
src/security_preview/engine/rules/__init__.py  stub → foundation/sast-engine
src/security_preview/sca/__init__.py        stub → foundation/sca
src/security_preview/sca/parsers.py         stub → foundation/sca
src/security_preview/sca/osv_client.py      stub → foundation/sca
src/security_preview/enrich/__init__.py     stub → foundation/enrichment
src/security_preview/enrich/nvd_client.py   stub → foundation/enrichment
src/security_preview/enrich/cache.py        stub → foundation/enrichment
src/security_preview/report/__init__.py     stub → foundation/report-renderers
src/security_preview/report/renderers.py    stub → foundation/report-renderers
src/security_preview/server/__init__.py     stub → foundation/browser-app
src/security_preview/server/app.py          stub → foundation/browser-app
tests/__init__.py                           FROZEN
tests/conftest.py                           FROZEN  (shared fixtures)
tests/test_scaffold.py                      FROZEN  (contract sanity checks)
tests/fixtures/.gitkeep
progress/.gitkeep
```

### `pyproject.toml`

```toml
[project]
name = "security-preview"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
  "jinja2>=3.1",
  "httpx>=0.27",
  "fastapi>=0.110",
  "uvicorn[standard]>=0.29",
  "pydantic>=2.6",
]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio>=0.23", "ruff>=0.4", "mypy>=1.9"]

[project.scripts]
security-preview = "security_preview.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/security_preview"]

[tool.pytest.ini_options]
pythonpath = ["src"]
asyncio_mode = "auto"

[tool.ruff]
line-length = 100
```

### `src/security_preview/__init__.py`

```python
__version__ = "0.1.0"
```

### `src/security_preview/models.py` (the data contract — do not edit on any branch)

```python
"""Shared data model. FROZEN in Phase 0. Every module imports from here."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum

TOOL_VERSION = "0.1.0"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[self.value]

    def meets(self, minimum: "Confidence") -> bool:
        return self.rank <= minimum.rank


@dataclass(frozen=True)
class Component:
    ecosystem: str          # "PyPI" | "npm" | "Go" | "Maven" | "RubyGems"
    name: str
    version: str
    source_manifest: str    # path relative to scan root, posix separators


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: RiskLevel
    confidence: Confidence
    category: str            # "Injection" | "Crypto" | "Secrets" | "Config" | ...
    cwe_id: str | None
    file_path: str           # relative to scan root, posix separators
    line: int
    code_snippet: str        # secrets already masked by the producer
    description: str
    remediation_vulnerable: str
    remediation_secure: str
    cve_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d["severity"] = RiskLevel(d["severity"])
        d["confidence"] = Confidence(d["confidence"])
        return cls(**d)


@dataclass
class DependencyFinding:
    ecosystem: str
    package: str
    version: str
    advisory_ids: list[str]      # OSV / GHSA / CVE ids
    severity: RiskLevel
    fixed_version: str | None
    source_manifest: str
    summary: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DependencyFinding":
        d = dict(d)
        d["severity"] = RiskLevel(d["severity"])
        return cls(**d)


@dataclass
class ScanError:
    stage: str              # "walk" | "sast" | "sca" | "enrich"
    target: str
    message: str


class ErrorCollector:
    """Mutable; passed into every stage. Replaces bare `except: pass`."""

    def __init__(self) -> None:
        self._errors: list[ScanError] = []

    def add(self, stage: str, target: str, message: str) -> None:
        self._errors.append(ScanError(stage=stage, target=target, message=str(message)))

    def to_list(self) -> list[ScanError]:
        return list(self._errors)

    @property
    def partial(self) -> bool:
        return bool(self._errors)


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    finished_at: datetime | None
    findings: list[Finding]
    dependency_findings: list[DependencyFinding]
    files_scanned: int
    dependencies_scanned: int
    errors: list[ScanError]
    partial: bool
    tool_version: str = TOOL_VERSION

    def summary(self) -> dict:
        by_sev = {lvl.value: 0 for lvl in RiskLevel}
        for f in self.findings:
            by_sev[f.severity.value] += 1
        dur = None
        if self.finished_at:
            dur = (self.finished_at - self.started_at).total_seconds()
        return {
            "target": self.target,
            "by_severity": by_sev,
            "total_findings": len(self.findings),
            "vulnerable_dependencies": len(self.dependency_findings),
            "files_scanned": self.files_scanned,
            "dependencies_scanned": self.dependencies_scanned,
            "duration_seconds": dur,
            "partial": self.partial,
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict:
        return {
            "tool_version": self.tool_version,
            "target": self.target,
            "started_at": self.started_at.astimezone(timezone.utc).isoformat(),
            "finished_at": self.finished_at.astimezone(timezone.utc).isoformat()
            if self.finished_at else None,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "dependency_findings": [d.to_dict() for d in self.dependency_findings],
            "errors": [asdict(e) for e in self.errors],
            "partial": self.partial,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        return cls(
            target=d["target"],
            started_at=datetime.fromisoformat(d["started_at"]),
            finished_at=datetime.fromisoformat(d["finished_at"]) if d["finished_at"] else None,
            findings=[Finding.from_dict(x) for x in d["findings"]],
            dependency_findings=[DependencyFinding.from_dict(x) for x in d["dependency_findings"]],
            files_scanned=d["summary"]["files_scanned"],
            dependencies_scanned=d["summary"]["dependencies_scanned"],
            errors=[ScanError(**e) for e in d["errors"]],
            partial=d["partial"],
            tool_version=d.get("tool_version", TOOL_VERSION),
        )
```

### `src/security_preview/config.py` (FROZEN)

```python
from __future__ import annotations
from dataclasses import dataclass
from .models import Confidence


@dataclass(frozen=True)
class ScanConfig:
    offline: bool = False              # skip ALL network (NVD + OSV)
    run_sca: bool = True
    enrich_nvd: bool = True
    min_confidence: Confidence = Confidence.MEDIUM
    max_files: int = 20_000
    max_file_bytes: int = 2_000_000
    follow_symlinks: bool = False
    network_timeout: float = 8.0       # per request, seconds
    enrich_time_budget: float = 30.0   # whole NVD phase, seconds
    cache_ttl_hours: int = 24

    @classmethod
    def defaults(cls) -> "ScanConfig":
        return cls()
```

### `src/security_preview/contracts.py` (FROZEN — the seams the orchestrator depends on)

```python
"""Call contracts between foundation modules. Signatures are binding.

The orchestrator (scan.py) calls exactly these. Each owning branch must keep the
signature identical; behaviour is theirs.

    engine.walker.discover(root: str, cfg: ScanConfig, errors: ErrorCollector) -> list[str]
        Absolute file paths to scan. Applies skip-dirs, size/count caps, symlink
        policy. Records skips in `errors` (stage="walk").

    engine.sast.scan_paths(root: str, files: list[str], cfg: ScanConfig,
                           errors: ErrorCollector) -> list[Finding]
        file_path on each Finding is RELATIVE to `root`, posix. Secrets masked.
        No confidence filtering here — the orchestrator does that.

    sca.parsers.collect_components(root: str, errors: ErrorCollector) -> list[Component]
        Discovers & parses manifests/lockfiles. Parse failures -> errors (stage="sca").

    sca.osv_client.query_osv(components: list[Component], cfg: ScanConfig,
                             errors: ErrorCollector) -> list[DependencyFinding]
        [] when cfg.offline. Network failure -> errors, returns partial list.

    enrich.nvd_client.enrich_findings(findings: list[Finding], cfg: ScanConfig,
                                      errors: ErrorCollector) -> None
        Mutates findings[*].cve_ids in place. No-op when cfg.offline or
        not cfg.enrich_nvd. Failures -> errors (stage="enrich"), never raise.

    report.renderers.render(result: ScanResult, fmt: str) -> str
        fmt in {"text", "markdown", "json", "sarif", "html"}. Deterministic.

    scan.scan(path: str, cfg: ScanConfig) -> ScanResult

    cli.main(argv: list[str] | None = None) -> int

    server.app.create_app() -> fastapi.FastAPI
"""
```

### `tests/conftest.py` (FROZEN — shared fixtures)

```python
from __future__ import annotations
from datetime import datetime, timezone
import pytest
from security_preview.models import (
    Finding, DependencyFinding, ScanResult, RiskLevel, Confidence,
)


@pytest.fixture
def make_finding():
    def _make(**over) -> Finding:
        base = dict(
            rule_id="py.sqli", name="SQL Injection", severity=RiskLevel.CRITICAL,
            confidence=Confidence.HIGH, category="Injection", cwe_id="CWE-89",
            file_path="api/reports.py", line=142,
            code_snippet='cur.execute(f"... {owner}")',
            description="User input flows into a SQL string.",
            remediation_vulnerable='cur.execute(f"... {owner}")',
            remediation_secure='cur.execute("... %s", (owner,))', cve_ids=[],
        )
        base.update(over)
        return Finding(**base)
    return _make


@pytest.fixture
def make_dependency_finding():
    def _make(**over) -> DependencyFinding:
        base = dict(
            ecosystem="PyPI", package="pyyaml", version="5.1",
            advisory_ids=["CVE-2020-1747"], severity=RiskLevel.CRITICAL,
            fixed_version="5.3.1", source_manifest="requirements.txt",
            summary="Arbitrary code execution via full_load.",
        )
        base.update(over)
        return DependencyFinding(**base)
    return _make


@pytest.fixture
def make_scan_result(make_finding, make_dependency_finding):
    def _make(**over) -> ScanResult:
        base = dict(
            target="/tmp/proj",
            started_at=datetime(2026, 9, 1, 14, 22, tzinfo=timezone.utc),
            finished_at=datetime(2026, 9, 1, 14, 22, 3, tzinfo=timezone.utc),
            findings=[make_finding()],
            dependency_findings=[make_dependency_finding()],
            files_scanned=342, dependencies_scanned=47,
            errors=[], partial=False,
        )
        base.update(over)
        return ScanResult(**base)
    return _make


@pytest.fixture
def write_project(tmp_path):
    def _write(files: dict[str, str]) -> str:
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return str(tmp_path)
    return _write
```

### Stub template

Every stub file is the smallest thing that imports cleanly and returns an empty
result, so every branch can run end-to-end in isolation. Example
`src/security_preview/engine/sast.py`:

```python
"""STUB. Owned by branch `foundation/sast-engine`. Do NOT edit on other branches."""
from __future__ import annotations
from ..config import ScanConfig
from ..models import ErrorCollector, Finding


def scan_paths(root: str, files: list[str], cfg: ScanConfig,
               errors: ErrorCollector) -> list[Finding]:
    return []
```

Analogous one-function stubs: `walker.discover -> []`, `parsers.collect_components -> []`,
`osv_client.query_osv -> []`, `nvd_client.enrich_findings -> None`, `cache` (empty class),
`renderers.render -> ""`, `scan.scan` (returns a minimal valid `ScanResult`),
`cli.main -> 0`, `server.app.create_app` (bare `FastAPI()`).

---

## Phase 1 — parallel work units

Cut each branch from `main` **after Phase 0 is merged**:
`git switch main && git pull && git switch -c foundation/<area>`.

| # | Branch | Owns (only these paths) | Contracts to honor | Depends on |
|---|--------|-------------------------|--------------------|-----------|
| 1 | `foundation/sast-engine` | `src/security_preview/engine/**`, `tests/test_sast.py`, `tests/test_walker.py`, `tests/fixtures/vulnerable/**`, `tests/fixtures/safe/**` | `discover`, `scan_paths` | models, config |
| 2 | `foundation/sca` | `src/security_preview/sca/**`, `tests/test_sca.py`, `tests/fixtures/manifests/**` | `collect_components`, `query_osv` | models, config |
| 3 | `foundation/enrichment` | `src/security_preview/enrich/**`, `tests/test_enrich.py`, `tests/test_cache.py` | `enrich_findings`, cache | models, config |
| 4 | `foundation/report-renderers` | `src/security_preview/report/**`, `tests/test_report.py`, `tests/fixtures/golden/**`, `tests/fixtures/sample_scan_result.json` | `render` | models |
| 5 | `foundation/orchestrator-cli` | `src/security_preview/scan.py`, `src/security_preview/cli.py`, `tests/test_scan.py`, `tests/test_cli.py` | `scan`, `cli.main` (calls all seams) | all contracts (via stubs) |
| 6 | `foundation/browser-app` | `src/security_preview/server/**`, `tests/test_server.py` | `create_app`, `POST /api/scan` | `scan` contract (via stub) |
| 7 | `foundation/skill-packaging` | `SKILL.md`, `scripts/bootstrap.py`, `docs/USAGE.md`, `docs/CURSOR.md`, `.claude/hooks-example.json` | `security-preview` CLI surface | cli contract (docs only) |

### Definition of Done — every unit

- Public functions match `contracts.py` **exactly** (names, params, return types).
- `pytest tests/test_<area>*.py` green from a clean `pip install -e ".[dev]"`.
- No import of another foundation module's *implementation* — only `models`,
  `config`, `contracts`, and your own package.
- `ruff check src/security_preview/<area> tests/test_<area>*.py` clean.
- Output deterministic (no wall-clock / RNG in results except `ScanResult`
  timestamps).
- `progress/<area>.md` written: what's done, contract questions, any dependency
  you needed that isn't in `pyproject.toml`.
- Branch pushed: `git push -u origin foundation/<area>`.

### Per-unit specifics

**1 · sast-engine** — Port `SASTEngine` + 28 rules from
`../security_auditor/security_checker.py`. `walker.discover` applies `skip_dirs`,
`max_files`, `max_file_bytes` (record oversized files via `errors.add("walk", …)`),
symlink policy. `scan_paths` runs rules with a multi-line match window for
SQLi/command-injection/deserialization; mask secret values in `code_snippet`;
set `confidence` per rule. `tests/fixtures/vulnerable/` = must-detect samples,
`tests/fixtures/safe/` = must-**not**-detect (framework idioms). Assert both.

**2 · sca** — `collect_components` parses `requirements.txt`, `poetry.lock`,
`Pipfile.lock`, `package-lock.json`, `yarn.lock`, `go.mod`, `Gemfile.lock`,
`pom.xml`. `query_osv` → `POST https://api.osv.dev/v1/querybatch`, batched, honors
`cfg.network_timeout` and `cfg.offline` (return `[]`), maps OSV severity →
`RiskLevel`, picks the lowest fixed version. Network failures → `errors`, return
what you have. Tests: parser fixtures + one `query_osv` test with the HTTP layer
monkeypatched (no live call in CI).

**3 · enrichment** — `enrich_findings` groups by `cwe_id`, fetches example CVEs
from NVD, writes top 3 into `finding.cve_ids`. On-disk TTL cache in
`enrich/cache.py` at `~/.security-preview/cache/` keyed by `cwe_id` /
`pkg@version`; honor `cfg.cache_ttl_hours`. Respect `cfg.enrich_time_budget`,
`cfg.offline`, `cfg.enrich_nvd`. Never raise — all failures to `errors`.
Tests monkeypatch HTTP; include a cache hit/expiry test and an "all requests
fail → findings unchanged, errors populated" test.

**4 · report-renderers** — `render(result, fmt)` for `text|markdown|json|sarif|html`.
`json` = `result.to_dict()`. `html` from a Jinja template matching the
**ReportScreen** artboard + embedded `@media print` matching **ReportPrint**
(inline `<style>`, **no `<script>`**, no web fonts, deterministic).
`markdown` per design-brief §5.2; ship `tests/fixtures/sample-report.md` golden.
`sarif` = SARIF 2.1.0. Build `tests/fixtures/sample_scan_result.json` from
`make_scan_result().to_dict()` and snapshot every format under
`tests/fixtures/golden/`.

**5 · orchestrator-cli** — `scan.scan()` sequences: `discover` → `scan_paths` →
filter by `cfg.min_confidence` → (`collect_components` → `query_osv` if
`run_sca`) → (`enrich_findings` if `enrich_nvd and not offline`) → assemble
`ScanResult` with `partial = errors.partial`. `cli.main` = argparse:
`scan <path> [--format] [--offline] [--no-sca] [--min-confidence] [--out]`,
`serve [--port]` (imports `server.app` lazily), `selftest`. Works today against
the stubs (empty results); tests assert wiring, flag threading, exit codes, and
that `--offline` prevents any network seam being configured to call out.

**6 · browser-app** — `create_app()` → FastAPI bound to `127.0.0.1`.
`POST /api/scan` with Pydantic request/response models (validate both sides);
call `scan.scan()`. Path confined to the given root (no `..`, no symlink escape,
count/size caps, wall-clock timeout). `GET /` serves `server/static/index.html`
built to the **Empty / Scanning / Main / Detail / EdgeStates** artboards
(desktop-only, single window, vanilla JS, no external resources). Tests use
`fastapi.testclient` with `scan` monkeypatched.

**7 · skill-packaging** — `SKILL.md` (trigger + body per `security-preview-plan.md`
§11), `scripts/bootstrap.py` (create isolated venv, `pip install -e .`, prefer
`uv`), `docs/USAGE.md`, `docs/CURSOR.md`, `.claude/hooks-example.json`
(pre-session / pre-commit scan failing on new CRITICAL). No `src/` changes;
documents the CLI surface unit 5 owns.

### Kickoff prompt to paste into each session

> You are building ONE unit of the `security-preview` foundation, working in
> `C:\Users\lenovo\Codefiles\Python_files\security-preview-skill`.
> Read `security-preview-plan.md` and `security-preview-parallel-build-plan.md` first.
> Your branch: **`foundation/<area>`** (create it from an up-to-date `main`).
> You may edit **only** the paths your unit owns in the Phase 1 table — treat every
> other file as read-only. Import only `security_preview.models`,
> `security_preview.config`, `security_preview.contracts`, and your own package.
> Honor the contract signatures exactly. Meet every "Definition of Done" bullet.
> Write status to `progress/<area>.md`. Commit in small steps, then
> `git push -u origin foundation/<area>`. Do not merge or touch `main`.

---

## Phase 2 — merge & full foundation check (my job)

1. `git fetch origin`. For each `foundation/*`: review `git diff main...branch --stat`,
   confirm only owned paths changed, run that branch's tests in a clean venv.
2. Merge into `main` in this order (independent leaves first):
   `report-renderers` → `enrichment` → `sca` → `sast-engine` → `orchestrator-cli`
   → `browser-app` → `skill-packaging`. Run `pytest -q` after each.
3. Expected conflicts: essentially none (disjoint paths). If any:
   `pyproject.toml` (a session added a dep despite the rule) or a stub file left
   half-edited on the wrong branch → resolve by taking the owning branch's version.
4. Assemble `src/security_preview/__init__.py` public API from the subpackages.
5. Confirm `scan.py` now imports the **real** modules (the stubs are gone, replaced
   by unit 1–4's files) and delete any leftover stub.
6. **Full check:**
   - `pip install -e ".[dev]"` clean; `pytest -q` all green; `ruff check .`;
     `mypy src` (advisory).
   - `security-preview selftest` — scans `tests/fixtures/vulnerable/`, asserts the
     known findings and JSON schema.
   - `security-preview scan ../security_auditor --format json|md|sarif|html` —
     eyeball each; HTML diffed against the canvas (ReportScreen / ReportPrint).
   - `security-preview serve` — smoke the Empty → Scanning → Results → Detail flow.
   - `test_offline.py`: every HTTP call forced to fail → scan completes,
     `errors` populated, `partial=True`.
7. Tag `v0.1.0-foundation`, push `main`, delete merged `foundation/*` branches.

## Progress tracking

`progress/<area>.md` per branch — free-form, but include: **Status** (not started /
in progress / done), **Contract questions**, **Extra dependency needed**,
**Notes for the merger**.
