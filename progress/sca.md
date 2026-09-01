# progress: sca

## Status
Done.

## What's done
- `src/security_preview/sca/parsers.py` — `collect_components(root, errors)`:
  - Walks the tree from `root`, pruning noisy dirs (`node_modules`, `.git`, venvs,
    build dirs, `site-packages`, ...). Directory and file iteration is sorted for
    deterministic results.
  - Parsers for all 8 manifest types, with correct `ecosystem`:
    - `requirements.txt` (and `requirements*.txt`) -> PyPI. Only `==` pins are
      taken; markers/hashes/`-r` includes/extras are stripped or ignored.
    - `poetry.lock` -> PyPI (stdlib `tomllib`).
    - `Pipfile.lock` -> PyPI (JSON; `default` + `develop`; `"=="` versions only).
    - `package-lock.json` -> npm (v2/v3 `packages` map incl. nested
      `node_modules/...`; falls back to v1 `dependencies` recursion).
    - `yarn.lock` -> npm (classic `version "x"` and berry `version: x`; scoped
      names handled).
    - `go.mod` -> Go (single + block `require`; strips `// indirect` and
      `+incompatible`; version keeps the leading `v`).
    - `Gemfile.lock` -> RubyGems (`specs:` sections; 4-space entries only, so
      transitive sub-deps are excluded).
    - `pom.xml` -> Maven (`ElementTree`, namespace-stripped; `name` is
      `groupId:artifactId`; unresolved `${...}` versions skipped).
  - Parse failures -> `errors.add("sca", <rel-manifest-path>, "<ExcType>: <msg>")`,
    never raised. Other manifests still parse.
  - `Component.source_manifest` is relative to `root`, posix separators.
  - Result is de-duplicated (frozen `Component` as dict key) and sorted by
    `(source_manifest, ecosystem, name, version)`.
- `src/security_preview/sca/osv_client.py` — `query_osv(components, cfg, errors)`:
  - `cfg.offline` or empty input -> `[]` (no HTTP).
  - De-dupes components, batches to `MAX_BATCH = 1000`, `POST` to
    `https://api.osv.dev/v1/querybatch` with `timeout=cfg.network_timeout`.
  - querybatch only returns ids, so each unique vuln id is resolved once via
    `GET /v1/vulns/{id}` (cached per call).
  - Severity mapping: GHSA-style `database_specific.severity`
    (`CRITICAL/HIGH/MODERATE/LOW/...`) first; otherwise CVSS — numeric score or a
    `CVSS:3.x/...` vector run through a self-contained CVSS 3.1 base-score
    calculator, then bucketed (>=9 CRIT, >=7 HIGH, >=4 MED, >=0.1 LOW, else INFO).
    Multiple advisories on one component -> highest severity wins. Unknown -> MEDIUM.
  - Fixed version: collects every `ranges[].events[].fixed` across matching
    `affected` entries and picks the **lowest** (loose numeric/alpha version key).
  - `advisory_ids` = vuln id + `aliases`, de-duped and sorted.
  - HTTP seam is two module functions `_query_batch` / `_fetch_vuln`
    (monkeypatched in tests). Batch failure -> `errors.add("sca", <url>, ...)`,
    skip batch. Detail failure -> `errors.add("sca", <vuln-id>, ...)` and still
    emit a partial `DependencyFinding` (ids only, severity MEDIUM, no fix).
  - Returned list sorted by
    `(severity.rank, ecosystem, package, version, source_manifest)`.
- `src/security_preview/sca/__init__.py` exposes `collect_components`, `query_osv`.
- Tests: `tests/test_sca.py` (17 tests) + one fixture per manifest type under
  `tests/fixtures/manifests/<pip|poetry|pipenv|npm|yarn|go|ruby|maven>/`.
  Covers each parser, whole-tree walk + determinism, parse-failure recording,
  and OSV: offline short-circuit, empty input, GHSA + CVSS severity mapping,
  lowest-fixed-version, advisory-id dedupe, querybatch network failure ->
  partial + errors, vuln-detail failure -> partial finding, deterministic order.

## Verification
- `python -m pytest tests/test_sca.py -q` -> 17 passed.
- `python -m pytest -q` (whole repo) -> 23 passed.
- `python -m ruff check src/security_preview/sca tests/test_sca.py` -> clean.

## Contract questions
- None blocking. Signatures match `contracts.py` exactly.
- Minor semantic choices the merger may want to confirm:
  - Unpinned deps (`Django>=3.2`, bare `uvicorn`, Pipfile `"*"`) are dropped
    because OSV needs a concrete version. If range-based querying is wanted later
    it would need an OSV `query` (not `querybatch`) path.
  - Go versions keep the leading `v` (as written in `go.mod`). If OSV's Go
    ecosystem expects bare semver, normalise in `_build_finding`/payload.
  - Unknown OSV severity defaults to `RiskLevel.MEDIUM` (a known vuln with no
    severity data). Change here if INFO is preferred.
  - `query_osv` makes N+1 style calls (1 querybatch + 1 GET per unique vuln).
    Acceptable for typical projects; add concurrency/caching at the enrichment
    layer if it becomes a bottleneck.

## Extra dependency needed
- None. Uses only `httpx` (already in `pyproject.toml`) and stdlib
  (`tomllib`, `json`, `xml.etree.ElementTree`, `re`, `os`, `math`).

## Notes for the merger
- Only owned paths touched: `src/security_preview/sca/**`, `tests/test_sca.py`,
  `tests/fixtures/manifests/**`, `progress/sca.md`.
- No imports from other foundation implementation modules.
- `query_osv` never opens a real socket in tests — it goes through
  `osv_client._query_batch` / `osv_client._fetch_vuln`, both monkeypatched.
- `httpx.post` / `httpx.get` are called at module level (not a shared client) so
  the seam stays trivial to patch; swap to a pooled `httpx.Client` at merge if
  desired without changing the contract.
