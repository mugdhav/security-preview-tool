# foundation/enrichment

## Status
Done.

## What's done
- `src/security_preview/enrich/cache.py` — `Cache` class: on-disk JSON TTL cache.
  - Default dir `~/.security-preview/cache/` (`DEFAULT_CACHE_DIR`); `path=` arg makes
    it configurable for tests; `clock=` arg makes TTL/expiry testable without sleeping.
  - One file per key: `sha256(key).json` holding `{"stored_at": <unix s>, "value": ...}`.
    Atomic write via `*.tmp` + `replace`.
  - `get(key)` returns `None` on miss / expired (`age > ttl_hours*3600`) / corrupt file /
    OSError. `set(key, value)` never raises on OSError.
  - Key space is opaque strings: enrichment uses `cwe:<CWE-ID>`; `pkg@version` keys are
    supported for a future SCA/OSV cache but not written by this unit.
- `src/security_preview/enrich/nvd_client.py` — `enrich_findings(findings, cfg, errors) -> None`.
  - Signature matches `contracts.py` exactly. No-op when `cfg.offline` or not `cfg.enrich_nvd`.
  - Groups findings by `cwe_id` (skips `cwe_id is None`), one NVD request per distinct CWE.
  - `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=<CWE-ID>&resultsPerPage=5`,
    per-request `timeout=cfg.network_timeout`; takes first 3 unique
    `vulnerabilities[*].cve.id` and assigns `finding.cve_ids = [...]` in place for every
    finding in the group.
  - Whole-phase budget: `time.monotonic()` deadline from `cfg.enrich_time_budget`; when
    exhausted, records one `errors.add("enrich", "nvd", "time budget ... exhausted; N CWE
    group(s) not enriched")` and stops.
  - Every failure (network, HTTP status, JSON) -> `errors.add("enrich", <cwe>, ...)`,
    `continue`; findings for that CWE keep their existing `cve_ids`. Never raises
    (blind `except Exception` is intentional, `# noqa: BLE001`).
  - Results cached via `Cache(path=_cache_dir(), ttl_hours=cfg.cache_ttl_hours)`.
    `_cache_dir()` is a tiny indirection so tests can redirect the cache; production
    returns `DEFAULT_CACHE_DIR`.
- `src/security_preview/enrich/__init__.py` exposes `Cache`, `DEFAULT_CACHE_DIR`,
  `enrich_findings`.
- Tests: `tests/test_cache.py` (7) + `tests/test_enrich.py` (8). Cover cache
  roundtrip/hit/persist-across-instances/expiry/corrupt/format, and enrich
  top-3+grouping, cache reuse (no 2nd HTTP call), expired-cache refetch,
  all-requests-fail (findings unchanged + errors populated), offline no-op,
  `enrich_nvd=False` no-op, no-CWE skip, time-budget exhaustion. HTTP always
  monkeypatched — no live NVD calls.

## Determinism
No wall-clock in outputs. `time.time()` used only for cache `stored_at` / TTL
comparison; `time.monotonic()` only for the phase budget. CVE order is the order
NVD returns them (stable given identical responses).

## Contract questions
- None blocking. `enrich_findings` honors the frozen signature and semantics exactly.
- Minor: contract cache text mentions keying by `pkg@version` too. `Cache` accepts any
  string key, but this unit only writes `cwe:*` entries. Whoever wires the OSV cache can
  reuse `Cache` directly.

## Extra dependency needed
None. Uses `httpx` (already in `pyproject.toml`) and stdlib.

## Notes for the merger
- Only owned paths touched: `src/security_preview/enrich/**`, `tests/test_enrich.py`,
  `tests/test_cache.py`, `progress/enrichment.md`.
- `_cache_dir()` in `nvd_client.py` is the seam tests patch (`monkeypatch.setattr(
  nvd_client, "_cache_dir", ...)`). If you prefer the cache dir come from `ScanConfig`,
  add a field there and swap `_cache_dir()` for it — no other change needed.
- `enrich_findings` assigns `finding.cve_ids = list(cve_ids)` (rebinds the list attr on
  the mutable `Finding` dataclass). If a caller holds a reference to the old list, switch
  to slice assignment `finding.cve_ids[:] = ...` — say the word.
- Full suite `python -m pytest -q` green (21 passed); `ruff check` clean on owned paths.
