# progress: sast-engine

## Status
Done.

## What's done
- `src/security_preview/engine/walker.py` — `discover(root, cfg, errors)`:
  - `os.walk` with `followlinks=cfg.follow_symlinks`; prunes `SKIP_DIRS`
    (node_modules, venv, .git, dist, build, caches, …).
  - Filters to `KNOWN_EXTENSIONS` (ported from the auditor's `file_extensions`).
  - `cfg.max_file_bytes` — oversized files skipped, `errors.add("walk", path,
    "skipped oversized file: …")`.
  - `cfg.max_files` — stops once the cap is reached, records a single
    `errors.add("walk", root, "file-count cap reached …")`.
  - Symlinked files/dirs skipped (and recorded) unless `cfg.follow_symlinks`.
  - Non-directory root → `errors.add("walk", root, "not a directory")`, returns `[]`.
  - Returns absolute paths, sorted → deterministic.
- `src/security_preview/engine/rules/builtin_rules.py` — 28 rules ported from
  `security_auditor/security_checker.py` `_load_rules()`, adapted to a frozen
  `Rule` dataclass carrying `severity` (RiskLevel), `confidence` (Confidence),
  `category`, `cwe_id`, split `remediation_vulnerable` / `remediation_secure`,
  `languages`, `windowed`, `false_positive_patterns`.
  - `windowed=True` for SQLi, command injection, and the 3 deserialization rules
    — matched against a 3-line sliding window compiled with `re.DOTALL` so
    cross-line string concatenation is caught. All other rules match line-by-line
    with `re.MULTILINE` (parity with the original engine).
  - Confidence assigned per rule (HIGH for SQLi/cmd-injection/py-deser/hardcoded
    key/weak-hash/TLS-off/debug; LOW for noisy heuristics like insecure-random,
    ReDoS, insecure-HTTP, missing-headers, stack-trace, sensitive-logs,
    session-fixation, mass-assignment; MEDIUM otherwise).
- `src/security_preview/engine/sast.py` — `scan_paths(root, files, cfg, errors)`:
  - `file_path` on each `Finding` is relative to `root`, posix separators.
  - Secret values masked in `code_snippet` for `category == "Secrets"`
    (`hardcoded-credentials`, `hardcoded-crypto-key`) → first 3 chars + `••••••••`.
  - Per-file read errors → `errors.add("sast", …)`, never raises.
  - Findings sorted by `(file_path, line, rule_id)` → deterministic; verified by
    a `to_dict()` round-trip equality test.
  - `cfg` accepted but unused — no confidence filtering here (orchestrator's job).
- `src/security_preview/engine/__init__.py` exposes `discover`, `scan_paths`,
  `RULES`, `Rule`, `KNOWN_EXTENSIONS`, `SKIP_DIRS`.
- Fixtures: `tests/fixtures/vulnerable/` (13 must-detect, one per major category)
  and `tests/fixtures/safe/` (11 must-NOT-detect: parameterised query, arg-vector
  subprocess, `textContent`/DOMPurify, env-var secrets, Fernet, bcrypt,
  `yaml.safe_load`/json, pinned https + `verify=True`, `DEBUG=False`, defusedxml).
- Tests: `tests/test_walker.py` (8) + `tests/test_sast.py` (32 incl. parametrised)
  — 40 tests. Full repo suite: 46 passed.

## Checks
- `python -m pytest tests/test_sast.py tests/test_walker.py -q` → 40 passed.
- `python -m pytest -q` → 46 passed.
- `python -m ruff check src/security_preview/engine tests/test_sast.py tests/test_walker.py` → clean.

## Contract questions
None. `discover` / `scan_paths` signatures match `contracts.py` exactly.

Minor note for the merger (not blocking): `scan_paths` takes `cfg` per the
contract but does not use it (min-confidence filtering is the orchestrator's
job, as the contract states). Left in for signature stability.

## Extra dependency needed
None — stdlib only (`os`, `re`, `pathlib`).

## Notes for the merger
- The ported regexes are the auditor's originals and remain broad. Known
  imprecision that shaped the safe fixtures: the weak-crypto pattern's
  `cryptography.*(?:DES|RC4|Blowfish)` / `(?:DES|…)(?:\.|\s|Cipher)` alternatives
  match the substring "des" inside the word "modes" — so `safe_crypto.py` uses
  the Fernet API rather than `cryptography.hazmat…ciphers…modes`. Precision work
  (AST pass, wider allowlists) is milestone M7, out of scope here.
- `RULES_BY_EXT` (ext → list[Rule]) is built once at import for the scan loop.
- Masking only rewrites quoted RHS of `=` / `:` assignments; it is intentionally
  conservative so it never corrupts non-secret snippets.
- Pushed to `origin/foundation/sast-engine` successfully.
