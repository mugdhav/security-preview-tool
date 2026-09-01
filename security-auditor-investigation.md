# Security Auditor — Investigation Findings

Date: 2026-09-01
Scope: `security_checker.py`, `gradio_app.py`, `modal_app.py`, HF Space deployment wiring

## What the app does

A Gradio web UI backed by `SecurityChecker` (security_checker.py), which orchestrates:
- `SASTEngine` — 28 regex-based static analysis rules over local source code
- `WebAppScanner` — black-box HTTP probing of a live/remote URL (headers, exposed paths, HTTP vs HTTPS, error leakage)
- `NVDClient` — live queries against the real NIST NVD API to attach example CVEs to findings by CWE

Scanning can run in-process or be offloaded to a Modal.com serverless backend (`modal_app.py`), which imports and reuses the same `SASTEngine`, so local and cloud scans stay consistent. The app is git-deployed to a Hugging Face Space (`mugdhav/security_auditor`, served at `mugdhav-security-auditor.hf.space`) via a manual `git push hf`.

## Features genuinely better than asking Claude directly

1. **Scale & cost of bulk scanning** — `SASTEngine.scan_directory` runs 28 regexes in parallel across an entire codebase (parallel file-reading workers, chunked Modal calls) for near-zero cost and no context-window limit. Claude reviewing thousands of files means chunking around context limits and high token cost; this tool doesn't have that ceiling.
2. **Deterministic, reproducible output** — same input always yields the same findings/CWE IDs/JSON schema, suitable for CI gating and diffing scan results over time. An LLM review of the same file can vary between runs.
3. **Live black-box network probing** — `WebAppScanner` actually sends HTTP requests to a running URL: missing security headers, exposed `/.git/config`, `/wp-admin`, `/backup.sql`, HTTP-vs-HTTPS, leaked stack traces/debug flags in responses. Claude has no built-in batch network-probing tool; doing this manually via WebFetch would be one request at a time and much slower.
4. **Live NVD/CVE lookups** — queries `services.nvd.nist.gov` at scan time, so CVE data is current as of the scan. Claude's knowledge has a training cutoff and needs explicit web search to cite anything recent.

## Where it's weaker than an LLM-based review

- Per-line regex matching only (`SASTRule.matches`) — no dataflow/taint tracking across variables, functions, or files.
- No framework awareness — flags idiomatic, safe code (e.g. ORM query builders) as false positives because it can't distinguish parameterized calls from raw string concatenation.
- Fixed rule set (28 patterns) — anything outside it (business-logic flaws, broken auth/authz, race conditions, novel vuln classes) is invisible to the tool.
- No real SCA/dependency scanning — never checks `requirements.txt`/`package.json` against known-vulnerable versions, despite having NVD access.

## Serious issues and bugs to fix

1. **NVD enrichment silently broken for Remote URL scans** (`gradio_app.py:1415`)
   `self.checker.scan_web(url, include_nvd=False)` hardcodes `include_nvd=False` and ignores the `nvd_check` parameter passed into `scan_web_app(url, nvd_check)`. The "NVD Enriched Scan Results" toggle in the UI has zero effect on Remote URL mode, even though it visually applies to both modes. Compare to `scan_local_files` (line 1151), which correctly passes `include_nvd=nvd_check`.
   **Fix:** change line 1415 to `self.checker.scan_web(url, include_nvd=nvd_check)`.

2. **Regex-only, single-line SAST engine is prone to false positives/negatives**
   `SASTRule.matches` (security_checker.py:151) checks one line at a time with no cross-line or cross-file context. Multi-line injection constructs are missed entirely; safe framework idioms (parameterized ORM calls, escaped templating) are frequently flagged as vulnerable because the regex only looks for syntactic shape, not semantics.
   **Fix:** at minimum, expand context window used for matching (not just for the display snippet) or move toward an AST-based/semantic approach for the highest-severity rules (SQLi, command injection).

3. **No dependency/SCA scanning despite NVD access**
   The app markets NVD integration but never cross-references `requirements.txt`/`package.json`/lockfiles against known-vulnerable package versions — the only NVD usage is attaching illustrative CVEs by CWE category, not real vulnerability matches. Users may reasonably assume "NVD integration" means their dependencies are checked; it does not.
   **Fix:** either add real SCA (e.g., cross-check parsed manifests against NVD/OSV) or make the UI copy explicit that CVE enrichment is illustrative-by-category, not a dependency match.

4. **Uncommitted/undeployed work diverges from the live HF Space**
   Current branch (`sa-modal`) has uncommitted edits to `gradio_app.py` and `ui_components.py`, plus many untracked files (`modal_app.py`, `hf_space_deploy/`, test scripts). The `hf` remote (the actual live Space) is on a different, further-ahead commit (`fbf255d`) than local `main`. There's no CI/CD — deployment is a manual `git push hf`, so it's easy for the deployed Space to silently drift from what's being tested locally.
   **Fix:** commit and push intentionally, and consider a deploy script/GitHub Action so "what's live" is never a manual guess.

5. **Silent exception swallowing hides scan failures**
   Multiple methods in `WebAppScanner` (`_check_security_headers`, `_check_sensitive_paths`, `_check_response_content`) catch broad `except Exception: pass`, and `_enrich_with_nvd` does the same around CVE fetches. A network error, TLS failure, or NVD outage produces a clean-looking (but incomplete) report with no indication to the user that checks were skipped.
   **Fix:** surface partial-failure state into `ScanResult.errors` instead of swallowing silently, and show it in the UI.

6. **`ModalScanResult` duck-typing is fragile** (`gradio_app.py:38-66`)
   It builds `Vulnerability`-like objects via `type('Vulnerability', (), v)()` from raw dict fields returned by the Modal API, with a `to_dict` lambda bound to `_raw`. Any schema drift between the Modal backend response and what the UI expects (a renamed/missing key) will fail silently or produce malformed cards rather than a clear error, since there's no schema validation at this boundary.
   **Fix:** define a proper shared `Vulnerability` (de)serialization function instead of dynamic `type()` construction, and validate the Modal response shape.
