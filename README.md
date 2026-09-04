# Vulnascan

**Vulnascan** is a **deterministic, non-LLM** static security scanner for your
application's local project directory. Provide it the directory containing your
application code and get a detailed vulnerability report with remediation advice.
No model, no randomness — identical report for identical input in every run.

Run it yourself as a desktop application or CLI, or give it to your coding agent
to run a quick review and remediation — fast and free.

## What it does

- **Finds vulnerable code (SAST).** A pattern engine — regex + AST rules —
  searches your source for injection, XSS, path traversal, hardcoded secrets,
  weak crypto, insecure deserialization, SSRF, and around two dozen other
  vulnerability classes (28 rule types in all). Every finding carries a CWE id
  and a *vulnerable → secure* remediation pair.
- **Finds vulnerable dependencies (SCA).** It parses your lockfiles and checks
  every pinned package against the OSV vulnerability database (CVE / GHSA / OSV
  advisories, with the fixed version and severity). Reported in a separate
  section from the code findings.
- **Produces a report you can act on.** `text`, `markdown`, `json`, `sarif`, or
  a single self-contained `html` file — each finding with its location, a masked
  code snippet, a plain-language explanation, and the fix. Secrets are masked
  before they ever reach a report.

The pipeline runs in fixed order — **discover files → SAST rules → confidence
gate → dependency scan (OSV) → CVE enrichment (NVD)**. A network or parse failure
never aborts the scan; it marks the report **PARTIAL** and lists what was
skipped, and the code findings are still complete. `--offline` skips all network
and still runs the full SAST pass. OSV/NVD responses are cached on disk for 24 h.

## Try it

Point Vulnascan at a directory:

![Vulnascan — choosing a folder to scan](docs/images/app-empty.png)

Read the report it produces — severity tiles, then every finding with its
location, the masked snippet, and the fix:

![Vulnascan — the scan report](docs/images/app-results.png)

## Run it

Vulnascan is free and open source, and ships in **three shapes over one shared
engine**. All three call the same `scan(path, ScanConfig) -> ScanResult` — there
are no divergent code paths.

| Shape | What it is | Docs |
|---|---|---|
| **Desktop app** | Double-click, choose a folder, read a rendered report. No Python, no terminal. | [`docs/DESKTOP.md`](docs/DESKTOP.md) |
| **CLI** | `security-preview scan <path>` — for terminals and CI, with `--format`, `--offline`, `--min-confidence`, and exit-code gating. | [`docs/USAGE.md`](docs/USAGE.md) |
| **Coding-agent skill** | Claude Code / Cursor run the scan on request and summarise the findings. | [`SKILL.md`](SKILL.md), [`docs/CURSOR.md`](docs/CURSOR.md) |

![Architecture — one engine, three shapes](docs/images/architecture.svg)

## Supported languages

Pattern rules match **14 languages and config formats** (17 file extensions).
Coverage is deep for the first six and targeted for the rest; dependency (CVE)
scanning is separate and language-agnostic.

| Language | Extensions | Rule checks |
|---|---|---|
| Python | `.py` | 24 |
| JavaScript | `.js` `.jsx` | 24 |
| TypeScript | `.ts` `.tsx` | 24 |
| Java | `.java` | 24 |
| PHP | `.php` | 23 |
| Ruby | `.rb` | 17 |
| Go | `.go` | 14 |
| C# | `.cs` | 7 |
| YAML | `.yml` `.yaml` | 3 |
| JSON | `.json` | 3 |
| C | `.c` | 1 |
| C++ | `.cpp` | 1 |
| HTML | `.html` | 1 |
| Shell | `.sh` | 1 |

Dependency scanning reads lockfiles for **Python, npm, Go, Ruby and Maven**
(`requirements.txt`, `poetry.lock`, `Pipfile.lock`, `package-lock.json`,
`yarn.lock`, `go.mod`, `Gemfile.lock`, `pom.xml`) and matches every pinned
package against the OSV database.

## Develop

```bash
python -m venv .venv && . .venv/Scripts/activate    # Windows
pip install -e ".[dev]"
pytest -q
ruff check . && mypy src
```

- **Build plan:** `security-preview-plan.md`
- **UI & report design:** `security-preview-design-brief.md` + the design canvas
- **Parallel foundation build:** `security-preview-parallel-build-plan.md`
- **Desktop packaging:** `security-preview-desktop-packaging-plan.md`
- **Test plan:** `security-preview-test-plan.md`

### Regenerating the screenshots

The images under `docs/images/` are captured from a live `security-preview serve`
against `tests/fixtures/` with the Offline switch on (fast, deterministic, no
network). `architecture.svg` is hand-authored. The tooltip callouts in
`app-tooltips.png` are annotations drawn over the real UI; the copy in them is
verbatim from the `title` attributes in `server/static/index.html`.
