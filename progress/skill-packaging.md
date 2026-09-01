# progress — skill-packaging (unit 7)

## Status

Done.

## What's done

Five new files, no `src/` changes:

- `SKILL.md` — YAML frontmatter (`name: security-preview`, `description` = the
  §11 trigger sentence **verbatim**), then a body: when to trigger, how to run
  (`scripts/bootstrap.py` then `security-preview scan <dir> --format json
  --min-confidence medium`), how to present results, and the full unit-5 CLI
  surface (`scan` with `--format text|markdown|json|sarif|html`, `--offline`,
  `--no-sca`, `--min-confidence`, `--out`; `serve [--port]`; `selftest`).
- `scripts/bootstrap.py` — stdlib only, no third-party imports. Prefers `uv`
  (`uv venv` + `uv pip install --python <venv> -e <root>[extra]`), falls back to
  `python -m venv` + venv `pip install -e`. Cross-platform venv path
  (`Scripts/python.exe` vs `bin/python`). Flags: `--venv`, `--dev`, `--no-uv`,
  `--dry-run`, `--help`. Prints activation + next-step instructions. Uses the
  absolute project root as the install target so it works from any cwd.
- `docs/USAGE.md` — end-user guide: bootstrap, every subcommand + flag, reading
  each report format, offline mode, `serve` UI, and both a Claude-hook gate and a
  plain-CI baseline-diff gate.
- `docs/CURSOR.md` — CLI use inside Cursor / VS Code: chat invocation, a
  `.vscode/tasks.json` block, a `.cursorrules` snippet, and how to consume
  JSON (full shape documented) / SARIF / markdown / html.
- `.claude/hooks-example.json` — valid JSON (no comments; notes in a `_README`
  string array). `SessionStart` hook runs a quiet high-confidence scan as
  context (no-op if CLI absent). `PreToolUse` (`matcher: "Bash"`) hook: on a
  `git commit` command, scans `--format json` and exits `2` (blocks) when the
  CRITICAL count exceeds `.security-preview/baseline-critical` (0 if absent).
  Install instructions in the `_README` and in `docs/USAGE.md`.

## Verification

- `python scripts/bootstrap.py --help` — OK, no traceback.
- `python scripts/bootstrap.py --dry-run` (uv path) and `--dry-run --no-uv --dev`
  (venv path) — both print the expected commands, exit 0.
- `python -c "import json;json.load(open('.claude/hooks-example.json'))"` — valid.
- Embedded hook Python `compile()`s clean (both commands).
- `python -m ruff check scripts/bootstrap.py` — All checks passed.

## Contract questions

None blocking. Assumptions made against the frozen contracts:

- CLI exit code is `0` for any completed scan regardless of findings; non-zero
  only on hard errors (path missing / not a directory). Documented that way in
  SKILL.md / USAGE.md / CURSOR.md and the CI gates key off JSON content, not exit
  code. If unit 5 chooses a non-zero exit on findings, USAGE.md "CI / commit
  gate" and the exit-code notes need a one-line tweak.
- `--min-confidence` accepts lowercase `low|medium|high` on the CLI (maps to the
  `Confidence` enum). If unit 5 uses different tokens, update the flag tables.
- `serve` binds `127.0.0.1`, random free port when `--port` omitted, auto-opens a
  browser — per plan §8. Docs assume this.
- JSON output == `ScanResult.to_dict()` from `models.py` exactly (documented
  shape in CURSOR.md is copied from the frozen model + conftest fixtures).

## Extra dependency needed

None. `scripts/bootstrap.py` is stdlib-only; docs add nothing. `pyproject.toml`
untouched.

## Notes for the merger

- No overlap with any other unit's files. `.claude/` and `docs/` and `scripts/`
  are new top-level dirs created by this branch only.
- `.claude/hooks-example.json` is an **example**, not wired into anything. The
  `PreToolUse` command embeds a ~1KB Python script as a `python -c "..."` string
  with real newlines. This is fine for POSIX `/bin/sh` (how Claude Code runs
  hooks on macOS/Linux); on Windows `cmd.exe` a multi-line quoted arg can be
  fragile. If you want it bulletproof cross-platform, the embedded script could
  move to a committed `scripts/commit_gate.py` (out of this unit's ownership, so
  left for merge/Phase 2).
- SKILL.md `description` is the §11 sentence unchanged — no discrepancy found
  between the task brief and plan §11.
- SKILL.md references `docs/USAGE.md`, `docs/CURSOR.md`, `.claude/hooks-example.json`
  by relative path; keep them side-by-side if the skill is copied into
  `.claude/skills/`.
