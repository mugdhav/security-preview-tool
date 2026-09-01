# security-preview

Deterministic, **non-LLM** static security scanner for a local project directory.
Runs regex + AST pattern analysis (SAST) and real dependency CVE matching (SCA),
then produces a vulnerability report with remediation. One engine, three shapes:
a local browser app, a CLI, and a coding-agent skill.

- **What to build:** `security-preview-plan.md`
- **UI & report design:** `security-preview-design-brief.md` + design canvas
- **Parallel foundation build:** `security-preview-parallel-build-plan.md`

## Status

Foundation scaffold. Modules are stubs pending the Phase 1 branches — see the
parallel build plan.

## Develop

```bash
python -m venv .venv && . .venv/Scripts/activate    # Windows
pip install -e ".[dev]"
pytest -q
```
