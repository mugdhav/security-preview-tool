#!/usr/bin/env python3
"""Bootstrap an isolated environment for security-preview and install the CLI.

Prefers ``uv`` when it is on PATH (``uv venv`` + ``uv pip install -e .``) and
falls back to the stdlib (``python -m venv`` + that venv's ``pip install -e .``).

Runnable with a plain interpreter and no third-party imports::

    python scripts/bootstrap.py            # create .venv and install
    python scripts/bootstrap.py --dev      # also install the "dev" extra
    python scripts/bootstrap.py --dry-run  # print the commands only
    python scripts/bootstrap.py --help
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_VENV = PROJECT_ROOT / ".venv"


def venv_python(venv_dir: Path) -> Path:
    """Path to the interpreter inside ``venv_dir`` for the current platform."""
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def activate_hint(venv_dir: Path) -> str:
    """Human-readable 'how to activate this venv' line for the current platform."""
    if os.name == "nt":
        return (
            f"{venv_dir}\\Scripts\\activate.bat      (cmd.exe)\n"
            f"     {venv_dir}\\Scripts\\Activate.ps1     (PowerShell)"
        )
    return f"source {venv_dir}/bin/activate"


def run(cmd: list[str], dry_run: bool) -> None:
    """Echo and (unless dry-run) execute a command, raising on non-zero exit."""
    print("  $ " + " ".join(str(c) for c in cmd))
    if dry_run:
        return
    subprocess.run([str(c) for c in cmd], check=True)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bootstrap.py",
        description="Create an isolated environment and install security-preview.",
    )
    parser.add_argument(
        "--venv",
        type=Path,
        default=DEFAULT_VENV,
        help=f"virtualenv location (default: {DEFAULT_VENV})",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help='install the "dev" extra (pytest, pytest-asyncio, ruff, mypy)',
    )
    parser.add_argument(
        "--no-uv",
        action="store_true",
        help="ignore uv even if it is installed; use python -m venv + pip",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print every command without creating or installing anything",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    venv_dir = args.venv.resolve()
    extra = "[dev]" if args.dev else ""
    target = f"{PROJECT_ROOT}{extra}"
    uv = None if args.no_uv else shutil.which("uv")

    print("security-preview bootstrap")
    print(f"  project : {PROJECT_ROOT}")
    print(f"  venv    : {venv_dir}")
    print(f"  backend : {'uv' if uv else 'python -m venv + pip'}")
    print()

    if uv:
        run([uv, "venv", str(venv_dir)], args.dry_run)
        run(
            [uv, "pip", "install", "--python", str(venv_python(venv_dir)),
             "-e", target],
            args.dry_run,
        )
    else:
        run([sys.executable, "-m", "venv", str(venv_dir)], args.dry_run)
        py = str(venv_python(venv_dir))
        run([py, "-m", "pip", "install", "--upgrade", "pip"], args.dry_run)
        run([py, "-m", "pip", "install", "-e", target], args.dry_run)

    py = venv_python(venv_dir)
    print()
    print("Done." if not args.dry_run else "Dry run complete.")
    print("Next steps:")
    print("  1. Activate the environment:")
    print(f"     {activate_hint(venv_dir)}")
    print("  2. Verify the install:")
    print("     security-preview selftest")
    print("  3. Run a scan:")
    print("     security-preview scan . --format markdown --out SECURITY_REPORT.md")
    print()
    print(f"  Without activating: {py} -m security_preview.cli scan .")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
