"""Command-line interface. Owned by branch ``foundation/orchestrator-cli``.

Subcommands::

    security-preview scan <path> [--format text|markdown|json|sarif|html]
                                 [--offline] [--no-sca]
                                 [--min-confidence HIGH|MEDIUM|LOW] [--out FILE]
    security-preview serve [--port PORT]
    security-preview selftest

Exit codes for ``scan``/``selftest``: ``0`` when the scan completed with no
CRITICAL findings, ``1`` when at least one CRITICAL finding exists (or the run was
partial, for ``selftest``), ``2`` for a usage/IO error. Enrichment or network
failure alone never changes the exit code.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from . import scan as scan_mod
from .config import ScanConfig
from .models import Confidence, RiskLevel
from .report import renderers

__all__ = ["main"]

_FORMATS = ("text", "markdown", "json", "sarif", "html")
_CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
_DEFAULT_PORT = 8765


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-preview",
        description="Deterministic, non-LLM static security scanner for a local directory.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a project directory")
    p_scan.add_argument("path", help="path to the project directory to scan")
    p_scan.add_argument(
        "--format",
        default="text",
        help="report format: " + " | ".join(_FORMATS),
    )
    p_scan.add_argument(
        "--offline",
        action="store_true",
        help="skip all network access (NVD + OSV)",
    )
    p_scan.add_argument(
        "--no-sca",
        action="store_true",
        help="skip dependency (SCA) scanning",
    )
    p_scan.add_argument(
        "--min-confidence",
        choices=_CONFIDENCES,
        default=None,
        help="drop findings below this confidence (default: MEDIUM)",
    )
    p_scan.add_argument(
        "--out",
        default=None,
        help="write the report to this file instead of stdout",
    )

    p_serve = sub.add_parser("serve", help="run the local browser app")
    p_serve.add_argument("--port", type=int, default=_DEFAULT_PORT, help="TCP port to bind")

    sub.add_parser("selftest", help="scan bundled fixtures and print a JSON summary")
    return parser


def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    min_conf = (
        Confidence(args.min_confidence)
        if args.min_confidence
        else ScanConfig.defaults().min_confidence
    )
    return ScanConfig(
        offline=bool(args.offline),
        run_sca=not args.no_sca,
        min_confidence=min_conf,
    )


def _exit_code_for(result) -> int:
    return 1 if any(f.severity is RiskLevel.CRITICAL for f in result.findings) else 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.format not in _FORMATS:
        print(
            f"error: unknown format {args.format!r}; choose from {', '.join(_FORMATS)}",
            file=sys.stderr,
        )
        return 2
    if not os.path.isdir(args.path):
        print(f"error: not a directory: {args.path}", file=sys.stderr)
        return 2

    cfg = _config_from_args(args)
    result = scan_mod.scan(args.path, cfg)
    output = renderers.render(result, args.format)

    if args.out:
        try:
            Path(args.out).write_text(output, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.out}: {exc}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(output)
        if output and not output.endswith("\n"):
            sys.stdout.write("\n")

    return _exit_code_for(result)


def _cmd_serve(args: argparse.Namespace) -> int:
    # Lazy import: the server + uvicorn stack is only needed for this subcommand.
    import uvicorn

    from .server import app as server_app

    application = server_app.create_app()
    uvicorn.run(application, host="127.0.0.1", port=args.port)
    return 0


def _cmd_selftest(_args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    fixtures = repo_root / "tests" / "fixtures" / "vulnerable"

    cleanup: str | None = None
    if fixtures.is_dir():
        target = str(fixtures)
    else:
        target = tempfile.mkdtemp(prefix="security-preview-selftest-")
        cleanup = target
        (Path(target) / "app.py").write_text(
            "import os\n\n\ndef run(user_input):\n    os.system('echo ' + user_input)\n",
            encoding="utf-8",
        )

    try:
        result = scan_mod.scan(target, ScanConfig(offline=True))
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)

    print(json.dumps(result.summary(), indent=2, sort_keys=True))
    critical = result.summary()["by_severity"]["CRITICAL"]
    return 1 if (critical or result.partial) else 0


_COMMANDS = {
    "scan": _cmd_scan,
    "serve": _cmd_serve,
    "selftest": _cmd_selftest,
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return _COMMANDS[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
