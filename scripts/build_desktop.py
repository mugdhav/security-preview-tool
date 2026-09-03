#!/usr/bin/env python3
"""Build helpers for the Vulnascan desktop app (the security-preview engine).

Subcommands
-----------
    python scripts/build_desktop.py icons        derive the .icns + Linux PNG
                                                 ladder from resources/icons/
                                                 vulnascan.png (the .png master
                                                 and .ico are hand-authored)
    python scripts/build_desktop.py portable     one-file PyInstaller build
    python scripts/build_desktop.py installer     Briefcase installer for this OS
    python scripts/build_desktop.py inno          Inno Setup installer (Windows;
                                                 wraps the portable exe, adds the
                                                 folder right-click verb)
    python scripts/build_desktop.py check         import + healthz smoke test

None of these need network access. `installer`/`portable` need the `package`
extra: `python -m pip install -e ".[package]"`. `inno` needs Inno Setup 6
(`iscc` on PATH) and a prior `portable` build.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ICON_DIR = ROOT / "resources" / "icons"
MASTER = ICON_DIR / "vulnascan.png"

_PNG_LADDER = (16, 32, 48, 64, 128, 256, 512)


def _run(cmd: list[str]) -> int:
    print("+", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(ROOT))


def cmd_icons(_argv: list[str]) -> int:
    if not MASTER.is_file():
        print(f"no master icon at {MASTER}; add a 1024x1024 PNG first", file=sys.stderr)
        return 1
    try:
        from PIL import Image
    except ImportError:
        print("Pillow is required: python -m pip install pillow", file=sys.stderr)
        return 1

    img = Image.open(MASTER).convert("RGBA")

    # vulnascan.png (master) and vulnascan.ico are hand-authored and checked in as
    # the source of truth; this command only derives the formats we don't hand-make.
    for size in _PNG_LADDER:
        out = ICON_DIR / f"vulnascan-{size}.png"
        img.resize((size, size), Image.LANCZOS).save(out)
        print("wrote", out.relative_to(ROOT))

    ico = ICON_DIR / "vulnascan.ico"
    if ico.is_file():
        print("kept  ", ico.relative_to(ROOT), "(hand-authored; not regenerated)")
    else:
        img.save(ico, sizes=[(s, s) for s in (16, 32, 48, 64, 128, 256)])
        print("wrote", ico.relative_to(ROOT), "(no hand-authored .ico found)")

    icns = ICON_DIR / "vulnascan.icns"
    try:
        img.save(icns)
        print("wrote", icns.relative_to(ROOT))
    except (OSError, ValueError):
        print("skipped .icns (Pillow build lacks icns support; Briefcase on macOS "
              "will generate it from the PNG ladder)")
    return 0


def cmd_portable(_argv: list[str]) -> int:
    return _run([sys.executable, "-m", "PyInstaller", "pyinstaller/vulnascan.spec"])


def cmd_inno(_argv: list[str]) -> int:
    import shutil

    exe = ROOT / "dist" / ("vulnascan.exe" if sys.platform == "win32" else "vulnascan")
    if not exe.exists():
        print("run 'build_desktop.py portable' first (missing dist/vulnascan.exe)",
              file=sys.stderr)
        return 1
    iscc = shutil.which("iscc") or shutil.which("ISCC")
    if not iscc:
        print("Inno Setup not found: install v6 and put 'iscc' on PATH "
              "(https://jrsoftware.org/isdl.php)", file=sys.stderr)
        return 1
    return _run([iscc, "resources/installer/vulnascan.iss"])


def cmd_installer(argv: list[str]) -> int:
    target = argv[0] if argv else {"win32": "windows", "darwin": "macOS"}.get(
        sys.platform, "linux"
    )
    for step in ("create", "build", "package"):
        rc = _run([sys.executable, "-m", "briefcase", step, target])
        if rc != 0:
            return rc
    return 0


def cmd_check(_argv: list[str]) -> int:
    import importlib
    import socket
    import threading
    import urllib.request

    sys.path.insert(0, str(ROOT / "src"))
    desktop = importlib.import_module("security_preview.desktop")
    app_mod = importlib.import_module("security_preview.server.app")

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    import uvicorn

    app = app_mod.create_app(mode="desktop", folder_picker=lambda: None)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        ok = desktop._wait_healthz(port, timeout=10)
        if not ok:
            print("healthz did not answer", file=sys.stderr)
            return 1
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz") as r:
            body = r.read().decode()
        pick = urllib.request.Request(f"http://127.0.0.1:{port}/api/pick-folder", method="POST")
        with urllib.request.urlopen(pick) as r:
            pick_body = r.read().decode()
    finally:
        server.should_exit = True
        t.join(timeout=5)

    print("healthz:      ", body)
    print("pick-folder:  ", pick_body)
    return 0


_COMMANDS = {
    "icons": cmd_icons,
    "portable": cmd_portable,
    "installer": cmd_installer,
    "inno": cmd_inno,
    "check": cmd_check,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in _COMMANDS:
        print(__doc__)
        return 2
    return _COMMANDS[argv[0]](argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
