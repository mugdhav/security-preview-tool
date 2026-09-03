# PyInstaller spec for the portable, no-install desktop build.
#
#   python -m pip install -e ".[package]"
#   pyinstaller pyinstaller/vulnascan.spec
#
# Output: dist/vulnascan(.exe) -- a single file that opens the native
# window. Used for a quick portable download and as a CI smoke check; the
# shipping installers come from Briefcase (see pyproject [tool.briefcase]).
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

_root = Path(SPECPATH).resolve().parent
_pkg = _root / "src" / "security_preview"

block_cipher = None

datas = [
    (str(_pkg / "server" / "static"), "security_preview/server/static"),
]

hiddenimports = (
    collect_submodules("uvicorn")
    + collect_submodules("webview")
    + ["security_preview.desktop", "security_preview.server.app"]
)

a = Analysis(
    [str(_pkg / "__main__.py")],
    pathex=[str(_root / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff", "tkinter"],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="vulnascan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=str(_root / "resources" / "icons" / "vulnascan.ico"),
)
