# App icons

`security-preview.png` (1024×1024) is the **master**. Everything else in this
folder is generated from it:

| Name | Platform |
|---|---|
| `security-preview.ico` | Windows |
| `security-preview.icns` | macOS |
| `security-preview-16.png` … `-512.png` | Linux PNG ladder |

Briefcase reads them via `icon = "resources/icons/security-preview"` in
`pyproject.toml`; PyInstaller reads the `.ico` directly.

## Regenerate

```
python scripts/make_icon_master.py       # (re)draw the placeholder master
python scripts/build_desktop.py icons     # fan out to .ico / .icns / PNG ladder
```

Both need Pillow (`python -m pip install pillow`).

The current master is a **placeholder** — a shield holding a magnifier in the
UI's terracotta accent (`#d97757`), drawn by `scripts/make_icon_master.py`.
Replace `security-preview.png` with a designed 1024² logo and re-run
`build_desktop.py icons`; delete `make_icon_master.py` once a real logo lands.
