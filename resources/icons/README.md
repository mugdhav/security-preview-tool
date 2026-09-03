# App icons

The Vulnascan mark: a magnifier over two bars in the UI's terracotta accent
(`#d97757`).

| Name | Platform | Source |
|---|---|---|
| `vulnascan.png` | 1024² master / Linux base | **hand-authored** |
| `vulnascan.ico` | Windows | **hand-authored** (multi-size) |
| `vulnascan.icns` | macOS | derived from `vulnascan.png` |
| `vulnascan-16.png` … `-512.png` | Linux PNG ladder | derived from `vulnascan.png` |

`vulnascan.png` and `vulnascan.ico` are the checked-in source of truth — edit or
replace them directly. The `.icns` and the PNG ladder are generated.

The earlier `security-preview*` placeholder set (shield + magnifier) was retired
in the Vulnascan rebrand; recover it from git history if ever needed.

## Who reads what

- **Briefcase** — `icon = "resources/icons/vulnascan"` in `pyproject.toml`; it
  appends the per-OS suffix (`.ico` / `.icns` / `vulnascan-<size>.png`).
- **PyInstaller** — `pyinstaller/vulnascan.spec` embeds `vulnascan.ico` in the
  portable `vulnascan.exe`; the Explorer right-click verb and the uninstaller
  pick the icon up from that exe.

## Regenerate the derived files

```
python scripts/build_desktop.py icons     # vulnascan.png -> .icns + PNG ladder
```

Needs Pillow (`python -m pip install pillow`). This leaves `vulnascan.png` and a
hand-authored `vulnascan.ico` untouched; re-run it whenever the master changes.
