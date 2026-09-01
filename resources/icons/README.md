# App icons

Drop a single **1024×1024 PNG** master here as `security-preview.png`, then
generate the per-platform sets:

```
# Briefcase reads these names next to `icon = "resources/icons/security-preview"`:
#   security-preview.ico                      (Windows)
#   security-preview.icns                     (macOS)
#   security-preview-16.png … -512.png        (Linux PNG ladder)

python scripts/build_desktop.py icons        # regenerates all of the above
```

`scripts/build_desktop.py icons` needs Pillow (`pip install pillow`). Until a
master is added, Briefcase falls back to its stock icon and the build still
succeeds.
