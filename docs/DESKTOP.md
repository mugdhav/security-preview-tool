# security-preview — Desktop app

The desktop app is the **no-Python, no-terminal, no-config** way to run
security-preview:

> Double-click the icon → a window opens → click **Choose folder…** → pick any
> directory → **Scan**.

Nothing leaves your machine except optional CVE lookups (NVD / OSV). The app
binds `127.0.0.1` only and works offline.

---

## Install

### Windows

1. Download `security-preview-<version>.msi` (installer) **or**
   `security-preview.exe` (portable, no install).
2. Run it. The installer adds a **Start-Menu** and **Desktop** shortcut.
3. First launch: if Windows SmartScreen shows *"Windows protected your PC"* on an
   unsigned build, click **More info → Run anyway**. (Signed builds show the
   publisher and skip this.)
4. Windows 11 already has the Edge **WebView2** runtime. On Windows 10 the
   installer pulls it in automatically; if the app reports it missing, install
   *Evergreen WebView2 Runtime* from Microsoft and relaunch.

### macOS

1. Open `security-preview-<version>.dmg`, drag the app to **Applications**.
2. First launch on an unsigned build: **right-click → Open → Open**, or
   *System Settings → Privacy & Security → Open Anyway*.

### Linux

1. `chmod +x security-preview-<version>.AppImage && ./security-preview-<version>.AppImage`
   — **or** install the `.deb` / `.rpm`.
2. The AppImage bundles its Python; the host needs a WebKitGTK runtime
   (`gir1.2-webkit2-4.1` on Debian/Ubuntu, `webkit2gtk` on Fedora). If the
   window fails to open, the app falls back to your default browser.

---

## Using it

| Action | How |
|---|---|
| Choose what to scan | **Choose folder…** → native OS dialog → any directory, any drive |
| Options | `Offline`, `Scan dependencies`, `Min confidence` in the bar |
| Run | **Scan** (disabled until a folder is chosen) |
| Read a finding | click a row → detail drawer with remediation |
| Save a report | `Download ▾` → `.json` in-app; `.md` / `.sarif` / `.html` via the CLI |
| Stop | close the window (a scan in progress is cancelled cleanly) |

There is **no allowed-root restriction**: the folder you pick *is* the root for
that scan. `..` in a typed path and symlinks that resolve elsewhere are still
rejected.

### Explorer / Finder right-click (when installed)

`security-preview-desktop --scan "<folder>"` opens the window pre-pointed at that
folder and starts scanning. The Windows installer can add a
*"Scan with security-preview"* entry to the folder right-click menu.

---

## Headless / server install

No window needed? `security-preview serve` still works:

```
security-preview serve                # OS-assigned port, opens your browser
security-preview serve --no-open      # just prints the URL
security-preview serve --desktop      # force the native window (needs pywebview)
```

`pip install "security-preview[desktop]"` adds `pywebview` for the native window;
without it, `serve` uses the system browser.

---

## Building the installers

```
python -m pip install -e ".[package]"      # pywebview + briefcase + pyinstaller

python scripts/build_desktop.py check      # launcher smoke test (no network)
python scripts/build_desktop.py icons      # regenerate icons from a 1024² master
python scripts/build_desktop.py installer  # Briefcase installer for this OS
python scripts/build_desktop.py portable   # one-file PyInstaller .exe
```

CI (`.github/workflows/desktop-release.yml`) builds all three OSes on a `v*` tag,
runs the test suite + a self-scan first, and attaches the installers to the
GitHub Release. Code-signing secrets are used when configured; otherwise builds
ship unsigned with the allow-steps above.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Window never appears | WebView2 (Win) / WebKitGTK (Linux) runtime missing — see Install. The app falls back to the browser. |
| "server did not become healthy in time" | Another process may hold the port; relaunch. Logs print to the console for the portable `.exe`. |
| SmartScreen / Gatekeeper block | Unsigned preview build — use the allow-step above. |
| Scan seems stuck | Large tree; there is a 120 s wall-clock budget, after which the scan returns HTTP 504 and the UI shows an error. |
