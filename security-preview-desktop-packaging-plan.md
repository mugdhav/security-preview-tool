# security-preview — Desktop App Packaging Plan

Date: 2026-09-01
Covers: turning `security-preview serve` into a zero-config, double-click desktop app.
Reads with: `security-preview-plan.md` (tool behaviour), `security-preview-design-brief.md`
(UI spec, Target A), `security-preview-test-plan.md` (§4 app tests).

---

## 0. Status (2026-09-02)

**Landed** — the "double-click an icon, pick a folder, scan" path works end to end:

- **D0** `serve` QoL: `--port 0` default (OS-assigned, URL printed), `--open` /
  `--no-open`, `GET /healthz`, quiet uvicorn.
- **D1** root decoupling: `create_app(mode=…)`, the picked folder *is* the root
  per scan, `SECURITY_PREVIEW_ROOT` removed. `..` / symlink escapes still 400.
- **D2** launcher + picker: `src/security_preview/desktop.py`
  (`security-preview-desktop` script, `python -m security_preview`,
  `serve --desktop`), `POST /api/pick-folder` (desktop-mode only),
  **Choose folder…** button + mode detection + `?path=&autoscan=1` deep link in
  `index.html`. Falls back to the system browser when `pywebview` is absent.
- **Packaging scaffold**: `[tool.briefcase.*]` tables, `pyinstaller/security-preview.spec`,
  `scripts/build_desktop.py` (`check` / `icons` / `portable` / `installer`),
  `.github/workflows/desktop-release.yml`, `docs/DESKTOP.md`.
- Tests: `tests/test_desktop.py` (+ server/CLI updates); test-plan §3.5, §4.1,
  §4.4, §6.3, §6.5 revised. `pytest -q` → 151 passed.

**Not yet** — D3 finish (real icon master + built installers on all 3 OSes), D4
(code-signing certs + notarization), D5 (Explorer right-click installer entry;
the `--scan` launcher hook itself is done).

---

## 1. Goal

A non-technical user gets the browser UI with **no Python, no terminal, no config**:

> Double-click a desktop / Start-Menu icon → a native window opens → click
> **"Choose folder…"** → pick any directory → **Scan**.

No `pip`, no venv, no `SECURITY_PREVIEW_ROOT`, no `http://127.0.0.1:…` to type,
no "path escapes the allowed root" errors.

### Non-goals

- Replacing the CLI (`security-preview scan/selftest`) — it stays as-is for
  agents, CI, and power users.
- A cloud/hosted version. The app is local-only, offline-capable, `127.0.0.1` only.
- Auto-update infrastructure (tracked separately; see §9).
- Mobile / web distribution — the UI is desktop-only per design brief §3.

---

## 2. Current launch flow vs. target

| Step | Today | Target |
|---|---|---|
| Get the tool | `pip install -e ".[dev]"` or `scripts/bootstrap.py` | Run an installer once (or portable exe) |
| Start it | open shell → activate venv → `cd` → `set SECURITY_PREVIEW_ROOT` → `security-preview serve` | double-click icon |
| Open UI | manually browse to `http://127.0.0.1:8765` | native window opens itself |
| Choose what to scan | type a path that must live under the launch dir / env root | OS folder picker, any directory |
| Stop | `Ctrl+C` in the terminal | close the window |

---

## 3. Root causes to remove

1. **Python toolchain dependency** → bundle CPython + all deps into the artifact.
2. **Terminal ritual** → a launcher process that starts the server and a window.
3. **Allowed-root coupling** (`_resolve_allowed_root` = `SECURITY_PREVIEW_ROOT`
   env or `os.getcwd()`) → replace with a per-scan root chosen in the UI via a
   native folder dialog. Path confinement stays, but is computed **relative to
   the folder the user just picked**, so it can never surprise them.

---

## 4. Architecture

```
security-preview.exe  (Briefcase/PyInstaller bundle: CPython + libs + static/)
        │
        ├─ launcher  (new: security_preview/desktop.py)
        │     1. pick a free 127.0.0.1 port
        │     2. start uvicorn(create_app(mode="desktop")) on a daemon thread
        │     3. wait for /healthz to answer
        │     4. webview.create_window("security-preview", http://127.0.0.1:<port>)
        │     5. webview.start()  ── blocks until window closed
        │     6. signal uvicorn to shut down, exit
        │
        └─ FastAPI app  (existing server/app.py, two small additions)
              • GET /healthz            → {"ok": true}
              • POST /api/pick-folder   → opens native dir dialog, returns path
                                          (desktop mode only; 404 in browser mode)
              • POST /api/scan          → unchanged contract, root = request-supplied
```

### 4.1 Why pywebview (not Electron/Tauri/system browser)

| Option | Verdict |
|---|---|
| **pywebview** | ✅ Pure-Python, ~1 dep. Windows uses built-in Edge **WebView2** (present on Win 11), macOS uses WKWebView, Linux uses WebKitGTK. Gives us a real window + native file dialogs. |
| System browser (`webbrowser.open`) | ⚠️ Works, but it's a browser tab, not an "app"; no native folder picker; user sees `localhost`. Keep as the headless fallback. |
| Electron / Tauri | ❌ Adds a Node/Rust toolchain and hundreds of MB (Electron) or a second language (Tauri) for a UI we already have as static HTML. |

### 4.2 Why Briefcase (primary) with PyInstaller as the fallback

| | Briefcase (BeeWare) | PyInstaller + Inno Setup |
|---|---|---|
| Windows output | `.msi` / signed installer + Start-Menu & desktop shortcut + icon | `--onefile .exe`; installer & shortcuts hand-rolled in Inno Setup |
| macOS output | `.app` + `.dmg`, notarization hooks | `.app` via extra config |
| Linux output | AppImage / `.deb` / `.rpm` | AppImage via extra tooling |
| Effort | One `pyproject.toml` table + icon set | More manual, but fewer surprises with native deps |
| Recommendation | **Use for the shipping installers.** | Keep a PyInstaller spec for a quick portable `.exe` and CI smoke. |

---

## 5. Implementation phases

### Phase D0 — `serve` quality-of-life (ship independently, no packaging)

Files: `src/security_preview/cli.py`, `src/security_preview/server/app.py`

- `serve --port 0` (new default) → bind an OS-assigned free port; print the
  resolved URL.
- `serve --open / --no-open` (default `--open`) → `webbrowser.open(url)` once the
  server answers `/healthz`.
- Add `GET /healthz` to the app.
- Quiet uvicorn: `log_level="warning"`, no access log; print one
  `security-preview → http://127.0.0.1:<port>  (Ctrl+C to stop)` line.
- Docs: update `SKILL.md` §serve, `docs/USAGE.md`, `security-preview-test-plan.md`
  CLI-40…43.

**Outcome:** even the terminal path stops requiring a hand-typed URL.

### Phase D1 — decouple the scan root from cwd/env

Files: `src/security_preview/server/app.py`, `tests/test_server.py`

- `create_app(mode: str = "browser", allowed_root: str | None = None)`.
- `POST /api/scan` request gains the picked folder as an **absolute `path`**;
  the server confines `..`/symlink escapes **relative to that path's own real
  directory** (i.e. the picked folder *is* the root for that request). No global
  root.
- `browser` mode keeps a soft default root (user home) + the free-text field for
  when there's no native picker.
- Remove `SECURITY_PREVIEW_ROOT` from code and docs (leave a one-line note in
  `docs/USAGE.md` that it's gone).
- Update tests API-06…11 to the new model (escape attempts still 400).

### Phase D2 — desktop launcher + native folder picker

New file: `src/security_preview/desktop.py`
Files: `src/security_preview/server/app.py`, `src/security_preview/server/static/index.html`,
`pyproject.toml`

- `desktop.py`: free-port pick → uvicorn on daemon thread → poll `/healthz`
  (timeout 10 s) → `webview.create_window(...)` → on close, `server.should_exit`.
- `POST /api/pick-folder` (desktop mode only): calls
  `window.create_file_dialog(webview.FOLDER_DIALOG)`, returns `{path}` or
  `{cancelled: true}`. Returns 404 in browser mode.
- `index.html`: add a **"Choose folder…"** button next to the path field.
  Desktop mode → button calls `/api/pick-folder` and fills the field.
  Browser mode → button hidden, field stays free-text. A `GET /healthz` /
  `window.pywebview` check picks the mode client-side.
- `pyproject.toml`:
  - `dependencies` unchanged for the library;
  - new optional group `desktop = ["pywebview>=5.0"]`;
  - new console entry `security-preview-desktop = "security_preview.desktop:main"`.
- `cli.py`: `serve --desktop` → delegates to `desktop.main()` (nice for dev).

### Phase D3 — Briefcase packaging

Files: `pyproject.toml` (`[tool.briefcase...]` tables), `resources/icons/*`,
`resources/installer/*`

- `[tool.briefcase.app.security-preview]`: `formal_name`, `bundle`
  (`com.<org>.securitypreview`), `icon`, `sources = ["src/security_preview"]`,
  `requires` = runtime deps + `pywebview`.
- Per-target tables for `windows`, `macOS`, `linux`.
- Icon set: `.ico` (Win), `.icns` (mac), PNG ladder (Linux) — from one 1024²
  master in `resources/icons/`.
- `briefcase create/build/run/package` per OS.
- Windows: ensure the **WebView2 evergreen runtime** is present — add the
  bootstrapper to the installer (or detect + prompt) for Win 10 machines that
  lack it. Win 11 ships it.

### Phase D4 — CI, signing, release

Files: `.github/workflows/desktop-release.yml`

- Matrix build on `windows-latest`, `macos-latest`, `ubuntu-latest`.
- `pytest -q` gate → `briefcase package` → upload installers as release assets on
  a `v*` tag.
- Code signing: Windows Authenticode cert + `signtool`; macOS Developer-ID +
  `notarytool`. Secrets in CI. (If certs aren't available yet: ship unsigned with
  a documented SmartScreen / Gatekeeper "allow" step, track signing as a
  follow-up.)
- PyInstaller `--onefile` portable `.exe` built in the same workflow as a
  no-install option.

### Phase D5 — Windows Explorer right-click (optional, high-value)

Files: `resources/installer/context-menu.reg` (or Inno Setup `[Registry]`)

- Add `HKCR\Directory\shell\SecurityPreview` and
  `HKCR\Directory\Background\shell\SecurityPreview` verbs →
  `security-preview.exe --scan "%V"`.
- `desktop.py` accepts an optional `--scan <path>` → opens the window with that
  folder pre-selected and kicks off the scan.
- Installer checkbox: "Add 'Scan with security-preview' to the folder right-click
  menu". Uninstaller removes the keys.

---

## 6. UX details

- **First run:** window opens centered, ~1100×760, min ~900×600, app icon in
  titlebar & taskbar. Empty state per design brief §3 artboard 1, plus the
  "Choose folder…" button.
- **No folder chosen:** Scan button disabled; hint text "Choose a folder to
  scan".
- **Scanning:** progress per brief §3 artboard 3; window not resizable-broken;
  closing mid-scan cancels and exits cleanly.
- **Offline:** the app never needs the network to start; the **Offline** checkbox
  still controls OSV/NVD as today.
- **Multiple windows:** single-window app; launching again focuses the existing
  window (pywebview single-instance guard) — or is allowed as a fresh scan,
  decide during D2 (default: focus existing).
- **Errors (bad path / 400 / 504):** inline, recoverable, per brief EdgeStates.

---

## 7. Security review points

- Server still binds `127.0.0.1` only; the bundled app must not change that.
- `POST /api/scan` confinement logic is retained; D1 changes *where* the root
  comes from, not *whether* escapes are blocked. Re-run test-plan §6.3 SEC-01.
- `/api/pick-folder` only exists in desktop mode and only opens a dialog — it
  performs no filesystem writes and returns a path the user explicitly picked.
- No new remote resources in `index.html` (design brief §2 restriction holds).
- Bundled Python: pin all deps; run `security-preview scan` on the build tree in
  CI (dogfood) before packaging.
- Signed installers so users aren't trained to click through SmartScreen.

---

## 8. Testing additions (fold into `security-preview-test-plan.md`)

| ID | Case |
|---|---|
| DESK-01 | Fresh Windows 11 VM, no Python: run installer → desktop icon present → double-click → window opens < 5 s → scan a folder → results shown. |
| DESK-02 | Same on macOS (`.app` from `.dmg`) and Linux (AppImage). |
| DESK-03 | "Choose folder…" opens the native dialog; cancel leaves the field unchanged; pick fills an absolute path. |
| DESK-04 | Scan a folder on a **different drive / outside any "root"** — succeeds (no root coupling). |
| DESK-05 | `..`, symlink-to-`/etc`, UNC path in the free-text field → still 400. |
| DESK-06 | Close window mid-scan → process exits, port freed, no orphan `uvicorn`. |
| DESK-07 | Launch twice → single window focused (or defined behaviour). |
| DESK-08 | Offline machine (no NIC) → app starts, scans with Offline checked, PARTIAL banner shown. |
| DESK-09 | WebView2 missing (Win 10 clean) → installer bootstraps it or the app prompts with a working link. |
| DESK-10 | Explorer right-click "Scan with security-preview" on a folder → app opens pre-pointed and scans. |
| DESK-11 | Uninstaller removes app, shortcuts, and the context-menu keys. |
| DESK-12 | Antivirus / SmartScreen: signed build shows publisher, no hard block. |
| DESK-13 | `security-preview serve` (headless, no pywebview installed) still works — browser fallback, `--open`. |

---

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| pywebview native-dep quirks in a frozen bundle (WebKitGTK on Linux, WebView2 on Win) | Prototype D2 + a Briefcase build on all three OSes **before** committing to D3 polish. Keep the system-browser fallback always working. |
| Bundle size (~40–60 MB) | Acceptable for a desktop app; strip test deps; `--exclude-module` in PyInstaller. |
| Code-signing certs not yet procured | Ship unsigned initially with a documented allow step; make signing a release blocker for v1.0, not for the first preview. |
| macOS notarization latency in CI | Cache the notarization; allow a manual re-run job. |
| Users on Win 10 without WebView2 | Installer bundles the evergreen bootstrapper (~2 MB stub, pulls the runtime). |
| Maintaining CLI + desktop entry points | They share `create_app()`; only `desktop.py` is extra. Contract tests cover both. |
| Auto-update expectations | Out of scope for v1; document "download the new installer". Revisit with `briefcase`'s update story or Squirrel/Sparkle later. |

---

## 10. Deliverables

1. `src/security_preview/desktop.py` — launcher (`main`, `--scan`, free-port,
   healthz-wait, window lifecycle).
2. `server/app.py` — `mode` param, `/healthz`, `/api/pick-folder`, root-per-scan.
3. `server/static/index.html` — "Choose folder…" button + mode detection.
4. `pyproject.toml` — `desktop` optional deps, `security-preview-desktop` script,
   `[tool.briefcase.*]` tables.
5. `resources/icons/` (1024² master + generated sets), `resources/installer/`
   (context-menu reg, Inno spec for the portable route).
6. `.github/workflows/desktop-release.yml` — 3-OS build/sign/package/publish.
7. `pyinstaller/security-preview.spec` — portable `.exe` + CI smoke.
8. Docs: `docs/DESKTOP.md` (install + uninstall + troubleshooting per OS),
   updates to `SKILL.md`, `docs/USAGE.md`, `security-preview-test-plan.md`.

---

## 11. Suggested sequencing

- **Preview quality (fast):** D0 → D1 → D2, plus a single unsigned Briefcase
  Windows installer built by hand. Gets "double-click an icon, pick a folder,
  scan" working for real users.
- **v1.0:** D3 (all three OSes) → D4 (CI + signing) → D5 (Explorer menu).
- D0 and D1 are independently shippable and improve the current `serve` even if
  the desktop bundle slips.

## 12. Effort estimate

| Phase | Estimate |
|---|---|
| D0 serve QoL | ~0.5 day |
| D1 root decoupling (+ test updates) | ~1–2 days |
| D2 launcher + folder picker + UI | ~2–3 days |
| D3 Briefcase packaging (3 OSes, icons) | ~2–3 days |
| D4 CI + signing | ~2–3 days (excl. cert procurement) |
| D5 Explorer right-click | ~0.5–1 day |
| **Total to signed v1.0** | **~10–14 days** |
| **Total to usable unsigned preview (D0–D2 + manual Win installer)** | **~4–6 days** |
