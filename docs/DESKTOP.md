# Vulnascan desktop app

The **no-Python, no-terminal, no-config** way to run Vulnascan: double-click the
icon, choose a folder, read the report. Nothing leaves your machine except
optional CVE lookups (OSV / NVD); the app binds `127.0.0.1` only and works fully
offline.

## Screenshots

Empty state — paste or pick a folder, set options, press **Scan** (disabled
until a path is set):

![Empty state](images/app-empty.png)

Desktop mode adds a **Choose folder…** button that opens the native OS directory
dialog:

![Desktop mode with the Choose folder button](images/app-desktop-picker.png)

Progress view — the four stages (Discover files → SAST rules → Dependency scan →
CVE enrichment) with a running elapsed timer:

![Scanning](images/app-scanning.png)

Results — severity tiles, a files / dependencies / duration line, then findings
grouped by severity:

![Results](images/app-results.png)

Finding detail — click any row for the drawer: the masked snippet with the
offending line highlighted, **Copy path**, "What's wrong", the
**Vulnerable → Secure** remediation pair, and illustrative CVEs for the same CWE:

![Finding detail drawer](images/app-finding-detail.png)

## Install

Download the build for your OS from the
[**Releases page**](https://github.com/mugdhav/security-preview-tool/releases).

### Windows

1. Download `Vulnascan-<version>.msi` (installer) **or** `vulnascan.exe`
   (portable, no install) / `vulnascan-setup-<version>.exe` (Inno installer).
2. Run it. The installer adds a **Start-Menu** and **Desktop** shortcut.
3. First launch: if Windows SmartScreen shows *"Windows protected your PC"* on an
   unsigned build, click **More info → Run anyway**. (Signed builds show the
   publisher and skip this.)
4. Windows 11 already has the Edge **WebView2** runtime. On Windows 10 the
   installer pulls it in automatically; if the app reports it missing, install
   *Evergreen WebView2 Runtime* from Microsoft and relaunch.

### macOS

1. Open `Vulnascan-<version>.dmg`, drag the app to **Applications**.
2. First launch on an unsigned build: **right-click → Open → Open**, or
   *System Settings → Privacy & Security → Open Anyway*.

### Linux

1. `chmod +x Vulnascan-<version>.AppImage && ./Vulnascan-<version>.AppImage`
   — **or** install the `.deb` / `.rpm`.
2. The AppImage bundles its Python; the host needs a WebKitGTK runtime
   (`gir1.2-webkit2-4.1` on Debian/Ubuntu, `webkit2gtk` on Fedora). If the
   window fails to open, the app falls back to your default browser.

### From a Python install

No packaged build needed: `security-preview serve` opens the same UI in your
browser, and `pip install "security-preview[desktop]"` adds `pywebview` for the
native window. See [Headless / server](#headless--server) and
[`USAGE.md`](USAGE.md).

## Running a scan

| Step | How |
|---|---|
| Choose what to scan | **Choose folder…** → native OS dialog → any directory, any drive. The folder you pick *is* the scan root — there is no global allowed root; `..` and symlink escapes in a typed path are still rejected with HTTP 400. |
| Set options | The scan-bar controls below — hover any of them (or the `local only` badge) for the same tooltip text |
| Run | **Scan** (disabled until a folder is chosen) |
| Stop | close the window — a scan in progress is cancelled cleanly |
| Save a report | `Download ▾` → `.json` in-app; `.md` / `.sarif` / `.html` via the CLI |

### Options

| Control | What it does |
|---|---|
| **Offline** | Skip every network call (OSV dependency lookups and NVD CVE examples). Pattern and dependency-manifest analysis still run in full; the report is marked PARTIAL to flag the skipped enrichment. Use on air-gapped or CI machines. |
| **Scan dependencies** | Also parse lockfiles (`requirements.txt`, `package-lock.json`, `go.mod`, `pom.xml`, …) and match every dependency against the OSV known-vulnerability database. Turn off to run pattern rules only. |
| **Min confidence** | Hide findings whose confidence is below this level. Confidence is how sure a rule is that this specific match is real — it is independent of severity. High = only near-certain matches; Medium = the balanced default; Low = show everything, including weak or heuristic matches. |
| **`127.0.0.1 · local only`** badge | The app is bound to 127.0.0.1 and refuses connections from any other machine. Your source code is read on this computer and never uploaded. The only traffic that can leave is optional CVE lookups to OSV and NVD — and the Offline switch disables those too. |

### Explorer / Finder right-click (when installed)

`vulnascan-desktop --scan "<folder>"` (alias: `security-preview-desktop`) opens
the window pre-pointed at that folder and starts scanning.

On Windows, the **Inno Setup** installer (`vulnascan-setup-<version>.exe`) offers
a checkbox *"Add 'Scan with Vulnascan' to the folder right-click menu"*. When
ticked it writes `HKCU\Software\Classes\Directory\shell\SecurityPreview` (and the
`Background` verb for right-clicking inside a folder), both running
`vulnascan.exe --scan "%V"`. The uninstaller removes them. For a portable copy,
edit the two exe paths in `resources/installer/context-menu.reg` and double-click
it; `context-menu-uninstall.reg` reverses it. The Briefcase `.msi` does **not**
add the verb yet (needs a WiX fragment).

## Interpreting the report

**Severity tiles** — CRITICAL / HIGH / MEDIUM / LOW / INFO, plus **Vuln deps**,
in fixed order, then a files / dependencies / duration line. An amber
**PARTIAL** banner above the tiles means some work could not finish (network
failure, oversized file, parse error); the `errors` list says what was skipped,
and the code findings are still complete.

**Code findings** — grouped by severity, highest first. Toggle the severity
chips to filter, **Group by file**, or re-sort by severity / confidence / file.
Each row opens the detail drawer:

- the masked code snippet with the offending line highlighted — secret values
  show as `sk_live_••••…`, masked before they ever reach the report;
- **What's wrong** — a plain-language description of the risk;
- **Vulnerable → Secure** — a before/after remediation code pair;
- the **CWE** id, and any illustrative CVEs for that CWE (a link for context,
  not a claim that your code contains that specific CVE).

**Vulnerable dependencies** — a separate section: package, version, ecosystem,
advisory ids (OSV / GHSA / CVE), severity, the fixed version when known, and
which lockfile the package came from. These are real known-vulnerability matches
from OSV, distinct from the pattern-based code findings.

**Saving** — `Download ▾` gives you `.json` from the app directly; for `.md`,
`.sarif`, or `.html`, run the CLI: `security-preview scan <path> --format markdown
--out SECURITY_REPORT.md` (see [`USAGE.md`](USAGE.md)).

## Headless / server

No window needed? `security-preview serve` still works:

```
security-preview serve                # OS-assigned port, opens your browser
security-preview serve --no-open      # just prints the URL
security-preview serve --desktop      # force the native window (needs pywebview)
```

`pip install "security-preview[desktop]"` adds `pywebview` for the native window;
without it, `serve` uses the system browser.

## Building the installers

```
python -m pip install -e ".[package]"      # pywebview + briefcase + pyinstaller

python scripts/build_desktop.py check      # launcher smoke test (no network)
python scripts/build_desktop.py icons      # fan resources/icons/vulnascan.png out to .icns + PNG ladder
python scripts/build_desktop.py installer  # Briefcase installer for this OS
python scripts/build_desktop.py portable   # one-file PyInstaller .exe
python scripts/build_desktop.py inno       # Windows: Inno Setup installer (needs iscc)
```

CI (`.github/workflows/desktop-release.yml`) builds all three OSes on a `v*` tag,
runs the test suite + a self-scan first, and attaches the installers to the
GitHub Release.

**Signing is dormant**: each signing step no-ops until its repo secret exists,
and the build ships unsigned with the allow-steps above until then. Set
`WINDOWS_PFX_BASE64` + `WINDOWS_PFX_PASSWORD` for Authenticode; and
`APPLE_CERT_P12_BASE64`, `APPLE_CERT_P12_PASSWORD`, `APPLE_IDENTITY`,
`APPLE_TEAM_ID`, `APPLE_NOTARY_USER`, `APPLE_NOTARY_PASSWORD` for the Apple
Developer ID + notarization path.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Window never appears | WebView2 (Win) / WebKitGTK (Linux) runtime missing — see Install. The app falls back to the browser. |
| "server did not become healthy in time" | Another process may hold the port; relaunch. Logs print to the console for the portable `.exe`. |
| SmartScreen / Gatekeeper block | Unsigned preview build — use the allow-step above. |
| Scan seems stuck | Large tree; there is a 120 s wall-clock budget, after which the scan returns HTTP 504 and the UI shows an error. |
