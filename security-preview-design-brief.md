# security-preview — UI & Report Design Brief (Claude Design handoff)

Date: 2026-09-01
Companion to: `security-preview-plan.md`
Audience: Claude Design
Canvas (drafted from this brief): https://claude.ai/code/artifact/90379dde-2cfb-4287-bfc3-058bb240b1ee
— token + component sheet, desktop app screens (empty / scanning / results / detail
drawer / zero / partial / error), and the HTML report (screen + print). Concrete
token and severity-hex values are locked in `security-preview-plan.md` §6.

## 0. How to use this brief

`security-preview` has **one report information architecture** and **one atomic
component** (the Finding card). Everything below is rendered into **four targets**
that differ only by how much capability they are allowed:

| # | Target | What it is | Interactivity |
|---|--------|------------|---------------|
| A | **Desktop app UI** | Local browser window served at `127.0.0.1` | Full: input, scan, filter, sort, expand |
| B | **CLI report** | One self-contained `.html` file written to disk | Native only (`<details>`), print-ready |
| C-html | **Skill report (HTML)** | Same file as B, stricter | None. Zero JS. Safe to embed/preview |
| C-md | **Skill report (Markdown)** | One `.md` file | None. Plaintext-first, emoji severity |

> The skill's second output format is a **Markdown (`.md`) file** — a portable,
> plaintext-first report for pasting into a PR, issue, or chat. It is specified
> in §5.2.

Design targets A and B fully; C-html is B minus JavaScript; C-md is a
text specification plus a reference sample, not a visual comp.

---

## 1. Shared foundations (design once, reused by all targets)

### 1.1 Severity system

Five levels, fixed order, always shown with **three redundant signals** (color +
icon + text) so nothing depends on hue alone (WCAG 1.4.1).

| Level | Semantic role | Suggested hue (Design owns final value) | Icon shape | Markdown token |
|-------|---------------|------------------------------------------|------------|----------------|
| CRITICAL | Highest alarm | deep red | filled octagon / ✖ | `🔴 CRITICAL` |
| HIGH | Strong alarm | orange-red | filled triangle | `🟠 HIGH` |
| MEDIUM | Caution | amber | filled diamond | `🟡 MEDIUM` |
| LOW | Minor | slate / blue | filled circle | `🔵 LOW` |
| INFO | Note | neutral gray | outline circle / ℹ | `⚪ INFO` |

- Provide light **and** dark values; validate text-on-badge and badge-on-page
  contrast (≥ 4.5:1 text, ≥ 3:1 UI) in both.
- Palette is carried forward from Security Auditor's `theme.py` (warm neutral
  ground `#faf9f6`, ink `#131314`, terracotta accent `#d97757`) and still
  delivered as swappable tokens. Resolved values: `security-preview-plan.md` §6.
- A separate accent (dependency / SCA class, violet `#6941c6`) — not in the
  severity ramp — so vulnerable dependencies read as a different class from code
  findings.
- The interactive accent (terracotta) is **never** a severity badge; keep it on
  buttons / links / focus only, so it is not confused with HIGH.

### 1.2 Type & layout tokens

- System font stack only (`ui-sans-serif, -apple-system, Segoe UI, Roboto, …`);
  monospace stack for paths, code, line numbers.
- One type scale (e.g. 12 / 14 / 16 / 20 / 28), one spacing scale, one radius,
  one border/divider token. Same scale in app and document.
- Max readable content width for the report body (~ 820px in HTML; ~100 chars in MD).

### 1.3 The Finding card (the atomic unit)

Appears in every target. Required fields, in this order:

1. **Severity badge** (color + icon + label)
2. **Rule title** (e.g. "SQL Injection")
3. **CWE id** — hyperlink to MITRE in HTML; `CWE-89` + URL in MD
4. **Confidence** — HIGH / MEDIUM / LOW, as a small meter or tag
5. **Category tag** (Injection, Crypto, Auth, Config, …)
6. **Location** — `path/to/file.py:142`, monospace, copyable
7. **Code snippet** — 3–7 lines, offending line visually marked; **secrets masked**
8. **Description** — 1–3 sentences
9. **Remediation** — labelled **Vulnerable** vs **Secure** code blocks
10. **Illustrative CVEs** — chips/links (may be empty; hide section if so)

Collapsed state shows rows 1–6; expanded adds 7–10.

### 1.4 Report information architecture (all targets)

```
Report header      — tool name+version, scan target path, timestamp, duration
Summary            — counts per severity, files scanned, deps scanned, PARTIAL flag
[Partial banner]    — shown only if enrichment/SCA had failures (§1.5)
Code Findings       — grouped by severity desc, then by file
Vulnerable Dependencies — package@version, OSV/CVE ids, fixed version, advisory link
Skipped / Errors    — what did not run and why
Footer             — "non-LLM deterministic scan" disclaimer, re-run command
```

### 1.5 Cross-cutting states to design

Empty / options-filled / scanning / results / results+detail / **zero findings**
(reassuring, not blank) / **partial failure** (amber banner: "N enrichment lookups
failed — code findings are complete") / **hard error** (bad path, timeout).

### 1.6 Accessibility (all targets)

Color never the sole signal; visible focus rings in the app; semantic headings and
landmarks in HTML; one `<h1>`; alt/aria on icons; keyboard-operable filters and
disclosure controls in the app.

---

## 2. Consistency & restriction matrix

`✅ include · ❌ remove · ⚠ degraded form`

| Element | A. Desktop app | B. CLI HTML | C-html Skill | C-md Skill |
|---|---|---|---|---|
| Path input + scan button + options bar | ✅ | ❌ | ❌ | ❌ |
| Live filter / sort (severity, confidence, file) | ✅ (JS) | ❌ pre-sorted, static | ❌ | ❌ |
| Expand / collapse a finding | ✅ (JS) | ✅ `<details>` | ✅ `<details>` | ❌ flat `###` headings |
| Severity **color** | ✅ | ✅ | ✅ | ⚠ emoji only |
| Severity **icon + text label** | ✅ | ✅ | ✅ | ✅ (emoji + word) |
| Code snippet with offending line highlighted | ✅ | ✅ | ✅ | ⚠ fenced block, caption not highlight |
| CWE / CVE hyperlinks | ✅ | ✅ | ✅ | ✅ inline `[text](url)` |
| Download menu (md / json / sarif / html) | ✅ | ❌ (it *is* the artifact) | ❌ | ❌ |
| Scanning / progress indicator | ✅ | ❌ | ❌ | ❌ |
| Partial-failure / error banner | ✅ | ✅ static | ✅ static | ✅ blockquote callout |
| Dark-mode **toggle control** | ✅ | ❌ | ❌ | n/a |
| `prefers-color-scheme` response | ✅ | ✅ | ✅ | n/a |
| JavaScript | ✅ vanilla | ⚠ none preferred, ≤ tiny inline for collapse | ❌ absolutely none | ❌ none |
| External resources (fonts / CDN / remote img) | ❌ | ❌ | ❌ | ❌ |
| Print / PDF stylesheet | optional | ✅ required | ✅ required | n/a |
| Full-viewport / fixed-position chrome | ✅ | ⚠ avoid | ❌ (must embed safely) | n/a |

---

## 3. Target A — Desktop app UI

**Nature:** single-window local web app, JS allowed, served at `127.0.0.1` on a
random port, auto-opens in the user's browser.

### Screens / artboards to deliver
1. **Empty** — path field, options (checkboxes: *offline*, *scan dependencies*;
   *min confidence* select), primary **Scan** button, short "what this does" line.
2. **Options filled** — validation on the path field (exists / is a directory).
3. **Scanning** — progress (files walked, current stage: SAST → SCA → enrichment),
   cancel affordance.
4. **Results — list** — summary dashboard (stat tiles per severity) + scrollable
   findings list (collapsed cards) + filter/sort bar + download menu.
5. **Results — detail open** — a finding expanded inline, or a right-side drawer
   with the full card (rows 7–10).
6. **Zero findings** — positive confirmation, still shows what was scanned.
7. **Partial failure** — amber banner above results.
8. **Hard error** — invalid path / timeout / server error.

Also deliver a **component sheet**: severity badge, stat tile, filter chip,
confidence meter, finding card (collapsed + expanded), banner (info/amber/error),
code-snippet block, remediation block, CVE chip, download menu.

### Restrictions (A)
- **Desktop only.** Baseline 1280×800; support 1024–1920 width. **No mobile,
  no tablet, no touch layouts, no hamburger nav.**
- **Single window, single route.** No multi-page navigation, no client-side
  router, no stacked modals. Detail view is inline panel or one drawer.
- **No account surface of any kind:** no login, signup, billing, plans,
  onboarding wizard, sharing, "invite team", org/workspace switching, upgrade
  prompts, marketing hero.
- **No external resources:** system fonts only, icons as inline SVG, no CDN,
  no web fonts, no remote images, no analytics/telemetry/consent widgets.
- **No settings screen** beyond the inline options bar. No theming UI beyond a
  single light/dark toggle.
- JS is vanilla; Design delivers HTML + CSS + a written interaction spec, **not**
  a framework component tree.
- Every severity and confidence value carries an icon + label, not color alone.
- Must specify all states in §1.5 — no "happy path only" comps.

---

## 4. Target B — CLI report (HTML file only)

**Nature:** the `scan` command writes **one `.html` file** to disk. The user
double-clicks it; it opens via `file://` with no server and no network. It is a
**document, not an app**.

### Deliverables
- One **report document design**, annotated, covering: header + summary,
  partial banner, Code Findings section, Vulnerable Dependencies section,
  Skipped/Errors section, footer.
- A **table of contents** with in-page anchor links.
- A **`@media print`** treatment (see restrictions).
- Light and dark via `prefers-color-scheme`.

### Restrictions (B)
- **No application UI whatsoever:** no path input, no scan/run button, no forms,
  no live filter/sort, no live/refresh anything, no server calls.
- **No network, ever:** all CSS in a single inline `<style>`; **no web fonts**
  (system stack); images only inline SVG or `data:` URI; no `<script src>`;
  no `fetch`/`XHR`.
- **JavaScript: avoid entirely.** Use `<details>/<summary>` for collapse. If any
  inline JS is truly unavoidable it must be a few lines for disclosure only, and
  the page must be **fully readable with JS disabled**.
- **Print / PDF friendly (required):** sensible page margins, `break-inside:
  avoid` on finding cards, no clipped or scroll-only content, expand all
  `<details>` in print, show link URLs in print, no dark background ink-dump.
- **Light/dark by `prefers-color-scheme` only — no toggle control.**
- **Deterministic:** identical scan input → byte-identical HTML. No random ids,
  no unstable ordering, timestamp only in the header.
- **Self-contained size budget:** target < ~500 KB for a typical report.
- **Standalone document semantics:** exactly one `<h1>`, logical heading order,
  landmark regions, skip-to-content anchor.

---

## 5. Target C — Skill report (HTML **or** Markdown file)

**Nature:** the skill emits a **report-only artifact** for a coding harness
(Claude Code / Cursor) to embed, preview, paste into a PR or issue, or save. No
UI, no server, no interactivity, deterministic.

### 5.1 C-html — reuse target B, stricter

- **Identical design to B**, with these hard deltas:
  - **Zero `<script>` tags. No JS at all**, not even inline. Collapse is
    `<details>` only.
  - **Safe to embed inside another page / preview pane:** no `position: fixed`,
    no full-viewport takeover, no assumptions about being the top-level document,
    styles scoped under a single wrapper class, no global resets that would leak.
  - Full color coding via inline CSS (same tokens as B).
- All other B restrictions (no network, no fonts, deterministic, print rules,
  size budget) apply unchanged.

### 5.2 C-md — Markdown specification + reference sample

Deliver a **written spec** plus **one hand-authored `sample-report.md`** showing
the exact structure. Not a visual comp.

- **CommonMark + GitHub-Flavored Markdown only.** GFM tables allowed.
- **No embedded raw HTML, no `<style>`, no CSS, no `<details>`.**
- **"Color coding" = severity emoji + UPPERCASE word**, in the fixed order from
  §1.1. Must stay unambiguous in **pure plaintext with emoji stripped** (the word
  carries the meaning; the emoji is a bonus).
- **Structure / heading hierarchy (stable, for auto-TOC):**
  - `# security-preview report` (title)
  - `## Summary` — a GFM table of severity counts + a **PARTIAL** note if any
  - `## Code findings` → one `### 🔴 CRITICAL — SQL Injection — app/db.py:142` per finding
  - `## Vulnerable dependencies`
  - `## Skipped / errors`
- **Per-finding body:** description line; **Location** as inline code;
  fenced code block for the snippet with a language hint and a caption line
  (`> offending line: 142` — no in-block highlight is possible); remediation as
  two fenced blocks labelled **Vulnerable** / **Secure**; CVEs as a bullet list
  of inline links.
- **Line width ≤ ~100 chars**; keep tables narrow (≤ 4 columns).
- **Links:** inline `[CWE-89](https://cwe.mitre.org/…)` — no reference-style
  link definitions.
- **Partial/error notices** as `>` blockquote callouts.
- Must render correctly in: **GitHub, the Claude Code terminal pager, Cursor's
  Markdown preview, and plain `cat`.**

### Restrictions (C, both modes)
- **No UI. No interactivity. No JavaScript. No external resources. No network.**
- **Deterministic** output (same as B).
- Report-only: never includes scan controls, progress, or download menus.
- C-html must not visually or stylistically collide with a host page it is
  embedded in.

---

## 6. Global out of scope (do not design)

- Any authentication, account, team, billing, or sharing flow.
- Remote-URL / live-site scanning UI (removed from product scope).
- Mobile or tablet layouts for any target.
- A settings/preferences area beyond the desktop app's inline options bar.
- Framework-specific component code — deliver HTML + CSS + interaction notes.
- Marketing pages, logos, or brand identity (palette ships as swappable tokens).

---

## 7. Handoff checklist — what Claude Design returns

1. **Token sheet** — severity palette (light + dark, contrast-validated),
   SCA accent, type scale, spacing, radius, borders.
2. **Component sheet** — every component named in §1.3 and §3.
3. **Target A artboards** — the 8 screens in §3 + all states in §1.5.
4. **Target B artboard set** — the report document (screen view) + the print
   view, fully annotated, with the TOC.
5. **Target C-html note** — the diff list against B (what is removed / scoped).
6. **Target C-md deliverable** — the written spec (this §5.2) refined + a
   complete `sample-report.md` reference file.
7. **Redline pass** — annotate each target against the matrix in §2 so the
   removals are unambiguous to implementers.
