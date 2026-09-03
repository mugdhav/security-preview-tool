# Handoff: vulnascan landing page

## Overview

A single-screen marketing page for **vulnascan**, an open-source security auditor
for source code. The page has one job: state what vulnascan is in one line, then
present its three distribution flavours (desktop app, CLI tool, coding-harness
skill) side by side. It is designed to be hosted on GitHub Pages as the project's
`index.html`.

The defining constraint: **the intro and all three flavours must fit in one
viewport, with no scrolling**, at desktop widths. Below 700px the page is allowed
to stack and scroll.

## About the design files

The files in this bundle are **design references authored in HTML** — a prototype
of the intended look and layout, not production code to lift wholesale. The task
is to **recreate this design in the target codebase's environment** (Astro, Next,
Eleventy, plain HTML, whatever the project uses) with that codebase's established
patterns. If no environment exists yet — likely, since this is a GitHub Pages site
for a CLI/desktop tool — a single static `index.html` plus one stylesheet is the
correct choice; do not introduce a framework for one page.

Two things in the prototype are scaffolding and must NOT be carried over:

- `support.js`, `<x-dc>` and `<helmet>` are the design tool's runtime wrapper.
  Emit ordinary `<!DOCTYPE html><html><head>…` markup instead.
- `image-slot.js` / `<image-slot>` is a drag-and-drop placeholder for images the
  designer had not yet supplied. Replace each with a real `<img>` (see *Assets*).
- Styles in the prototype are inline because the design tool requires it. In the
  real page, move them to one stylesheet; keep the values exactly.

## Fidelity

**High-fidelity.** Colors, type, spacing and layout are final and should be
matched precisely. Every value is listed under *Design tokens* and *Screens*.
Copy is final — reproduce it verbatim.

## Screens / views

### Single screen: landing page

**Purpose.** A visitor arriving from GitHub or a link learns in one line what
vulnascan does, then picks the flavour that matches how they work and follows its
call to action.

**Page shell.** `height: 100vh`, `display: flex`, `flex-direction: column`,
`box-sizing: border-box`. Three children: nav (`flex: none`), content band
(`flex: 1 1 auto; min-height: 0`), footer (`flex: none`). Body font is the body
serif; background is the page ground.

> **Implementation note — the one thing that is easy to get wrong.** The content
> band must be allowed to shrink: it and its descendant column wrappers all carry
> `min-height: 0`, and the flavours grid uses
> `grid-template-rows: minmax(0, 1fr)`. Without those, grid/flex items default to
> `min-height: auto`, refuse to shrink below their content, and the cards spill
> through the footer instead of fitting. The image plates carry an explicit
> `height` (not `flex: 1`) for the same reason — a flexible plate collapses to
> zero when the band has no free space to distribute.

#### 1. Nav bar

- Layout: flex row, `align-items: center`, `gap: 24px`, padding
  `13px clamp(20px, 4vw, 48px)`, `border-bottom: 1px solid` divider.
- Brand cluster (`margin-right: auto` pushes the rest right): 24×24px logo mark,
  `gap: 10px`, then the wordmark "vulnascan" — heading serif, weight 600, 18px,
  `letter-spacing: .01em`. Lowercase, always; never title-case it.
- Text link: "Documentation" — 12.5px, `letter-spacing: .08em`,
  `text-transform: uppercase`, no underline, accent-700 ink.
- Button: "GitHub" — heading serif, 600, 13.5px, `line-height: 1.2`, ink text,
  `1px solid` accent border, `border-radius: 4px`, padding `8px 15px`,
  transparent background. Hover: `background: color-mix(in srgb, accent 10%, transparent)`.
  Outlined, never filled.

#### 2. Content band

`max-width: 1180px`, centred (`margin: 0 auto`), padding
`clamp(20px, 3.4vh, 52px) clamp(20px, 4vw, 48px)`, flex column,
`justify-content: flex-start`, `gap: clamp(18px, 3.2vh, 44px)`.

**Hero cluster** (flex column, `gap: clamp(10px, 1.6vh, 20px)`):

- `h1`: "Read the codebase like a proofreader reads a page."
  Heading serif, weight **400** (the display size takes the normal cut, never
  bold), `font-size: min(4.55vw, 54px)`, `line-height: 1.07`,
  `letter-spacing: -0.012em`, `margin-left: -0.042em` (optical left alignment for
  the serif's cap), **`white-space: nowrap`** — it is meant to hold one line across
  the full measure; the `vw` term is what keeps it fitting.
- `p`: "vulnascan audits a repository for security vulnerabilities and returns
  them as errata — file, line, severity, reason."
  Body serif, `font-size: min(1.6vw, 17px)`, `line-height: 1.5`,
  `white-space: nowrap`, ink at 78% opacity. Note the em dash and the lowercase
  product name.

**Hairline** between hero and flavours: `height: 1px`, `border: 0`,
`background:` divider.

**Flavours cluster** (flex column, `flex: 1 1 auto`, `min-height: 0`,
`gap: clamp(14px, 2.4vh, 30px)`):

- Kicker: "Three flavours, one engine" — 12.5px, `letter-spacing: .08em`,
  uppercase, accent-700, tabular figures.
- Grid: `display: grid`, `grid-template-columns: repeat(3, minmax(0, 1fr))`,
  `grid-template-rows: minmax(0, 1fr)`, `gap: clamp(26px, 3.4vw, 56px)`.
  **Equal-measure trick:** the vertical hairlines between columns are
  `border-left` + matching `padding-left` on the cards. Card 1 gets the same
  padding and a `1px solid transparent` border so all three text measures are
  identical, and the grid is pulled back into the page axis with
  `margin-left: calc(-1 * clamp(26px, 3.4vw, 56px) - 1px)`. If you draw the rules
  another way (e.g. pseudo-elements at the gutter centres), drop the negative
  margin with them.

#### 3. Flavour card (×3)

Flex column, `min-height: 0`, `gap: clamp(9px, 1.4vh, 16px)`,
`padding-left: clamp(26px, 3.4vw, 56px)`, `border-left: 1px solid` divider
(transparent on card 1).

1. **Header row** — flex, `align-items: baseline`, `gap: 10px`:
   - Numeral "01" / "02" / "03": heading serif, 400, 18px, accent, tabular figures.
   - `h2`: heading serif, 400, `clamp(22px, 1.9vw, 28px)`, `line-height: 1.1`,
     `letter-spacing: -0.005em`.
2. **Copy** — 14.5px, `line-height: 1.55`, ink at 78%. Two lines at the design
   width; keep it to two.
3. **Image plate** — `height: clamp(84px, 21vh, 200px)`, `flex: none`,
   `margin-top: 2px`, wrapped in the design system's `.plate` treatment:
   `filter: sepia(0.22) saturate(0.82) contrast(1.05)`, `6px solid` surface-color
   border, `outline: 1px solid` divider, `box-sizing: border-box`. The image
   inside should `object-fit: cover` the box.
4. **Foot block** — `margin-top: auto` (pins it to the card bottom),
   `padding-top: clamp(9px, 1.4vh, 15px)`, `border-top: 1px solid` divider,
   flex column, `gap: 5px`.

| # | Heading | Copy | Plate image | Foot line 1 | Foot line 2 |
| --- | --- | --- | --- | --- | --- |
| 01 | Desktop app | Read the findings as a bound report, severities in the margin. | Screenshot of the desktop report | Link: "Download for macOS, Windows, Linux" | "Universal build, 42 MB" |
| 02 | CLI tool | One binary. Exits non-zero above the severity gate you set. | Terminal screenshot | `code`: `vulnascan . --fail-on high` | "Homebrew, apt, Scoop, or go install" |
| 03 | Harness skill | Scans the diff before the commit, patch proposed in place. | Screenshot of the agent transcript | `code`: `/skills add vulnascan` | "Claude Code, Cursor, and MCP clients" |

Foot line 1 styling — links: heading serif, 600, 13.5px, no underline, accent-700.
Code: `ui-monospace, SFMono-Regular, Menlo, monospace`, 13px, `line-height: 1.4`,
ink. Foot line 2: 12px, ink at 60%.

#### 4. Footer

`border-top: 1px solid` divider, padding `11px clamp(20px, 4vw, 48px)`, flex row,
`flex-wrap: wrap`, `gap: 8px 26px`, `align-items: center`, 12px, ink at 70%.

- Left (`margin-right: auto`): "MIT licensed · 14 languages · analysis runs
  locally, nothing uploaded" (middle dots are `·`, U+00B7).
- Links: "Repository", "Report an issue" — no underline, accent-700.

## Interactions & behavior

The page is static — no JavaScript is required. All of it:

- **Links.** Nav "Documentation" → docs. Nav "GitHub", footer "Repository" → the
  repo. Footer "Report an issue" → the repo's issues. Card 01's download link →
  the latest release. In the prototype every href is a `https://github.com`
  placeholder; substitute real URLs.
- **Hover.** Links move from accent-700 to accent-600. The GitHub button takes a
  10% accent tint. Nothing else has a hover state.
- **Focus.** Global: `:focus-visible { outline: 2px solid accent; outline-offset: 2px; }`.
  Do not fall back to the browser's default ring.
- **No animation, no transitions, no loading or error states, no forms.**

### Responsive behavior

Two states only.

- **≥701px — the one-page layout.** Three columns; the whole page fits 100vh. The
  `vh`-based `clamp()` gaps and plate height absorb short viewports; the `vw`-based
  hero sizes absorb narrow ones. Verified target: at 925×540 nothing scrolls and
  no card crosses the footer.
- **≤700px — stacked.** `height: auto; min-height: 100vh` (scrolling allowed);
  flavours become one column, `gap: 36px`, negative margin removed, card
  `border-left`/`padding-left` removed, card `max-width: 62ch`; the hero `h1` and
  intro drop `nowrap` and become 30px / 15.5px; plates become `height: 210px`.

Both breakpoint bodies exist verbatim in the prototype's `<style>` block.

## State management

None. No state variables, no data fetching, no client-side routing.

## Design tokens

From the "Classical" design system: an editorial book aesthetic — serif display
over serif text, hairline rules, color applied as stroke rather than fill,
photographs matted like tipped-in plates. Rules worth keeping: buttons are
outlined not filled; large fills stay off the page; display type is never bold;
figures are tabular wherever they stand as numbers (`font-feature-settings: 'tnum'`).

### Colors (Paper scheme — the one to ship)

| Token | Value | Used for |
| --- | --- | --- |
| `--color-bg` | `#f3f2f2` | Page ground |
| `--color-surface` | `#eae9e9` | Plate mat border |
| `--color-text` | `#201f1d` | Ink; body copy at 78%, secondary at 60–70% |
| `--color-accent` | `#b68235` | Numerals, borders, focus ring (large/UI only — 3:1) |
| `--color-accent-600` | `#a06f24` | Link hover |
| `--color-accent-700` | `#7d5411` | Small accent text and links (6:1) |
| `--color-divider` | `color-mix(in srgb, #201f1d 16%, transparent)` | All hairlines |

Opacity ramps are written as `color-mix(in srgb, var(--color-text) N%, transparent)`
with N = 78 (body), 70 (footer), 60 (card meta).

Three alternative schemes ship in this bundle as drop-in replacements — same
layout, only the token block and logo colorway differ. If the developer needs to
switch, swap the `:root` overrides and the logo file:

| Scheme | bg | surface | text | accent / 600 / 700 | Notes |
| --- | --- | --- | --- | --- | --- |
| Ink | `#100f0d` | `#1c1a17` | `#f3f2f2` | `#c99a4e` / `#e2bd7c` / `#d3a659` | Nav + footer bands `#0a0908`; plate filter gains `brightness(0.9)`; divider is `#f3f2f2` at 18% |
| Oxblood | `#f6f1e9` | `#ece4d8` | `#241a19` | `#8c3230` / `#732725` / `#601f1e` | Nav + footer take surface; `h1` set in accent-700; divider ink at 18% |
| Blueprint | `#16243a` | `#101b2c` | `#e8eaee` | `#7ea6d8` / `#a3c3e8` / `#9dbde3` | Nav + footer `#101b2c`; `h1` in accent-700; divider `#e8eaee` at 20% |

### Typography

- Heading: **Cormorant Garamond** — weight 400 at display sizes, 600 for interface
  headings (wordmark, buttons, card links). Never bold.
- Body: **Lora** — weight 400.
- Mono: `ui-monospace, SFMono-Regular, Menlo, monospace` (system stack, no webfont).
- Both webfonts are Google Fonts; self-host or link them, and set
  `font-display: swap`.

Scale as used: 54px/1.07 h1 · 28px/1.1 h2 · 18px numerals and wordmark ·
17px/1.5 intro · 14.5px/1.55 card copy · 13.5px links and buttons · 13px code ·
12.5px kicker and nav link · 12px card meta and footer.

### Spacing, radius, elevation

Spacing scale (1.15× density): 4.6 · 9.2 · 13.8 · 18.4 · 27.6 · 36.8px. This page
mostly uses `clamp()` gaps keyed to viewport height — the exact expressions are in
the layout notes above. Radius: 2 / 4 / 8px (`--radius-sm/md/lg`); the GitHub
button uses 4px. No shadows anywhere on this page — elevation in this system is a
whisper, and a flat editorial page needs none.

## Assets

| File | What it is |
| --- | --- |
| `marks/mark-d-ink.svg` | The vulnascan logo for light grounds. Hand-drawn vector: a loupe rim over a 3×3 cipher grid with three cells struck in gold, gold handle. Ink strokes `#201f1d`, gold `#b68235`. |
| `marks/mark-d.svg` | Same mark for dark grounds (paper-white strokes) — pairs with the Ink scheme. |
| `marks/mark-d-oxblood.svg`, `marks/mark-d-blueprint.svg` | Mark in the alternative colorways. |
| `exports/mark-d-1024.png`, `-256.png` | Transparent-background PNG renders. |
| `exports/mark-d.ico` | Multi-size favicon (16/32/48/64/128/256) — wire this up as the page's `<link rel="icon">`. |

**Missing assets — the three plate images.** The prototype leaves them as
drag-and-drop placeholders because no real screenshots existed yet. The developer
(or designer) needs to supply: (1) the desktop app showing a findings report,
(2) a terminal running `vulnascan . --fail-on high`, (3) a coding-agent transcript
proposing a patch. All three render inside the `.plate` treatment at
`object-fit: cover`; a 16:9-ish crop suits the box. Until they exist, a flat
surface-colored rectangle is a better placeholder than a stretched image.

No icon set is used on this page. If icons are added later, the design system
specifies Lucide.

## Files in this bundle

| File | What it is |
| --- | --- |
| `Landing Paper.dc.html` | **The design to build.** Light ground, gold accent. |
| `Landing Ink.dc.html` | Alternative scheme: gold on near-black. |
| `Landing Oxblood.dc.html` | Alternative scheme: warm cream, deep red display. |
| `Landing Blueprint.dc.html` | Alternative scheme: navy, pale blue display. |
| `styles.css` | The Classical design system stylesheet — the source of every token, and of the `.plate` rule. Take values from here rather than re-deriving them. |
| `marks/`, `exports/` | Logo vectors, PNG renders, favicon. |

To view a design file, open it in a browser — they are self-contained apart from
`styles.css` and the runtime wrapper noted above, and the layout renders as
designed.

## Definition of done

- At 1280×800 and at 925×540, the nav, hero, all three flavour cards and the
  footer are fully visible with **no scrollbar** and no element overlapping the
  footer.
- All three card text measures are equal in width.
- The `h1` and the intro paragraph each hold a single line at ≥701px.
- Below 700px the page stacks to one column, the column hairlines are gone, and
  scrolling is expected.
- Keyboard focus shows the 2px accent ring on every link and button.
- Copy matches this document verbatim, including the lowercase "vulnascan".
