#!/usr/bin/env python3
"""Generate the 1024x1024 app-icon master at resources/icons/security-preview.png.

A placeholder mark -- a shield (security) holding a magnifier (static analysis) --
in the UI's terracotta accent. Replace with a designed logo when one exists, then
re-run `python scripts/build_desktop.py icons`.

Needs Pillow: python -m pip install pillow
"""
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parents[1] / "resources" / "icons" / "security-preview.png"

SIZE = 1024
SS = 4  # supersample factor for smooth edges

ACCENT = (217, 119, 87, 255)      # --accent  #d97757
ACCENT_DK = (204, 105, 68, 255)   # --accent-hover  #cc6944
PAPER = (250, 249, 246, 255)      # --ground  #faf9f6


def _rounded_rect(draw: ImageDraw.ImageDraw, box, radius, fill) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def _shield_points(cx: float, top: float, w: float, h: float) -> list[tuple[float, float]]:
    """A shield outline: flat shoulders, straight upper flanks, curved taper to a point."""
    half = w / 2
    shoulder = 0.38  # fraction of height where the straight flank ends
    steps = 48

    def flank_x(t: float) -> float:
        # Full width held through the upper flank, then a smooth taper to the tip.
        return half * (1.0 - t**2.4) ** 0.62

    right: list[tuple[float, float]] = []
    for i in range(steps + 1):
        t = i / steps
        right.append((cx + flank_x(t), top + h * shoulder + h * (1 - shoulder) * t))

    pts: list[tuple[float, float]] = [(cx - half, top), (cx + half, top)]
    pts += right
    pts += [(x - 2 * (x - cx), y) for x, y in reversed(right)]
    return pts


def main() -> int:
    c = SIZE * SS
    img = Image.new("RGBA", (c, c), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # App-tile background: full-bleed rounded square in the accent colour.
    margin = int(c * 0.06)
    _rounded_rect(d, (margin, margin, c - margin, c - margin), radius=int(c * 0.22), fill=ACCENT)

    # Shield.
    sw = c * 0.52
    sh = c * 0.60
    stop = c * 0.20
    scx = c / 2
    d.polygon(_shield_points(scx, stop, sw, sh), fill=PAPER)

    # Magnifier inside the shield.
    lens_cx = scx - c * 0.015
    lens_cy = stop + sh * 0.34
    lens_r = c * 0.125
    ring = int(c * 0.045)
    d.ellipse(
        (lens_cx - lens_r, lens_cy - lens_r, lens_cx + lens_r, lens_cy + lens_r),
        outline=ACCENT_DK,
        width=ring,
    )
    ang = math.radians(45)
    h0 = (lens_cx + math.cos(ang) * (lens_r + ring * 0.2),
          lens_cy + math.sin(ang) * (lens_r + ring * 0.2))
    h1 = (lens_cx + math.cos(ang) * (lens_r + c * 0.13),
          lens_cy + math.sin(ang) * (lens_r + c * 0.13))
    d.line([h0, h1], fill=ACCENT_DK, width=int(ring * 1.15))

    img = img.resize((SIZE, SIZE), Image.LANCZOS)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT)
    print("wrote", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
