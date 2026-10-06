#!/usr/bin/env python3
"""
Regenerate the icon set in the new identity: hard squares, purple → blue.

Writes favicon.svg and apple-touch-icon.png (180).
og-image.png is rendered separately: node og-image.js
Nothing here is hand-edited afterwards; re-run it to change the mark.
"""
from PIL import Image, ImageDraw, ImageFont
import pathlib

REPO = pathlib.Path("/tmp/work")

INK = (8, 8, 12)
PURPLE = (153, 69, 255)
BLUE = (0, 209, 255)
TEXT = (236, 236, 242)
MUTED = (155, 155, 171)
ACCENT_TEXT = (185, 140, 255)
SAFE = (20, 241, 149)
CAUTION = (255, 176, 32)
DANGER = (255, 107, 129)

POPPINS_B = "/usr/share/fonts/truetype/google-fonts/Poppins-Bold.ttf"
POPPINS_M = "/usr/share/fonts/truetype/google-fonts/Poppins-Medium.ttf"
POPPINS_R = "/usr/share/fonts/truetype/google-fonts/Poppins-Regular.ttf"
MONO_B = "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf"
MONO_R = "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"


def diagonal_gradient(size, c0, c1):
    """135° linear gradient, the same angle the CSS uses for the mark."""
    w, h = size
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            t = (x / max(w - 1, 1) + y / max(h - 1, 1)) / 2
            px[x, y] = tuple(round(a + (b - a) * t) for a, b in zip(c0, c1))
    return img


def radial_glow(base, centre, radius, colour, strength):
    """Soft corner glow, matching the page background."""
    w, h = base.size
    glow = Image.new("L", (w, h), 0)
    d = ImageDraw.Draw(glow)
    steps = 60
    for i in range(steps, 0, -1):
        r = radius * i / steps
        a = int(strength * 255 * (1 - i / steps) ** 2)
        d.ellipse([centre[0] - r * 1.5, centre[1] - r, centre[0] + r * 1.5, centre[1] + r], fill=a)
    return Image.composite(Image.new("RGB", (w, h), colour), base, glow)


def mark(size):
    """The brand mark: a hard square in the gradient, with a dark check."""
    img = diagonal_gradient((size, size), PURPLE, BLUE)
    d = ImageDraw.Draw(img)
    w = max(2, round(size * 0.115))
    d.line([(size * 0.27, size * 0.52), (size * 0.44, size * 0.70), (size * 0.74, size * 0.31)],
           fill=INK, width=w, joint="curve")
    # Square the stroke ends by hand — PIL has no line cap control.
    for cx, cy in [(size * 0.27, size * 0.52), (size * 0.74, size * 0.31), (size * 0.44, size * 0.70)]:
        d.rectangle([cx - w / 2, cy - w / 2, cx + w / 2, cy + w / 2], fill=INK)
    return img


# ------------------------------------------------------------- favicon.svg
FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#9945FF"/>
      <stop offset="1" stop-color="#00D1FF"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" fill="#08080C"/>
  <rect x="8" y="8" width="48" height="48" fill="url(#g)"/>
  <path d="M19 33 l9 10 17-20" fill="none" stroke="#08080C" stroke-width="7"
        stroke-linecap="square" stroke-linejoin="miter"/>
</svg>
"""
(REPO / "favicon.svg").write_text(FAVICON, encoding="utf-8")

# ------------------------------------------------------ apple-touch-icon
touch = Image.new("RGB", (180, 180), INK)
touch.paste(mark(132), (24, 24))
touch.save(REPO / "apple-touch-icon.png")

# og-image.png is rendered from og-image.html by og-image.js.
print("wrote favicon.svg, apple-touch-icon.png")
