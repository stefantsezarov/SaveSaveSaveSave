#!/usr/bin/env python3
"""
Regenerate the icon set in the new identity: hard squares, purple → blue.

Writes favicon.svg, apple-touch-icon.png (180) and og-image.png (1200x630).
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

# ------------------------------------------------------------- og-image
W, H = 1200, 630
og = Image.new("RGB", (W, H), INK)
og = radial_glow(og, (150, -40), 520, (153, 69, 255), 0.30)
og = radial_glow(og, (1180, -20), 460, (0, 209, 255), 0.14)
d = ImageDraw.Draw(og)

f_brand = ImageFont.truetype(POPPINS_B, 38)
f_h1 = ImageFont.truetype(POPPINS_B, 62)
f_sub = ImageFont.truetype(POPPINS_R, 26)
f_badge = ImageFont.truetype(MONO_B, 21)
f_foot = ImageFont.truetype(MONO_R, 19)
f_chains = ImageFont.truetype(MONO_R, 24)

# brand row
og.paste(mark(46), (76, 56))
x = 138
for word, colour in [("Save", TEXT), ("Save", (150, 150, 162)), ("Save", (104, 104, 118)), ("Save", ACCENT_TEXT)]:
    d.text((x, 54), word, font=f_brand, fill=colour)
    x += d.textlength(word, font=f_brand) + 2

chains = "EVM · Solana · Sui · TRON"
d.text((W - 76 - d.textlength(chains, font=f_chains), 66), chains, font=f_chains, fill=MUTED)

# gradient hairline, same device as the site header
line = diagonal_gradient((W - 152, 2), PURPLE, (24, 24, 32))
og.paste(line, (76, 124))

# headline
d.text((76, 176), "Is this a scam?", font=f_h1, fill=TEXT)
part1 = "Check the message "
d.text((76, 250), part1, font=f_h1, fill=TEXT)
d.text((76 + d.textlength(part1, font=f_h1), 250), "and", font=f_h1, fill=ACCENT_TEXT)
d.text((76, 324), "the address.", font=f_h1, fill=ACCENT_TEXT)

# subtitle
for i, line_text in enumerate([
    "Hidden instructions, prompt injections and disguised links — plus",
    "honeypots, mint authority and sanctioned addresses. Free. In your browser.",
]):
    d.text((76, 414 + i * 36), line_text, font=f_sub, fill=MUTED)

# verdict badges
bx = 76
for label, colour in [("PASS", SAFE), ("CAUTION", CAUTION), ("FAIL", DANGER), ("INSUFFICIENT DATA", MUTED)]:
    tw = d.textlength(label, font=f_badge)
    d.rectangle([bx, 500, bx + tw + 34, 544], outline=colour, width=2)
    d.text((bx + 17, 510), label, font=f_badge, fill=colour)
    bx += tw + 34 + 14

d.line([(76, 570), (W - 76, 570)], fill=(38, 38, 48), width=1)
d.text((76, 588), "savesavesavesave.xyz", font=f_foot, fill=ACCENT_TEXT)
tag = "Save your funds. Save your time. Save your trust. Save the regret."
d.text((W - 76 - d.textlength(tag, font=f_foot), 588), tag, font=f_foot, fill=(120, 120, 134))

og.save(REPO / "og-image.png")
print("wrote favicon.svg, apple-touch-icon.png, og-image.png")
