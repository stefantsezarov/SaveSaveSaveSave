#!/usr/bin/env python3
"""Draw the Spot the Trap preview cards (1200x630 PNG).

Each card shows the question and the scenario title, never the answer.
Run from the repository root:  python3 trap-cards.py
Needs Python Playwright with Chromium. Fonts are the site's own files.
"""
import html, json, pathlib, subprocess
from playwright.sync_api import sync_playwright

root = pathlib.Path(__file__).resolve().parent
data = json.loads(subprocess.check_output(
    ['node', '-e', "process.stdout.write(JSON.stringify(require('./challenges.js').CHALLENGES.map(c=>({id:c.id,title:c.title}))))"],
    cwd=root))
fonts = root / 'fonts'

def page(kicker, big, small):
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{{font-family:SG;src:url('{(fonts/'space-grotesk-latin-700-normal.woff2').as_uri()}')}}
@font-face{{font-family:PS;src:url('{(fonts/'ibm-plex-sans-latin-400-normal.woff2').as_uri()}')}}
@font-face{{font-family:PM;src:url('{(fonts/'ibm-plex-mono-latin-400-normal.woff2').as_uri()}')}}
html,body{{margin:0;width:1200px;height:630px;background:#08080C;color:#ECECF2;}}
.c{{box-sizing:border-box;width:1200px;height:630px;padding:72px 80px;display:flex;flex-direction:column;justify-content:space-between;
   border-left:14px solid #B98CFF;}}
.k{{font-family:PM;font-size:26px;letter-spacing:.14em;text-transform:uppercase;color:#B98CFF;}}
.b{{font-family:SG;font-size:76px;line-height:1.05;margin:0;}}
.s{{font-family:PS;font-size:38px;line-height:1.3;color:#C9C9D6;margin:22px 0 0;max-width:980px;}}
.f{{font-family:PM;font-size:26px;color:#9B9BAB;}}
</style></head><body><div class="c"><div class="k">{html.escape(kicker)}</div>
<div><p class="b">{html.escape(big)}</p><p class="s">{html.escape(small)}</p></div>
<div class="f">savesavesavesave.xyz · Spot the Trap</div></div></body></html>"""

cards = [('spot-the-trap.png', page('Spot the Trap', 'Would you spot the trap?', 'Read an invented message. Choose your next step. See the explanation.'))]
for c in data:
    cards.append((f"spot-the-trap-{c['id']}.png", page('Spot the Trap', 'Would you spot the trap?', c['title'])))

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={'width': 1200, 'height': 630})
    for name, doc in cards:
        tmp = root / '.card.html'
        tmp.write_text(doc, encoding='utf-8')
        pg.goto(tmp.as_uri()); pg.wait_for_timeout(300)
        pg.screenshot(path=str(root / name))
        tmp.unlink()
        print('wrote', name)
    b.close()
