#!/usr/bin/env python3
"""Share-card CONCEPTS for Spot the Trap, for design review.

Writes design/share-cards/<id>-concept.png (1200x630) and
design/share-cards/phone-preview.png (all four at phone size).
Nothing here is published: design/ is in .assetsignore, and the live
cards (trap-cards.py) are unchanged until the concepts are approved.

Rules held: question and title only; no answer letters, ticks, crosses,
scores or "you solved it"; no real brand, logo, account number, payment
address or runnable command. Run:  python3 trap-cards-design.py
"""
import html, json, pathlib, subprocess, sys
LIVE = '--live' in sys.argv  # approved 21 Oct 2026: write the published scenario cards
from playwright.sync_api import sync_playwright

root = pathlib.Path(__file__).resolve().parent
out = root / 'design' / 'share-cards'
out.mkdir(parents=True, exist_ok=True)
data = {c['id']: c['title'] for c in json.loads(subprocess.check_output(
    ['node', '-e', "process.stdout.write(JSON.stringify(require('./challenges.js').CHALLENGES.map(c=>({id:c.id,title:c.title}))))"],
    cwd=root))}
F = root / 'fonts'
P, C, T, M = '#B98CFF', '#00D1FF', '#ECECF2', '#9B9BAB'   # purple, cyan, pale text, muted

def t(x, y, s, size, color=T, weight='', family='PS', anchor='start'):
    return f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" fill="{color}" text-anchor="{anchor}" {weight}>{html.escape(s)}</text>'

# Illustrations live in a 400x400 box. Outline style, two accents, no logos.
ILLU = {
 'deposit-job': f'''
  <rect x="10" y="40" width="230" height="64" rx="14" fill="none" stroke="{P}" stroke-width="3"/>
  <line x1="34" y1="64" x2="200" y2="64" stroke="{M}" stroke-width="6" stroke-linecap="round"/>
  <line x1="34" y1="84" x2="150" y2="84" stroke="{M}" stroke-width="6" stroke-linecap="round"/>
  <rect x="10" y="124" width="270" height="64" rx="14" fill="none" stroke="{P}" stroke-width="3"/>
  {t(32, 164, 'Before you withdraw…', 22, T)}
  <rect x="200" y="226" width="190" height="130" rx="12" fill="none" stroke="{C}" stroke-width="3"/>
  {t(222, 262, 'BALANCE', 18, C, family='PM')}
  {t(222, 320, '$486', 52, T, family='SG')}''',
 'safe-account': f'''
  <rect x="20" y="30" width="220" height="330" rx="28" fill="none" stroke="{P}" stroke-width="3"/>
  {t(130, 92, 'Incoming call', 20, M, anchor='middle')}
  {t(130, 132, 'Bank security', 28, T, family='SG', anchor='middle')}
  <path d="M100 210 q-8 -16 6 -24 l14 -6 l12 22 l-10 8 q8 22 30 30 l8 -10 l22 12 l-6 14 q-8 14 -24 6 q-44 -16 -52 -52 z" fill="none" stroke="{P}" stroke-width="3" stroke-linejoin="round"/>
  <circle cx="320" cy="200" r="34" fill="none" stroke="{C}" stroke-width="3"/>
  <path d="M262 316 q58 -96 116 0" fill="none" stroke="{C}" stroke-width="3"/>
  <rect x="262" y="330" width="116" height="30" rx="6" fill="none" stroke="{C}" stroke-width="3"/>''',
 'human-check': f'''
  <rect x="10" y="40" width="380" height="250" rx="12" fill="none" stroke="{P}" stroke-width="3"/>
  <line x1="10" y1="82" x2="390" y2="82" stroke="{P}" stroke-width="3"/>
  <circle cx="36" cy="61" r="7" fill="{P}"/><circle cx="60" cy="61" r="7" fill="{P}"/><circle cx="84" cy="61" r="7" fill="{P}"/>
  {t(200, 160, 'Verify you are human', 30, T, family='SG', anchor='middle')}
  <rect x="120" y="196" width="160" height="40" rx="8" fill="none" stroke="{M}" stroke-width="3"/>
  <rect x="90" y="312" width="220" height="74" rx="10" fill="none" stroke="{C}" stroke-width="3"/>
  ''' + ''.join(f'<rect x="{106 + i*40}" y="{326 + r*24}" width="28" height="16" rx="3" fill="none" stroke="{C}" stroke-width="2"/>' for r in range(2) for i in range(5)),
 'delivery-update': f'''
  <path d="M30 170 l100 -50 l100 50 l-100 50 z" fill="none" stroke="{P}" stroke-width="3"/>
  <path d="M30 170 v110 l100 50 v-110" fill="none" stroke="{P}" stroke-width="3"/>
  <path d="M230 170 v110 l-100 50" fill="none" stroke="{P}" stroke-width="3"/>
  <path d="M80 145 l100 50" fill="none" stroke="{P}" stroke-width="3"/>
  <rect x="170" y="40" width="220" height="110" rx="12" fill="none" stroke="{C}" stroke-width="3"/>
  {t(190, 82, 'Delivery update', 22, C, family='PM')}
  {t(190, 126, '14:00–16:00', 34, T, family='SG')}''',
}

def wrap(s, n):
    words, lines, cur = s.split(), [], ''
    for w in words:
        if len(cur) + len(w) + 1 > n and cur: lines.append(cur); cur = w
        else: cur = (cur + ' ' + w).strip()
    return lines + [cur]

def card(cid, title):
    lines = wrap(title, 22)
    title_svg = ''.join(t(80, 330 + i * 56, l, 48, T, family='SG') for i, l in enumerate(lines))
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{{font-family:SG;src:url('{(F/'space-grotesk-latin-700-normal.woff2').as_uri()}')}}
@font-face{{font-family:PS;src:url('{(F/'ibm-plex-sans-latin-400-normal.woff2').as_uri()}')}}
@font-face{{font-family:PM;src:url('{(F/'ibm-plex-mono-latin-400-normal.woff2').as_uri()}')}}
html,body{{margin:0;background:#08080C}}</style></head><body>
<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="#08080C"/>
  <rect x="0" y="0" width="1200" height="8" fill="{P}"/><rect x="0" y="622" width="1200" height="8" fill="{C}"/>
  {t(80, 120, 'SPOT THE TRAP', 28, C, family='PM')}
  {t(80, 214, 'What would you do next?', 62, T, family='SG')}
  {title_svg}
  {t(80, 566, 'savesavesavesave.xyz/spot-the-trap-' + cid, 26, M, family='PM')}
  <g transform="translate(790,250) scale(0.8)">{ILLU[cid]}</g>
</svg></body></html>"""

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={'width': 1200, 'height': 630})
    tmp = root / '.card.html'
    for cid, title in data.items():
        tmp.write_text(card(cid, title), encoding='utf-8')
        pg.goto(tmp.as_uri()); pg.wait_for_timeout(300)
        pg.screenshot(path=str(out / f'{cid}-concept.png')); print('wrote', cid)
        if LIVE: pg.screenshot(path=str(root / f'spot-the-trap-{cid}.png')); print('published card', cid)
    # Phone preview: each card at 340 px wide, as a feed would show it.
    imgs = ''.join(f'<figure><img src="{(out / (cid + "-concept.png")).as_uri()}"><figcaption>{html.escape(t_)}</figcaption></figure>' for cid, t_ in data.items())
    tmp.write_text(f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#f2f2f5;font:14px system-ui;padding:20px;display:flex;gap:20px}}
figure{{margin:0;width:340px;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px #0003}}
img{{width:340px;height:auto;display:block}} figcaption{{padding:8px 12px;color:#333}}</style></head><body>{imgs}</body></html>""", encoding='utf-8')
    pg.set_viewport_size({'width': 1480, 'height': 300}); pg.goto(tmp.as_uri()); pg.wait_for_timeout(400)
    pg.screenshot(path=str(out / 'phone-preview.png'), full_page=True)
    tmp.unlink(); b.close()
print('wrote phone-preview.png')
