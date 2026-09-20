#!/usr/bin/env node
/* =====================================================================
   AD PLACEMENT — ROUTE POLICY AND INSTALLER

   Run with: node apply-ads.js

   One source, eleven outputs. This decides, per page, whether the page
   carries advertising at all — and then makes the page match that
   decision in BOTH places it can be seen: the markup and the policy.

   WHY A ROUTE POLICY RATHER THAN "ads on every page". Between 18 and 20
   September every page on this site carried the AdSense loader,
   including the scanner and the phishing guides. That was a default,
   not a decision. A page whose subject is "this message is trying to
   rob you" should not also be carrying an unreviewed commercial link
   the reader could mistake for our recommendation, and an ad beside a
   FAIL verdict can read as endorsement no disclaimer undoes.

   So the sensitive routes are now OFF, and the file says why for each
   one, in words, where the next person will read them.

   WHAT "OFF" MEANS HERE — it is not a comment, it is four things:
     1. no loader script,
     2. no ad units,
     3. no reveal script,
     4. the Google advertising hosts REMOVED from that page's
        Content-Security-Policy.

   (4) is the one that makes it enforcement rather than intention. A
   page's meta policy and the response header are combined by the
   browser, and the RESULT IS THE INTERSECTION — the most restrictive
   of the two wins. So an ad-free page whose meta policy omits the ad
   hosts cannot load an ad even though the site-wide header still
   permits them for the pages that do carry ads. Deleting the markup
   alone would leave the page one careless paste away from serving.

   THE HEADER IS DELIBERATELY LEFT BROAD. _headers applies to every
   path, so it has to carry the union of what the ad-serving pages
   need. It is a ceiling, not an instruction.
   ===================================================================== */

const fs = require('fs');
const path = require('path');

const PUB = 'ca-pub-7192453271158919';

// ONE AD UNIT PER PLACEMENT.
//
// Both rails used slot 1457626247. AdSense permits the same unit twice
// on a page, but the two rails then sit in one auction and report as a
// single line, so neither placement can be judged on its own — you
// cannot tell whether the left rail earns anything, or whether the
// right one is carrying both.
//
// Each rail now has its own unit, so the two placements report
// separately and can be judged on their own. If they ever collapse back
// to one id the run below says so rather than letting it pass quietly.
const SLOT_LEFT = '1457626247';    // original unit
const SLOT_RIGHT = '8189344100';   // "rail-right", created 20 Sep 2026
const SLOTS_ARE_DISTINCT = SLOT_LEFT !== SLOT_RIGHT;

// ---------------------------------------------------------------------
// THE POLICY. `enabled` is the whole decision; `reason` is owed to
// whoever changes it later. Flipping one of these to true is a
// deliberate act that should be argued for in the commit message.
const AD_POLICY = {
  'index.html':                 { enabled: true,  mode: 'contextual', reason: 'The scanner and its explanation. Rails sit in the page gutters, never inside the result markup — asserted by promptscan.ui.test.js.' },
  'guides.html':                { enabled: true,  mode: 'contextual', reason: 'An index of articles. No verdict, no warning, nothing an ad could be mistaken for.' },
  'whitepaper.html':            { enabled: true,  mode: 'contextual', reason: 'General explanation of what the product is and how it is paid for.' },
  'technical-appendix.html':    { enabled: true,  mode: 'contextual', reason: 'Technical transparency document. Read by people checking claims, not by people in trouble.' },
  'honeypot-tokens.html':       { enabled: true,  mode: 'contextual', reason: 'Token mechanics. Educational, and not about a message someone has just received.' },

  'privacy.html':               { enabled: false, reason: 'A policy document should read as a policy document. Advertising beside the page that describes our advertising undermines both.' },
  'terms.html':                 { enabled: false, reason: 'Same as privacy: the terms are a commitment, not a surface.' },

  'invisible-characters.html':  { enabled: false, reason: 'Message-deception content. The reader is being taught to distrust what a message shows them; a commercial unit on the same screen works against that.' },
  'prompt-injection.html':      { enabled: false, reason: 'AI manipulation and unsafe instructions. Sensitive trust page.' },
  'seed-phrase-phishing.html':  { enabled: false, reason: 'The highest-harm guide on the site. Someone may be reading it while being robbed. Nothing commercial belongs on it.' },
  'disguised-links.html':       { enabled: false, reason: 'Phishing and disguised destinations. An unreviewed advertisement beside an article about unsafe links is the exact confusion the article warns about.' },
};

const PAGES = Object.keys(AD_POLICY);

// Google's ad stack, by role. Listed explicitly rather than with a
// wildcard on *.google.com, which would also admit every other Google
// product and is a far larger hole than this needs.
const AD_SCRIPT = [
  'https://pagead2.googlesyndication.com',
  'https://partner.googleadservices.com',
  'https://tpc.googlesyndication.com',
  'https://www.googletagservices.com',
  'https://adservice.google.com',
  // Google's Consent Management Platform. Without these the consent
  // dialogue is blocked by our own policy, and a blocked consent
  // dialogue in the EU means a policy problem, not a missing banner.
  'https://fundingchoicesmessages.google.com',
  'https://fundingchoices.google.com',
];
const AD_CONNECT = [
  'https://pagead2.googlesyndication.com',
  'https://googleads.g.doubleclick.net',
  'https://*.g.doubleclick.net',
  'https://fundingchoicesmessages.google.com',
];
const AD_IMG = [
  'https://pagead2.googlesyndication.com',
  'https://*.googlesyndication.com',
  'https://*.g.doubleclick.net',
  'https://www.google.com',
  'https://fundingchoicesmessages.google.com',
];
const AD_FRAME = [
  'https://googleads.g.doubleclick.net',
  'https://tpc.googlesyndication.com',
  'https://www.google.com',
  'https://fundingchoicesmessages.google.com',
];
// Every host this file may ever add, so narrowCsp can take them all
// back out again without a second list drifting from the first.
const ALL_AD_HOSTS = new Set([...AD_SCRIPT, ...AD_CONNECT, ...AD_IMG, ...AD_FRAME]);

function dedupe(v) {
  const seen = new Set();
  return v.split(/\s+/).filter(t => t && !seen.has(t) && seen.add(t) !== false).join(' ');
}

function widenCsp(csp) {
  const out = [];
  let sawFrame = false;
  for (const p of csp.split(';').map(s => s.trim()).filter(Boolean)) {
    const [name, ...rest] = p.split(/\s+/);
    let v = rest.join(' ');
    if (name === 'script-src') {
      if (!v.includes("'unsafe-inline'")) v = "'unsafe-inline' " + v;
      v += ' ' + AD_SCRIPT.join(' ');
    } else if (name === 'connect-src') { v += ' ' + AD_CONNECT.join(' ');
    } else if (name === 'img-src')     { v += ' ' + AD_IMG.join(' ');
    } else if (name === 'frame-src')   { sawFrame = true; v += ' ' + AD_FRAME.join(' '); }
    out.push(name + ' ' + dedupe(v));
  }
  // Ads render inside iframes. Without frame-src they fall back to
  // default-src 'self' and the creative is blocked even though the
  // script loaded — the failure that looks like "AdSense is broken".
  if (!sawFrame) out.push('frame-src ' + AD_FRAME.join(' '));
  return out.join('; ') + ';';
}

function narrowCsp(csp) {
  const out = [];
  for (const p of csp.split(';').map(s => s.trim()).filter(Boolean)) {
    const [name, ...rest] = p.split(/\s+/);
    const kept = rest.filter(t => !ALL_AD_HOSTS.has(t));
    if (name === 'frame-src') {
      // The directive existed only to let ad creatives render. On an
      // ad-free page, say so explicitly rather than deleting the line
      // and falling back to default-src: 'none' is the same result and
      // it is legible to whoever reads the policy next.
      out.push(kept.length ? name + ' ' + kept.join(' ') : "frame-src 'none'");
      continue;
    }
    if (!kept.length) continue;
    out.push(name + ' ' + dedupe(kept.join(' ')));
  }
  if (!/frame-src/.test(out.join(';'))) out.push("frame-src 'none'");
  return out.join('; ') + ';';
}

// The markup. One loader per page, two slots.
//
// NOTE ON THE SLOT ID: both rails currently use the same unit. That is
// permitted by AdSense — one unit may appear more than once on a page —
// but it means the two rails compete in the same auction and report as
// one line in the dashboard, so neither can be judged on its own. Worth
// splitting into two units before anyone tries to read performance per
// placement. Recorded here rather than in somebody's memory.
function railsHtml() {
  const unit = (side, slot) => `
  <aside class="ad-rail ad-rail-${side}" data-ad-state="pending">
    <span class="ad-label">Advertisement</span>
    <ins class="adsbygoogle"
         style="display:block"
         data-ad-client="${PUB}"
         data-ad-slot="${slot}"
         data-ad-format="auto"
         data-full-width-responsive="true"></ins>
    <script>
         (adsbygoogle = window.adsbygoogle || []).push({});
    </script>
  </aside>`;

  return `
<!-- ADVERTISING ==========================================================
     Google AdSense, publisher ${PUB}.

     This page carries advertising by an explicit decision recorded in
     AD_POLICY in apply-ads.js. Pages whose subject is a scam, a
     phishing message or an unsafe instruction do NOT carry it, and
     their Content-Security-Policy omits these hosts entirely.

     NOTHING SUBMITTED TO THE SCANNER EVER REACHES AN AD CALL. The ad
     code receives the page URL and nothing else: no finding, no
     verdict, no address, no URL taken from a message, no part of
     pasted text. promptscan.ui.test.js asserts the code path; a live
     network capture is the only thing that proves the behaviour, and
     that check belongs in the release routine, not in this comment.

     The rails are position:fixed in the page gutters and are NOT
     RENDERED below 1280px — they do not exist in the flow, so they
     cannot shift the page or crowd the scanner on a phone.

     A RAIL STAYS HIDDEN UNTIL AN AD ACTUALLY FILLS, so an unfilled
     slot cannot leave the word "Advertisement" over an empty box.

     KILL SWITCH: set data-ads="off" on <html> and every slot
     disappears with no deploy of the page content itself.
     ================================================================== -->
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${PUB}"
     crossorigin="anonymous"></script>
${unit('left', SLOT_LEFT)}
${unit('right', SLOT_RIGHT)}
<script>
/* Reveal a rail only once AdSense reports a filled creative. Reads one
   attribute AdSense sets on its own element; sends nothing anywhere. */
(function () {
  var rails = document.querySelectorAll('.ad-rail');
  if (!rails.length) return;
  function sync() {
    for (var i = 0; i < rails.length; i++) {
      var ins = rails[i].querySelector('ins.adsbygoogle');
      var filled = !!ins && ins.getAttribute('data-ad-status') === 'filled';
      rails[i].setAttribute('data-ad-state', filled ? 'filled' : 'empty');
    }
  }
  if (typeof MutationObserver === 'function') {
    var obs = new MutationObserver(sync);
    for (var i = 0; i < rails.length; i++) {
      var ins = rails[i].querySelector('ins.adsbygoogle');
      if (ins) obs.observe(ins, { attributes: true, attributeFilter: ['data-ad-status'] });
    }
    /* Stop watching once the network has had its chance. */
    setTimeout(function () { sync(); obs.disconnect(); }, 8000);
  } else {
    setTimeout(sync, 4000);
  }
})();
</script>
`;
}

let on = 0, off = 0, changed = 0;
const noPolicy = [];

for (const file of PAGES) {
  const p = path.join(__dirname, file);
  if (!fs.existsSync(p)) { console.error('FAIL: ' + file + ' is in AD_POLICY but does not exist.'); process.exit(1); }

  let html = fs.readFileSync(p, 'utf8');
  const before = html;
  const policy = AD_POLICY[file];

  // A page with no meta policy is a hard failure. Adding one
  // automatically would be worse: it would guess a policy for a page
  // nobody reviewed. seed-phrase-phishing.html once shipped without
  // one and this loop said "unchanged" and moved on.
  if (!/<meta http-equiv="Content-Security-Policy" content="/.test(html)) noPolicy.push(file);

  html = html.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]+)(")/,
    (_, a, csp, c) => a + (policy.enabled ? widenCsp(csp) : narrowCsp(csp)) + c);

  // Always strip first, then add back if the policy says so. This is
  // what makes the script idempotent AND able to withdraw advertising
  // from a page that previously had it. The block is always the last
  // thing before </body>; keep it that way.
  html = html.replace(/\n*<!-- ADVERTISING [\s\S]*?(?=<\/body>)/, '\n');
  if (policy.enabled) {
    html = html.replace(/\n?<\/body>/, '\n' + railsHtml() + '</body>');
    on++;
  } else {
    off++;
  }

  if (html !== before) { fs.writeFileSync(p, html, 'utf8'); changed++; }
  console.log(`  ${policy.enabled ? 'ADS  ' : 'clean'}  ${file.padEnd(28)}${html !== before ? '(rewritten)' : ''}`);
}

if (noPolicy.length) {
  console.error('\nFAIL: these pages have no Content-Security-Policy meta tag, '
    + 'so nothing above applied to them:');
  noPolicy.forEach(f => console.error('      - ' + f));
  console.error('\nCopy the policy from a page that has one. Do not let this '
    + 'script invent it.');
  process.exit(1);
}

// The response header covers every path, including files with no meta
// tag of their own, so it carries the union of what the ad-serving
// pages need. Pages that opt out do so through their own meta policy,
// which the browser intersects with this one.
const hp = path.join(__dirname, '_headers');
let headers = fs.readFileSync(hp, 'utf8');
headers = headers.replace(/^(\s*Content-Security-Policy: )(.+)$/m, (_, a, csp) => a + widenCsp(csp));
fs.writeFileSync(hp, headers, 'utf8');

console.log(`\n${on} page(s) carry advertising, ${off} deliberately do not. ${changed} file(s) rewritten.`);
console.log('Reasons are in AD_POLICY at the top of this file.');
if (!SLOTS_ARE_DISTINCT) {
  console.log(`\nNOTE: both rails still use the same ad unit (${SLOT_LEFT}), so they`);
  console.log('      compete in one auction and report as one line. Set SLOT_RIGHT');
  console.log('      to a second unit id to separate them.');
}
