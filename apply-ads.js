#!/usr/bin/env node
/* =====================================================================
   AD SLOT INSTALLER

   Puts the AdSense rails on every page, and widens the Content-Security
   -Policy so they can actually load. Run once; it is idempotent.

   WHY THIS IS A SCRIPT AND NOT NINE HAND EDITS: the CSP has to be
   identical everywhere or the ads work on some pages and silently fail
   on others, which is the worst possible outcome because it looks like
   an AdSense problem for weeks. One source, nine identical outputs.

   WHAT IT DOES NOT DO: it does not put an ad inside the scan result
   markup. The rails are position:fixed in the page gutters, so they sit
   beside everything on the page — results included — without entering
   the result DOM. Nothing about a verdict can be confused for a paid
   placement, and no ad call can ever see a finding.
   ===================================================================== */

const fs = require('fs');
const path = require('path');

const PUB = 'ca-pub-7192453271158919';
const SLOT = '1457626247';

const PAGES = [
  'index.html', 'whitepaper.html', 'technical-appendix.html', 'guides.html',
  'privacy.html', 'terms.html', 'honeypot-tokens.html',
  'invisible-characters.html', 'prompt-injection.html',
];

// Google's ad stack, by role. Listed explicitly rather than with a
// wildcard on *.google.com, which would also admit every other Google
// product and is a much larger hole than this needs.
const AD_SCRIPT = [
  'https://pagead2.googlesyndication.com',
  'https://partner.googleadservices.com',
  'https://tpc.googlesyndication.com',
  'https://www.googletagservices.com',
  'https://adservice.google.com',
  // Google's Consent Management Platform. Enabled in the AdSense account
  // on 18 Sep to produce the European regulations message. Without these
  // hosts the consent dialogue is blocked by our own CSP, and a blocked
  // consent dialogue in the EU means no personalised ads and a policy
  // problem, not just a missing banner.
  'https://fundingchoicesmessages.google.com',
  'https://fundingchoices.google.com',
].join(' ');
const AD_CONNECT = [
  'https://pagead2.googlesyndication.com',
  'https://googleads.g.doubleclick.net',
  'https://*.g.doubleclick.net',
  'https://fundingchoicesmessages.google.com',
].join(' ');
const AD_IMG = [
  'https://pagead2.googlesyndication.com',
  'https://*.googlesyndication.com',
  'https://*.g.doubleclick.net',
  'https://www.google.com',
  'https://fundingchoicesmessages.google.com',
].join(' ');
const AD_FRAME = [
  'https://googleads.g.doubleclick.net',
  'https://tpc.googlesyndication.com',
  'https://www.google.com',
  'https://fundingchoicesmessages.google.com',
].join(' ');

function widenCsp(csp) {
  const parts = csp.split(';').map(s => s.trim()).filter(Boolean);
  const out = [];
  let sawFrame = false;
  for (const p of parts) {
    const [name, ...rest] = p.split(/\s+/);
    let v = rest.join(' ');
    if (name === 'script-src') {
      if (!v.includes("'unsafe-inline'")) v = "'unsafe-inline' " + v;
      if (!v.includes('fundingchoices')) v += ' ' + AD_SCRIPT;
    } else if (name === 'connect-src') {
      if (!v.includes('fundingchoices')) v += ' ' + AD_CONNECT;
    } else if (name === 'img-src') {
      if (!v.includes('fundingchoices')) v += ' ' + AD_IMG;
    } else if (name === 'frame-src') {
      sawFrame = true;
      if (!v.includes('fundingchoices')) v += ' ' + AD_FRAME;
    }
    // Deduplicate. Re-running this script must not append a host that is
    // already there — an earlier pass did exactly that and every page
    // carried the ad hosts twice. Harmless to the browser, but a policy
    // nobody can read is a policy nobody audits.
    const seen = new Set();
    v = v.split(/\s+/).filter(t => t && !seen.has(t) && seen.add(t) !== false).join(' ');
    out.push(name + ' ' + v);
  }
  // Ads render inside iframes. Without frame-src they fall back to
  // default-src 'self' and the creative is blocked even though the
  // script loaded — the failure that looks like "AdSense is broken".
  if (!sawFrame) out.push('frame-src ' + AD_FRAME);
  return out.join('; ') + ';';
}

// The markup. One loader per page, two slots. The loader is the exact
// snippet Google issued; only the placement is ours.
function railsHtml() {
  const unit = side => `
  <aside class="ad-rail ad-rail-${side}" aria-label="Advertisement">
    <span class="ad-label">Advertisement</span>
    <ins class="adsbygoogle"
         style="display:block"
         data-ad-client="${PUB}"
         data-ad-slot="${SLOT}"
         data-ad-format="auto"
         data-full-width-responsive="true"></ins>
    <script>
         (adsbygoogle = window.adsbygoogle || []).push({});
    </script>
  </aside>`;

  return `
<!-- ADVERTISING ==========================================================
     Google AdSense, publisher ${PUB}.

     Placement rule, and the reason these are rails rather than inline
     units: NOTHING SUBMITTED TO THE SCANNER EVER REACHES AN AD CALL.
     The ad code receives the page URL and nothing else. It is not given
     a finding, a verdict, an address, a URL from a message, or any part
     of pasted text, and promptscan.ui.test.js asserts that.

     The rails are position:fixed in the page gutters and are NOT
     RENDERED below 1280px — they do not exist in the flow, so they
     cannot shift the page or crowd the scanner on a phone.

     KILL SWITCH: set data-ads="off" on <html> and every slot disappears
     with no deploy of the page content itself.
     ================================================================== -->
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${PUB}"
     crossorigin="anonymous"></script>
${unit('left')}
${unit('right')}
`;
}

let changed = 0;
for (const file of PAGES) {
  const p = path.join(__dirname, file);
  let html = fs.readFileSync(p, 'utf8');

  const before = html;

  // 1. CSP in the meta tag.
  html = html.replace(/(<meta http-equiv="Content-Security-Policy" content=")([^"]+)(")/,
    (_, a, csp, c) => a + widenCsp(csp) + c);

  // 2. The rails, immediately before </body>, after the analytics beacon.
  if (!html.includes('class="ad-rail')) {
    html = html.replace(/\n?<\/body>/, '\n' + railsHtml() + '</body>');
  }

  if (html !== before) { fs.writeFileSync(p, html, 'utf8'); changed++; console.log('  updated ' + file); }
  else console.log('  unchanged ' + file);
}

// 3. The same widening in the response headers, which cover every path
//    including the ones with no meta tag at all.
const hp = path.join(__dirname, '_headers');
let headers = fs.readFileSync(hp, 'utf8');
headers = headers.replace(/^(\s*Content-Security-Policy: )(.+)$/m,
  (_, a, csp) => a + widenCsp(csp));
fs.writeFileSync(hp, headers, 'utf8');
console.log('  updated _headers');

console.log(`\n${changed} page(s) changed.`);
