#!/usr/bin/env node
/* =====================================================================
   LIVE SITE CHECK — what is actually being served

   Run with:  node live.test.js [https://savesavesavesave.xyz]

   WHY THIS EXISTS. Every other suite in this repository proves the FILES
   are right. Not one of them can see the deploy. In three days that gap
   produced three separate failures, all the same shape — true in the
   repository, false on the live site:

     · the deploy's own .git directory was served, so every document
       excluded by name was still readable at its object hash;
     · advertising ran on the scanner and on the phishing guides for two
       days, because the installer added it everywhere by default;
     · a guide shipped with no Content-Security-Policy meta tag at all.

   Each was found by a person happening to look. This looks on purpose.

   NO DEPENDENCIES. Node's own https module, nothing installed. It has to
   run anywhere — a laptop, a CI runner, a machine nobody has set up.

   EXIT CODE is the point: 0 clean, 1 something is wrong on the live
   site right now. Wire it to run after every deploy.
   ===================================================================== */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const BASE = (process.argv[2] || 'https://savesavesavesave.xyz').replace(/\/+$/, '');

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; failures.push(name + (detail ? ' — ' + detail : '')); console.log('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}
function section(t) { console.log('\n== ' + t + ' =='); }

// A GET that resolves rather than throws, so one dead URL cannot end the
// run before the checks that matter have been made.
//
// IT FOLLOWS REDIRECTS, and the first version did not. That single
// omission produced about forty failures on the first real run: this
// deploy serves /guides.html as a 301 to /guides, so every page request
// came back as an empty redirect body and every check that read a page
// failed at once. A checker that cannot tell "the page is wrong" from
// "I did not fetch the page" is worse than no checker, because a wall of
// red teaches everyone to stop reading it.
//
// The redirect chain is RETURNED rather than swallowed — a URL that
// redirects is itself worth knowing about when it came from a sitemap or
// a canonical tag.
async function get(path, depth) {
  depth = depth || 0;
  return new Promise(resolve => {
    let u;
    try { u = new URL(path.startsWith('http') ? path : BASE + path); }
    catch (e) { return resolve({ status: 0, body: '', headers: {}, redirects: 0, error: String(e) }); }
    const client = u.protocol === 'http:' ? http : https;
    const req = client.get(u, { timeout: 15000, headers: { 'User-Agent': 'savesavesavesave-live-check' } }, res => {
      const loc = res.headers.location;
      if (res.statusCode >= 300 && res.statusCode < 400 && loc && depth < 5) {
        res.resume();
        const next = new URL(loc, u).href;
        return resolve(get(next, depth + 1).then(r => ({ ...r, redirects: r.redirects + 1, redirectedFrom: u.href, firstStatus: res.statusCode })));
      }
      let body = '';
      res.setEncoding('utf8');
      res.on('data', c => { if (body.length < 400000) body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers, redirects: 0, finalUrl: u.href }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: '', headers: {}, redirects: 0, error: 'timeout' }); });
    req.on('error', e => resolve({ status: 0, body: '', headers: {}, redirects: 0, error: e.message }));
  });
}

const AD_MARKUP = /adsbygoogle|data-ad-client|data-ad-slot|class="ad-rail/;
const AD_HOSTS = /googlesyndication|googleadservices|googletagservices|adservice\.google|doubleclick|fundingchoices/;

// Mirrors AD_POLICY in apply-ads.js. Kept as its own list on purpose:
// this file checks the DEPLOY, so reading the policy from the repository
// would let a page and its policy be wrong together and still agree.
const ADS_ON  = ['/index.html', '/guides.html', '/whitepaper.html',
                 '/technical-appendix.html', '/honeypot-tokens.html'];
const ADS_OFF = ['/privacy.html', '/terms.html', '/invisible-characters.html',
                 '/prompt-injection.html', '/seed-phrase-phishing.html',
                 '/disguised-links.html'];

// Must not be reachable. The .git paths are the ones that made an
// exclusion list decorative; the rest are documents and source that the
// deploy is configured not to upload.
const MUST_404 = [
  '/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD', '/.gitignore',
  '/PROJECT-STATE.md', '/README.md', '/ARCHITECTURE.md',
  '/SaveSaveSaveSave_Wallet_Risk_Intelligence_Proposal.md',
  '/SaveSaveSaveSave_Whitepaper_v3.0.md',
  '/promptscan.js', '/core.js', '/apply-ads.js', '/promptscan.test.js',
];

(async () => {
  console.log('Checking ' + BASE + '\n');

  // A control, so "everything 404s" cannot be mistaken for success. If
  // the site is down, every MUST_404 check would pass for the wrong
  // reason and this run would look clean.
  section('The site is actually up');
  const home = await get('/');
  check('the home page responds 200', home.status === 200,
    'got ' + (home.status || home.error) + ' — every check below is meaningless if this failed');
  check('...and it is the scanner', /SaveSaveSaveSave/.test(home.body) && /promptInput|Check a message|scan/i.test(home.body));
  if (home.status !== 200) {
    console.log('\nAborting: the site did not respond. Nothing below would mean anything.');
    process.exit(1);
  }

  section('Nothing is served that should not be');
  for (const p of MUST_404) {
    const r = await get(p);
    check('not served: ' + p, r.status === 404 || r.status === 0,
      'returned ' + r.status + (r.body ? ', ' + r.body.length + ' bytes' : ''));
  }

  section('Security headers');
  const h = home.headers;
  check('Content-Security-Policy header present', !!h['content-security-policy']);
  check('X-Content-Type-Options: nosniff', h['x-content-type-options'] === 'nosniff');
  check('X-Frame-Options: DENY', (h['x-frame-options'] || '').toUpperCase() === 'DENY');
  check('Strict-Transport-Security present', /max-age=\d+/.test(h['strict-transport-security'] || ''));
  check('Referrer-Policy present', !!h['referrer-policy']);

  section('Advertising matches the route policy');
  for (const p of ADS_ON) {
    const r = await get(p);
    check('serves ads: ' + p, r.status === 200 && AD_MARKUP.test(r.body),
      r.status !== 200 ? 'page returned ' + r.status : 'policy says ads, page has no ad markup');
  }
  for (const p of ADS_OFF) {
    const r = await get(p);
    const metaCsp = (r.body.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/) || [])[1] || '';
    check('ad-free: ' + p, r.status === 200 && !AD_MARKUP.test(r.body),
      r.status !== 200 ? 'page returned ' + r.status : 'this page is supposed to carry no advertising');
    // The markup being absent is not enough. The policy is what stops a
    // stray paste from serving, and it is the half that fails silently.
    check('ad-free policy: ' + p, !!metaCsp && !AD_HOSTS.test(metaCsp),
      !metaCsp ? 'the page has no meta Content-Security-Policy at all' : 'its policy still permits the ad hosts');
  }

  section('Every page has a policy, and the rails are distinct');
  for (const p of [...ADS_ON, ...ADS_OFF]) {
    const r = await get(p);
    check('has a meta CSP: ' + p,
      /<meta http-equiv="Content-Security-Policy" content="/.test(r.body),
      'a page shipped once with none; the response header covered it and nothing complained');
  }
  const idx = await get('/index.html');
  const slots = [...idx.body.matchAll(/class="ad-rail[\s\S]{0,400}?data-ad-slot="(\d+)"/g)].map(m => m[1]);
  check('the two rails carry different ad units',
    slots.length === 2 && slots[0] !== slots[1],
    slots.length !== 2 ? 'found ' + slots.length + ' rail slots' : 'both rails are unit ' + slots[0]);

  section('Navigation and content');
  const sm = await get('/sitemap.xml');
  check('sitemap.xml is served', sm.status === 200);
  const locs = [...sm.body.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
  check('sitemap lists pages', locs.length > 0, 'found ' + locs.length);
  for (const loc of locs) {
    // Take the PATH out of the entry rather than string-replacing BASE.
    // The sitemap carries absolute production URLs, so a run against any
    // other origin would otherwise report every page as broken.
    let p;
    try { p = new URL(loc).pathname || '/'; } catch (_) { p = loc; }
    const r = await get(p);
    check('sitemap entry resolves: ' + p, r.status === 200, 'returned ' + r.status);
  }

  section('Addresses the site gives out are the addresses it serves');
  // Not cosmetic. A canonical tag that redirects tells a crawler the
  // authoritative address is somewhere other than the one it just
  // fetched, and every sitemap entry costs an extra round trip.
  const redirecting = [];
  for (const loc of locs) {
    let p; try { p = new URL(loc).pathname || '/'; } catch (_) { p = loc; }
    const r = await get(p);
    if (r.redirects > 0) redirecting.push(p + ' -> ' + (r.finalUrl || '').replace(BASE, ''));
  }
  check('no sitemap entry redirects', redirecting.length === 0,
    redirecting.join(', '));

  const canon = (idx.body.match(/<link rel="canonical" href="([^"]+)"/) || [])[1];
  if (canon) {
    const cr = await get(canon);
    check('the canonical URL does not redirect', cr.redirects === 0,
      canon + ' redirects, so it is not the address being served');
  }

  // The live scan console. It is the only thing on screen while somebody
  // waits for a verdict, and it is built entirely in JavaScript — so a
  // deploy that shipped the script without the markup would show nothing
  // at all and nothing else in this file would notice.
  section('The scan console is actually on the page');
  check('the console markup is served', /id="scanConsole"/.test(idx.body));
  check('...as a polite live region', /id="scanConsole"[^>]*role="status"/.test(idx.body)
    && /id="scanConsole"[^>]*aria-live="polite"/.test(idx.body),
    'without this a screen reader hears nothing while a scan runs');
  check('...with its stage list and figure', /id="consoleStages"/.test(idx.body) && /id="cfNodes"/.test(idx.body));
  check('the console stylesheet shipped with it', /\.console-stages/.test(idx.body),
    'the markup without the CSS is an unstyled list in the middle of the page');
  check('reduced motion is honoured on the deploy',
    /prefers-reduced-motion:reduce\)\{[\s\S]{0,800}?animation:none;/.test(idx.body));

  // The logo is the way home from every page but the scanner, where it
  // would discard a message somebody had just pasted.
  const guide = await get('/disguised-links.html');
  check('the logo links home from a guide', /<a class="brand" href="index\.html"/.test(guide.body));
  check('the logo does NOT link on the scanner', !/<a class="brand"/.test(idx.body),
    'clicking it there would reload the page and lose a pasted message');

  // A contact route that does not depend on a platform account. This one
  // broke in production the moment the repository changed visibility.
  for (const p of ['/privacy.html', '/terms.html']) {
    const r = await get(p);
    check('reachable without a third-party account: ' + p,
      /href="mailto:[^"@]+@[^"]+"/.test(r.body));
  }

  // The guides invite readers to paste their examples into the scanner.
  check('the links guide still carries its worked example',
    /class="msg"/.test(guide.body) && /ledgerlive-verify\.example/.test(guide.body));
  const article = (guide.body.match(/<article[\s\S]*?<\/article>/) || [''])[0];
  const clickable = [...article.matchAll(/href="(https?:\/\/[^"]+)"/g)].map(m => m[1])
    .filter(u => {
      let host; try { host = new URL(u).hostname.toLowerCase(); } catch (_) { return true; }
      return !/(?:^|\.)(?:savesavesavesave\.xyz|github\.com|support\.metamask\.io)$/.test(host);
    });
  check('...and makes none of its example addresses clickable',
    clickable.length === 0,
    clickable.join(', ') + ' — an article about unsafe links must not ship one you can click');

  console.log('\n' + '='.repeat(60));
  if (fail) {
    console.log(fail + ' FAILED, ' + pass + ' passed — the LIVE SITE is wrong right now');
    failures.forEach(f => console.log('  - ' + f));
    console.log('='.repeat(60));
    process.exit(1);
  }
  console.log(pass + '/' + pass + ' live checks passed');
  console.log('='.repeat(60));
})();
