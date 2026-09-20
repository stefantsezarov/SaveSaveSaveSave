#!/usr/bin/env node
/* =====================================================================
   GUIDE EXAMPLES — RELEASE CHECK
   Run with: node guide-examples.test.js

   Every guide in the series prints a worked example of the thing it
   describes, and every one of those guides carries an editor's note
   saying the example is scanned by our own engine before release.

   That note was true only as long as somebody remembered to do it by
   hand. This makes it true automatically.

   WHY IT MATTERS MORE THAN IT LOOKS. The examples are the most-read,
   most-copied text on the site: a reader is explicitly invited to paste
   them into the scanner. If the engine changes and an example quietly
   stops being detected, the article becomes a live demonstration that
   the tool does not work — on the exact case the article says it
   catches. That is worse than having no example at all.

   This check reads the PUBLISHED HTML, not a copy of the text kept
   somewhere convenient. An example that only exists in a test fixture
   proves nothing about the page a visitor actually loads.
   ===================================================================== */

const fs = require('fs');
const path = require('path');
const S = require('./promptscan.js');

let pass = 0, fail = 0;
const failures = [];

function check(name, cond, detail) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; failures.push(name + (detail ? ' — ' + detail : '')); console.log('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}

// What each guide's example must come back as, and why that guide needs
// that specific answer. A guide whose example does not reach its stated
// verdict is a broken promise on a page we invite people to test.
const EXPECTED = [
  {
    file: 'invisible-characters.html',
    label: 'FAIL',
    // This guide renders its examples with .demo rather than .msg,
    // because the point is the individual characters, not a message.
    blockClass: 'demo',
    why: 'the article tells the reader to copy this line and watch it come back flagged',
  },
  {
    file: 'prompt-injection.html',
    label: 'FAIL',
    mustHaveRule: null,
    why: 'the whole article is about text an assistant would obey and a reader would not notice',
  },
  {
    file: 'seed-phrase-phishing.html',
    label: 'FAIL',
    mustHaveCategory: 'CRYPTO_SECRET_REQUEST',
    why: 'the highest-harm guide in the series; a recovery-phrase request must be the strongest finding we have',
  },
  {
    file: 'disguised-links.html',
    label: 'FAIL',
    mustHaveRule: 'URL_USERINFO_001',
    why: 'the example turns on the @ trick specifically, and the reveal says so in as many words',
  },
];

// The example blocks are rendered markup. Strip the tags the guides use
// for highlighting inside them (prompt-injection.html marks the injected
// sentence with <span class="inj">), then undo the entity encoding, so
// what we scan is what the reader would copy off the page.
function textOf(html) {
  return html
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&');
}

for (const spec of EXPECTED) {
  const p = path.join(__dirname, spec.file);
  if (!fs.existsSync(p)) {
    check(`${spec.file} exists`, false, 'file not found — has it been renamed?');
    continue;
  }
  const html = fs.readFileSync(p, 'utf8');
  const cls = spec.blockClass || 'msg';
  const re = new RegExp('<div class="' + cls + '"[^>]*>([\\s\\S]*?)<\\/div>', 'g');
  const blocks = [...html.matchAll(re)].map(m => textOf(m[1]));

  if (!blocks.length) {
    check(`${spec.file} still carries a worked example`, false,
      'no <div class="' + cls + '"> block found — the article lost its example');
    continue;
  }

  // Take the strongest verdict across the blocks: some guides print more
  // than one, including a deliberately benign counter-example.
  const RANK = { PASS: 0, UNKNOWN: 1, CAUTION: 2, FAIL: 3 };
  const results = blocks.map(b => S.scanPrompt(b));
  const worst = results.reduce((a, b) => (RANK[b.label] > RANK[a.label] ? b : a));

  check(`${spec.file}: example scores ${spec.label}`,
    worst.label === spec.label,
    `got ${worst.label} — ${spec.why}`);

  if (spec.mustHaveRule) {
    check(`${spec.file}: example still triggers ${spec.mustHaveRule}`,
      results.some(r => r.findings.some(f => f.ruleId === spec.mustHaveRule)),
      spec.why);
  }
  if (spec.mustHaveCategory) {
    check(`${spec.file}: example still triggers ${spec.mustHaveCategory}`,
      results.some(r => r.findings.some(f => f.category === spec.mustHaveCategory)),
      spec.why);
  }
}

// ---- the addresses printed in the guides must not be visitable --------
// A security article about dangerous links must never ship one that
// resolves. Reserved names (RFC 2606 / RFC 6761) cannot, by definition.
const RESERVED = /(?:\.example|\.invalid|\.test|\.localhost|example\.(?:com|net|org))$/i;
const linkGuide = path.join(__dirname, 'disguised-links.html');
if (fs.existsSync(linkGuide)) {
  const full = fs.readFileSync(linkGuide, 'utf8');

  // Only the article body. The <head> carries a Content-Security-Policy
  // listing a dozen Google hosts, and every <svg> names the W3C
  // namespace; neither is an address printed for a reader to look at,
  // and counting them would make this check noise instead of a check.
  const aStart = full.indexOf('<article');
  const aEnd = full.indexOf('</article>');
  const body = ((aStart !== -1 && aEnd > aStart) ? full.slice(aStart, aEnd) : full)
    // XML namespace declarations are identifiers that happen to be
    // shaped like URLs. Nothing fetches them and no reader sees them.
    .replace(/\sxmlns(?::[a-z]+)?="[^"]*"/gi, '');

  // Domains the article deliberately shows as the CORRECT form — the
  // left-hand side of "this is where the name belongs". Deliberately a
  // short explicit list rather than a pattern: adding a live domain to a
  // guide about dangerous links should cost a conscious decision.
  const SHOWN_AS_CORRECT = new Set(['metamask.io', 'savesavesavesave.xyz']);

  const hosts = new Set();
  for (const m of body.matchAll(/https?:\/\/([^\s<>"'`\])}\/]+)/g)) {
    let h = m[1];
    const at = h.lastIndexOf('@');
    if (at !== -1) h = h.slice(at + 1);            // the userinfo trick
    h = h.replace(/[:;,.]+$/, '').toLowerCase();
    if (h) hosts.add(h);
  }

  const live = [...hosts].filter(h => !RESERVED.test(h) && !SHOWN_AS_CORRECT.has(h));
  check('disguised-links.html prints no address that could actually resolve',
    live.length === 0,
    live.length ? 'found: ' + live.join(', ') : '');

  // And nothing dangerous may be clickable. Same-page and same-site
  // links are how the guide cross-references the rest of the series.
  const bad = [...body.matchAll(/href="(https?:\/\/[^"]+)"/g)]
    .map(m => m[1])
    .filter(u => {
      let host;
      try { host = new URL(u).hostname.toLowerCase(); } catch (_) { return true; }
      return !/(?:^|\.)(?:savesavesavesave\.xyz|github\.com|support\.metamask\.io)$/i.test(host);
    });
  check('disguised-links.html makes none of its example addresses clickable',
    bad.length === 0,
    bad.join(', '));
}

// ---- the capability table must describe the real engine --------------
// disguised-links.html prints a table of what the scan can help identify.
// A row there is a promise, and a reader can test any of them in about
// ten seconds by pasting the example into the scanner. So each row is
// probed against the live engine here: if a check is claimed but no
// longer fires, this fails, and if a check is quietly dropped from the
// engine the guide stops being allowed to claim it.
const CLAIMS = [
  { row: '<code>@</code> user-information tricks',       probe: 'https://ledger.com@x.example/a',            rule: 'URL_USERINFO_001' },
  { row: 'Bare IP hosts',                                probe: 'http://185.22.67.9/wallet',                 rule: 'URL_IP_001' },
  { row: 'Recognized shorteners',                        probe: 'https://bit.ly/3xK9pQr',                    rule: 'URL_SHORTENER_001' },
  { row: 'Punycode indicators',                          probe: 'https://xn--ledgr-2we.example/v',           rule: 'URL_PUNYCODE_001' },
  { row: 'Brand names in suspicious positions',          probe: 'https://metamask.io.x.example/a',           rule: 'URL_BRAND_001' },
  { row: 'Brand names with extra words attached',        probe: 'https://metamask-wallet.example/a',         rule: 'URL_BRAND_AFFIX_001' },
  { row: 'Some confusable characters',                   probe: 'https://metarnask.example/a',               rule: 'URL_LOOKALIKE_001' },
  { row: 'Suspicious encoded URL content',               probe: 'https://x.example/go?d=%7B%22a%22%3A%22' + 'b'.repeat(40) + '%22%7D', rule: 'URL_ENCODED_PARAMS_001' },
];

const guidePath = path.join(__dirname, 'disguised-links.html');
if (fs.existsSync(guidePath)) {
  const guide = fs.readFileSync(guidePath, 'utf8');
  for (const c of CLAIMS) {
    const fires = S.scanPrompt('See ' + c.probe).findings.some(f => f.ruleId === c.rule);
    const claimed = guide.includes(c.row);
    check(`claim matches engine: ${c.row.replace(/<[^>]+>/g, '')}`,
      fires && claimed,
      !fires ? `the guide claims it but ${c.rule} did not fire`
             : 'the engine performs this check but the guide no longer lists it');
  }

  // Address extraction is claimed in the same table.
  const addr = S.scanPrompt('Send to 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B');
  check('claim matches engine: supported crypto addresses in the message',
    !!(addr.addresses && addr.addresses.length)
    && guide.includes('Supported crypto addresses in the message'));

  // Phrases the guide must not use, from the editorial rules: a
  // structural scan does not prove safety, and must not be described as
  // if it did.
  const FORBIDDEN = [
    'catches phishing',
    'proves the link is dangerous',
    'knows where a short link goes',
    'recognizes every fake domain',
    'every address is taken apart',
  ];
  const used = FORBIDDEN.filter(p => guide.toLowerCase().includes(p));
  check('the guide makes no claim that a structural scan proves safety',
    used.length === 0, used.join('; '));

  check('the guide keeps the central lesson prominent',
    guide.includes('The familiar name being present is not evidence'));

  check('the guide states that structure is not reputation',
    guide.includes('Structure is not reputation'));

  check('the example message is labelled as fictional',
    /Fictional example using reserved domains/i.test(guide));

  // The note must be accurate, not merely present. metamask.io is real
  // and resolvable, and the guide prints it deliberately as the example
  // of where a name belongs — so a blanket "all domains are reserved"
  // claim would be false in the one article that must be exact about
  // domains. The note has to name the exception.
  check('the reserved-name note is present and names the live exception',
    /demonstrates a trick uses a reserved example name/i.test(guide)
    && /metamask\.io<\/code>, which is real/i.test(guide));
}


// ---- advertising route policy -----------------------------------------
// Between 18 and 20 September 2026 every page on this site carried the
// AdSense loader, including the scanner and the guides that explain
// phishing. That was a default nobody chose. The policy now lives in
// apply-ads.js and this asserts the pages match it — in the markup AND
// in the page's own Content-Security-Policy.
//
// The policy matters because the browser enforces the INTERSECTION of a
// page's meta policy and the response header. Stripping the ad hosts
// from an ad-free page's meta policy is therefore enforcement, not
// decoration: the page cannot load an ad even though the site-wide
// header still permits them for the pages that do carry one.
{
  const applySrc = fs.readFileSync(path.join(__dirname, 'apply-ads.js'), 'utf8');
  const block = applySrc.slice(applySrc.indexOf('const AD_POLICY'), applySrc.indexOf('const PAGES'));

  const policy = {};
  for (const m of block.matchAll(/'([a-z0-9-]+\.html)':\s*\{\s*enabled:\s*(true|false)/g)) {
    policy[m[1]] = m[2] === 'true';
  }

  check('the advertising route policy is readable and covers every page',
    Object.keys(policy).length === 11, 'found ' + Object.keys(policy).length);

  // Every disabled entry must carry a reason. A silent exclusion is a
  // decision nobody can argue with later.
  const entries = [...block.matchAll(/'([a-z0-9-]+\.html)':\s*\{([^}]*)\}/g)];
  check('every route in the policy states a reason',
    entries.length === 11 && entries.every(e => /reason:\s*'[^']{20,}'/.test(e[2])));

  const AD_MARKERS = /adsbygoogle|data-ad-client|data-ad-slot|class="ad-rail/;
  const AD_HOSTS = /googlesyndication|googleadservices|googletagservices|adservice\.google|doubleclick|fundingchoices/;

  for (const [file, enabled] of Object.entries(policy)) {
    const fp = path.join(__dirname, file);
    if (!fs.existsSync(fp)) { check(file + ' exists', false); continue; }
    const html = fs.readFileSync(fp, 'utf8');
    const meta = (html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/) || [])[1] || '';

    check(`${file}: markup matches policy (ads ${enabled ? 'on' : 'off'})`,
      AD_MARKERS.test(html) === enabled,
      enabled ? 'policy says ads but the page has no ad markup'
              : 'policy says NO ads but the page still contains ad markup');

    check(`${file}: its own CSP matches policy (ad hosts ${enabled ? 'present' : 'absent'})`,
      !!meta && AD_HOSTS.test(meta) === enabled,
      !meta ? 'the page has no meta Content-Security-Policy at all'
            : (enabled ? 'ads are on but the policy would block them'
                       : 'ads are off but the policy still permits the ad hosts'));
  }

  // The guides that teach people to distrust a message must never be
  // the place we put an unreviewed commercial link.
  for (const sensitive of ['disguised-links.html', 'seed-phrase-phishing.html',
                           'prompt-injection.html', 'invisible-characters.html']) {
    check(`${sensitive} is ad-free by policy`, policy[sensitive] === false,
      'this guide explains a deception; advertising beside it reads as endorsement');
  }

  // And the claim has to be true in the documents that make it.
  const priv = fs.readFileSync(path.join(__dirname, 'privacy.html'), 'utf8');
  check('the privacy policy no longer claims ads run on every page',
    !/It runs on every page/i.test(priv) && /deliberately do not/i.test(priv));
}

console.log('\n' + '='.repeat(60));
if (fail) {
  console.log(`${fail} FAILED, ${pass} passed`);
  failures.forEach(f => console.log('  - ' + f));
  console.log('='.repeat(60));
  process.exit(1);
}
console.log(`${pass}/${pass} guide-example checks passed`);
console.log('='.repeat(60));
