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
    guide.includes('The familiar name being there is not evidence'));

  check('the guide states that structure is not reputation',
    guide.includes('Structure is not reputation'));

  // The label must sit ON the message block, not in the prose above it,
  // so it travels with the example if the page is skimmed or excerpted.
  check('the example message is labelled as fictional, on the block itself',
    /<p class="msg-label">Fictional example \u00b7 reserved domains<\/p>\s*<div class="msg">/.test(guide));

  // The note must be accurate, not merely present. metamask.io is real
  // and resolvable, and the guide prints it deliberately as the example
  // of where a name belongs — so a blanket "all domains are reserved"
  // claim would be false in the one article that must be exact about
  // domains. The note has to name the exception.
  check('the reserved-name note is present and names the live exception',
    /demonstrates a trick points at a reserved example domain/i.test(guide)
    && /The one live domain printed here is <code>metamask\.io<\/code>/i.test(guide));
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
    Object.keys(policy).length === 18, 'found ' + Object.keys(policy).length);

  // Every disabled entry must carry a reason. A silent exclusion is a
  // decision nobody can argue with later.
  const entries = [...block.matchAll(/'([a-z0-9-]+\.html)':\s*\{([^}]*)\}/g)];
  check('every route in the policy states a reason',
    entries.length === 18 && entries.every(e => /reason:\s*'[^']{20,}'/.test(e[2])));

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
                           'prompt-injection.html', 'invisible-characters.html',
                           'sanctioned-addresses.html']) {
    check(`${sensitive} is ad-free by policy`, policy[sensitive] === false,
      'this guide explains a deception; advertising beside it reads as endorsement');
  }

  // And the claim has to be true in the documents that make it.
  const priv = fs.readFileSync(path.join(__dirname, 'privacy.html'), 'utf8');
  check('the privacy policy no longer claims ads run on every page',
    !/It runs on every page/i.test(priv) && /deliberately do not/i.test(priv));
}


// ---- guide 7: what it says the scanner does --------------------------
// "The Address You Can't Pay" describes the sanctions checks in a table.
// Every row of that table is a claim about this code. If the code
// changes, the article has to change with it, and this is what says so.
{
  const C = require('./core.js');
  const g7 = fs.readFileSync(path.join(__dirname, 'sanctioned-addresses.html'), 'utf8');
  const defs = C.EVM_WALLET_CHECK_DEFS;
  const mk = over => defs.map(d => C.buildCheck(d, over[d.key] || '0', 'test')).filter(Boolean);
  const crit = defs.filter(d => d.critical).length;
  const sanc = defs.find(d => d.key === 'sanctioned');
  check('guide 7: a sanctions flag is a critical wallet check named "On a sanctions list"',
    !!sanc && sanc.critical && sanc.label === 'On a sanctions list' && /On a sanctions list/.test(g7));
  check('guide 7: a listed EVM address comes back FAIL',
    C.VerdictEngine.evaluate(mk({ sanctioned: '1' }), defs.length, 'EVM', crit).label === 'FAIL');
  const cp = { id: 'recent_counterparty_sanctioned_0', category: 'exposure', status: 'RISK', critical: false,
               severityWeight: 3, label: 'x', detail: 'x', source: 'x' };
  check('guide 7: a sanctioned counterparty is CAUTION, not FAIL',
    C.VerdictEngine.evaluate(mk({}).concat([cp]), defs.length + 1, 'EVM', crit).label === 'CAUTION');
  check('guide 7: "eight EVM chains" is still the number with a counterparty check',
    C.COUNTERPARTY_CHECK_SUPPORTED_CHAINS.size === 8 && /On eight EVM chains/.test(g7));
  const worker = fs.readFileSync(path.join(__dirname, 'goplus-proxy-worker.js'), 'utf8');
  const range = Number((worker.match(/const LOG_BLOCK_RANGE = (\d+);/) || [])[1]);
  // Twelve-second Ethereum blocks: 2,000 of them is 400 minutes.
  check('guide 7: "a little under seven hours on Ethereum" still matches the look-back window',
    range === 2000 && /a little under seven hours on Ethereum/.test(g7), 'LOG_BLOCK_RANGE is ' + range);
  check('guide 7: Solana wallets are checked against the OFAC list; Sui and TRON wallets are not screened',
    ['sui', 'tron'].every(k => C.Adapters[k].capabilities.walletScreening === false)
      && C.OFAC_SOLANA_ADDRESSES.size > 0 && /OFAC/.test(C.Adapters.solana.capabilityNotes.walletScreening)
      && /Solana wallets<\/td><td data-label="What happens">Checked against the Solana addresses on the US Treasury OFAC list/.test(g7)
      && /Sui and TRON wallets<\/td><td data-label="What happens">Not screened/.test(g7));
  check('guide 7: token scans still carry no sanctions check',
    !C.EVM_TOKEN_CHECK_DEFS.some(d => d.key === 'sanctioned'));
  const clean = C.VerdictEngine.evaluate(mk({}), defs.length, 'EVM', crit);
  check('guide 7: a clean result still says "no major risk indicators" and "not a safety guarantee"',
    /No major risk indicators/.test(clean.sub || '') && /not a safety guarantee/.test(clean.sub || ''),
    clean.sub);
  check('guide 7: the real listed address is labelled as one, and is never a link',
    /Real listed address · do not send anything to it/.test(g7)
      && !/href="[^"]*0x098B716B8Aaf21512996dC57EB0615e2383E2f96/i.test(g7));
}


// ---- guide 8: its example pair really is caught ------------------------
{
  const vm = require('vm');
  const idx = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const a = idx.indexOf('function compareAddresses('), b = idx.indexOf('function twinRow(');
  const cx = {}; vm.createContext(cx);
  vm.runInContext(idx.slice(a, b) + ';this.cmp = compareAddresses;', cx);
  const g8 = fs.readFileSync(path.join(__dirname, 'address-poisoning.html'), 'utf8');
  const pair = [...g8.matchAll(/<div class="msg"[^>]*>(0x[0-9a-fA-F]{40})<\/div>/g)].map(m => m[1]);
  const r = pair.length === 2 ? cx.cmp(pair[0], pair[1]) : null;
  check('guide 8: its two example addresses are flagged as a look-alike by the comparison tool',
    !!r && r.state === 'different' && r.lookalike, JSON.stringify(r));
  const short = x => x.slice(0, 6) + '…' + x.slice(-4);
  check('guide 8: both examples really do shorten to the "0x7a3F…9E2c" the guide shows',
    pair.length === 2 && short(pair[0]) === '0x7a3F…9E2c' && short(pair[1]) === '0x7a3F…9E2c');
}


// ---- guide 9: AI leftovers — every example agrees with the engine --------
{
  const PS = require('./promptscan.js');
  const g9 = fs.readFileSync(path.join(__dirname, 'ai-leftovers.html'), 'utf8');
  const unesc = t => t.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
  const blocks = [...g9.matchAll(/<div class="msg"( id="(\w+)")?>([\s\S]*?)<\/div>/g)].map(m => ({ id: m[2] || '', text: unesc(m[3]) }));
  const left = t => PS.scanPrompt(t).findings.filter(f => f.category === 'AI_ASSISTANT_LEFTOVER').map(f => f.ruleId);
  const leftoverBlocks = blocks.filter(b => b.id !== 'exClean');
  check('guide 9: has its example blocks', blocks.length >= 7, 'found ' + blocks.length);
  for (const b of leftoverBlocks) {
    check('guide 9: the scanner flags the example "' + b.text.split('\n')[0].slice(0, 40) + '"', left(b.text).length > 0);
  }
  const copied = blocks.find(b => b.id === 'exCopied');
  const ids = copied ? left(copied.text) : [];
  check('guide 9: the "as copied" example shows all three leftovers the guide names',
    ['AI_LEFTOVER_PREAMBLE_001', 'AI_LEFTOVER_SIGNOFF_001', 'AI_LEFTOVER_TEMPLATE_001'].every(i => ids.includes(i)), ids.join(','));
  const clean = blocks.find(b => b.id === 'exClean');
  check('guide 9: the cleaned version shows no leftovers', !!clean && left(clean.text).length === 0);
  check('guide 9: leftovers alone keep a PASS, as the guide says', !!copied && PS.scanPrompt(copied.text).label === 'PASS');
  check('guide 9: never calls the check an AI detector', !/AI detector|detects AI|detect whether/i.test(g9.replace(/<!--[\s\S]*?-->/g, '')));
  check('guide 9: points at the result label the page actually uses',
    g9.includes('"AI-assistant leftovers"') && fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8').includes("'AI-assistant leftovers'"));
}

// ---- verdict cards: warnings only, fixed wording, no message text -------
{
  const idx = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const a = idx.indexOf('const CARD_CATEGORY'), b = idx.indexOf('let SHARE_MODEL');
  const vm = require('vm');
  const cx = vm.createContext({ CHAIN_LABEL: { '1': 'Ethereum' } });
  vm.runInContext(idx.slice(a, b) + ';this.api = { verdictCardModel, addressCardInput, messageCardInput, cardStamp, CARD_CATEGORY };', cx);
  const api = cx.api;
  const addr = '0x1234567890abcdef1234567890abcdef12345678';
  const res = v => ({ verdict: v, checksUnknown: 1, checksExpected: 14,
    checks: [{ status: 'RISK', label: 'Honeypot pattern' }, { status: 'PASS', label: 'Open source' }] });
  const caps = { name: 'x', capabilities: { txSimulation: true, liquidityAnalysis: true, contractAnalysis: true, walletScreening: true } };
  check('card: no card for PASS', api.verdictCardModel(api.addressCardInput(res('pass'), addr, '1', caps, 'token')) === null);
  check('card: no card for INSUFFICIENT DATA', api.verdictCardModel(api.addressCardInput(res('unknown'), addr, '1', caps, 'token')) === null);
  const m = api.verdictCardModel(api.addressCardInput(res('fail'), addr, '1', caps, 'token'));
  check('card: FAIL gets a card with the approved header and link',
    m && m.label === 'FAIL' && m.header === 'SAVESAVESAVESAVE · Automated risk assessment'
      && m.site === 'Check it yourself: savesavesavesave.xyz');
  check('card: the full address is on it, never shortened', m && m.groups.join('') === addr);
  check('card: says what was found and what was not checked',
    m && m.found.join('|') === 'Honeypot pattern' && m.notChecked.join('|') === '1 of 14 checks unreadable'
      && m.target === 'Ethereum · Token scan');
  check('card: the time is stated in UTC and says it is not a guarantee',
    api.cardStamp(new Date(Date.UTC(2026, 8, 27, 14, 5))) === 'Checked 27 Sep 2026, 14:05 UTC · Not a guarantee');
  const planted = 'PLANTED-SECRET-7731', plantedAddr = '0xfeedfacefeedfacefeedfacefeedfacefeedface';
  const pr = { input: { characters: 120 }, findings: [
    { category: 'CRYPTO_SECRET_REQUEST', severity: 'CRITICAL', title: 'asks for ' + planted, evidence: { excerpt: planted } },
    { category: 'NOT_A_REAL_CATEGORY', severity: 'HIGH', title: planted },
    { category: 'BENIGN_INFORMATIONAL', severity: 'INFO', title: planted } ] };
  const msg = { text: planted, addresses: [{ address: plantedAddr, scan: null }] };
  const mm = api.verdictCardModel(api.messageCardInput({ verdict: 'caution' }, pr, msg));
  const blob = JSON.stringify(mm);
  check('card: a message card never carries the message text or an address from it',
    mm && !blob.includes(planted) && !blob.includes(plantedAddr));
  check('card: message findings use fixed wording only',
    mm && mm.found.join('|') === 'Asks for a recovery phrase or private key|Other risk pattern'
      && mm.notChecked.includes('1 address in it not checked'));
  const cats = [...new Set([...idx.matchAll(/category: '([A-Z_]+)'/g)].map(x => x[1]))].filter(c => c !== 'BENIGN_INFORMATIONAL');
  const missing = cats.filter(c => !api.CARD_CATEGORY[c]);
  check('card: every category the engine can report has card wording', missing.length === 0, missing.join(', '));
  const pk = api.verdictCardModel({ kind: 'package', verdict: 'fail', packageLabel: 'crossenv@0.0.2-security',
    found: ['Removed by npm for security reasons'], notChecked: ['Package code not analysed'], when: new Date(Date.UTC(2026, 8, 28, 9, 0)) });
  check('card: a package card names the package and keeps the fixed wording',
    pk && pk.target === 'npm package \u00b7 crossenv@0.0.2-security' && pk.groups === null && pk.label === 'FAIL');
  check('card: the share control sits outside the results area',
    idx.indexOf('id="shareCard"') > idx.indexOf('<section id="results"></section>'));
}

// ---- every guide is linked from the homepage and from other guides ------
{
  const idx = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const gi = fs.readFileSync(path.join(__dirname, 'guides.html'), 'utf8');
  const live = [...gi.matchAll(/<a class="guide-card" href="([a-z-]+\.html)"/g)].map(m => m[1]);
  const learn = (idx.match(/<section class="how learn"[\s\S]*?<\/section>/) || [''])[0];
  const missing = live.filter(h => !learn.includes('href="' + h + '"'));
  check('homepage: links every published guide', live.length >= 7 && missing.length === 0, missing.join(', '));
  for (const g of live) {
    const page = fs.readFileSync(path.join(__dirname, g), 'utf8');
    const nav = (page.match(/<nav class="keep-reading"[\s\S]*?<\/nav>/) || [''])[0];
    const links = [...nav.matchAll(/href="([^"]+)"/g)].map(m => m[1]);
    check(g + ': links three other published guides',
      links.length === 3 && links.every(h => h !== g && live.includes(h)), links.join(', '));
  }
}

// ---- "How the pass is built" matches the selected scan ------------------
{
  const idx = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const how = (idx.match(/<section class="how">[\s\S]*?<\/section>/) || [''])[0];
  for (const [id, hidden] of [['address', false], ['prompt', true], ['package', true]]) {
    const m = how.match(new RegExp('<div class="steps" id="how-' + id + '"( hidden)?>([\\s\\S]*?)\\n    </div>'));
    check('how it works: the ' + id + ' scan has three steps' + (hidden ? ', hidden until selected' : ', shown first'),
      !!m && !!m[1] === hidden && (m[2].match(/class="step"/g) || []).length === 3);
  }
  check('how it works: switching scans switches the steps', /\['how-package', isPkg\]/.test(idx) && /\.steps\[hidden\]\{display:none;\}/.test(idx));
}

// ---- guide 8 is reachable from the tool it pairs with --------------------
{
  const idx = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const twin = (idx.match(/<details class="twin" id="twinCheck">[\s\S]*?<\/details>/) || [''])[0];
  check('compare tool: links to the address-poisoning guide',
    /<a [^>]*href="address-poisoning\.html"/.test(twin));
  check('compare tool: the guide link sits outside the live result area',
    !/id="twinResult"[^>]*>[^<]*<a /.test(twin));
}

// ---- the donation address is the one we published ----------------------
{
  const page = fs.readFileSync(path.join(__dirname, 'support.html'), 'utf8');
  const md = fs.readFileSync(path.join(__dirname, 'SUPPORT.md'), 'utf8');
  const inPage = [...page.matchAll(/0x[0-9a-fA-F]{40}/g)].map(m => m[0]);
  const inMd = [...md.matchAll(/0x[0-9a-fA-F]{40}/g)].map(m => m[0]);
  check('support: the page shows exactly one address, the one in SUPPORT.md',
    inPage.length === 1 && inMd.length === 1 && inPage[0] === inMd[0], JSON.stringify({ inPage, inMd }));
  check('support: the address is shown as text, never as a link', !/href="[^"]*0x[0-9a-fA-F]{40}/.test(page));
  check('support: the page says we never ask for crypto by message', /We will never message you asking for crypto/.test(page));
  check('support: the code licence is AGPL-3.0 and the notice says what it does not cover',
    /GNU AFFERO GENERAL PUBLIC LICENSE/.test(fs.readFileSync(path.join(__dirname, 'LICENSE'), 'utf8'))
      && /AGPL-3\.0-only/.test(fs.readFileSync(path.join(__dirname, 'LICENSE.md'), 'utf8')));
}


// ---- the wordmark is the way home -------------------------------------
// Every page except the scanner must let a visitor get back with one
// click on the logo. It has to be a real <a href> rather than a click
// handler on a <div>, so the keyboard reaches it, middle-click opens a
// tab, and a screen reader announces it as a link.
//
// index.html is deliberately excluded: there the logo would reload a
// page someone may have just pasted a long message into, and losing
// their input to a stray click is worse than a logo that does nothing
// while they are already home.
{
  const SUBPAGES = ['guides.html', 'whitepaper.html', 'technical-appendix.html',
    'privacy.html', 'terms.html', 'honeypot-tokens.html', 'invisible-characters.html',
    'prompt-injection.html', 'seed-phrase-phishing.html', 'disguised-links.html',
    'sanctioned-addresses.html', 'address-poisoning.html', 'ai-leftovers.html', 'support.html', 'tools.html', 'agents.html', 'about.html'];

  for (const f of SUBPAGES) {
    const fp = path.join(__dirname, f);
    if (!fs.existsSync(fp)) { check(f + ' exists', false); continue; }
    const html = fs.readFileSync(fp, 'utf8');
    const brand = (html.match(/<a class="brand"[^>]*>/) || [])[0];
    check(f + ': the logo links home',
      !!brand && /href="index\.html"/.test(brand),
      brand ? 'found a brand link but it does not point at index.html' : 'the logo is not a link');
    check(f + ': the logo link has an accessible name',
      !!brand && /aria-label="[^"]{10,}"/.test(brand),
      'a link whose text is four styled spans needs a label saying where it goes');
  }

  const home = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  check('index.html does NOT link the logo',
    !/<a class="brand"/.test(home),
    'on the scanner the logo would reload the page and discard whatever was pasted');
}


// ---- what the site publishes ------------------------------------------
// The deploy's asset directory is the repository root, so by DEFAULT every
// file here becomes a URL. That was not a decision anyone made: it was
// found by fetching savesavesavesave.xyz/README.md and getting the whole
// whitepaper back. .assetsignore is what turns "everything is published"
// into a list somebody chose.
//
// The check that matters most runs in the SAFE direction: nothing the
// pages actually link to may be ignored. Getting that wrong ships a site
// with a broken download link and no error anywhere.
{
  const ignorePath = path.join(__dirname, '.assetsignore');
  check('.assetsignore exists', fs.existsSync(ignorePath),
    'without it every file in this folder is served at its own URL');

  if (fs.existsSync(ignorePath)) {
    const pats = fs.readFileSync(ignorePath, 'utf8')
      .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

    const toRe = p => new RegExp('^' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
    const isIgnored = f => pats.some(p => toRe(p).test(f));

    // Internal documents must not be published by the deploy.
    for (const doc of ['ARCHITECTURE.md', 'UPLOAD-NOTES.md', 'PAGES-SETUP.md',
                       'SaveSaveSaveSave_Whitepaper_v3.0.md', 'SaveSaveSaveSave_Whitepaper_Short_v3.0.md']) {
      check('not published: ' + doc, isIgnored(doc),
        'this document was written for the people building the site, not for readers');
    }

    // PRIVATE documents are held to a stricter rule: they must not be in
    // the repository AT ALL. This repository is public, so an ignore list
    // only controls what the website serves — it does nothing about what
    // GitHub shows, and nothing about the deploy's own .git directory.
    // Both of these were committed and stayed public for weeks before
    // anyone checked. They live in ../private/ now.
    for (const doc of ['PROJECT-STATE.md',
                       'SaveSaveSaveSave_Wallet_Risk_Intelligence_Proposal.md']) {
      check('absent from the repository: ' + doc,
        !fs.existsSync(path.join(__dirname, doc)),
        'a public repository is the wrong place to decide what stays unread');
    }

    // Engine source is embedded in the page; serving a second copy only
    // creates something that can fall out of step with what runs.
    for (const src of ['promptscan.js', 'core.js', 'scanmodel.js']) {
      check('not published: ' + src, isIgnored(src),
        'index.html carries this verbatim — a served copy is a second source of truth');
    }

    // The deploy's own .git directory. Cloudflare's builder uploads the
    // checkout it produced, .git and all — confirmed live: /.git/config,
    // /.git/HEAD, /.git/logs/HEAD and /.git/index each returned 200, and
    // .git/index holds the blob hash of every tracked file, so each
    // document excluded above was still fetchable at /.git/objects/<hash>.
    // Excluding files by name is worth nothing while a second copy of all
    // of them is served from .git. This asserts the rule is present; only
    // a fetch against the deployed site proves the upload honoured it.
    const ignoresPath = p => pats.some(pat => {
      const base = pat.replace(/\/+$/, '');
      return toRe(base).test(p) || p === base || p.startsWith(base + '/');
    });
    for (const p of ['.git', '.git/config', '.git/index', '.git/logs/HEAD',
                     '.git/objects/33/bf2bfd58cf52cc587383ac007d3a7d9c5cac21']) {
      check('not published: ' + p, ignoresPath(p),
        'the git directory republishes every file this list excludes');
    }

    // THE SAFE DIRECTION. Anything the pages link to must still be served.
    const PAGES = ['index.html', 'guides.html', 'whitepaper.html', 'technical-appendix.html',
      'privacy.html', 'terms.html', 'honeypot-tokens.html', 'invisible-characters.html',
      'prompt-injection.html', 'seed-phrase-phishing.html', 'disguised-links.html',
    'sanctioned-addresses.html', 'address-poisoning.html', 'ai-leftovers.html', 'support.html', 'tools.html', 'agents.html', 'about.html'];
    const referenced = new Set();
    for (const f of PAGES) {
      const fp = path.join(__dirname, f);
      if (!fs.existsSync(fp)) continue;
      const html = fs.readFileSync(fp, 'utf8');
      for (const m of html.matchAll(/(?:href|src)="(?!https?:|data:|#|mailto:)([^"?#]+)"/g)) {
        referenced.add(m[1].replace(/^\.\//, ''));
      }
    }
    const broken = [...referenced].filter(r => isIgnored(r));
    check('nothing the pages link to is excluded from the deploy',
      broken.length === 0,
      broken.length ? 'these would 404: ' + broken.join(', ') : '');

    // And every page itself must still be served.
    check('every published page is still served',
      !PAGES.some(isIgnored));
  }
}


// ---- the site must stay reachable -------------------------------------
// The privacy policy once gave a GitHub issue tracker as the ONLY way to
// reach the operator, including for privacy requests. Making the
// repository private turned that into a dead end overnight: a legally
// meaningful contact route, broken by a setting on somebody else's
// platform. A contact route must not depend on a reader having an
// account, or on a repository's visibility.
{
  for (const f of ['privacy.html', 'terms.html']) {
    const fp = path.join(__dirname, f);
    if (!fs.existsSync(fp)) { check(f + ' exists', false); continue; }
    const html = fs.readFileSync(fp, 'utf8');
    check(f + ': offers a contact route that needs no third-party account',
      /href="mailto:[^"@]+@[^"]+"/.test(html),
      'the only contact was an issue tracker, which broke the moment the repo went private');
  }

  // And no page may present a platform link as the sole route.
  const priv = fs.readFileSync(path.join(__dirname, 'privacy.html'), 'utf8');
  check('privacy.html does not call the issue tracker the only route',
    !/privacy requests: <a href="https:\/\/github\.com[^"]*">[^<]*<\/a>\.<\/p>/.test(priv));
}


// ---- the declared address is the served address -----------------------
// The deploy serves /guides and 301s /guides.html to it. Both work, but
// a canonical tag naming the redirecting form tells a crawler the
// authoritative address is one the site answers with a redirect rather
// than a page, and every sitemap entry cost an extra round trip.
//
// Internal links deliberately keep .html — they survive the redirect and
// cannot break if the platform's extension handling changes. This is
// only about the addresses published AS authoritative.
{
  const PAGES = ['index.html', 'guides.html', 'whitepaper.html', 'technical-appendix.html',
    'privacy.html', 'terms.html', 'honeypot-tokens.html', 'invisible-characters.html',
    'prompt-injection.html', 'seed-phrase-phishing.html', 'disguised-links.html',
    'sanctioned-addresses.html', 'address-poisoning.html', 'ai-leftovers.html', 'support.html', 'tools.html', 'agents.html', 'about.html'];

  for (const f of PAGES) {
    const fp = path.join(__dirname, f);
    if (!fs.existsSync(fp)) continue;
    const canon = (fs.readFileSync(fp, 'utf8').match(/rel="canonical" href="([^"]+)"/) || [])[1];
    check(f + ': canonical names the served address',
      !!canon && !/\.html$/.test(canon),
      canon ? canon + ' redirects; it is not the address served' : 'no canonical tag');
  }

  const sm = path.join(__dirname, 'sitemap.xml');
  if (fs.existsSync(sm)) {
    const locs = [...fs.readFileSync(sm, 'utf8').matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
    check('sitemap lists every page', locs.length === PAGES.length, 'found ' + locs.length);
    const withExt = locs.filter(l => /\.html$/.test(l));
    check('no sitemap entry points at a redirecting address',
      withExt.length === 0, withExt.join(', '));
  }
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
