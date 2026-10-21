#!/usr/bin/env node
/* =====================================================================
   SPOT THE TRAP — content, page and script checks

   A test can confirm that every scenario is complete, that the pages
   carry no third-party code and that nothing records the visitor's
   answer. It cannot tell whether the advice is right or whether a source
   supports it; a person approves that (`reviewed` in challenges.js).

   Run with: node challenge.test.js
   ===================================================================== */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { CHALLENGES } = require('./challenges.js');

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; failures.push(name + (detail ? ' — ' + detail : '')); console.log('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}
const read = (f) => fs.readFileSync(path.join(__dirname, f), 'utf8');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const textOf = (m) => [typeof m.from === 'object' && m.from ? m.from.text : m.from || ''].concat(m.parts.map(p => typeof p === 'string' ? p : p.text)).join(' ');
const marksOf = (c) => c.messages.flatMap(m => [m.from].concat(m.parts)).filter(p => p && typeof p === 'object').map(p => p.mark);

// Real brands a scenario must not name as a sender or in a message.
const BRANDS = /\b(binance|coinbase|metamask|paypal|dhl|ups|fedex|amazon|microsoft|google|apple|whatsapp|telegram|revolut|wise|visa|mastercard|hsbc|barclays|chase|dsk|unicredit|fibank|ftc)\b/i;

console.log('== Scenario content ==');
check('there are four starter scenarios', CHALLENGES.length === 4, String(CHALLENGES.length));
check('ids are unique', new Set(CHALLENGES.map(c => c.id)).size === CHALLENGES.length);
for (const c of CHALLENGES) {
  const id = c.id;
  check(id + ': id is a lowercase slug', /^[a-z0-9]+(-[a-z0-9]+)*$/.test(id));
  check(id + ': has a whole-number version', Number.isInteger(c.version) && c.version >= 1);
  check(id + ': has title, scene, label, channel and takeaway',
    [c.title, c.scene, c.exchangeLabel, c.channel, c.remember].every(s => typeof s === 'string' && s.trim().length > 3));
  check(id + ': has at least one message', Array.isArray(c.messages) && c.messages.length > 0);
  check(id + ': offers three or four choices', c.choices.length >= 3 && c.choices.length <= 4);
  check(id + ': choices are lettered A, B, C…', c.choices.map(x => x.key).join('') === 'ABCD'.slice(0, c.choices.length));
  check(id + ': exactly one recommended choice', c.choices.filter(x => x.recommended).length === 1);
  check(id + ': every choice has feedback', c.choices.every(x => x.feedback && x.feedback.length > 20));
  const marks = marksOf(c).sort((a, b) => a - b);
  check(id + ': numbered details match the highlighted parts one to one',
    JSON.stringify(marks) === JSON.stringify(c.details.map((_, i) => i + 1)), 'marks ' + marks + ', details ' + c.details.length);
  check(id + ': details heading present', typeof c.detailsHeading === 'string' && c.detailsHeading.length > 3);
  check(id + ': a source with an https link and its own wording',
    c.source && /^https:\/\//.test(c.source.url) && c.source.label && c.source.text.length > 30);
  check(id + ': reviewed is empty or a date', c.reviewed === null || /^\d{4}-\d{2}-\d{2}$/.test(c.reviewed));
  const msgText = c.messages.map(textOf).join(' ') + ' ' + c.scene;
  check(id + ': no web address except a .example one',
    (msgText.match(/\b[a-z0-9-]+\.(com|net|org|io|xyz|co|app|link|info)\b/gi) || []).length === 0
    && !/https?:\/\//i.test(msgText));
  check(id + ': no real brand named in the scene or message', !BRANDS.test(msgText), (msgText.match(BRANDS) || [])[0]);
  check(id + ': no phone number in the message', !/\+?\d[\d\s()-]{8,}\d/.test(c.messages.map(textOf).join(' ')));
}
check('the recommended answer is not always in the same position',
  new Set(CHALLENGES.map(c => c.choices.find(x => x.recommended).key)).size > 1);
check('at least one ordinary-looking round with nothing to highlight',
  CHALLENGES.some(c => c.details.length === 0 && marksOf(c).length === 0));
check('the ordinary-looking round is not called genuine',
  CHALLENGES.filter(c => c.details.length === 0).every(c => !/\bgenuine\b/i.test(c.title + c.scene + c.exchangeLabel)));

console.log('\n== Generated pages ==');
let upToDate = true;
try { execFileSync('node', ['build-challenges.js', '--check'], { cwd: __dirname, stdio: 'pipe' }); } catch (_) { upToDate = false; }
check('pages are up to date with challenges.js (node build-challenges.js)', upToDate);

const pages = ['spot-the-trap.html'].concat(CHALLENGES.map(c => 'spot-the-trap-' + c.id + '.html'));
for (const f of pages) {
  const html = read(f);
  const csp = (html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/) || [])[1] || '';
  const dir = (n) => ((csp.split(';').map(x => x.trim()).find(x => x.startsWith(n + ' ')) || '').slice(n.length + 1)).trim();
  check(f + ": script-src is this site only", dir('script-src') === "'self'", dir('script-src'));
  check(f + ': connects nowhere and embeds no frames', dir('connect-src') === "'none'" && dir('frame-src') === "'none'");
  const scripts = [...html.matchAll(/<script\b([^>]*)>/g)].map(m => m[1]);
  check(f + ': no external script', scripts.every(a => !/src="https?:/.test(a)));
  check(f + ': no inline executable script', scripts.every(a => /src="spot-the-trap\.js"/.test(a) || /type="application\/ld\+json"/.test(a)));
  check(f + ': no advertising or analytics', !/adsbygoogle|googlesyndication|fundingchoices|cloudflareinsights|data-ad-slot/.test(html));
  const canon = (html.match(/rel="canonical" href="([^"]+)"/) || [])[1];
  const og = (html.match(/property="og:url" content="([^"]+)"/) || [])[1];
  check(f + ': canonical is the served address and matches the card', !!canon && !/\.html$/.test(canon) && canon === og);
  const img = (html.match(/property="og:image" content="https:\/\/savesavesavesave\.xyz\/([^"]+)"/) || [])[1];
  const png = img && fs.existsSync(path.join(__dirname, img)) ? fs.readFileSync(path.join(__dirname, img)) : null;
  check(f + ': has its own 1200x630 preview image',
    !!png && img === f.replace(/\.html$/, '.png') && png.readUInt32BE(16) === 1200 && png.readUInt32BE(20) === 630, img);
}

for (const c of CHALLENGES) {
  const f = 'spot-the-trap-' + c.id + '.html';
  const html = read(f);
  const url = 'https://savesavesavesave.xyz/spot-the-trap-' + c.id;
  check(f + ': every choice and its feedback is in the delivered HTML',
    c.choices.every(x => html.includes(esc(x.text)) && html.includes(esc(x.feedback))));
  check(f + ': no choice is pre-selected', !/<input[^>]*type="radio"[^>]*checked/.test(html));
  check(f + ': the explanation starts hidden', /<section class="stt-explanation" id="stt-explanation"[^>]*hidden>/.test(html));
  check(f + ': detail numbers start hidden', (html.match(/<sup class="sign-n" hidden>/g) || []).length === marksOf(c).length);
  check(f + ': takeaway and source are on the page', html.includes(esc(c.remember)) && html.includes(esc(c.source.url)));
  const share = (html.match(/<button[^>]*id="stt-share"[^>]*>/) || [''])[0];
  const shareText = esc('Would you spot the trap?\n' + c.title + '\nTry the challenge at SaveSaveSaveSave.');
  check(f + ': share carries the fixed words and this public address only',
    share.includes('data-url="' + url + '"') && share.includes('data-text="' + shareText + '"'));
  check(f + ': the card download is this scenario\'s preview image', html.includes('href="spot-the-trap-' + c.id + '.png" download'));
  check(f + ': the page description does not give the answer',
    !c.choices.some(x => (html.match(/<meta name="description" content="([^"]+)"/) || [, ''])[1].includes(esc(x.text))));
}
const idx = read('spot-the-trap.html');
check('index links every challenge', CHALLENGES.every(c => idx.includes('href="spot-the-trap-' + c.id + '.html"')));
check('the scanner links to Spot the Trap', read('index.html').includes('<a class="nav-link" href="spot-the-trap.html">Spot the Trap</a>'));
check('the privacy page describes the challenge pages', /id="spot-the-trap"/.test(read('privacy.html')));

console.log('\n== The page script ==');
const js = read('spot-the-trap.js');
const code = js.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
const banned = [
  ['browser storage', /localStorage|sessionStorage|indexedDB|document\.cookie|caches\./],
  ['network requests', /fetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource|new Image|\.src\s*=/],
  ['clipboard reads', /clipboard\.read|readText|execCommand/],
  ['keyboard listeners', /keydown|keyup|keypress/],
  ['HTML injection', /innerHTML|outerHTML|insertAdjacentHTML|document\.write/],
  ['writing the address bar', /location\s*\.\s*(href|hash|search)\s*=|history\.(push|replace)State/],
  ['evaluating text', /\beval\s*\(|new Function/],
];
for (const [name, re] of banned) check('spot-the-trap.js: no ' + name, !re.test(code), (code.match(re) || [])[0]);
check('spot-the-trap.js: the shared text is read from the fixed button attribute, not the answer',
  /getAttribute\('data-text'\)/.test(code) && !/data-text[^\n]*chosen\(/.test(code));
check('spot-the-trap.js is published; challenges.js and the builders are not',
  (() => { const ig = read('.assetsignore'); return !/^spot-the-trap\.js$/m.test(ig) && /^challenges\.js$/m.test(ig) && /^build-challenges\.js$/m.test(ig) && /^trap-cards\.py$/m.test(ig); })());
check('trap-cards.py draws only the title, never choices or feedback', !/choice|feedback|recommended|remember/i.test(read('trap-cards.py').replace(/^"""[\s\S]*?"""/m, '')));

console.log('\n' + '='.repeat(60));
console.log(`${pass}/${pass + fail} Spot the Trap checks passed`);
if (failures.length) { console.log('\nFailures:'); failures.forEach(f => console.log('  - ' + f)); }
console.log('='.repeat(60));
process.exit(fail ? 1 : 0);
