#!/usr/bin/env node
/* =====================================================================
   SEO TESTS

   Structured data is markup nobody looks at, describing a page to a
   machine. That combination is how it goes wrong: a typo, a stale date
   or a claim the page does not support can sit there for months with
   everything looking fine. Worse, schema that misrepresents a page is a
   manual-action risk — and on a site whose whole argument is that it
   does not overstate what it knows, it would be the wrong kind of
   mistake to make.

   So these read the FILES as they will be served and check that every
   machine-readable claim matches something a human can verify on the
   page: the canonical, the title, the heading, the dates, the author,
   the breadcrumb trail.

   Run:  node seo.test.js
   ===================================================================== */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const SITE = 'https://savesavesavesave.xyz';
const PAGES = [
  'index.html', 'guides.html', 'whitepaper.html', 'technical-appendix.html',
  'honeypot-tokens.html', 'invisible-characters.html', 'prompt-injection.html',
  'seed-phrase-phishing.html', 'disguised-links.html', 'privacy.html', 'terms.html',
];
const GUIDES = ['honeypot-tokens.html', 'invisible-characters.html', 'prompt-injection.html',
                'seed-phrase-phishing.html', 'disguised-links.html'];

let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; failures.push(name + (detail ? ' — ' + detail : '')); console.log('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}
function section(t) { console.log('\n== ' + t + ' =='); }

const read = f => fs.readFileSync(path.join(__dirname, f), 'utf8');
const decode = s => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
                     .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, ' ');
function graphOf(html) {
  const out = [];
  for (const m of html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)) {
    const parsed = JSON.parse(m[1]);
    (parsed['@graph'] || [parsed]).forEach(n => out.push(n));
  }
  return out;
}
const nodeOf = (g, type) => g.find(n => n['@type'] === type);

// ---------------------------------------------------------------------
section('Every page is describable at all');
for (const f of PAGES) {
  const s = read(f);
  const title = (s.match(/<title>([\s\S]*?)<\/title>/) || [])[1];
  const desc = (s.match(/<meta name="description" content="([\s\S]*?)"\s*\/?>/) || [])[1];
  const canon = (s.match(/<link rel="canonical" href="([^"]+)"/) || [])[1];
  const h1 = (s.match(/<h1[^>]*>([\s\S]*?)<\/h1>/g) || []);
  check(f + ': has a title, a description and a canonical', !!title && !!desc && !!canon);
  check(f + ': has exactly one h1', h1.length === 1, h1.length + ' found');
  check(f + ': the canonical is absolute and on this site',
    !!canon && canon.startsWith(SITE), canon);
  // Extensionless, because that is what the deploy actually serves — a
  // canonical that redirects tells a crawler the real address is
  // somewhere other than the one it just fetched.
  check(f + ': the canonical is extensionless', !!canon && !/\.html$/.test(canon), canon);
}

section('Titles and descriptions are unique');
{
  const titles = {}, descs = {};
  PAGES.forEach(f => {
    const s = read(f);
    titles[f] = (s.match(/<title>([\s\S]*?)<\/title>/) || [])[1];
    descs[f] = (s.match(/<meta name="description" content="([\s\S]*?)"\s*\/?>/) || [])[1];
  });
  check('no two pages share a title', new Set(Object.values(titles)).size === PAGES.length);
  check('no two pages share a description', new Set(Object.values(descs)).size === PAGES.length);
  const longTitles = Object.entries(titles).filter(([, t]) => decode(t).length > 70).map(([f]) => f);
  check('titles stay inside what a result actually shows', longTitles.length === 0,
    longTitles.join(', ') + ' — anything past ~70 characters is cut off');
}

section('Social cards exist on every page');
for (const f of PAGES) {
  const s = read(f);
  const need = ['og:title', 'og:description', 'og:url', 'og:image', 'twitter:card'];
  const missing = need.filter(k => !new RegExp('(property|name)="' + k + '"').test(s));
  // Before this existed, every page but the scanner pasted into X,
  // Telegram or Discord as a bare grey link.
  check(f + ': has a shareable card', missing.length === 0, 'missing ' + missing.join(', '));
  const ogUrl = (s.match(/property="og:url" content="([^"]+)"/) || [])[1];
  const canon = (s.match(/<link rel="canonical" href="([^"]+)"/) || [])[1];
  check(f + ': the card points at the canonical URL', ogUrl === canon, ogUrl + ' vs ' + canon);
}
check('the card image is actually in the repository',
  fs.existsSync(path.join(__dirname, 'og-image.png')),
  'a card pointing at a 404 renders worse than no card at all');

section('Structured data says only what the page supports');
for (const f of PAGES) {
  const s = read(f);
  let g;
  try { g = graphOf(s); } catch (e) { check(f + ': JSON-LD parses', false, e.message); continue; }
  check(f + ': JSON-LD parses and is non-empty', g.length > 0);

  const crumbs = nodeOf(g, 'BreadcrumbList');
  if (f !== 'index.html') {
    check(f + ': has a breadcrumb trail', !!crumbs);
    if (crumbs) {
      const pos = crumbs.itemListElement.map(i => i.position);
      check(f + ': breadcrumb positions are 1..n in order',
        pos.every((p, i) => p === i + 1), JSON.stringify(pos));
      check(f + ': the trail starts at the scanner',
        crumbs.itemListElement[0].item === SITE + '/');
    }
  }
}

section('Article claims match the article');
for (const f of GUIDES) {
  const s = read(f);
  const g = graphOf(s);
  const art = nodeOf(g, 'TechArticle');
  check(f + ': is marked up as an article', !!art);
  if (!art) continue;

  const h1 = decode(((s.match(/<h1[^>]*>([\s\S]*?)<\/h1>/) || [])[1] || '').replace(/<[^>]+>/g, '').trim());
  check(f + ': the headline is the heading on the page', art.headline === h1.slice(0, 110),
    JSON.stringify(art.headline) + ' vs ' + JSON.stringify(h1));

  const canon = (s.match(/<link rel="canonical" href="([^"]+)"/) || [])[1];
  check(f + ': the article URL is the canonical', art.url === canon);

  check(f + ': has an author', art.author && art.author.name);
  check(f + ': has a publisher', art.publisher && art.publisher.name);

  const iso = /^\d{4}-\d{2}-\d{2}$/;
  check(f + ': dates are real dates', iso.test(art.datePublished) && iso.test(art.dateModified),
    art.datePublished + ' / ' + art.dateModified);
  check(f + ': was not modified before it was published',
    art.dateModified >= art.datePublished, art.datePublished + ' -> ' + art.dateModified);
  check(f + ': is not dated in the future',
    art.dateModified <= new Date().toISOString().slice(0, 10), art.dateModified);

  // The date a reader sees and the date a crawler sees have to be the
  // same date. Two different answers to "when was this written" is the
  // kind of small dishonesty that costs more than it gains.
  const t = s.match(/<time datetime="(\d{4}-\d{2}-\d{2})"/);
  check(f + ': the visible byline carries the same published date',
    !!t && t[1] === art.datePublished, (t ? t[1] : 'no <time> on the page') + ' vs ' + art.datePublished);
  check(f + ': the visible byline names the author',
    s.includes('by ' + art.author.name),
    'a named author is the cheapest credibility signal there is, and this is safety advice about money');

  const body = s.replace(/<head[\s\S]*?<\/head>/i, '').replace(/<script[\s\S]*?<\/script>/g, '')
               .replace(/<style[\s\S]*?<\/style>/g, '').replace(/<[^>]+>/g, ' ');
  const real = body.split(/\s+/).filter(Boolean).length;
  check(f + ': the word count is not inflated',
    art.wordCount <= real && art.wordCount > real * 0.7,
    'claims ' + art.wordCount + ', page has about ' + real);
}

section('Nothing claims a rich result it has not earned');
for (const f of PAGES) {
  const s = read(f);
  // Review, rating and FAQ markup on pages that are none of those things
  // is the single most common way a small site collects a manual action.
  check(f + ': no invented ratings or reviews',
    !/aggregateRating|"@type"\s*:\s*"Review"|reviewCount/.test(s));
  check(f + ': no FAQ markup on a page that is not an FAQ',
    !/"@type"\s*:\s*"FAQPage"/.test(s) || /faq/i.test(f));
}

section('The crawl surface is coherent');
{
  const robots = read('robots.txt');
  check('robots.txt allows crawling', /User-agent:\s*\*/i.test(robots) && /Allow:\s*\//i.test(robots));
  check('robots.txt declares the sitemap', robots.includes(SITE + '/sitemap.xml'));

  const sm = read('sitemap.xml');
  const locs = [...sm.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
  check('the sitemap lists every public page', locs.length >= PAGES.length,
    locs.length + ' entries for ' + PAGES.length + ' pages');
  check('sitemap URLs are extensionless, like the canonicals',
    locs.every(l => !/\.html$/.test(l)), locs.filter(l => /\.html$/.test(l)).join(', '));

  // Every canonical should appear in the sitemap and the reverse, or one
  // of the two is lying about what this site consists of.
  const canons = PAGES.map(f => (read(f).match(/<link rel="canonical" href="([^"]+)"/) || [])[1]);
  const missing = canons.filter(c => !locs.includes(c));
  check('every canonical URL is in the sitemap', missing.length === 0, missing.join(', '));

  const noindex = PAGES.filter(f => /noindex/i.test(read(f)));
  check('no page accidentally carries noindex', noindex.length === 0, noindex.join(', '));
}

section('IndexNow can actually prove ownership');
{
  // The key file IS the ownership proof. If it is missing, or drifts
  // from the key in the script, every submission comes back 403 — in
  // CI, silently, forever.
  const src = read('indexnow.js');
  const key = (src.match(/const KEY = '([0-9a-f]{8,128})'/) || [])[1];
  check('indexnow.js declares a key of a legal shape', !!key, 'must be 8–128 hex characters');
  if (key) {
    const file = key + '.txt';
    check('the key file is in the repository', fs.existsSync(path.join(__dirname, file)), file);
    if (fs.existsSync(path.join(__dirname, file))) {
      check('the key file contains exactly the key',
        read(file).trim() === key, JSON.stringify(read(file).slice(0, 40)));
    }
    // .assetsignore stops files being published. Excluding this one
    // would break the proof while leaving everything looking fine.
    const ignore = fs.existsSync(path.join(__dirname, '.assetsignore')) ? read('.assetsignore') : '';
    const lines = ignore.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    check('the key file is not excluded from the deploy',
      !lines.includes(file) && !lines.includes('*.txt'),
      'an excluded key file is a 403 on every ping');
  }
  check('the ping script sends URLs and nothing else',
    !/scan|prompt|address|finding|verdict/i.test(read('indexnow.js').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')),
    'nothing about a visitor or a scan may ride along to a search engine');
}

section('The generator is idempotent and its output is committed');
{
  // A build step that changes files every time it runs makes "is the
  // working tree clean" meaningless, which is how an uncommitted fix
  // sits on one machine for a week.
  let out = '';
  try { out = execSync('node seo.js --check', { cwd: __dirname, encoding: 'utf8' }); }
  catch (e) { out = (e.stdout || '') + (e.stderr || ''); }
  check('every page carries an up-to-date generated block',
    /All \d+ pages carry an up-to-date SEO block/.test(out),
    out.trim().split('\n').slice(-2).join(' | ') + ' — run: node seo.js');
}

console.log('\n' + '='.repeat(60));
console.log(`${pass}/${pass + fail} SEO checks passed`);
if (failures.length) { console.log('\nFailures:'); failures.forEach(f => console.log('  - ' + f)); }
console.log('='.repeat(60));
process.exit(fail ? 1 : 0);
