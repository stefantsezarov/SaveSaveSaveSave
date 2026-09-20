#!/usr/bin/env node
/* =====================================================================
   SITEMAP GENERATOR

   The hand-written sitemap went stale within two days, which is the
   normal fate of a date you have to remember to update. This reads the
   real last-commit date of each page from git instead, so `lastmod` is
   correct by construction or the script fails loudly.

   Run with: node build-sitemap.js
   Then commit the regenerated sitemap.xml alongside your changes.
   ===================================================================== */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SITE = 'https://savesavesavesave.xyz';

// Only pages a person should land on. Deliberately excludes the .md
// documents and the test files: a search result pointing at
// promptscan.test.js helps nobody.
const PAGES = [
  { file: 'index.html',      loc: '/',                changefreq: 'weekly',  priority: '1.0' },
  { file: 'whitepaper.html', loc: '/whitepaper.html', changefreq: 'monthly', priority: '0.7' },
  { file: 'technical-appendix.html', loc: '/technical-appendix.html', changefreq: 'monthly', priority: '0.5' },
  { file: 'guides.html',     loc: '/guides.html',     changefreq: 'weekly',  priority: '0.8' },
  { file: 'honeypot-tokens.html', loc: '/honeypot-tokens.html', changefreq: 'monthly', priority: '0.7' },
  { file: 'invisible-characters.html', loc: '/invisible-characters.html', changefreq: 'monthly', priority: '0.7' },
  { file: 'prompt-injection.html', loc: '/prompt-injection.html', changefreq: 'monthly', priority: '0.7' },
  { file: 'seed-phrase-phishing.html', loc: '/seed-phrase-phishing.html', changefreq: 'monthly', priority: '0.7' },
  { file: 'disguised-links.html', loc: '/disguised-links.html', changefreq: 'monthly', priority: '0.7' },
  { file: 'privacy.html',    loc: '/privacy.html',    changefreq: 'monthly', priority: '0.3' },
  { file: 'terms.html',      loc: '/terms.html',      changefreq: 'monthly', priority: '0.3' },
];

function lastCommitDate(file) {
  const out = execSync(`git log -1 --format=%ad --date=short -- "${file}"`, {
    cwd: __dirname, encoding: 'utf8',
  }).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(out)) return out;

  // No commit date. There are two very different reasons for that, and
  // guessing the same answer for both is how a sitemap starts lying.
  //
  // A brand-new page genuinely has no history yet: it is being added in
  // this very commit, so today IS its last-modified date, and refusing
  // to build would mean every new page needs two commits — one to exist,
  // one to appear in the sitemap. That is a chore nobody remembers, and
  // a page missing from the sitemap is a page search engines do not see.
  //
  // A shallow clone, by contrast, has history it simply cannot read, and
  // filling in today's date there would silently mark the entire site as
  // modified today, every time.
  const tracked = execSync(`git ls-files --error-unmatch "${file}" 2>/dev/null || true`, {
    cwd: __dirname, encoding: 'utf8',
  }).trim();
  const shallow = fs.existsSync(path.join(__dirname, '.git', 'shallow'));

  if (!tracked && !shallow) {
    const today = new Date().toISOString().slice(0, 10);
    console.log(`  NOTE: ${file} is not committed yet — using today (${today}) as its date.`);
    return today;
  }

  throw new Error(`No usable git date for ${file} (got "${out}"). `
    + (shallow
      ? 'This is a shallow clone, which reports one date for every file — run this in a full clone.'
      : 'The file is tracked but has no commit date, which should not happen. Investigate before shipping a sitemap.'));
}

const missing = PAGES.filter(p => !fs.existsSync(path.join(__dirname, p.file)));
if (missing.length) {
  console.error('FAIL: listed pages do not exist: ' + missing.map(m => m.file).join(', '));
  process.exit(1);
}

const entries = PAGES.map(p => {
  const d = lastCommitDate(p.file);
  console.log(`  ${p.file.padEnd(18)} lastmod ${d}`);
  return `  <url>
    <loc>${SITE}${p.loc}</loc>
    <lastmod>${d}</lastmod>
    <changefreq>${p.changefreq}</changefreq>
    <priority>${p.priority}</priority>
  </url>`;
}).join('\n');

const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${entries}
</urlset>
`;

fs.writeFileSync(path.join(__dirname, 'sitemap.xml'), xml, 'utf8');
console.log('\nsitemap.xml written');
