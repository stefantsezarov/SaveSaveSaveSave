#!/usr/bin/env node
/* =====================================================================
   INDEXNOW PING

   Tells Bing (and Yandex, Seznam, Naver — they share the endpoint) that
   specific URLs on this site have changed, instead of waiting for a
   crawler to come back and notice.

   WHY IT IS WORTH HAVING. A five-week-old domain is at the bottom of
   every crawl queue there is. Google has no equivalent — its own
   indexing API is restricted to job postings and live streams, so this
   does nothing for Google and is not claimed to. What it does is turn
   Bing's discovery from weeks into minutes, and Bing is what feeds
   DuckDuckGo and several assistants' browsing.

   HOW OWNERSHIP IS PROVED. A key file sits at the root of the site
   containing nothing but the key. Anyone who can put a file there
   controls the site, which is the whole proof. Losing the key is not a
   security event — the worst an attacker can do with it is ask a search
   engine to look at pages that are already public.

   WHAT IT SENDS. URLs from sitemap.xml, and nothing else. No scan
   content, no visitor data, no headers of ours. There is nothing else
   it could send: it runs in CI, long after any visitor has gone.

   Run:  node indexnow.js            (submit every URL in sitemap.xml)
         node indexnow.js --dry-run  (print what would be sent)
         node indexnow.js <url> ...  (submit specific URLs)
   ===================================================================== */

const fs = require('fs');
const path = require('path');
const https = require('https');

const HOST = 'savesavesavesave.xyz';
const KEY = 'd59f6b302872707ba718bed5e47e0ce0';
const KEY_FILE = KEY + '.txt';
const ENDPOINT = 'https://api.indexnow.org/IndexNow';

// The key file is the entire ownership proof. If it is missing from the
// repository, or its contents drift from the key below, every
// submission comes back 403 — and it would do so silently, in CI,
// forever. So this refuses to send rather than ask a search engine a
// question it cannot answer.
function assertKeyFile() {
  const p = path.join(__dirname, KEY_FILE);
  if (!fs.existsSync(p)) {
    throw new Error('Missing ' + KEY_FILE + '. IndexNow proves ownership with that file; without it every ping is a 403.');
  }
  const got = fs.readFileSync(p, 'utf8').trim();
  if (got !== KEY) {
    throw new Error(KEY_FILE + ' contains "' + got + '" but the key is "' + KEY + '". One of the two is wrong; not guessing which.');
  }
}

function urlsFromSitemap() {
  const sm = fs.readFileSync(path.join(__dirname, 'sitemap.xml'), 'utf8');
  const locs = [...sm.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1].trim());
  // Only URLs on this host. Submitting anything else returns 422, and
  // repeatedly doing so is how a host gets rate-limited.
  return locs.filter(u => {
    try { return new URL(u).hostname === HOST; } catch (_) { return false; }
  });
}

function post(body) {
  return new Promise((resolve) => {
    const data = Buffer.from(JSON.stringify(body), 'utf8');
    const req = https.request(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': data.length },
      timeout: 20000,
    }, res => {
      let out = '';
      res.setEncoding('utf8');
      res.on('data', c => { out += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: out.slice(0, 400) }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
    req.on('error', e => resolve({ status: 0, body: e.message }));
    req.write(data);
    req.end();
  });
}

// Documented meanings, so a red CI line says what actually went wrong
// rather than printing a bare number.
const MEANING = {
  200: 'accepted',
  202: 'accepted, key validation pending',
  400: 'bad request — the JSON body was malformed',
  403: 'forbidden — the key file is missing from the site, or does not contain this key',
  422: 'unprocessable — a URL does not belong to this host, or the key does not match',
  429: 'rate limited — too many submissions, back off',
};

(async () => {
  const args = process.argv.slice(2);
  const dry = args.includes('--dry-run');
  const explicit = args.filter(a => a.startsWith('http'));

  assertKeyFile();
  const urlList = explicit.length ? explicit : urlsFromSitemap();
  if (!urlList.length) throw new Error('No URLs to submit. sitemap.xml had none on ' + HOST + '.');

  const body = { host: HOST, key: KEY, keyLocation: 'https://' + HOST + '/' + KEY_FILE, urlList };

  console.log('IndexNow → ' + ENDPOINT);
  console.log('  host        ' + HOST);
  console.log('  keyLocation ' + body.keyLocation);
  console.log('  urls        ' + urlList.length);
  urlList.forEach(u => console.log('              ' + u));

  if (dry) { console.log('\nDry run — nothing sent.'); return; }

  const res = await post(body);
  const note = MEANING[res.status] || (res.status === 0 ? 'no response' : 'unexpected status');
  console.log('\n' + res.status + ' ' + note + (res.body ? ' · ' + res.body : ''));

  // A failed ping is not a failed deploy. The site is fine; a search
  // engine simply was not told. Exit non-zero only for the two states
  // that mean this is broken rather than busy.
  if (res.status === 403 || res.status === 400) process.exit(1);
})().catch(e => { console.error('IndexNow: ' + e.message); process.exit(1); });
