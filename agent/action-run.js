'use strict';
// Entry point for the GitHub Action (action.yml at the repository root).
// Uses only Node's standard library and this package: nothing is installed.
const fs = require('fs');
const D = require('./deps-check.js');

(async () => {
  const dir = process.env.S4_PATH || '.';
  const failOn = process.env.S4_FAIL_ON === 'caution' ? 'caution' : 'fail';
  const rep = await D.checkDeps(dir, { includeDev: process.env.S4_DEV !== 'false' });
  const md = D.markdown(rep, failOn);
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
  console.log(md);
  const clean = s => String(s || '').replace(/[\r\n%]/g, ' ').slice(0, 400);
  for (const r of rep.results) {
    if (r.verdict === 'fail') console.log(`::error title=${clean(r.name)}::${clean(r.label)}: ${clean(r.summary)}`);
    else if (r.verdict === 'caution' || r.verdict === 'unknown') console.log(`::warning title=${clean(r.name)}::${clean(r.label)}: ${clean(r.summary)}`);
  }
  const bad = D.failed(rep.results, failOn);
  if (bad.length) { console.log(`${bad.length} dependenc${bad.length === 1 ? 'y' : 'ies'} at or above "${failOn}".`); process.exit(1); }
})().catch(e => { console.log('::error::' + String((e && e.message) || e).replace(/[\r\n]/g, ' ')); process.exit(1); });
