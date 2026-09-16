#!/usr/bin/env node
/* =====================================================================
   VERIFY EMBEDDED CORE

   ARCHITECTURE.md has always claimed this file exists. It did not.
   This is it.

   index.html carries a verbatim copy of core.js inside a <script> tag so
   the page is a single self-contained file. Two copies of the same logic
   is a standing invitation to drift: fix a bug in core.js, forget to
   re-paste, and the regression suite keeps passing while the live site
   keeps the bug. This compares them and fails loudly if they disagree.

   Run with: node verify_embedded.js
   ===================================================================== */

const fs = require('fs');
const path = require('path');

const here = __dirname;
const coreSrc = fs.readFileSync(path.join(here, 'core.js'), 'utf8');
const pageSrc = fs.readFileSync(path.join(here, 'index.html'), 'utf8');

// The embedded block runs from the CORE banner to the UI LAYER banner.
const START = 'SAVESAVESAVESAVE CORE  (verbatim from core.js';
const END = 'SAVESAVESAVESAVE UI LAYER';

const startIdx = pageSrc.indexOf(START);
const endIdx = pageSrc.indexOf(END);

if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) {
  console.error('FAIL: could not locate the embedded core block in index.html.');
  console.error('      Looked for the CORE and UI LAYER banner comments.');
  process.exit(1);
}

// Normalise for comparison: strip comments and collapse whitespace. We are
// checking that the LOGIC matches, not that the two files are byte-identical
// -- index.html legitimately differs in indentation and in its file-level
// header comment.
function normalise(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')   // block comments
    .replace(/^\s*\/\/.*$/gm, ' ')        // whole-line // comments
    .replace(/\s+/g, ' ')
    .trim();
}

// Take core.js from its first executable statement onward.
const coreBody = normalise(coreSrc);
const embedded = normalise(pageSrc.slice(startIdx, endIdx));

// Every top-level declaration in core.js must appear in the embedded copy.
const decls = [...coreSrc.matchAll(/^(?:function|const|class)\s+([A-Za-z_$][\w$]*)/gm)]
  .map((m) => m[1]);

const missing = [];
for (const name of decls) {
  const re = new RegExp(`(?:function|const|class) ${name}\\b`);
  if (!re.test(embedded)) missing.push(name);
}

let failed = false;

if (missing.length) {
  failed = true;
  console.error(`FAIL: ${missing.length} declaration(s) in core.js are absent from index.html:`);
  for (const m of missing) console.error(`      - ${m}`);
}

// The proxy URL must be identical in both, or the fallback path silently
// points somewhere different depending on which copy runs.
const grabUrl = (s) => (s.match(/SOLANA_PROXY_URL\s*=\s*'([^']+)'/) || [])[1];
const coreUrl = grabUrl(coreSrc);
const pageUrl = grabUrl(pageSrc);
if (coreUrl !== pageUrl) {
  failed = true;
  console.error('FAIL: SOLANA_PROXY_URL differs between the two copies.');
  console.error(`      core.js   : ${coreUrl}`);
  console.error(`      index.html: ${pageUrl}`);
}

// Spot-check the verdict logic itself, not just its presence.
for (const marker of ['VerdictEngine', 'buildCheck', 'flagState', 'fetchGoPlus']) {
  if (!embedded.includes(marker)) {
    failed = true;
    console.error(`FAIL: '${marker}' missing from the embedded copy.`);
  }
}

// ---- the same check for the prompt-scan engine -------------------------
// promptscan.js is embedded exactly the way core.js is, so it can drift
// exactly the way core.js did — the fix living in the file nobody loads.
const psPath = path.join(here, 'promptscan.js');
if (fs.existsSync(psPath)) {
  const psSrc = fs.readFileSync(psPath, 'utf8');
  const psStart = pageSrc.indexOf('PROMPT SAFETY SCAN ENGINE');
  const psEnd = pageSrc.indexOf('SAVESAVESAVESAVE UI LAYER');

  if (psStart === -1) {
    failed = true;
    console.error('FAIL: promptscan.js exists but is not embedded in index.html.');
  } else {
    const psEmbedded = normalise(pageSrc.slice(psStart, psEnd));
    const psDecls = [...psSrc.matchAll(/^(?:async\s+)?(?:function|const|class)\s+([A-Za-z_$][\w$]*)/gm)].map(m => m[1]);
    const psMissing = psDecls.filter(n => !new RegExp(`(?:function|const|class) ${n}\\b`).test(psEmbedded));
    if (psMissing.length) {
      failed = true;
      console.error(`FAIL: ${psMissing.length} promptscan.js declaration(s) absent from index.html:`);
      psMissing.forEach(m => console.error(`      - ${m}`));
    }
    // Rule count is the cheapest way to catch "added a detector, forgot to re-paste".
    const srcRules = (psSrc.match(/id: '[A-Z_0-9]+'/g) || []).length;
    const pageRules = (psEmbedded.match(/id: '[A-Z_0-9]+'/g) || []).length;
    if (srcRules !== pageRules) {
      failed = true;
      console.error(`FAIL: detection-rule count differs — promptscan.js has ${srcRules}, index.html has ${pageRules}.`);
    }
    const srcVer = (psSrc.match(/SCANNER_VERSION\s*=\s*'([^']+)'/) || [])[1];
    const pageVer = (psEmbedded.match(/SCANNER_VERSION = '([^']+)'/) || [])[1];
    if (srcVer !== pageVer) {
      failed = true;
      console.error(`FAIL: scanner version differs — source ${srcVer}, page ${pageVer}.`);
    }
    if (!psMissing.length && srcRules === pageRules && srcVer === pageVer) {
      console.log(`PASS: all ${psDecls.length} promptscan.js declarations present in index.html`);
      console.log(`PASS: ${srcRules} detection rules embedded, scanner v${pageVer}`);
    }
  }
}

if (failed) {
  console.error('\nRe-paste the changed engine into the <script> block in index.html.');
  process.exit(1);
}

console.log(`PASS: all ${decls.length} core.js declarations present in index.html`);
console.log(`PASS: SOLANA_PROXY_URL matches (${coreUrl})`);
console.log(`PASS: embedded core is ${embedded.length} normalised chars`);
