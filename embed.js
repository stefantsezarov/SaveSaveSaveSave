#!/usr/bin/env node
/* =====================================================================
   EMBED THE ENGINE MODULES INTO index.html

   index.html carries a verbatim copy of core.js, scanmodel.js and
   promptscan.js inside <script> so the page is one self-contained file.
   verify_embedded.js already CATCHES the two copies drifting apart. This
   is the other half: it makes them agree, so "did you remember to
   re-paste it" stops being a matter of memory.

   That question has cost this project real bugs. A fix lands in the
   module, the regression suite goes green against the module, and the
   live site keeps serving the old logic out of the page — with every
   test passing the whole time.

   Run with: node embed.js && node verify_embedded.js

   HOW IT WORKS: each embedded region runs from its own banner comment to
   the comment that opens the next region. Only what sits BETWEEN those
   comments is replaced; the banners are landmarks and stay exactly where
   they are.

   IT WILL NOT GUESS. A missing landmark is a hard failure, and nothing
   is written at all — a half-embedded page is worse than a stale one,
   because a stale one still runs.

   VERBATIM MEANS VERBATIM. The module's CommonJS export tail is copied
   too, exactly as it is on disk. Its `typeof module` guard is false in a
   browser, so it costs nothing, and copying everything means there is no
   transformation step here that could itself be the bug.
   ===================================================================== */

const fs = require('fs');
const path = require('path');

const here = __dirname;
const pagePath = path.join(here, 'index.html');

// Ordered, because each block ends where the next one begins.
const BLOCKS = [
  { file: 'core.js',       banner: 'SAVESAVESAVESAVE CORE  (verbatim from core.js' },
  { file: 'scanmodel.js',  banner: 'SCAN RESULT MODEL  (verbatim from scanmodel.js' },
  { file: 'promptscan.js', banner: 'PROMPT SAFETY SCAN ENGINE  (verbatim from promptscan.js' },
];
const TERMINATOR = 'SAVESAVESAVESAVE UI LAYER';

let page = fs.readFileSync(pagePath, 'utf8');

function die(msg, detail) {
  console.error('FAIL: ' + msg);
  if (detail) console.error('      ' + detail);
  console.error('      Nothing was written to index.html.');
  process.exit(1);
}

// A landmark's offset points at the banner TEXT. The comment that
// contains it opens a couple of characters earlier, and that opener must
// survive — slicing from the text alone silently eats the `/* ====` line
// and leaves an unterminated comment that takes the whole page down.
function commentStart(pos) {
  const at = page.lastIndexOf('/*', pos);
  return at === -1 ? pos : at;
}

// Locate every landmark before touching anything.
const marks = BLOCKS.map(b => {
  const at = page.indexOf(b.banner);
  if (at === -1) die(`banner for ${b.file} not found in index.html.`, 'Looked for: ' + b.banner);
  return at;
});
const endAt = page.indexOf(TERMINATOR);
if (endAt === -1) die(`terminator banner "${TERMINATOR}" not found.`);

for (let i = 1; i < marks.length; i++) {
  if (marks[i] <= marks[i - 1]) die('embedded blocks are out of order in index.html.');
}
if (endAt <= marks[marks.length - 1]) die('the UI layer banner sits above the engine blocks.');

const bounds = BLOCKS.map((b, i) => ({
  ...b,
  from: marks[i],
  to: commentStart(i + 1 < marks.length ? marks[i + 1] : endAt),
}));

// Rebuild from the BOTTOM UP, so the offsets of the blocks above stay
// valid while the ones below are being rewritten.
for (let i = bounds.length - 1; i >= 0; i--) {
  const b = bounds[i];
  const src = fs.readFileSync(path.join(here, b.file), 'utf8').replace(/^#!.*\r?\n/, '');

  // Keep the landmark banner itself; replace the body that follows it.
  const bannerEnd = page.indexOf('*/', b.from);
  if (bannerEnd === -1 || bannerEnd > b.to) {
    die(`could not find the end of the ${b.file} landmark banner.`);
  }

  page = page.slice(0, bannerEnd + 2) + '\n' + src.replace(/\s+$/, '') + '\n\n' + page.slice(b.to);
  console.log(`  embedded ${b.file} (${src.length.toLocaleString()} chars)`);
}

fs.writeFileSync(pagePath, page, 'utf8');
console.log('\nindex.html rewritten. Now run: node verify_embedded.js');
