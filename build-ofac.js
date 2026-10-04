#!/usr/bin/env node
/* Refresh the OFAC sanctions list of Solana addresses inside core.js.

   Source: the public extraction of OFAC's SDN list at
   github.com/0xB10C/ofac-sanctioned-digital-currency-addresses (branch
   "lists"), which parses the Treasury's own SDN export daily. Only
   entries that are valid Solana addresses are kept.

   node build-ofac.js          rewrite the block in core.js (then run
                               node embed.js && node agent/build.js)
   node build-ofac.js --check  exit 1 if the published list differs */
const fs = require('fs');
const path = require('path');
const URL_ = 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_SOL.txt';
const FILE = path.join(__dirname, 'core.js');
const BEGIN = '// OFAC-SOL:BEGIN', END = '// OFAC-SOL:END';

(async () => {
  const res = await fetch(URL_);
  if (!res.ok) { console.error('FAIL: list source answered HTTP ' + res.status); process.exit(2); }
  const fresh = [...new Set((await res.text()).split(/\s+/).filter(a => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)))].sort();
  if (!fresh.length) { console.error('FAIL: the source returned no Solana addresses; refusing to empty the list'); process.exit(2); }
  const src = fs.readFileSync(FILE, 'utf8');
  const a = src.indexOf(BEGIN), b = src.indexOf(END);
  if (a < 0 || b < 0) { console.error('FAIL: markers not found in core.js'); process.exit(2); }
  const current = [...src.slice(a, b).matchAll(/'([1-9A-HJ-NP-Za-km-z]{32,44})'/g)].map(m => m[1]).sort();
  const same = current.length === fresh.length && current.every((x, i) => x === fresh[i]);
  if (process.argv.includes('--check')) {
    if (same) { console.log('OFAC Solana list is current (' + fresh.length + ' addresses).'); return; }
    console.error('FAIL: the OFAC Solana list changed. Added: ' + fresh.filter(x => !current.includes(x)).join(', ') +
      ' Removed: ' + current.filter(x => !fresh.includes(x)).join(', ') + '. Run node build-ofac.js.');
    process.exit(1);
  }
  if (same) { console.log('No change (' + fresh.length + ' addresses).'); return; }
  const today = new Date().toISOString().slice(0, 10);
  const block = BEGIN + '\n' + "const OFAC_SOLANA_AS_OF = '" + today + "';\nconst OFAC_SOLANA_ADDRESSES = new Set([\n" +
    fresh.map(x => "  '" + x + "',").join('\n') + '\n]);\n';
  fs.writeFileSync(FILE, src.slice(0, a) + block + src.slice(b));
  console.log('Updated: ' + fresh.length + ' addresses. Now run: node embed.js && node agent/build.js');
})().catch(e => { console.error('FAIL: ' + e.message); process.exit(2); });
