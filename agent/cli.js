#!/usr/bin/env node
'use strict';
// savesavesavesave mcp | message "text" | package <name> | address <addr> [chain] [token|wallet] | compare <a> <b>
// Prints JSON. Exit code: 0 PASS, 1 CAUTION or unknown, 2 FAIL, 3 usage or error.
const S = require('./index.js');
const [cmd, ...args] = process.argv.slice(2);
const code = r => r.verdict === 'pass' ? 0 : r.verdict === 'fail' ? 2 : 1;
(async () => {
  if (cmd === 'mcp') { require('./mcp-server.js'); return; }   // savesavesavesave mcp: start the MCP server (stdio)
  let r;
  if (cmd === 'message') r = S.scanMessage(args.length ? args.join(' ') : require('fs').readFileSync(0, 'utf8'));
  else if (cmd === 'package') r = await S.checkPackage(args.join(' '));
  else if (cmd === 'address') r = await S.scanAddress(args[0], { chain: args[1], mode: args[2] });
  else if (cmd === 'compare') r = S.compareAddresses(args[0], args[1]);
  else { console.error('Usage: savesavesavesave message "text" | package <name> | address <addr> [chain] [token|wallet] | compare <expected> <actual>'); process.exit(3); }
  console.log(JSON.stringify(r, null, 2));
  process.exit(code(r));
})().catch(e => { console.error(String(e.message || e)); process.exit(3); });
