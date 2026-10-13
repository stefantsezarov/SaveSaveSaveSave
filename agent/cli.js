#!/usr/bin/env node
'use strict';
// savesavesavesave mcp | message "text" | package <name> | deps [dir] | address <addr> [chain] [token|wallet] | compare <a> <b>
//                  | guard [--mode m] -- <install command> | hook claude-code [--mode m]
// Prints JSON. Exit code: 0 PASS, 1 CAUTION or unknown, 2 FAIL, 3 usage or error.
// guard: 0 allow, 1 review, 2 deny, 3 usage or error.
const S = require('./index.js');
const [cmd, ...args] = process.argv.slice(2);
const code = r => r.verdict === 'pass' ? 0 : r.verdict === 'fail' ? 2 : 1;
(async () => {
  if (cmd === 'mcp') { require('./mcp-server.js'); return; }   // savesavesavesave mcp: start the MCP server (stdio)
  if (cmd === 'guard') {                                        // savesavesavesave guard [--mode observe|guard|strict] -- <install command>
    const G = require('./guard.js');
    const at = args.indexOf('--mode');
    const sep = args.indexOf('--');
    const mode = G.modeFrom(at >= 0 ? args[at + 1] : null, process.env);
    const line = sep >= 0 ? args.slice(sep + 1).join(' ') : args.filter((a, i) => a !== '--mode' && args[i - 1] !== '--mode').join(' ');
    if (!line.trim()) { console.error('Usage: savesavesavesave guard [--mode observe|guard|strict] -- npm install <pkg>'); process.exit(3); }
    const res = await G.guardCommand(line, mode);
    console.log(JSON.stringify(res, null, 2));
    console.error(G.explain(res));
    process.exit({ allow: 0, review: 1, deny: 2 }[res.decision]);
  }
  if (cmd === 'hook') {                                         // savesavesavesave hook claude-code [--mode ...]  (reads the hook event on stdin)
    const H = require('./hook.js');
    const at = args.indexOf('--mode');
    const out = await H.claudeCodePreToolUse(require('fs').readFileSync(0, 'utf8'), at >= 0 ? args[at + 1] : null, process.env);
    if (out) process.stdout.write(JSON.stringify(out) + '\n');
    process.exit(0);
  }
  if (cmd === 'deps') {                                         // savesavesavesave deps [dir] [--fail-on caution] [--no-dev] [--markdown]
    const D = require('./deps-check.js');
    const flag = f => args.includes(f);
    const at = f => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
    const dir = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--fail-on') || '.';
    const failOn = at('--fail-on') === 'caution' ? 'caution' : 'fail';
    const rep = await D.checkDeps(dir, { includeDev: !flag('--no-dev') });
    console.log(flag('--markdown') ? D.markdown(rep, failOn) : JSON.stringify(rep, null, 2));
    process.exit(D.failed(rep.results, failOn).length ? 2 : 0);
  }
  let r;
  if (cmd === 'message') r = S.scanMessage(args.length ? args.join(' ') : require('fs').readFileSync(0, 'utf8'));
  else if (cmd === 'package') r = await S.checkPackage(args.join(' '));
  else if (cmd === 'address') r = await S.scanAddress(args[0], { chain: args[1], mode: args[2] });
  else if (cmd === 'compare') r = S.compareAddresses(args[0], args[1]);
  else { console.error('Usage: savesavesavesave message "text" | package <name> | guard [--mode m] -- <install command> | hook claude-code | deps [dir] [--fail-on caution] [--markdown] | address <addr> [chain] [token|wallet] | compare <expected> <actual>'); process.exit(3); }
  console.log(JSON.stringify(r, null, 2));
  process.exit(code(r));
})().catch(e => { console.error(String(e.message || e)); process.exit(3); });
