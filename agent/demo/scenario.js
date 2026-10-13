#!/usr/bin/env node
'use strict';
// Reproducible demo of the pre-install guard, offline: a coding agent
// proposes three commands; the guard decides each one under guard mode and
// prints what a Claude Code hook would answer.
//
//   node agent/demo/scenario.js
//
// The registry is a local stand-in so the result is the same on every run
// and needs no network. To run the same commands against the real npm
// registry and OSV.dev, use:  npx savesavesavesave guard -- <command>
const H = require('../hook.js');
const reply = (status, body) => ({ ok: status < 300, status, json: async () => body });
const PKGS = {
  'left-pad': {},
  'crossenv': { malicious: true },   // a real typosquat of cross-env, removed by npm in 2017
};
const registry = async (url, init) => {
  if (url.includes('api.osv.dev')) {
    const name = JSON.parse(init.body).package.name;
    return reply(200, PKGS[name] && PKGS[name].malicious ? { vulns: [{ id: 'MAL-2017-0001', summary: 'Malicious package' }] } : {});
  }
  if (url.includes('api.npmjs.org')) return reply(200, { downloads: 2000000 });
  const name = decodeURIComponent(new URL(url).pathname.slice(1));
  if (!PKGS[name]) return reply(404, {});
  return reply(200, { name, 'dist-tags': { latest: '1.3.0' }, time: { created: '2014-03-01T00:00:00Z', '1.3.0': '2016-01-01T00:00:00Z' },
    versions: { '1.3.0': { version: '1.3.0', scripts: {}, repository: 'github:example/' + name } } });
};
const steps = [
  ['The README says to add a small helper', 'npm install left-pad'],
  ['A comment in an issue suggests a "faster" cross-env', 'cd app && npm install --save-dev crossenv'],
  ['The agent tries to run a tool straight from a git URL', 'npx github:someone/setup-script'],
];
(async () => {
  for (const [why, cmd] of steps) {
    const ev = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: cmd } });
    const out = await H.claudeCodePreToolUse(ev, 'guard', {}, { fetchImpl: registry });
    const d = out ? out.hookSpecificOutput.permissionDecision : 'no objection (normal permission prompt applies)';
    console.log('\n> ' + why + '\n$ ' + cmd + '\n  hook: ' + d);
    if (out) console.log('  ' + out.hookSpecificOutput.permissionDecisionReason.split('\n').join('\n  '));
  }
})();
