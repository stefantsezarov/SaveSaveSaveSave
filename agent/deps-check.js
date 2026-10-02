'use strict';
// Check a project's npm dependencies with the same package check the
// website runs. Used by `savesavesavesave deps` and by the GitHub Action.
//
// What it reads: package.json (direct dependencies) and, if present,
// package-lock.json (the exact versions installed, and any dependency
// that does not come from the npm registry). What it sends: only package
// names and versions, to npm and OSV.dev. It never downloads or runs a
// package's code and never sends the files themselves anywhere.
const fs = require('fs');
const path = require('path');
const S = require('./index.js');

const RANK = { pass: 0, unknown: 1, caution: 1, fail: 2 };
const NON_REGISTRY = /^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|[^@\s]+\/[^@\s]+$)/;

function readJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return null; }
}

// Collect what to check. Returns { deps: [{name, spec, version, dev}], notes: [] }.
function collect(dir, opts) {
  const o = opts || {};
  const pkg = readJson(path.join(dir, 'package.json'));
  if (!pkg) throw new Error('No readable package.json in ' + dir);
  const lock = o.lockfile === false ? null : readJson(path.join(dir, 'package-lock.json'));
  const lockPkgs = (lock && lock.packages) || {};
  const sections = [['dependencies', false], ['optionalDependencies', false], ['peerDependencies', false]];
  if (o.includeDev !== false) sections.push(['devDependencies', true]);
  const seen = new Map();
  for (const [sec, dev] of sections) {
    for (const [name, spec] of Object.entries(pkg[sec] || {})) {
      if (seen.has(name)) continue;
      const locked = lockPkgs['node_modules/' + name];
      seen.set(name, { name, spec: String(spec), dev, version: locked && locked.version ? locked.version : null,
        resolved: locked && locked.resolved ? String(locked.resolved) : null });
    }
  }
  return { deps: [...seen.values()], hasLock: !!lock };
}

// Specs that bypass the npm registry are a supply-chain signal by
// themselves, and the registry checks cannot see what they contain.
function sourceFinding(d) {
  const spec = d.spec.replace(/^npm:/, '');
  if (NON_REGISTRY.test(spec) && !/^\d|^[~^<>=*]|^latest$/.test(spec)) {
    return 'Installed from outside the npm registry (' + d.spec + '), so the registry and OSV.dev checks do not cover it.';
  }
  if (d.resolved && !/^https:\/\/registry\.npmjs\.org\//.test(d.resolved)) {
    return 'package-lock.json resolves it from outside the npm registry (' + d.resolved.slice(0, 120) + ').';
  }
  return null;
}

async function checkDeps(dir, opts, checkFn) {
  const o = opts || {};
  const check = checkFn || S.checkPackage;
  const { deps, hasLock } = collect(dir, o);
  const results = [];
  const queue = deps.slice();
  const worker = async () => {
    while (queue.length) {
      const d = queue.shift();
      const src = sourceFinding(d);
      if (src) { results.push({ ...d, verdict: 'caution', label: 'NOT FROM NPM', summary: src }); continue; }
      const spec = d.version ? d.name + '@' + d.version : d.name;
      try {
        const r = await check(spec);
        results.push({ ...d, verdict: r.verdict, label: r.label, summary: r.summary || '',
          findings: (r.checks || []).filter(c => c.status === 'fail' || c.status === 'warn').map(c => c.label + (c.detail ? ': ' + c.detail : '')) });
      } catch (e) {
        results.push({ ...d, verdict: 'unknown', label: 'NOT CHECKED', summary: String((e && e.message) || e) });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(o.concurrency || 4, deps.length || 1) }, worker));
  results.sort((a, b) => (RANK[b.verdict] || 0) - (RANK[a.verdict] || 0) || a.name.localeCompare(b.name));
  return { results, hasLock, checked: results.length };
}

function failed(results, failOn) {
  const limit = failOn === 'caution' ? 1 : 2;
  return results.filter(r => (RANK[r.verdict] || 0) >= limit);
}

function markdown(report, failOn) {
  const bad = failed(report.results, failOn);
  const count = v => report.results.filter(r => r.verdict === v).length;
  const lines = [
    '## SaveSaveSaveSave dependency check',
    '',
    `${report.checked} direct dependencies checked${report.hasLock ? ' (exact versions from package-lock.json)' : ''}: ` +
      `${count('fail')} FAIL, ${count('caution') + count('unknown')} CAUTION or not checked, ${count('pass')} PASS.`,
    '',
    bad.length ? `**${bad.length} at or above the failure level (${failOn}).**` : `Nothing at or above the failure level (${failOn}).`,
    '',
    '| Package | Version | Verdict | Why |',
    '|---|---|---|---|',
  ];
  const esc = s => String(s || '').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').slice(0, 300);
  for (const r of report.results.filter(x => x.verdict !== 'pass')) {
    lines.push(`| \`${esc(r.name)}\` | ${esc(r.version || r.spec)} | ${esc(r.label || r.verdict)} | ${esc([r.summary].concat(r.findings || []).filter(Boolean).join('; '))} |`);
  }
  if (count('pass')) lines.push(`| ${count('pass')} more | | PASS | no covered risk found |`);
  lines.push('', 'Checks: npm security removals, OSV.dev malware and vulnerability reports, install scripts, look-alike names of popular packages, signs of a hijacked release. Package code is never downloaded or run. Transitive dependencies are not checked. PASS means no covered risk was found, not that a package is safe.');
  return lines.join('\n');
}

module.exports = { collect, checkDeps, failed, markdown, sourceFinding };
