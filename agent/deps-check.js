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

// Collect what to check. Returns { deps: [{name, target, spec, version, dev, versionNote}], hasLock }.
// `name` is the key in package.json; `target` is the package npm will
// actually install. They differ for aliases ("x": "npm:other@1.0.0"), and
// checking the key instead of the target would pass a package that is never
// looked at.
const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
function splitNameVersion(s) {
  const at = s.lastIndexOf('@');
  return at > 0 ? { name: s.slice(0, at), version: s.slice(at + 1) || null } : { name: s, version: null };
}
function collect(dir, opts) {
  const o = opts || {};
  const pkg = readJson(path.join(dir, 'package.json'));
  if (!pkg) throw new Error('No readable package.json in ' + dir);
  const lock = o.lockfile === false ? null : readJson(path.join(dir, 'package-lock.json'));
  const lockPkgs = (lock && lock.packages) || {};      // lockfile v2 / v3
  const lockDepsV1 = (lock && lock.dependencies) || {}; // lockfile v1
  const sections = [['dependencies', false], ['optionalDependencies', false], ['peerDependencies', false]];
  if (o.includeDev !== false) sections.push(['devDependencies', true]);
  const seen = new Map();
  for (const [sec, dev] of sections) {
    for (const [name, rawSpec] of Object.entries(pkg[sec] || {})) {
      if (seen.has(name)) continue;
      const spec = String(rawSpec);
      let target = name, specVersion = spec;
      if (/^npm:/i.test(spec)) { const a = splitNameVersion(spec.slice(4)); target = a.name; specVersion = a.version || ''; }
      let version = null, resolved = null;
      const v3 = Object.prototype.hasOwnProperty.call(lockPkgs, 'node_modules/' + name) ? lockPkgs['node_modules/' + name] : null;
      const v1 = Object.prototype.hasOwnProperty.call(lockDepsV1, name) ? lockDepsV1[name] : null;
      const entry = v3 || v1;
      if (entry && typeof entry === 'object') {
        if (v3 && typeof v3.name === 'string' && v3.name) target = v3.name;
        let ver = entry.version ? String(entry.version) : null;
        if (ver && /^npm:/i.test(ver)) { const a = splitNameVersion(ver.slice(4)); target = a.name; ver = a.version; }
        version = ver;
        resolved = entry.resolved ? String(entry.resolved) : null;
      }
      let versionNote = null;
      if (!version) {
        if (EXACT_VERSION.test(specVersion.trim())) version = specVersion.trim().replace(/^v/, '');
        else versionNote = 'Installed version not known (no lockfile entry; spec "' + spec + '" is a range). The latest version was checked instead, which may not be what gets installed.';
      }
      seen.set(name, { name, target, spec, dev, version, resolved, versionNote });
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
      const target = d.target || d.name;
      const spec = d.version ? target + '@' + d.version : target;
      try {
        const r = await check(spec);
        const findings = (r.checks || []).filter(c => c.status === 'fail' || c.status === 'warn').map(c => c.label + (c.detail ? ': ' + c.detail : ''));
        if (target !== d.name) findings.unshift('Alias: installed as "' + d.name + '" but the package is ' + target);
        let verdict = r.verdict, label = r.label, summary = r.summary || '';
        // An unknown installed version must never read as a clean PASS.
        if (d.versionNote) { findings.unshift(d.versionNote); if (verdict === 'pass') { verdict = 'caution'; label = 'VERSION NOT RESOLVED'; } }
        results.push({ ...d, checked: spec, verdict, label, summary, findings });
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
  const esc = s => String(s || '').replace(/[`\[\]!<>]/g, ' ').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').slice(0, 300);
  for (const r of report.results.filter(x => x.verdict !== 'pass')) {
    lines.push(`| \`${esc(r.name)}\`${r.target && r.target !== r.name ? ' (alias of ' + esc(r.target) + ')' : ''} | ${esc(r.version || r.spec)} | ${esc(r.label || r.verdict)} | ${esc([r.summary].concat(r.findings || []).filter(Boolean).join('; '))} |`);
  }
  if (count('pass')) lines.push(`| ${count('pass')} more | | PASS | no covered risk found |`);
  lines.push('', 'Checks: npm security removals, OSV.dev malware and vulnerability reports, install scripts, look-alike names of popular packages, signs of a hijacked release. Package code is never downloaded or run. Transitive dependencies are not checked. PASS means no covered risk was found, not that a package is safe.');
  return lines.join('\n');
}

module.exports = { collect, checkDeps, failed, markdown, sourceFinding };
