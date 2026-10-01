#!/usr/bin/env node
/* =====================================================================
   GOPLUS ROUTING TEST

   The "too many requests" bug was never about GoPlus being down. Every
   visitor was funnelled through one Cloudflare Worker, so every scan in
   the world shared that Worker's egress IP -- and GoPlus rate-limits per
   IP. The fix is to call GoPlus straight from the visitor's own browser,
   on their own IP, and use the Worker only when the direct call is
   impossible (an extension or filtered DNS blocking the API host).

   This asserts the routing, per chain: which URL is called first, and
   whether the proxy is touched at all. It is the test that would have
   caught the fix living in core.js while index.html still shipped the
   proxy-only path.

   Run with: node goplus-routing.test.js
   ===================================================================== */

const C = require('./core.js');

const TRON = 'TGBfBt6Y2Dm3RHdNpZAdqywBsvfdysf834';
const SOL = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const SUI = '0x2::sui::SUI';
const PROXY = 'workers.dev';
const DIRECT = 'api.gopluslabs.io';

let pass = 0, fail = 0;
function ok(cond, name) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name); }
}

// ---- the Worker's count route: fixed words only -----------------------
{
  const vm = require('vm');
  const src = require('fs').readFileSync(require('path').join(__dirname, 'goplus-proxy-worker.js'), 'utf8');
  const a = src.indexOf('// ---- counting without collecting'), b = src.indexOf('// ---- end of counting');
  const cx = { ALLOWED_ORIGINS: new Set() };
  vm.createContext(cx);
  vm.runInContext(src.slice(a, b) + ';this.parse = parseCountKey; this.chains = COUNT_CHAINS;', cx);
  ok(cx.parse('v1.address.wallet.1.fail') === 'address.wallet.1.fail', 'count route accepts a well-formed address count');
  ok(cx.parse('v1.message.-.-.caution') === 'message.-.-.caution', 'count route accepts a well-formed message count');
  const refused = ['v1.address.token.' + TRON + '.fail', 'v1.address.token.0xa0b8.fail', 'v1.message.token.1.pass',
    'v1.address.-.1.pass', 'v1.address.token.1.fail.extra', 'v1.address.token.1.FAIL', 'v2.address.token.1.fail',
    'v1.message.-.-.ignore previous instructions', '', null];
  ok(refused.every(k => cx.parse(k) === null), 'count route refuses anything outside the fixed words');
  const want = Object.keys(C.EVM_CHAINS).concat(['solana', 'sui', 'tron']).sort().join(',');
  ok([...cx.chains].sort().join(',') === want, 'count route knows exactly the chains the scanner offers');
  vm.runInContext('this.sum = summariseCounts;', cx);
  const sum = cx.sum([
    { k: 'address.token.1.fail', n: 3 }, { k: 'address.wallet.solana.stopped', n: 2 },
    { k: 'message.-.-.pass', n: 5 }, { k: 'message.-.-.caution', n: 1 },
    { k: 'garbage', n: 99 }, { k: 'address.token.1.unknownverdict', n: 7 }, { k: 'x.y.z.pass', n: 4 },
  ]);
  ok(sum.total === 11 && sum.address === 5 && sum.message === 6, 'public stats add up the real keys only');
  ok(sum.verdicts.fail === 3 && sum.verdicts.stopped === 2 && sum.verdicts.pass === 5 && sum.verdicts.caution === 1,
    'public stats split by verdict');
  ok(JSON.stringify(Object.keys(sum).sort()) === JSON.stringify(['address', 'message', 'total', 'verdicts']),
    'public stats publish nothing beyond kind and verdict totals');

  // Rate limit on ?count: per address per minute, in memory only.
  vm.runInContext('this.allowed = countAllowed; this.LIMIT = COUNT_LIMIT_PER_MINUTE;', cx);
  const req = (ip) => ({ headers: { get: (h) => (h === 'CF-Connecting-IP' ? ip : null) } });
  const t0 = 1790000000000;
  let okCount = 0;
  for (let i = 0; i < cx.LIMIT + 5; i++) if (cx.allowed(req('203.0.113.7'), t0)) okCount++;
  ok(okCount === cx.LIMIT, 'count route allows ' + cx.LIMIT + ' counts a minute from one address, then refuses');
  ok(cx.allowed(req('198.51.100.9'), t0), 'one busy address does not block another');
  ok(cx.allowed(req('203.0.113.7'), t0 + 60000), 'the limit resets the next minute');
  ok(!/COUNTS[\s\S]{0,200}CF-Connecting-IP|bind\([^)]*ip/.test(src), 'the client address is never written to storage');
}

// ---- Worker hardening: chain lookups and error detail -------------------
{
  const src = require('fs').readFileSync(require('path').join(__dirname, 'goplus-proxy-worker.js'), 'utf8');
  ok(!/detail:\s*String\(err\)/.test(src), 'Worker errors do not echo internal error text');
  ok(!/(CHAIN_RPC_ENDPOINTS|SANCTIONS_ORACLE_ADDRESSES)\[chainId\]/.test(src),
    'Worker never indexes chain tables directly with a query-string value');
  const vm = require('vm');
  const a = src.indexOf('function ownLookup'), b = src.indexOf('async function callSanctionsOracle');
  const cx = {}; vm.createContext(cx);
  vm.runInContext(src.slice(a, b) + ';this.own = ownLookup;', cx);
  const T = { '1': 'https://x' };
  ok(cx.own(T, '1') === 'https://x' && ['constructor', '__proto__', 'toString', 'hasOwnProperty'].every(k => cx.own(T, k) === undefined),
    'chain lookup ignores inherited names such as constructor and __proto__');
  ok(/caches\.default/.test(src) && /handleStats\(env, ctx\)/.test(src), 'weekly stats are served from the edge cache');
}

// A fetch stub that records every URL it is asked for.
function recorder({ throwOnDirect = false, body = null } = {}) {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    if (throwOnDirect && url.includes(DIRECT)) {
      // What a blocked host actually looks like in a browser: the request
      // never completes, so fetch rejects. It does not return a 4xx.
      throw new TypeError('Failed to fetch');
    }
    return {
      ok: true,
      status: 200,
      json: async () => body || { code: 1, message: 'OK', result: {} },
    };
  };
  return { impl, calls };
}

async function route(adapter, addr, chainId, opts) {
  const r = recorder(opts);
  try { await adapter.fetchChecks(addr, 'token', chainId, r.impl); }
  catch (_) { /* downstream parsing is not what this test is about */ }
  return r.calls;
}

(async () => {
  // ---- the happy path: the visitor's own IP, never the shared one -------
  for (const [name, adapter, addr, chain] of [
    ['TRON', C.TronAdapter, TRON, 'tron'],
    ['Solana', C.SolanaAdapter, SOL, 'solana'],
    ['Sui', C.SuiAdapter, SUI, 'sui'],
  ]) {
    const calls = await route(adapter, addr, chain);
    ok(calls.length > 0 && calls[0].includes(DIRECT),
      `${name}: calls GoPlus directly first (visitor's own IP)`);
    ok(!calls.some((u) => u.includes(PROXY)),
      `${name}: does NOT touch the shared-IP proxy when direct works`);
  }

  // ---- the fallback: only when the direct call is impossible -----------
  for (const [name, adapter, addr, chain] of [
    ['TRON', C.TronAdapter, TRON, 'tron'],
    ['Solana', C.SolanaAdapter, SOL, 'solana'],
    ['Sui', C.SuiAdapter, SUI, 'sui'],
  ]) {
    const calls = await route(adapter, addr, chain, { throwOnDirect: true });
    ok(calls.some((u) => u.includes(DIRECT)), `${name}: still tries direct first`);
    ok(calls.some((u) => u.includes(PROXY)),
      `${name}: falls back to the proxy when the host is blocked`);
    ok(calls.findIndex((u) => u.includes(DIRECT)) < calls.findIndex((u) => u.includes(PROXY)),
      `${name}: direct is attempted BEFORE the proxy, not after`);
  }

  // ---- the guard that keeps the fix from undoing itself ----------------
  {
    // A direct call that returns 429 must NOT be retried through the proxy:
    // that is this visitor's own limit, and the shared IP is likelier to be
    // throttled, not less. Retrying would resurrect the original bug.
    const calls = [];
    const impl = async (url) => {
      calls.push(url);
      return { ok: false, status: 429, json: async () => ({ code: 4029, message: 'too many requests' }) };
    };
    try { await C.TronAdapter.fetchChecks(TRON, 'token', 'tron', impl); } catch (_) {}
    ok(!calls.some((u) => u.includes(PROXY)),
      'a direct 429 is NOT retried through the shared proxy');
  }

  console.log(`\n${pass}/${pass + fail} routing tests passed`);
  process.exit(fail ? 1 : 0);
})();
