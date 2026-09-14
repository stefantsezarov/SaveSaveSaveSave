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
