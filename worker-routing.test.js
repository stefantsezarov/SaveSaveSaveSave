#!/usr/bin/env node
/* =====================================================================
   WORKER ONWARD ROUTING TEST

   A browser can see which hosts the page calls, but not where our
   Cloudflare Worker sends things next. The address-row disclosures and
   the privacy page describe those onward hops, so this test runs the
   real Worker with a stubbed fetch and records every outbound request:
   which host, and what it carried.

   It pins three facts the copy relies on:
   - token routes for Solana, Sui and TRON go to GoPlus and nowhere else;
   - a successful GoPlus answer is put in the edge cache, keyed by a URL
     that contains the address (the "up to 15 minutes" disclosure);
   - the EVM counterparty route sends the wallet address and the derived
     counterparty addresses (at most 15) to PublicNode, and nothing else.

   Run with: node worker-routing.test.js
   ===================================================================== */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let pass = 0, fail = 0;
function ok(cond, name, detail) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (detail ? ' — ' + detail : '')); }
}

const src = fs.readFileSync(path.join(__dirname, 'goplus-proxy-worker.js'), 'utf8')
  .replace('export default {', 'globalThis.__worker = {');

function load(respond) {
  const outbound = [];
  const cachePuts = [];
  const cx = {
    console, URL, Request, Response, Headers, AbortController, JSON, Math, Date, Map, Set, Promise,
    setTimeout, clearTimeout, TextEncoder, TextDecoder, crypto: globalThis.crypto,
    caches: { default: {
      match: async () => undefined,
      put: async (key) => { cachePuts.push(typeof key === 'string' ? key : key.url); },
    } },
    fetch: async (url, init) => {
      const u = typeof url === 'string' ? url : url.url;
      const body = init && init.body ? String(init.body) : '';
      outbound.push({ host: new URL(u).host, url: u, body });
      return respond(u, body);
    },
  };
  cx.globalThis = cx;
  vm.createContext(cx);
  vm.runInContext(src, cx);
  return { worker: cx.__worker, outbound, cachePuts };
}

const json = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: { 'Content-Type': 'application/json' } });
const GOPLUS_OK = { code: 1, message: 'OK', result: { x: {} } };
const req = (q) => new Request('https://worker.example/?' + q, { headers: { Origin: 'https://savesavesavesave.xyz' } });
const ctx = { waitUntil() {} };

(async () => {
  // ---- token routes -------------------------------------------------
  const SOL = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  const SUI = '0x2::sui::SUI'.replace('0x2', '0x' + '0'.repeat(63) + '2');
  const TRON = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';
  for (const [name, q, addr] of [
    ['Solana token', 'contract_addresses=' + SOL, SOL],
    ['Sui token', 'sui_contract_addresses=' + encodeURIComponent(SUI), SUI],
    ['TRON token', 'tron_contract_addresses=' + TRON, TRON],
  ]) {
    const w = load(() => json(GOPLUS_OK));
    const res = await w.worker.fetch(req(q), {}, ctx);
    ok(res.status === 200, name + ': route answers');
    ok(w.outbound.length === 1 && w.outbound[0].host === 'api.gopluslabs.io',
      name + ': goes to GoPlus and nowhere else', JSON.stringify(w.outbound.map(o => o.host)));
    ok(w.outbound.every(o => decodeURIComponent(o.url).includes(addr) && o.body === ''),
      name + ': carries the address and no body');
    ok(w.cachePuts.length === 1 && decodeURIComponent(w.cachePuts[0]).includes(addr),
      name + ': a successful answer is edge-cached under a key containing the address');
  }
  ok(/const CACHE_TTL_SECONDS = 900;/.test(src), 'edge cache lifetime is 900 seconds (the "up to 15 minutes" in the copy)');

  // A failed GoPlus answer is not cached.
  {
    const w = load(() => json({ code: 5000, message: 'system error', result: null }));
    await w.worker.fetch(req('contract_addresses=' + SOL), {}, ctx);
    ok(w.cachePuts.length === 0, 'an error answer is never cached');
  }

  // ---- EVM counterparty route ---------------------------------------
  const WALLET = '0x742d35cc6634c0532925a3b844bc454e4438f44e';
  const others = Array.from({ length: 20 }, (_, i) => '0x' + (i + 1).toString(16).padStart(40, '0'));
  const topic = (a) => '0x' + '0'.repeat(24) + a.slice(2);
  const logs = others.map((o, i) => ({
    topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef', topic(WALLET), topic(o)],
    transactionHash: '0x' + String(i).padStart(64, '0'),
  }));
  const w = load((url, body) => {
    const m = JSON.parse(body || '{}').method;
    if (m === 'eth_blockNumber') return json({ jsonrpc: '2.0', id: 1, result: '0x1000000' });
    if (m === 'eth_getLogs') {
      const p = JSON.parse(body).params[0];
      const outgoing = p.topics && p.topics[1] && p.topics[1].toLowerCase().endsWith(WALLET.slice(2));
      return json({ jsonrpc: '2.0', id: 1, result: outgoing ? logs : [] });
    }
    if (m === 'eth_call') return json({ jsonrpc: '2.0', id: 1, result: '0x' + '0'.repeat(64) });
    return json(GOPLUS_OK);
  });
  const res = await w.worker.fetch(req('counterparty_check=' + WALLET + '&chain=1'), {}, ctx);
  const out = await res.json();
  ok(out.available === true && out.checkedCounterpartyCount === 15 && out.counterpartyCheckLimited === true,
    'counterparty route checks at most 15 of 20 counterparties', JSON.stringify(out).slice(0, 160));
  const hosts = [...new Set(w.outbound.map(o => o.host))];
  ok(hosts.length === 1 && /publicnode\.com$/.test(hosts[0]), 'counterparty route contacts PublicNode only', hosts.join(','));
  const oracleCalls = w.outbound.filter(o => o.body.includes('"eth_call"'));
  ok(oracleCalls.length === 15, 'exactly 15 sanctions-oracle calls carry derived addresses', String(oracleCalls.length));
  const carried = oracleCalls.map(o => JSON.parse(o.body).params[0].data.slice(-40));
  ok(carried.every(a => others.map(x => x.slice(2)).includes(a)), 'each oracle call carries one derived counterparty address');
  ok(w.outbound.filter(o => o.body.includes('"eth_getLogs"')).every(o => o.body.toLowerCase().includes(WALLET.slice(2))),
    'the log queries carry the wallet address');
  ok(w.cachePuts.length === 0, 'the counterparty route writes nothing to the edge cache');

  console.log('\n' + '='.repeat(60));
  console.log(`${pass}/${pass + fail} worker routing tests passed`);
  console.log('='.repeat(60));
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
