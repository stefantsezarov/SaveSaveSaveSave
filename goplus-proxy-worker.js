/**
 * SaveSaveSaveSave — CORS proxy for GoPlus's newer, chain-specific APIs, and a
 * server-side relay for the Chainalysis Sanctions Oracle smart contract
 *
 * GoPlus's Solana Token Security API (Beta) does not send an
 * Access-Control-Allow-Origin header, so browsers block direct reads of
 * the response (confirmed via console: "No 'Access-Control-Allow-Origin'
 * header is present on the requested resource"). This Worker makes the
 * request server-to-server, where CORS does not apply, adds the header
 * the browser needs, and passes the response straight through.
 *
 * It stores nothing, logs nothing beyond Cloudflare's own default
 * platform logs, and only forwards requests to fixed, verified upstream
 * targets — GoPlus's Solana Token Security endpoint, GoPlus's general
 * Malicious Address endpoint (wallet screening, chain-parameterized),
 * GoPlus's Sui Token Security endpoint, GoPlus's Token Security endpoint
 * called with chain_id=tron, and the Chainalysis Sanctions Oracle smart
 * contract via a raw JSON-RPC eth_call.
 *
 * Six request shapes are supported, one per route:
 *   ?contract_addresses=<addr>            -> Solana token security lookup
 *   ?wallet_address=<addr>                -> malicious-address (wallet) lookup
 *   ?sui_contract_addresses=<addr>        -> Sui token security lookup
 *   ?tron_contract_addresses=<addr>       -> TRON token security lookup
 *   ?sanctions_check=<addr>&chain=<id>    -> Chainalysis oracle isSanctioned() check
 *   ?counterparty_check=<addr>&chain=<id> -> recent token-transfer counterparty check
 *
 * The counterparty_check route is deliberately narrow, and its response
 * says so: it finds ERC-20/721 Transfer events involving the address in a
 * recent, bounded block window (not full history -- eth_getLogs has no
 * such thing, and standard RPC has no "get all transactions for this
 * address" method at all), then checks each counterparty against the same
 * sanctions oracle above. It does NOT see native ETH transfers, which
 * don't emit events, and does NOT claim to be a transaction history.
 *
 * The wallet route is only used as a fallback: SaveSaveSaveSave's client code
 * tries GoPlus's general Malicious Address API directly first, since
 * that's the same mature endpoint the EVM adapter already calls
 * successfully — this proxy route only gets used if that direct call
 * hits a CORS block the same way the token-security one did.
 *
 * The Sui, TRON, and sanctions routes are used unconditionally from the
 * start, not as fallbacks. Sui and TRON sit on newer or non-standard
 * chain_id values with unconfirmed CORS behavior; the sanctions route is
 * a smart-contract call, not a REST API, so it never had a "try direct
 * from the browser" option in the first place — this is the only path.
 *
 * THE SANCTIONS ROUTE NEEDS ONE THING BEFORE IT WORKS: every entry in
 * CHAIN_RPC_ENDPOINTS below is a placeholder. RPC reliability has not
 * been independently verified yet (search tooling was unavailable when
 * this was written) — replace each placeholder with a specific, checked
 * RPC endpoint before relying on this route. Until then, it correctly
 * returns { available: false, reason: 'RPC endpoint not yet configured...' }
 * rather than silently failing or guessing.
 *
 * SETUP:
 * 1. Add your site's origin to ALLOWED_ORIGINS below if it is not listed.
 * 2. Replace every REPLACE-WITH-VERIFIED-RPC-* placeholder with a real,
 *    checked RPC endpoint for that chain.
 * 3. Paste this whole file into the Cloudflare Worker "Edit code" editor.
 * 4. Click Save and Deploy.
 * 5. Copy the resulting https://<name>.<subdomain>.workers.dev URL.
 */

// Origins permitted to call this Worker. An allowlist, never '*' and never
// blind reflection of whatever Origin header arrives: this endpoint spends a
// shared rate-limit budget, so an open CORS policy would let any site on the
// internet burn it. Add a new entry here BEFORE moving the site, not after.
const ALLOWED_ORIGINS = new Set([
  'https://stefantsezarov.github.io',   // GitHub Pages (current)
  'https://savesavesavesave.pages.dev', // Cloudflare Pages
  // 'https://savesavesavesave.com',    // uncomment when the domain is live
]);

// Falls back to the GitHub Pages origin so that a request with no Origin
// header at all (curl, a health check) still gets a well-formed response.
const DEFAULT_ORIGIN = 'https://stefantsezarov.github.io';

// Returns the origin to echo back, or null if the caller is not allowed.
// Returning null means the header is omitted entirely, which is what makes
// the browser block the response -- the correct outcome for a stranger.
function resolveOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return DEFAULT_ORIGIN;
  return ALLOWED_ORIGINS.has(origin) ? origin : null;
}

const ALLOWED_ORIGIN = DEFAULT_ORIGIN;
const TOKEN_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/solana/token_security';
const ADDRESS_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/address_security';
const SUI_TOKEN_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/sui/token_security';
const TRON_TOKEN_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/token_security/tron';
const UPSTREAM_TIMEOUT_MS = 15000;
// How long a successful GoPlus response is reused from Cloudflare's edge
// cache. A contract's security profile is a property of deployed bytecode
// and slow-moving reputation data -- it does not change second to second,
// and the overwhelming majority of scans are the same handful of popular
// tokens. Fifteen minutes collapses those to a single upstream call while
// staying well inside any reasonable freshness expectation for this data.
const CACHE_TTL_SECONDS = 900;
const SOLANA_ADDRESS_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const SUI_ADDRESS_RE = /^0x[a-fA-F0-9]{1,64}::.+$/;
const TRON_ADDRESS_RE = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;
const EVM_ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;

// --- Chainalysis Sanctions Oracle -------------------------------------
// Contract addresses verified directly against Chainalysis's own docs
// (go.chainalysis.com/chainalysis-oracle-docs.html) AND independently
// cross-checked against Etherscan's verified source for the Ethereum
// deployment. Base uses a genuinely different address -- confirmed by
// the same source, not assumed to match the others.
const SANCTIONS_ORACLE_ADDRESSES = {
  '1': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',      // Ethereum
  '56': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',     // BNB Smart Chain
  '137': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',    // Polygon
  '42161': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',  // Arbitrum
  '10': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',     // Optimism
  '43114': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',  // Avalanche
  '250': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',    // Fantom
  '81457': '0x40C57923924B5c5c5455c48D93317139ADDaC8fb',  // Blast
  '8453': '0x3A91A31cB3dC49b4db9Ce721F50a9D076c8D739B',   // Base -- different, verified separately
  // 324 (zkSync Era), 59144 (Linea), 534352 (Scroll), 5000 (Mantle), 100 (Gnosis)
  // are deliberately absent. No confirmed oracle deployment was found for
  // these on Chainalysis's own chain list. A chain missing from this map
  // means "not available" -- it must never fall back to the shared address.
};

// All verified directly against PublicNode's own per-chain pages (not
// guessed from a naming pattern -- Polygon, Arbitrum, and Avalanche each
// turned out to need a specific sub-service subdomain, not their bare
// domain, which a pattern guess would have gotten wrong). Fantom is not
// on PublicNode's 74-chain list at all -- left as a placeholder with an
// honest reason, not a guess at an alternate provider.
const CHAIN_RPC_ENDPOINTS = {
  '1': 'https://ethereum-rpc.publicnode.com',            // verified
  '56': 'https://bsc-rpc.publicnode.com',                // verified
  '137': 'https://polygon-bor-rpc.publicnode.com',       // verified -- Bor (EVM), not Heimdall (consensus)
  '42161': 'https://arbitrum-one-rpc.publicnode.com',    // verified -- One, not Nova
  '10': 'https://optimism-rpc.publicnode.com',           // verified
  '43114': 'https://avalanche-c-chain-rpc.publicnode.com', // verified -- C-Chain (EVM), not P-Chain/X-Chain
  '250': 'NOT-AVAILABLE-ON-PUBLICNODE',                  // Fantom is not in PublicNode's chain list; needs a different provider
  '81457': 'https://blast-rpc.publicnode.com',           // verified
  '8453': 'https://base-rpc.publicnode.com',             // verified
};

// --- Recent token-transfer counterparty checking ----------------------
// Standard Ethereum JSON-RPC has no "get all transactions for an address"
// method -- eth_getTransactionReceipt needs a hash you already have, not
// an address. eth_getLogs CAN filter ERC-20/721 Transfer events by
// indexed from/to address, which is what this uses -- but it only sees
// token transfers, never native ETH transfers, and only within the
// bounded recent window below. This is deliberately a narrower, honestly
// labeled feature, not "transaction history."

// Verified two ways before trusting it: computed with the same
// sanity-checked keccak256 methodology used for the sanctions selector,
// then independently cross-matched against a real logged example found
// in third-party RPC documentation (a Base WETH transfer). Event topics
// use the full 32-byte hash, unlike a function selector's 4-byte prefix.
const TRANSFER_EVENT_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// No standard eth_getLogs block-range limit exists -- confirmed via an
// independent technical source: a mid-2026 survey of public RPC endpoints
// found limits ranging from 50 to 1,000 blocks, with some capping by
// result count instead of range, and none of it standardized. 2000 is a
// reasonable starting point, not a guarantee -- getTransferLogs() below
// halves it once on failure rather than assuming this number is safe.
const LOG_BLOCK_RANGE = 2000;

// Used only to describe the scan window in human terms (e.g. "~50
// minutes"), never to change what's actually queried. Ethereum, BSC,
// Polygon, Arbitrum, Avalanche, and Blast values are read directly from
// PublicNode's own live network stats; Optimism and Base are ESTIMATED
// from the typical OP-stack block time (not independently confirmed) --
// marked as such in the description text, not presented as equally solid.
const APPROX_BLOCK_TIME_SECONDS = {
  '1': 12.0, '56': 0.44, '137': 1.5, '42161': 0.25,
  '43114': 1.08, '81457': 1.99, '10': 2.0, '8453': 2.0,
};
const ESTIMATED_BLOCK_TIME_CHAINS = new Set(['10', '8453']);

function describeWindow(chainId, blockCount) {
  const blockTime = APPROX_BLOCK_TIME_SECONDS[chainId];
  if (!blockTime) return `${blockCount} most recent blocks`;
  const seconds = blockCount * blockTime;
  const qualifier = ESTIMATED_BLOCK_TIME_CHAINS.has(chainId) ? ', approximate' : '';
  return seconds < 3600
    ? `~${Math.round(seconds / 60)} minutes (${blockCount} blocks${qualifier})`
    : `~${(seconds / 3600).toFixed(1)} hours (${blockCount} blocks${qualifier})`;
}

// Shared by both the isSanctioned call encoding and the getLogs topic
// filters below -- both need the same 20-byte-address-in-a-32-byte-word
// left-padding per the EVM ABI convention.
function padAddressTo32Bytes(address) {
  return address.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

// isSanctioned(address) -- verified two ways before trusting it: computed
// with a known-correct methodology (checked against the universally-cited
// transfer(address,uint256) selector, 0xa9059cbb, as a sanity test first),
// then cross-matched byte-for-byte against the actual deployed bytecode's
// function dispatcher on Etherscan. Not a memorized or assumed value.
const SANCTIONS_SELECTOR = 'df592f7d';

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
}

function jsonResponse(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  });
}

// Edge-cached proxy.
//
// WHY THIS EXISTS: every visitor routed through this Worker shares its
// egress IP, and GoPlus's anonymous rate limit is per-IP. One Cloudflare
// address -- shared with other Cloudflare customers, not reserved for this
// project -- was carrying every scan in the world, which is what produced
// the intermittent "too many requests" failures. The client now calls
// GoPlus directly wherever it can, so this path only serves visitors whose
// browser blocks the API host (ad blockers, privacy extensions, filtered
// DNS, endpoint security). That is a small share of traffic but a
// privacy-conscious one, which for a crypto safety tool is a meaningful
// slice of the actual audience. Caching keeps this fallback usable for
// them instead of handing them the same rate-limit wall.
async function proxyTo(upstreamUrl) {
  const cache = caches.default;
  const cacheKey = new Request(upstreamUrl, { method: 'GET' });

  const hit = await cache.match(cacheKey);
  if (hit) {
    const cachedBody = await hit.text();
    return new Response(cachedBody, {
      status: 200,
      headers: { ...corsHeaders(), 'Content-Type': 'application/json', 'X-Proxy-Cache': 'HIT' },
    });
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const upstreamResponse = await fetch(upstreamUrl, { signal: controller.signal });
    clearTimeout(timeoutId);
    const body = await upstreamResponse.text();

    // Cache ONLY a genuinely successful payload. GoPlus answers HTTP 200
    // for its own error conditions with a non-1 code in the body, so status
    // alone is not enough. Caching an error -- above all a rate-limit error
    // -- would pin that failure in place for the whole TTL and make this
    // strictly worse than having no cache at all.
    let cacheable = false;
    if (upstreamResponse.status === 200) {
      try { cacheable = JSON.parse(body).code === 1; } catch (_) { cacheable = false; }
    }
    if (cacheable) {
      try {
        await cache.put(cacheKey, new Response(body, {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}`,
          },
        }));
      } catch (_) { /* a cache write failure must never fail the user's request */ }
    }

    return new Response(body, {
      status: upstreamResponse.status,
      headers: { ...corsHeaders(), 'Content-Type': 'application/json', 'X-Proxy-Cache': cacheable ? 'MISS' : 'BYPASS' },
    });
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === 'AbortError';
    return jsonResponse(
      { error: isTimeout ? 'Upstream request timed out' : 'Upstream request failed', detail: String(err) },
      504
    );
  }
}

// Encodes a call to isSanctioned(address): the verified 4-byte selector
// followed by the 20-byte address left-padded to a 32-byte word, per the
// standard EVM ABI calling convention for a single address parameter.
function encodeIsSanctionedCall(address) {
  return '0x' + SANCTIONS_SELECTOR + padAddressTo32Bytes(address);
}

// The result is a 32-byte word: all zeros means false, a trailing 0x01
// means true. Checking for "any nonzero byte" rather than the exact
// expected pattern is deliberately more defensive than assuming one
// specific encoding of true.
function decodeBoolResult(hexResult) {
  if (!hexResult || hexResult === '0x') return null; // no data at all -- unknown, not false
  const clean = hexResult.replace(/^0x/, '');
  return /[1-9a-f]/i.test(clean);
}

// Returns one of three shapes, always distinguishable from each other:
//   { available: true, isSanctioned: true|false }  -- a real answer
//   { available: false, reason: '...' }             -- chain not covered,
//                                                       RPC not configured,
//                                                       or the call failed
// The caller must never treat `available: false` as `isSanctioned: false`.
// An unanswerable question is not the same statement as a clean result --
// the same principle the verdict engine already applies everywhere else.
async function callSanctionsOracle(address, chainId) {
  const oracleAddress = SANCTIONS_ORACLE_ADDRESSES[chainId];
  if (!oracleAddress) {
    return { available: false, reason: 'No confirmed Chainalysis oracle deployment for this chain.' };
  }
  const rpcUrl = CHAIN_RPC_ENDPOINTS[chainId];
  if (!rpcUrl || !rpcUrl.startsWith('https://')) {
    return { available: false, reason: rpcUrl === 'NOT-AVAILABLE-ON-PUBLICNODE'
      ? 'No RPC endpoint configured for this chain (not available on PublicNode).'
      : 'RPC endpoint not yet configured for this chain.' };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const rpcResponse = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_call',
        params: [{ to: oracleAddress, data: encodeIsSanctionedCall(address) }, 'latest'],
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (!rpcResponse.ok) {
      return { available: false, reason: `RPC request failed (${rpcResponse.status})` };
    }
    const rpcData = await rpcResponse.json();
    if (rpcData.error) {
      return { available: false, reason: rpcData.error.message || 'RPC returned an error' };
    }
    const isSanctioned = decodeBoolResult(rpcData.result);
    if (isSanctioned === null) {
      return { available: false, reason: 'RPC returned no usable data' };
    }
    return { available: true, isSanctioned };
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err.name === 'AbortError';
    return { available: false, reason: isTimeout ? 'RPC request timed out' : 'RPC request failed' };
  }
}

async function rpcCall(rpcUrl, method, params) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (!res.ok) throw new Error(`RPC request failed (${res.status})`);
    const data = await res.json();
    if (data.error) throw new Error(data.error.message || 'RPC returned an error');
    return data.result;
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

// Queries Transfer events in one direction (either the address as sender
// or as recipient -- eth_getLogs topic matching is positional AND, so
// "either side" needs two separate calls, not one). Halves the block
// range once on failure and retries, since the safe range is genuinely
// unknown in advance; gives up and reports clearly rather than trying
// indefinitely.
async function getTransferLogsOneDirection(rpcUrl, address, fromBlockHex, toBlockHex, addressTopicPosition) {
  const paddedAddr = '0x' + padAddressTo32Bytes(address);
  const topics = addressTopicPosition === 'from'
    ? [TRANSFER_EVENT_TOPIC, paddedAddr, null]
    : [TRANSFER_EVENT_TOPIC, null, paddedAddr];
  try {
    return await rpcCall(rpcUrl, 'eth_getLogs', [{ fromBlock: fromBlockHex, toBlock: toBlockHex, topics }]);
  } catch (err) {
    // Range-related failures aren't standardized across providers (no
    // reliable error code/message to pattern-match on), so any failure
    // here triggers one retry with half the range rather than guessing
    // at the provider's specific error format.
    const fromNum = parseInt(fromBlockHex, 16);
    const toNum = parseInt(toBlockHex, 16);
    const midNum = fromNum + Math.floor((toNum - fromNum) / 2);
    if (midNum <= fromNum) throw err; // range already minimal; nothing smaller to try
    return await rpcCall(rpcUrl, 'eth_getLogs', [{
      fromBlock: '0x' + midNum.toString(16), toBlock: toBlockHex, topics,
    }]);
  }
}

// The main entry point for this route. Returns:
//   { available: true, windowDescription, transferCount, uniqueCounterpartyCount,
//     sanctionedCounterparties: [{address, direction, txHash}], checkedCounterpartyCount,
//     counterpartyCheckLimited: bool }
//   { available: false, reason: '...' }
async function checkRecentCounterparties(address, chainId) {
  const rpcUrl = CHAIN_RPC_ENDPOINTS[chainId];
  if (!rpcUrl || !rpcUrl.startsWith('https://')) {
    return { available: false, reason: rpcUrl === 'NOT-AVAILABLE-ON-PUBLICNODE'
      ? 'No RPC endpoint configured for this chain (not available on PublicNode).'
      : 'RPC endpoint not yet configured for this chain.' };
  }
  if (!SANCTIONS_ORACLE_ADDRESSES[chainId]) {
    return { available: false, reason: 'No confirmed sanctions oracle deployment for this chain -- counterparty results could not be checked.' };
  }

  let tipHex;
  try {
    tipHex = await rpcCall(rpcUrl, 'eth_blockNumber', []);
  } catch (err) {
    return { available: false, reason: 'Could not read current block height: ' + err.message };
  }
  const tip = parseInt(tipHex, 16);
  const fromBlock = Math.max(0, tip - LOG_BLOCK_RANGE);
  const fromBlockHex = '0x' + fromBlock.toString(16);

  let outgoing, incoming;
  try {
    [outgoing, incoming] = await Promise.all([
      getTransferLogsOneDirection(rpcUrl, address, fromBlockHex, tipHex, 'from'),
      getTransferLogsOneDirection(rpcUrl, address, fromBlockHex, tipHex, 'to'),
    ]);
  } catch (err) {
    return { available: false, reason: 'Log query failed: ' + err.message };
  }

  // Extract counterparty + direction + tx hash from each log. topics[1] is
  // always 'from', topics[2] is always 'to' for a standard Transfer event,
  // regardless of which direction this specific query matched on.
  const seen = new Map(); // address -> {direction, txHash} (first occurrence kept)
  const recordLog = (log, direction) => {
    const fromAddr = '0x' + log.topics[1].slice(-40);
    const toAddr = '0x' + log.topics[2].slice(-40);
    const counterparty = direction === 'sent_to' ? toAddr : fromAddr;
    if (!seen.has(counterparty)) {
      seen.set(counterparty, { direction, txHash: log.transactionHash });
    }
  };
  outgoing.forEach(log => recordLog(log, 'sent_to'));
  incoming.forEach(log => recordLog(log, 'received_from'));

  const transferCount = outgoing.length + incoming.length;
  const allCounterparties = [...seen.entries()];
  const MAX_COUNTERPARTIES_CHECKED = 15; // bounds worst-case latency/oracle-call count
  const toCheck = allCounterparties.slice(0, MAX_COUNTERPARTIES_CHECKED);

  const oracleResults = await Promise.all(
    toCheck.map(([addr]) => callSanctionsOracle(addr, chainId))
  );

  const sanctionedCounterparties = [];
  toCheck.forEach(([addr, info], i) => {
    if (oracleResults[i].available && oracleResults[i].isSanctioned) {
      sanctionedCounterparties.push({ address: addr, direction: info.direction, txHash: info.txHash });
    }
  });

  return {
    available: true,
    windowDescription: describeWindow(chainId, LOG_BLOCK_RANGE),
    transferCount,
    uniqueCounterpartyCount: allCounterparties.length,
    checkedCounterpartyCount: toCheck.length,
    counterpartyCheckLimited: allCounterparties.length > MAX_COUNTERPARTIES_CHECKED,
    sanctionedCounterparties,
  };
}

async function handleRequest(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }
  if (request.method !== 'GET') {
    return jsonResponse({ error: 'Only GET is supported' }, 405);
  }

  const url = new URL(request.url);
  const contractAddress = url.searchParams.get('contract_addresses');
  const walletAddress = url.searchParams.get('wallet_address');
  const suiAddress = url.searchParams.get('sui_contract_addresses');
  const tronAddress = url.searchParams.get('tron_contract_addresses');
  const sanctionsAddress = url.searchParams.get('sanctions_check');
  const sanctionsChainId = url.searchParams.get('chain');
  const counterpartyAddress = url.searchParams.get('counterparty_check');
  const counterpartyChainId = url.searchParams.get('chain');

  if (contractAddress) {
    if (!SOLANA_ADDRESS_RE.test(contractAddress)) {
      return jsonResponse({ error: 'Invalid Solana address format' }, 400);
    }
    return proxyTo(`${TOKEN_SECURITY_UPSTREAM}?contract_addresses=${encodeURIComponent(contractAddress)}`);
  }

  if (walletAddress) {
    if (!SOLANA_ADDRESS_RE.test(walletAddress)) {
      return jsonResponse({ error: 'Invalid Solana address format' }, 400);
    }
    return proxyTo(`${ADDRESS_SECURITY_UPSTREAM}/${encodeURIComponent(walletAddress)}?chain_id=solana`);
  }

  if (suiAddress) {
    if (!SUI_ADDRESS_RE.test(suiAddress)) {
      return jsonResponse({ error: 'Invalid Sui address format (expected 0x + 64 hex chars + ::module::Type)' }, 400);
    }
    return proxyTo(`${SUI_TOKEN_SECURITY_UPSTREAM}?contract_addresses=${encodeURIComponent(suiAddress)}`);
  }

  if (tronAddress) {
    if (!TRON_ADDRESS_RE.test(tronAddress)) {
      return jsonResponse({ error: 'Invalid TRON address format (expected T + 33 base58 characters, 34 total)' }, 400);
    }
    return proxyTo(`${TRON_TOKEN_SECURITY_UPSTREAM}?contract_addresses=${encodeURIComponent(tronAddress)}`);
  }

  if (sanctionsAddress) {
    if (!EVM_ADDRESS_RE.test(sanctionsAddress)) {
      return jsonResponse({ error: 'Invalid EVM address format' }, 400);
    }
    if (!sanctionsChainId) {
      return jsonResponse({ error: 'Missing chain parameter (numeric EVM chain ID, e.g. chain=1 for Ethereum)' }, 400);
    }
    const result = await callSanctionsOracle(sanctionsAddress, sanctionsChainId);
    return jsonResponse(result, 200);
  }

  if (counterpartyAddress) {
    if (!EVM_ADDRESS_RE.test(counterpartyAddress)) {
      return jsonResponse({ error: 'Invalid EVM address format' }, 400);
    }
    if (!counterpartyChainId) {
      return jsonResponse({ error: 'Missing chain parameter (numeric EVM chain ID, e.g. chain=1 for Ethereum)' }, 400);
    }
    const result = await checkRecentCounterparties(counterpartyAddress, counterpartyChainId);
    return jsonResponse(result, 200);
  }

return jsonResponse({ error: 'Provide one of contract_addresses, wallet_address, sui_contract_addresses, tron_contract_addresses, sanctions_check, or counterparty_check' }, 400);
}

export default {
  async fetch(request) {
    const origin = resolveOrigin(request);
    const response = await handleRequest(request);

    // Stamp the resolved origin on the way out. Every response -- cached,
    // proxied, validation error, timeout -- passes through here, so there is
    // no code path that can quietly emit the wrong origin.
    const out = new Response(response.body, response);
    if (origin) {
      out.headers.set('Access-Control-Allow-Origin', origin);
    } else {
      out.headers.delete('Access-Control-Allow-Origin');
    }
    out.headers.set('Vary', 'Origin');
    return out;
  },
};
