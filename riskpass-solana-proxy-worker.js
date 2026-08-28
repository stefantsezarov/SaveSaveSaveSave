/**
 * RiskPass — CORS proxy for GoPlus's newer, chain-specific APIs
 *
 * GoPlus's Solana Token Security API (Beta) does not send an
 * Access-Control-Allow-Origin header, so browsers block direct reads of
 * the response (confirmed via console: "No 'Access-Control-Allow-Origin'
 * header is present on the requested resource"). This Worker makes the
 * request server-to-server, where CORS does not apply, adds the header
 * the browser needs, and passes the response straight through.
 *
 * It stores nothing, logs nothing beyond Cloudflare's own default
 * platform logs, and only forwards GET requests to four fixed upstream
 * URLs — GoPlus's Solana Token Security endpoint, GoPlus's general
 * Malicious Address endpoint (wallet screening, chain-parameterized),
 * GoPlus's Sui Token Security endpoint, and GoPlus's Token Security
 * endpoint called with chain_id=tron.
 *
 * Four request shapes are supported, one per route:
 *   ?contract_addresses=<addr>      -> Solana token security lookup
 *   ?wallet_address=<addr>          -> malicious-address (wallet) lookup
 *   ?sui_contract_addresses=<addr>  -> Sui token security lookup
 *   ?tron_contract_addresses=<addr> -> TRON token security lookup
 *
 * The wallet route is only used as a fallback: RiskPass's client code
 * tries GoPlus's general Malicious Address API directly first, since
 * that's the same mature endpoint the EVM adapter already calls
 * successfully — this proxy route only gets used if that direct call
 * hits a CORS block the same way the token-security one did.
 *
 * The Sui and TRON routes are used unconditionally from the start, not
 * as fallbacks — both sit on newer or non-standard chain_id values with
 * unconfirmed CORS behavior. Routing through the proxy from day one
 * avoids relying on an untested guess, the same reasoning applied to Sui.
 *
 * SETUP:
 * 1. Change ALLOWED_ORIGIN below to your actual site origin if different.
 * 2. Paste this whole file into the Cloudflare Worker "Edit code" editor.
 * 3. Click Save and Deploy.
 * 4. Copy the resulting https://<name>.<subdomain>.workers.dev URL.
 */

const ALLOWED_ORIGIN = 'https://stefantsezarov.github.io';
const TOKEN_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/solana/token_security';
const ADDRESS_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/address_security';
const SUI_TOKEN_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/sui/token_security';
const TRON_TOKEN_SECURITY_UPSTREAM = 'https://api.gopluslabs.io/api/v1/token_security/tron';
const UPSTREAM_TIMEOUT_MS = 15000;
const SOLANA_ADDRESS_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const SUI_ADDRESS_RE = /^0x[a-fA-F0-9]{1,64}::.+$/;
const TRON_ADDRESS_RE = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;

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

async function proxyTo(upstreamUrl) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const upstreamResponse = await fetch(upstreamUrl, { signal: controller.signal });
    clearTimeout(timeoutId);
    const body = await upstreamResponse.text();
    return new Response(body, {
      status: upstreamResponse.status,
      headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
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

export default {
  async fetch(request) {
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

    return jsonResponse({ error: 'Provide one of contract_addresses, wallet_address, sui_contract_addresses, or tron_contract_addresses' }, 400);
  },
};
