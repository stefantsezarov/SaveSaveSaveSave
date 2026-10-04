/* =====================================================================
   SAVESAVESAVESAVE CORE (formerly RiskPass)
   Layers 0-6 from the architecture: input validation, data acquisition,
   evidence normalization, chain adapters, verdict engine, confidence.
   This block has NO DOM dependency except an optional escapeHtml path,
   so it can be eval()'d in Node for regression testing, unmodified,
   exactly as it ships in the browser.
   ===================================================================== */

// ---------- Sanitization ----------
// One implementation everywhere. The browser used to take a DOM shortcut
// (textContent -> innerHTML) that escapes < > & but NOT quotes, while
// Node took this path, so the tests checked a function the page did not
// run, and any value placed inside an attribute was one quote away from
// breaking out of it.
function escapeHtml(str){
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// Every invisible formatting character (Unicode category Cf), not a
// hand-picked list: the list missed LRM/RLM (U+200E/F), the word joiner
// and invisible operators (U+2060-2064), the soft hyphen, the Arabic
// letter mark and the whole Tags block, all usable to dress up a token name.
function stripSpoofChars(str){
  return String(str).replace(/\p{Cf}/gu, '');
}

function getPath(obj, path){
  let cur = obj;
  for(const key of path){
    if(cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    cur = cur[key];
  }
  return cur;
}

// ---------- Layer 1/2: flag classification + evidence model ----------
// Every raw provider value is classified into exactly one bucket.
// 'missing' fields never become a CHECK object at all — they are simply
// absent, and absence is accounted for via checksExpected vs checksValid,
// never silently treated as clear.
function flagState(v){
  if(v === '1' || v === 1 || v === true) return 'on';
  if(v === '0' || v === 0 || v === false) return 'off';
  if(v === undefined || v === null) return 'missing';
  return 'unrecognized';
}

// CHECK = { id, category, status: 'PASS'|'RISK'|'UNKNOWN', critical, severityWeight, label, detail, source }
function buildCheck(def, rawValue, source){
  const state = flagState(rawValue);
  if(state === 'missing') return null;
  if(state === 'unrecognized'){
    return { id: def.key, category: def.category || 'general', status: 'UNKNOWN', critical: !!def.critical,
      severityWeight: 1, label: def.label, detail: def.detail + ' (provider returned an unrecognized value type for this field)', source };
  }
  const on = state === 'on';
  return { id: def.key, category: def.category || 'general', status: on ? 'RISK' : 'PASS',
    critical: !!def.critical, severityWeight: def.sev === 'bad' ? 3 : 1, label: def.label, detail: def.detail, source };
}

// ---------- Layer 5/6: Verdict engine — knows NOTHING about any provider or chain ----------
const VerdictEngine = {
  evaluate(checks, expectedChecks, source, criticalDefsTotal){
    const risks = checks.filter(c => c.status === 'RISK');
    const unknowns = checks.filter(c => c.status === 'UNKNOWN');
    const valid = checks.filter(c => c.status === 'PASS' || c.status === 'RISK').length;
    const criticalFindings = risks.filter(c => c.critical).length;
    const criticalHit = criticalFindings > 0;
    const criticalSeen = checks.filter(c => c.critical).length; // critical-tier checks we got ANY answer for, PASS/RISK/UNKNOWN alike
    const criticalMissing = typeof criticalDefsTotal === 'number' ? Math.max(0, criticalDefsTotal - criticalSeen) : 0;

    // Only confirmed findings can make a FAIL. Unreadable fields push toward
    // CAUTION but never, on their own, claim a risk was found: six of them
    // used to add up to "Significant risk indicators detected" with no
    // indicator detected at all.
    let riskScore = 0;
    risks.forEach(c => { riskScore += c.severityWeight; });
    const score = riskScore + unknowns.length;

    const coverage = expectedChecks ? valid / expectedChecks : 0;
    const insufficientData = valid === 0 || coverage < 0.4;

    let verdict, label, sub;
    if(criticalHit){
      verdict = 'fail'; label = 'FAIL';
      sub = 'A confirmed high-severity indicator was detected';
    } else if(insufficientData){
      verdict = 'unknown'; label = 'INSUFFICIENT DATA';
      sub = `Only ${valid}/${expectedChecks} indicators returned usable data — too little to form a judgment. This is not a clean result.`;
    } else if(riskScore >= 6){
      verdict = 'fail'; label = 'FAIL';
      sub = 'Significant risk indicators detected';
    } else if(score >= 2 || unknowns.length > 0){
      verdict = 'caution'; label = 'CAUTION';
      sub = (risks.length === 0)
        ? 'Some indicators returned unreadable data — treat as unverified, not clean'
        : 'Risk indicators detected — review before proceeding';
    } else {
      verdict = 'pass'; label = 'PASS';
      sub = `No major risk indicators across ${valid}/${expectedChecks} checks — not a safety guarantee`;
    }

    // Additive disclosure: even a well-covered, otherwise-clean scan should
    // say so plainly if one of the specific high-stakes checks (e.g.
    // honeypot detection) simply wasn't answered by the provider. This is
    // deliberately separate from the coverage-driven INSUFFICIENT DATA
    // state above — losing one decisive check is a different, more
    // targeted kind of uncertainty than losing most of the response.
    if(criticalMissing > 0 && (verdict === 'pass' || verdict === 'caution')){
      sub += ` Note: ${criticalMissing} high-severity check${criticalMissing===1?'':'s'} could not be evaluated (no data returned) — treat this result as incomplete on that point.`;
    }

    const confidence = insufficientData ? 'low' : (unknowns.length > 0 || criticalMissing > 0 ? 'medium' : 'high');

    return {
      verdict, label, sub, score,
      checksExpected: expectedChecks,
      checksReceived: checks.length,
      checksValid: valid,
      checksUnknown: unknowns.length,
      criticalFindings,
      criticalMissing,
      coverage,
      confidence,
      source,
      checks
    };
  }
};

// ---------- Layer 3: chain adapters ----------

// -- EVM adapter --
const EVM_TOKEN_CHECK_DEFS = [
  {key:'is_honeypot', category:'liquidity', label:'Honeypot pattern', detail:'Token can be bought but may not be sellable.', sev:'bad', critical:true},
  {key:'cannot_sell_all', category:'liquidity', label:'Cannot sell full balance', detail:'Contract may block selling 100% of holdings.', sev:'bad', critical:true},
  {key:'selfdestruct', category:'control', label:'Self-destruct function present', detail:'Contract could be destroyed, freezing funds.', sev:'bad', critical:true},
  {key:'owner_change_balance', category:'control', label:'Owner can edit balances', detail:'Contract owner can directly alter holder balances.', sev:'bad', critical:true},
  {key:'can_take_back_ownership', category:'control', label:'Ownership can be reclaimed', detail:'A renounced-looking contract may still be controllable.', sev:'bad', critical:true},
  {key:'hidden_owner', category:'control', label:'Hidden owner address', detail:'Contract owner is concealed from standard checks.', sev:'bad', critical:false},
  {key:'is_blacklisted', category:'control', label:'Blacklist function present', detail:'Owner can block specific addresses from trading.', sev:'warn', critical:false},
  {key:'is_mintable', category:'supply', label:'Owner can mint new supply', detail:'Total supply is not fixed.', sev:'warn', critical:false},
  {key:'transfer_pausable', category:'control', label:'Transfers can be paused', detail:'Owner can freeze all trading at will.', sev:'warn', critical:false},
  {key:'slippage_modifiable', category:'economics', label:'Tax/slippage can be changed', detail:'Buy/sell tax is not locked.', sev:'warn', critical:false},
  {key:'is_proxy', category:'control', label:'Upgradeable proxy contract', detail:'Logic can be swapped after deployment.', sev:'warn', critical:false},
  {key:'is_anti_whale_modifiable', category:'control', label:'Anti-whale limits are adjustable', detail:'Transaction size limits can be changed by the owner.', sev:'warn', critical:false},
];

const EVM_WALLET_CHECK_DEFS = [
  {key:'sanctioned', category:'reputation', label:'On a sanctions list', detail:'Address appears on a known sanctions record.', sev:'bad', critical:true},
  {key:'phishing_activities', category:'reputation', label:'Linked to phishing', detail:'Address has been associated with phishing activity.', sev:'bad', critical:true},
  {key:'stealing_attack', category:'reputation', label:'Linked to theft', detail:'Address has been associated with a stealing attack.', sev:'bad', critical:true},
  {key:'money_laundering', category:'reputation', label:'Linked to money laundering', detail:'Flagged in money-laundering-related activity.', sev:'bad', critical:true},
  {key:'darkweb_transactions', category:'reputation', label:'Dark web transaction history', detail:'Address has interacted with dark web markets.', sev:'bad', critical:true},
  {key:'cybercrime', category:'reputation', label:'Linked to cybercrime', detail:'Address has been associated with cybercrime.', sev:'bad', critical:true},
  {key:'blackmail_activities', category:'reputation', label:'Linked to blackmail/extortion', detail:'Flagged in blackmail-related activity.', sev:'bad', critical:true},
  {key:'mixer', category:'reputation', label:'Mixer / tumbler service', detail:'Address is associated with a coin-mixing service.', sev:'warn', critical:false},
  {key:'fake_kyc', category:'reputation', label:'Fake KYC association', detail:'Linked to fraudulent identity-verification activity.', sev:'warn', critical:false},
  {key:'blacklist_doubt', category:'reputation', label:'On a community blacklist (unconfirmed)', detail:'Reported but not fully confirmed.', sev:'warn', critical:false},
  {key:'gas_abuse', category:'reputation', label:'Gas abuse pattern', detail:'Associated with gas-griefing or abuse patterns.', sev:'warn', critical:false},
];

const EVM_CHAINS = {"1":"Ethereum","56":"BNB Chain","137":"Polygon","42161":"Arbitrum","10":"Optimism","8453":"Base","43114":"Avalanche","250":"Fantom","324":"zkSync Era","59144":"Linea","534352":"Scroll","81457":"Blast","5000":"Mantle","100":"Gnosis"};

function normalizeEvmRecord(record, assetType){
  const defs = assetType === 'token' ? EVM_TOKEN_CHECK_DEFS : EVM_WALLET_CHECK_DEFS;
  const checks = [];
  let expected = defs.length;
  let criticalDefsTotal = defs.filter(d => d.critical).length;

  defs.forEach(def => {
    const c = buildCheck(def, record[def.key], 'GoPlus Security (EVM)');
    if(c) checks.push(c);
  });

  if(assetType === 'token'){
    expected += 2; // is_open_source + tax are extra checks beyond the base list
    if(record.is_open_source !== undefined){
      const openState = flagState(record.is_open_source);
      if(openState === 'on'){
        checks.push({id:'is_open_source', category:'transparency', status:'PASS', critical:false, severityWeight:0, label:'Source code verified', detail:'Contract code has been published/verified.', source:'GoPlus Security (EVM)'});
      } else if(openState === 'off'){
        checks.push({id:'is_open_source', category:'transparency', status:'RISK', critical:false, severityWeight:2, label:'Source code not verified', detail:'Contract code has not been published/verified.', source:'GoPlus Security (EVM)'});
      }
      // unrecognized type for is_open_source: leave unclassified rather than guess a boolean meaning
    }
    if(record.buy_tax !== undefined || record.sell_tax !== undefined){
      const buyNum = parseFloat(record.buy_tax);
      const sellNum = parseFloat(record.sell_tax);
      const buyOk = Number.isFinite(buyNum);
      const sellOk = Number.isFinite(sellNum);
      if(buyOk || sellOk){
        const buyPct = buyOk ? buyNum * 100 : null;
        const sellPct = sellOk ? sellNum * 100 : null;
        const high = (buyPct !== null && buyPct > 10) || (sellPct !== null && sellPct > 10);
        checks.push({id:'tax_rate', category:'economics', status: high ? 'RISK' : 'PASS', critical:false, severityWeight:2,
          label: high ? 'High buy/sell tax' : 'Buy/sell tax within normal range',
          detail: `Buy tax ${buyPct !== null ? buyPct.toFixed(1)+'%' : 'unknown'} · Sell tax ${sellPct !== null ? sellPct.toFixed(1)+'%' : 'unknown'}`,
          source:'GoPlus Security (EVM)'});
      } else {
        checks.push({id:'tax_rate', category:'economics', status:'UNKNOWN', critical:false, severityWeight:1,
          label:'Tax data unreadable', detail:'Buy/sell tax fields returned a non-numeric value.', source:'GoPlus Security (EVM)'});
      }
    }
  }

  return { checks, expected, criticalDefsTotal };
}

// Chains where the counterparty_check Worker route has a real RPC endpoint
// configured, not a placeholder. Must be kept in sync with
// CHAIN_RPC_ENDPOINTS in goplus-proxy-worker.js by hand — there's
// no shared config between the static client and the Worker, the same
// constraint every other cross-file constant in this project already has.
const COUNTERPARTY_CHECK_SUPPORTED_CHAINS = new Set(['1','56','137','42161','10','43114','81457','8453']);

// Turns a counterparty_check Worker response into CHECK objects, using the
// attributionType/evidenceRef fields from the wallet-risk proposal's
// extended schema. A sanctioned counterparty is scored as a serious but
// non-critical, additive signal (severityWeight 3, critical:false) —
// deliberately NOT the same unconditional FAIL override the wallet's own
// direct 'sanctioned' flag gets. That's the actual precedence rule this
// whole feature was designed around: a counterparty being sanctioned is
// one hop removed from the scanned address, and must never collapse into
// the same claim as the address itself being designated.
//
// Returns { checks, attempted }. `attempted` is false only when this
// chain has no RPC configured — a real coverage gap, not a failed check —
// so the caller can correctly leave it out of the expected-checks count
// rather than penalizing coverage for a capability that doesn't exist.
async function fetchCounterpartyChecks(addr, chainId, fetchImpl){
  if(!COUNTERPARTY_CHECK_SUPPORTED_CHAINS.has(String(chainId))) return { checks: [], attempted: false };
  if(SOLANA_PROXY_URL.includes('REPLACE-WITH-YOUR-WORKER-URL')) return { checks: [], attempted: false };

  const SOURCE = 'SaveSaveSaveSave (on-chain, via Chainalysis Sanctions Oracle)';
  try {
    const endpoint = `${SOLANA_PROXY_URL}?counterparty_check=${addr}&chain=${chainId}`;
    const res = await fetchImpl(endpoint);
    if(!res.ok) throw new Error(`Network response was not OK (${res.status})`);
    const data = await res.json();

    if(!data.available){
      return { attempted: true, checks: [{
        id:'recent_counterparty_check', category:'exposure', status:'UNKNOWN', critical:false, severityWeight:1,
        label:'Recent counterparty check unavailable',
        detail: data.reason || 'Could not complete the recent-transfer counterparty check.',
        source: SOURCE, attributionType: null, confidence: null,
      }]};
    }

    if(data.sanctionedCounterparties.length === 0){
      return { attempted: true, checks: [{
        id:'recent_counterparty_check', category:'exposure', status:'PASS', critical:false, severityWeight:0,
        label:'No sanctioned counterparties in recent transfers',
        detail:`Checked token transfers in the last ${data.windowDescription} — ${data.transferCount} transfer${data.transferCount===1?'':'s'} across ${data.uniqueCounterpartyCount} counterpart${data.uniqueCounterpartyCount===1?'y':'ies'}, none matched the sanctions oracle. Native ETH transfers and activity outside this window are not covered — this is not a full transaction history.`,
        source: SOURCE, attributionType: null, confidence: null,
      }]};
    }

    return { attempted: true, checks: data.sanctionedCounterparties.map((cp, i) => ({
      id: `recent_counterparty_sanctioned_${i}`, category:'exposure', status:'RISK', critical:false, severityWeight:3,
      label: cp.direction === 'sent_to' ? 'Sent tokens to a sanctioned address' : 'Received tokens from a sanctioned address',
      detail: `A token transfer ${cp.direction === 'sent_to' ? 'to' : 'from'} ${cp.address} was found in the last ${data.windowDescription}. That address matches the Chainalysis Sanctions Oracle. This is direct counterparty exposure — it is not a designation of the scanned address itself.`,
      source: SOURCE, attributionType: 'direct_counterparty', confidence: null, evidenceRef: cp.txHash,
    }))};
  } catch(err){
    return { attempted: true, checks: [{
      id:'recent_counterparty_check', category:'exposure', status:'UNKNOWN', critical:false, severityWeight:1,
      label:'Recent counterparty check unavailable',
      detail:'Network error while checking recent counterparties: ' + err.message,
      source: SOURCE, attributionType: null, confidence: null,
    }]};
  }
}

const EvmAdapter = {
  id: 'evm', name: 'EVM',
  capabilities: { tokenSecurity:true, walletScreening:true, txSimulation:false, liquidityAnalysis:false, contractAnalysis:true },
  chains: EVM_CHAINS,
  validateAddress(addr){ return /^0x[a-fA-F0-9]{40}$/.test(String(addr).trim()); },
  async fetchChecks(addr, assetType, chainId, fetchImpl){
    if(!EVM_CHAINS[chainId]) throw new Error('Unsupported or unrecognized chain for the EVM adapter.');
    if(assetType === 'wallet' && !this.capabilities.walletScreening) throw new Error('Wallet screening is not supported by this adapter.');
    const endpoint = assetType === 'token'
      ? `https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${addr}`
      : `https://api.gopluslabs.io/api/v1/address_security/${addr}?chain_id=${chainId}`;
    const res = await fetchImpl(endpoint);
    if(!res.ok){
      let detail = '';
      try { const errBody = await res.json(); detail = errBody.error || errBody.message || errBody.detail || ''; }
      catch(_){ /* response wasn't JSON, or already consumed — proceed without extra detail */ }
      throw new Error(`Network response was not OK (${res.status})${detail ? ': ' + detail : ''}`);
    }
    const data = await res.json();
    if(data.code !== 1 || !data.result) throw new Error(data.message || 'No security data returned for this address.');
    let record;
    if(assetType === 'token'){
      const keys = Object.keys(data.result);
      if(keys.length === 0) throw new Error('This address does not appear to be a recognized token contract on the selected chain.');
      record = data.result[keys[0]];
    } else {
      record = data.result;
    }
    const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(record, assetType);

    let finalChecks = checks, finalExpected = expected;
    if(assetType === 'wallet'){
      const cpResult = await fetchCounterpartyChecks(addr, chainId, fetchImpl);
      finalChecks = [...checks, ...cpResult.checks];
      if(cpResult.attempted) finalExpected += 1;
    }

    return { checks: finalChecks, expected: finalExpected, criticalDefsTotal, record, raw: data };
  }
};

// -- Solana adapter --
// Field names verified against GoPlus's published Solana Token Security
// response schema (nested {status} objects) — deliberately NOT the same
// shape as the EVM adapter's flat fields, per the architecture principle
// that each chain's native security model gets its own representation.
const SOLANA_CHECK_DEFS = [
  {key:'closable', path:['closable','status'], category:'control', label:'Program can be closed', detail:'Developer can close the token program, eliminating all associated assets.', sev:'bad', critical:true},
  {key:'balance_mutable', path:['balance_mutable_authority','status'], category:'control', label:'Balance can be altered', detail:'Developer retains authority to directly change user token balances.', sev:'bad', critical:true},
  {key:'freezable', path:['freezable','status'], category:'control', label:'Accounts can be frozen', detail:'Developer can freeze holder accounts, blocking trading.', sev:'bad', critical:false},
  {key:'mintable', path:['mintable','status'], category:'supply', label:'Supply can be minted', detail:'Total supply is not fixed; new tokens can be created.', sev:'warn', critical:false},
  {key:'metadata_mutable', path:['metadata_mutable','status'], category:'transparency', label:'Metadata can be changed', detail:'Name, symbol, or description can be altered after launch.', sev:'warn', critical:false},
  {key:'transfer_fee_upgradable', path:['transfer_fee_upgradable','status'], category:'economics', label:'Transfer fee can be changed', detail:'Fee equivalent to buy/sell tax is not locked.', sev:'warn', critical:false},
  {key:'default_account_state_upgradable', path:['default_account_state_upgradable','status'], category:'control', label:'Default account state is upgradable', detail:'The default frozen/initialized state for new accounts can be changed.', sev:'warn', critical:false},
  {key:'hook_upgradable', path:['transfer_hook_upgradable','status'], category:'control', label:'Transfer hook is upgradable', detail:'External hook logic attached to transfers can be changed later.', sev:'warn', critical:false},
];

function normalizeSolanaRecord(record){
  const checks = [];
  let expected = SOLANA_CHECK_DEFS.length + 4; // + non_transferable, transfer_hook presence, creator malicious, mint-authority malicious
  let criticalDefsTotal = SOLANA_CHECK_DEFS.filter(d => d.critical).length + 3; // non_transferable, creator_malicious, mint_authority_malicious are critical:true; transfer_hook_present is not
  const trusted = flagState(record.trusted_token) === 'on';

  SOLANA_CHECK_DEFS.forEach(def => {
    const raw = getPath(record, def.path);
    // GoPlus documents that trusted, well-known tokens (e.g. USDC) can
    // legitimately have functions like mint enabled without being a risk.
    // Only the mint check gets this exception, per GoPlus's own guidance.
    if(def.key === 'mintable' && trusted && flagState(raw) === 'on'){
      checks.push({id:'mintable', category:'supply', status:'PASS', critical:false, severityWeight:0,
        label:'Mint function present, but token is GoPlus-verified trusted', detail:'This token is on GoPlus\'s trusted-token list; mint authority is a known, accepted design choice for it.', source:'GoPlus Security (Solana)'});
      return;
    }
    const c = buildCheck(def, raw, 'GoPlus Security (Solana)');
    if(c) checks.push(c);
  });

  if(record.non_transferable !== undefined){
    const state = flagState(record.non_transferable);
    if(state === 'on'){
      checks.push({id:'non_transferable', category:'liquidity', status:'RISK', critical:true, severityWeight:3, label:'Token is non-transferable', detail:'Token cannot be transferred once acquired — functionally a honeypot.', source:'GoPlus Security (Solana)'});
    } else if(state === 'off'){
      checks.push({id:'non_transferable', category:'liquidity', status:'PASS', critical:false, severityWeight:0, label:'Token is transferable', detail:'No transfer restriction detected.', source:'GoPlus Security (Solana)'});
    }
  }

  const hookAddr = getPath(record, ['transfer_hook','address']);
  if(hookAddr !== undefined){
    const hasHook = typeof hookAddr === 'string' && hookAddr.length > 0;
    checks.push({id:'transfer_hook_present', category:'control', status: hasHook ? 'RISK' : 'PASS', critical:false, severityWeight:1,
      label: hasHook ? 'External transfer hook present' : 'No external transfer hook',
      detail: hasHook ? 'A hook contract can intervene in transfers and may block trading.' : 'No hook contract detected in the token program.',
      source:'GoPlus Security (Solana)'});
  }

  const creatorMalicious = getPath(record, ['creator','malicious_address']);
  if(creatorMalicious !== undefined){
    const state = flagState(creatorMalicious);
    if(state === 'on') checks.push({id:'creator_malicious', category:'reputation', status:'RISK', critical:true, severityWeight:3, label:'Creator address flagged malicious', detail:'The token creator address appears on a known malicious-address record.', source:'GoPlus Security (Solana)'});
    else if(state === 'off') checks.push({id:'creator_malicious', category:'reputation', status:'PASS', critical:false, severityWeight:0, label:'Creator address not flagged', detail:'Creator address does not appear on known malicious-address records.', source:'GoPlus Security (Solana)'});
  }

  const mintAuthority = getPath(record, ['mintable','authority']);
  if(mintAuthority === undefined || mintAuthority === null){
    // No authority object at all is consistent with mint authority having
    // been revoked (a positive signal) — but GoPlus's docs don't guarantee
    // that's the only reason it could be absent, so the wording below stays
    // deliberately hedged rather than asserting "revoked" as fact.
    checks.push({id:'mint_authority_malicious', category:'reputation', status:'PASS', critical:false, severityWeight:0,
      label:'No mint authority to check', detail:'No mint authority address was returned — consistent with mint authority having been revoked, though this cannot be confirmed from this field alone.', source:'GoPlus Security (Solana)'});
  } else {
    const state = flagState(mintAuthority.malicious_address);
    if(state === 'on') checks.push({id:'mint_authority_malicious', category:'reputation', status:'RISK', critical:true, severityWeight:3, label:'Mint authority flagged malicious', detail:'The address holding mint authority appears on a known malicious-address record.', source:'GoPlus Security (Solana)'});
    else if(state === 'off') checks.push({id:'mint_authority_malicious', category:'reputation', status:'PASS', critical:false, severityWeight:0, label:'Mint authority not flagged', detail:'Mint authority address does not appear on known malicious-address records.', source:'GoPlus Security (Solana)'});
    else if(state === 'unrecognized') checks.push({id:'mint_authority_malicious', category:'reputation', status:'UNKNOWN', critical:true, severityWeight:1, label:'Mint authority flagged malicious', detail:'A mint authority exists, but the malicious-address field for it returned an unreadable value.', source:'GoPlus Security (Solana)'});
    // state === 'missing' here (authority object present, malicious_address key absent within it) is a genuine
    // data gap and is deliberately left unpushed, so it still counts toward criticalMissing honestly.
  }

  // ---- Liquidity (Dex Info) ----
  // Field names verified against GoPlus's documented Solana schema: dexname,
  // type, id, tvl, lp_amount, fee_rate, day/week/month volume, price,
  // open_time, lp_holders[]. This data was already present in the response
  // this adapter was already fetching — it just wasn't being read before.
  let liquiditySummary = null;
  if(Array.isArray(record.dex)){
    if(record.dex.length === 0){
      checks.push({id:'has_liquidity', category:'liquidity', status:'RISK', critical:false, severityWeight:1,
        label:'No tracked DEX liquidity found', detail:'No liquidity pool was found for this token among tracked DEXs — it may not be actively tradable.', source:'GoPlus Security (Solana)'});
    } else {
      const totalTvl = record.dex.reduce((sum, d) => sum + (Number.isFinite(parseFloat(d.tvl)) ? parseFloat(d.tvl) : 0), 0);
      const topPool = [...record.dex].sort((a,b) => (parseFloat(b.tvl)||0) - (parseFloat(a.tvl)||0))[0];
      checks.push({id:'has_liquidity', category:'liquidity', status:'PASS', critical:false, severityWeight:0,
        label:`Liquidity found on ${record.dex.length} DEX pool${record.dex.length===1?'':'s'}`,
        detail:`Combined tracked TVL approximately $${totalTvl.toLocaleString(undefined,{maximumFractionDigits:0})}. Largest pool: ${topPool.dexname || 'unknown'}.`,
        source:'GoPlus Security (Solana)'});
      liquiditySummary = {
        poolCount: record.dex.length,
        totalTvl,
        pools: record.dex.map(d => ({
          dexname: d.dexname || 'Unknown',
          type: d.type || 'unknown',
          tvl: Number.isFinite(parseFloat(d.tvl)) ? parseFloat(d.tvl) : null,
          feeRate: d.fee_rate,
          openTime: d.open_time,
          topLpHolderLocked: Array.isArray(d.lp_holders) && d.lp_holders.length > 0 ? flagState(d.lp_holders[0].is_locked) : 'missing',
        })),
      };
    }
  }

  return { checks, expected, criticalDefsTotal, liquiditySummary };
}

// ---------- Solana wallet/address screening ----------
// Reuses the same check definitions as EVM wallet screening deliberately:
// the underlying provider endpoint (GoPlus's Malicious Address API) and its
// field names (sanctioned, phishing_activities, etc.) are the same across
// chains — this data describes address *reputation*, which is not a
// chain-specific mechanic the way token contract functions are. Reusing
// EVM_WALLET_CHECK_DEFS here is intentional, not a shortcut.
function normalizeSolanaWalletRecord(record){
  const defs = EVM_WALLET_CHECK_DEFS;
  const checks = [];
  const criticalDefsTotal = defs.filter(d => d.critical).length;
  defs.forEach(def => {
    const c = buildCheck(def, record[def.key], 'GoPlus Security (Solana)');
    if(c) checks.push(c);
  });
  return { checks, expected: defs.length, criticalDefsTotal };
}
// goplus-proxy-worker.js.
//
// CORRECTION (verified 2026-09-14): GoPlus DOES send CORS headers on these
// endpoints -- it reflects the Origin header back. Confirmed against
// solana/token_security, sui/token_security, token_security/tron and
// address_security, all returning access-control-allow-origin for this
// site's origin. Direct browser requests are allowed, so every adapter
// below now tries direct first.
//
// This matters for more than tidiness. Routing every user through one
// Worker meant every user shared a single egress IP, and GoPlus's
// anonymous rate limit is per-IP -- so one Cloudflare address, shared with
// other Cloudflare customers rather than reserved for this project,
// carried the whole world's scans. That is what produced the intermittent
// "too many requests" failures, most visibly on TRON. Calling GoPlus
// directly gives each visitor their own quota, which no realistic single
// user can exhaust.
//
// Privacy note: with direct calls GoPlus observes each visitor's IP
// address rather than only this proxy. Nothing is retained here, but that
// change is visible to a third party and is stated in the privacy section.
//
// The proxy is kept as a fallback for a direct call that THROWS (a future
// CORS policy change, or a network blocking the API host), and remains
// REQUIRED for the sanctions and counterparty routes, which are JSON-RPC
// calls to endpoints configured inside the Worker.
const SOLANA_PROXY_URL = 'https://cool-sound-6db2riskpass.stefan-tsezarov82.workers.dev';

// Try GoPlus directly; fall back to the Worker only when the direct call
// THROWS. Deliberately does NOT fall back on a non-ok HTTP status: a 429
// from a direct call is this visitor's own rate limit, and retrying it
// through the shared-IP proxy is more likely to fail than less -- and
// would hide the real cause, which is the bug this change exists to fix.
async function fetchGoPlus(directUrl, proxyUrl, fetchImpl){
  try {
    return await fetchImpl(directUrl);
  } catch(directErr){
    if(!proxyUrl || proxyUrl.includes('REPLACE-WITH-YOUR-WORKER-URL')) throw directErr;
    return fetchImpl(proxyUrl);
  }
}

// ---------- Solana on-chain account checks ----------
// GoPlus has no Solana wallet data (address_security?chain_id=solana
// answers code 5000 "system error" for every address, re-measured 3 October
// 2026). So the wallet scan reads the account itself from a public Solana
// RPC node: what kind of account it is, whether it exists, what it holds.
// Those are facts, not reputation, and the result says so. If GoPlus ever
// starts answering for Solana, its flags are added automatically.
const SOLANA_RPC_URL = 'https://solana-rpc.publicnode.com';
const SOLANA_SYSTEM_PROGRAM = '11111111111111111111111111111111';
const SOLANA_TOKEN_PROGRAMS = {
  'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA': 'SPL Token',
  'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb': 'Token-2022',
};

// US Treasury OFAC sanctions list: every Solana address on the SDN list
// ("Digital Currency Address - SOL"). Generated by build-ofac.js from the
// public extraction at github.com/0xB10C/ofac-sanctioned-digital-currency-addresses
// (lists branch), which parses OFAC's own SDN export. Do not edit by hand:
// run `node build-ofac.js`; CI runs `node build-ofac.js --check` daily.
// OFAC-SOL:BEGIN
const OFAC_SOLANA_AS_OF = '2026-10-03';
const OFAC_SOLANA_ADDRESSES = new Set([
  '42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi',
  '6wjqWWra8ombzaw6VHrG5xpQ972jCYF6bbHiFCbWmr4U',
  'Fc1EwQUZyTEagaDvA1utHXCcZNyG1x2PLt2DfNu1cJdH',
  'FuCC7GoYwt5TsNTjWL23Xx9UKCvC18chjMEFPL3vJDCC',
]);
// OFAC-SOL:END

async function solanaRpc(method, params, fetchImpl){
  const res = await fetchImpl(SOLANA_RPC_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  if(!res.ok) throw new Error('The Solana RPC node answered HTTP ' + res.status + '.');
  const data = await res.json();
  if(data.error) throw new Error('The Solana RPC node returned an error: ' + (data.error.message || 'unknown'));
  return data.result;
}

// What an address is on chain. kind: missing | wallet | mint |
// token-account | program | other.
async function solanaAccountKind(addr, fetchImpl){
  const r = await solanaRpc('getAccountInfo', [addr, { encoding: 'jsonParsed', commitment: 'confirmed' }], fetchImpl);
  const v = r && r.value;
  if(!v) return { kind: 'missing', lamports: 0 };
  const owner = String(v.owner || '');
  const parsed = v.data && v.data.parsed;
  if(v.executable) return { kind: 'program', owner, lamports: v.lamports };
  if(owner === SOLANA_SYSTEM_PROGRAM) return { kind: 'wallet', owner, lamports: v.lamports };
  if(SOLANA_TOKEN_PROGRAMS[owner] && parsed){
    if(parsed.type === 'mint') return { kind: 'mint', owner, lamports: v.lamports };
    if(parsed.type === 'account') return { kind: 'token-account', owner, lamports: v.lamports,
      tokenOwner: parsed.info && parsed.info.owner, mint: parsed.info && parsed.info.mint };
  }
  return { kind: 'other', owner, lamports: v.lamports };
}

function solanaKindSentence(info){
  if(info.kind === 'program') return 'This is a Solana program (executable code), not a wallet or a token.';
  if(info.kind === 'token-account') return 'This is a token account — a sub-account that holds one token' +
    (info.mint ? ' (mint ' + info.mint + ')' : '') + ' for its owner wallet' + (info.tokenOwner ? ' ' + info.tokenOwner : '') +
    '. It is not a wallet address or a token.' + (info.tokenOwner ? ' To check the person behind it, scan the owner wallet.' : '');
  if(info.kind === 'mint') return 'This is a token mint, not a wallet.';
  if(info.kind === 'other') return 'This account is owned by the program ' + info.owner + '; it is not an ordinary wallet or a token mint.';
  return '';
}

const SolanaAdapter = {
  id: 'solana', name: 'Solana',
  capabilities: { tokenSecurity:true, walletScreening:true, txSimulation:false, liquidityAnalysis:true, contractAnalysis:false },
  // Wallet scans are ON-CHAIN ACCOUNT checks, not reputation screening:
  // no provider currently answers for Solana wallets (see above).
  capabilityNotes: { walletScreening: 'on-chain account checks and the OFAC sanctions list; no scam-report provider covers Solana wallets yet',
    txSimulation: 'no free trade-simulation source', contractAnalysis: 'not applicable: every SPL token runs the same audited token program' },
  chains: { 'solana': 'Solana Mainnet' },
  validateAddress(addr){ return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(addr).trim()); },

  async fetchChecks(addr, assetType, chainId, fetchImpl){
    if(assetType === 'wallet') return this._fetchWalletChecks(addr, fetchImpl);
    const res = await fetchGoPlus(
      `https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=${encodeURIComponent(addr)}`,
      `${SOLANA_PROXY_URL}?contract_addresses=${addr}`,
      fetchImpl);
    if(!res.ok){
      let detail = '';
      try { const errBody = await res.json(); detail = errBody.error || errBody.message || errBody.detail || ''; }
      catch(_){ /* response wasn't JSON, or already consumed — proceed without extra detail */ }
      throw new Error(`Network response was not OK (${res.status})${detail ? ': ' + detail : ''}`);
    }
    const data = await res.json();
    const keys = data && data.code === 1 && data.result ? Object.keys(data.result) : [];
    if(!keys.length){
      // GoPlus answers a non-token address with "Not fungible spl token
      // address" (7012) or "system error" (5000), which reached people as
      // "Scan failed: system error". Ask the chain what the address is
      // instead of passing the vendor's word on.
      let info = null;
      try { info = await solanaAccountKind(addr, fetchImpl); } catch(_){ /* fall through to the provider's own message */ }
      if(info && (info.kind === 'wallet' || info.kind === 'missing')){
        throw new Error('This address does not appear to be a recognized token on Solana. It is a wallet address.');
      }
      if(info && info.kind !== 'mint') throw new Error(solanaKindSentence(info));
      throw new Error(keys.length === 0 && data && data.code === 1
        ? 'This address does not appear to be a recognized token on Solana.'
        : (data && (data.message || data.error)) || 'No security data returned for this address.');
    }
    const record = data.result[keys[0]];
    const { checks, expected, criticalDefsTotal, liquiditySummary } = normalizeSolanaRecord(record);
    return { checks, expected, criticalDefsTotal, record, raw: data, liquiditySummary };
  },

  async _fetchWalletChecks(addr, fetchImpl){
    const SRC = 'Solana RPC (on-chain account)';
    const info = await solanaAccountKind(addr, fetchImpl);
    const checks = [];
    const notWallet = info.kind === 'program' || info.kind === 'mint' || info.kind === 'token-account' || info.kind === 'other';
    checks.push({ id: 'sol_account_type', category: 'destination', critical: true, severityWeight: 3, source: SRC,
      status: notWallet ? 'RISK' : 'PASS',
      label: notWallet ? 'Not an ordinary wallet address' : 'Ordinary wallet account',
      detail: notWallet ? solanaKindSentence(info) + ' Sending funds directly to it can lose them.'
                        : 'Owned by the System Program, the way a normal wallet is.' });
    const listed = OFAC_SOLANA_ADDRESSES.has(String(addr).trim());
    checks.push({ id: 'sanctioned', category: 'sanctions', critical: true, severityWeight: 3, source: 'US Treasury OFAC SDN list',
      status: listed ? 'RISK' : 'PASS',
      label: listed ? 'On a sanctions list' : 'Not on the OFAC sanctions list',
      detail: listed
        ? 'This exact address is on the US Treasury OFAC Specially Designated Nationals list. Sending to it can be illegal for US persons and is likely to get funds frozen.'
        : 'Not among the Solana addresses on the US Treasury OFAC sanctions list (as of ' + OFAC_SOLANA_AS_OF + '). Other countries\' lists are not checked.' });
    if(!notWallet){
      checks.push({ id: 'sol_account_exists', category: 'activity', critical: false, severityWeight: 1, source: SRC,
        status: info.kind === 'missing' ? 'RISK' : 'PASS',
        label: info.kind === 'missing' ? 'Never funded' : 'Account exists on chain',
        detail: info.kind === 'missing'
          ? 'This address has never held SOL. It may be brand new or mistyped — confirm it with the recipient through a channel you trust before sending.'
          : 'The account has been funded at least once.' });
    }
    // Token holdings are not read: PublicNode refuses getTokenAccountsByOwner
    // ("Request blocked", tested 3 Oct 2026), and a blank is better than a guess.
    const tokenAccounts = null;
    // Reputation: tried, and reported honestly when the provider has nothing.
    let repo = null;
    try {
      // Through our Worker, which adds a GoPlus API key when one is configured
      // (anonymous requests get code 5000 for Solana).
      const res = await fetchImpl(`${SOLANA_PROXY_URL}?wallet_address=${encodeURIComponent(addr)}`);
      const data = res.ok ? await res.json() : null;
      if(data && data.code === 1 && data.result && String(data.result.data_source || '').trim()) repo = data.result;
    } catch(_){ repo = null; }
    let expected = checks.length + 1;
    if(repo){
      const w = normalizeSolanaWalletRecord(repo);
      w.checks.forEach(c => checks.push(c));
      expected = checks.length;
    } else {
      checks.push({ id: 'sol_reputation', category: 'reputation', critical: false, severityWeight: 1, source: 'GoPlus Security',
        status: 'UNKNOWN', label: 'Scam and fraud reports',
        detail: 'Not checked: no scam-report provider currently answers for Solana wallets. This is a gap in coverage, not a clean result.' });
    }
    const sol = typeof info.lamports === 'number' ? info.lamports / 1e9 : null;
    const record = {
      account_type: info.kind, owner_program: info.owner || '', sol_balance: sol, token_accounts: tokenAccounts,
      reputation_source: repo ? repo.data_source : '',
      _readout: [
        { k: 'source', v: 'Solana RPC (publicnode)' + (repo ? ' + GoPlus' : '') },
        { k: 'account type', v: { wallet: 'wallet (System Program)', missing: 'not on chain yet', mint: 'token mint', 'token-account': 'token account', program: 'program', other: 'other program account' }[info.kind],
          tone: notWallet ? 'risk' : (info.kind === 'missing' ? 'risk' : 'ok') },
        { k: 'SOL balance', v: sol === null ? undefined : sol.toLocaleString(undefined, { maximumFractionDigits: 6 }) },
        { k: 'token accounts', v: tokenAccounts === null ? undefined : String(tokenAccounts) },
        { k: 'owner wallet', v: info.tokenOwner || undefined },
        { k: 'OFAC sanctions', v: listed ? 'LISTED' : 'not listed (' + OFAC_SOLANA_AS_OF + ')', tone: listed ? 'risk' : 'ok' },
        { k: 'scam reports', v: repo ? 'GoPlus: ' + repo.data_source : 'not covered for Solana', tone: repo ? undefined : 'risk' },
      ],
    };
    return { checks, expected, criticalDefsTotal: 2, record, raw: { info }, liquiditySummary: null };
  }
};

const Adapters = { evm: EvmAdapter, solana: SolanaAdapter };

// ---------------------------------------------------------------------
// Sui adapter
// ---------------------------------------------------------------------
// Sui's Token Security API uses a genuinely different value convention
// from EVM and Solana: "0" means unavailable, but BOTH "1" and "2" mean
// the function is available (the distinction between 1 and 2 isn't
// documented at the field level GoPlus exposes). Reusing flagState() here
// would silently misread "2" as neither on nor off — this needed its own
// classifier, not a shortcut.
function suiFlagState(v){
  if(v === '0' || v === 0 || v === false) return 'off';
  if(v === '1' || v === '2' || v === 1 || v === 2 || v === true) return 'on';
  if(v === undefined || v === null) return 'missing';
  return 'unrecognized';
}

function buildSuiCheck(def, rawValue, source){
  const state = suiFlagState(rawValue);
  if(state === 'missing') return null;
  if(state === 'unrecognized'){
    return { id: def.key, category: def.category || 'general', status: 'UNKNOWN', critical: !!def.critical,
      severityWeight: 1, label: def.label, detail: def.detail + ' (provider returned an unrecognized value type for this field)', source };
  }
  const on = state === 'on';
  return { id: def.key, category: def.category || 'general', status: on ? 'RISK' : 'PASS',
    critical: !!def.critical, severityWeight: def.sev === 'bad' ? 3 : 1, label: def.label, detail: def.detail, source };
}

// Each of these fields is an object shaped { value, cap_owner } per GoPlus's
// documented Sui schema — buildSuiCheck reads def.path into that object.
const SUI_CHECK_DEFS = [
  {key:'contract_upgradeable', path:['contract_upgradeable','value'], category:'control', label:'Contract is upgradeable', detail:'Developers can arbitrarily modify contract functions after deployment.', sev:'bad', critical:true},
  {key:'blacklist', path:['blacklist','value'], category:'control', label:'Blacklist function present', detail:'Owner can block specific addresses from trading.', sev:'warn', critical:false},
  {key:'mintable', path:['mintable','value'], category:'supply', label:'Supply can be minted', detail:'Total supply is not fixed; new tokens can be created.', sev:'warn', critical:false},
  {key:'metadata_modifiable', path:['metadata_modifiable','value'], category:'transparency', label:'Metadata can be changed', detail:'Name, symbol, or description can be altered after launch.', sev:'warn', critical:false},
];

function normalizeSuiRecord(record){
  const checks = [];
  const criticalDefsTotal = SUI_CHECK_DEFS.filter(d => d.critical).length;
  const trusted = suiFlagState(record.trusted_token) === 'on';

  SUI_CHECK_DEFS.forEach(def => {
    const raw = getPath(record, def.path);
    if(def.key === 'mintable' && trusted && suiFlagState(raw) === 'on'){
      checks.push({id:'mintable', category:'supply', status:'PASS', critical:false, severityWeight:0,
        label:'Mint function present, but token is GoPlus-verified trusted', detail:'This token is on GoPlus\'s trusted-token list; mint capability is a known, accepted design choice for it.', source:'GoPlus Security (Sui)'});
      return;
    }
    const c = buildSuiCheck(def, raw, 'GoPlus Security (Sui)');
    if(c) checks.push(c);
  });

  // GoPlus does not yet return holder or DEX data for Sui ("awaiting
  // ecosystem infra", per GoPlus's own announcement) — no liquidity
  // summary is possible here, unlike the Solana adapter. Not a gap in
  // this adapter; a real gap in the upstream data as of this writing.
  return { checks, expected: SUI_CHECK_DEFS.length, criticalDefsTotal, liquiditySummary: null };
}

// SETUP: same requirement as Solana — GoPlus's Sui Token Security API is
// a newly-added, chain-specific endpoint. Its CORS behavior has not been
// confirmed (no network path to test it from this environment), so this
// routes through the proxy from the start rather than assuming a direct
// call will work and discovering otherwise via a user bug report.
const SuiAdapter = {
  id: 'sui', name: 'Sui',
  capabilities: { tokenSecurity:true, walletScreening:false, txSimulation:false, liquidityAnalysis:false, contractAnalysis:false },
  chains: { 'sui': 'Sui Mainnet' },
  // Sui "addresses" for token security purposes are Move type identifiers:
  // 0x + 64 hex chars, then ::module::TypeName. This is intentionally
  // lenient on the module/type suffix (generic types like ::coin::COIN<...>
  // exist in Move and aren't fully characterized here) but strict on the
  // address prefix, which is the part actually confirmed against a real
  // GoPlus example URL.
  // Sui's canonical address is 32 bytes (64 hex chars), but well-known
  // system packages are commonly referenced in short form (e.g. 0x2 for
  // the sui framework, as in the native coin type 0x2::sui::SUI) — being
  // strict about exact padding here isn't confirmed as GoPlus's actual
  // requirement, so this stays permissive on length and strict on shape.
  validateAddress(addr){ return /^0x[a-fA-F0-9]{1,64}::.+$/.test(String(addr).trim()); },
  async fetchChecks(addr, assetType, chainId, fetchImpl){
    if(assetType !== 'token') throw new Error('Wallet screening is not supported for Sui in SaveSaveSaveSave — token scans only.');
    const res = await fetchGoPlus(
      `https://api.gopluslabs.io/api/v1/sui/token_security?contract_addresses=${encodeURIComponent(addr)}`,
      `${SOLANA_PROXY_URL}?sui_contract_addresses=${encodeURIComponent(addr)}`,
      fetchImpl);
    if(!res.ok){
      let detail = '';
      try { const errBody = await res.json(); detail = errBody.error || errBody.message || errBody.detail || ''; }
      catch(_){ /* response wasn't JSON, or already consumed */ }
      throw new Error(`Network response was not OK (${res.status})${detail ? ': ' + detail : ''}`);
    }
    const data = await res.json();
    if(data.code !== 1 || !data.result) throw new Error(data.message || data.error || 'No security data returned for this address.');
    const keys = Object.keys(data.result);
    if(keys.length === 0) throw new Error('This address does not appear to be a recognized token on Sui.');
    const record = data.result[keys[0]];
    const { checks, expected, criticalDefsTotal, liquiditySummary } = normalizeSuiRecord(record);
    return { checks, expected, criticalDefsTotal, record, raw: data, liquiditySummary };
  }
};

Adapters.sui = SuiAdapter;

// ---------------------------------------------------------------------
// TRON adapter
// ---------------------------------------------------------------------
// Unlike Solana and Sui, TRON does not appear to have its own dedicated
// Token Security endpoint or schema page in GoPlus's docs — it shows up
// as just another chain_id value ("tron", a string rather than numeric)
// on the same generic token_security/{chain_id} endpoint EVM chains use.
// Combined with TVM being documented as broadly Solidity-compatible,
// this is a well-justified inference that the response schema is the
// same flat "1"/"0" EVM shape — but it's an inference from endpoint
// structure, not a confirmed field-by-field schema the way Solana and
// Sui's dedicated docs pages provided. Worth re-checking against a real
// response if scans return unexpected results.
//
// Aptos was considered alongside TRON and deliberately NOT built: it
// appears in GoPlus's marketing chain lists, but no dedicated technical
// endpoint or schema reference could be found to verify against, the
// way one was found for Solana, Sui, and (with the caveat above) TRON.
// Guessing at an unverified schema is exactly the mistake this project
// has already made once with Solana wallet screening — not repeating it
// on a whole new adapter.
const TronAdapter = {
  id: 'tron', name: 'TRON',
  capabilities: { tokenSecurity:true, walletScreening:false, txSimulation:false, liquidityAnalysis:false, contractAnalysis:true },
  chains: { 'tron': 'TRON Mainnet' },
  // TRON addresses are Base58Check-encoded, always exactly 34 characters,
  // always starting with 'T'. See the note on detectEcosystem() below for
  // why this specific, stricter pattern is checked before Solana's
  // broader base58 pattern.
  validateAddress(addr){ return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(String(addr).trim()); },
  async fetchChecks(addr, assetType, chainId, fetchImpl){
    if(assetType !== 'token') throw new Error('Wallet screening is not supported for TRON in SaveSaveSaveSave — token scans only.');
    // Direct-first. The defensive proxy routing that used to sit here was
    // justified by CORS being unconfirmed for the string chain_id "tron".
    // It has since been confirmed to work (Origin is reflected), and the
    // proxy was itself the cause of this chain's rate-limit failures.
    const res = await fetchGoPlus(
      `https://api.gopluslabs.io/api/v1/token_security/tron?contract_addresses=${encodeURIComponent(addr)}`,
      `${SOLANA_PROXY_URL}?tron_contract_addresses=${encodeURIComponent(addr)}`,
      fetchImpl);
    if(!res.ok){
      let detail = '';
      try { const errBody = await res.json(); detail = errBody.error || errBody.message || errBody.detail || ''; }
      catch(_){ /* response wasn't JSON, or already consumed */ }
      throw new Error(`Network response was not OK (${res.status})${detail ? ': ' + detail : ''}`);
    }
    const data = await res.json();
    if(data.code !== 1 || !data.result) throw new Error(data.message || data.error || 'No security data returned for this address.');
    const keys = Object.keys(data.result);
    if(keys.length === 0) throw new Error('This address does not appear to be a recognized token contract on TRON.');
    const record = data.result[keys[0]];
    // Deliberately reusing the EVM normalizer, not writing a near-duplicate
    // one — the whole justification for this adapter's design is that the
    // schema is the same family. If that inference turns out to be wrong,
    // the fix belongs here, not in a parallel TRON-specific normalizer.
    const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(record, 'token');
    return { checks, expected, criticalDefsTotal, record, raw: data, liquiditySummary: null };
  }
};

Adapters.tron = TronAdapter;

// ---------------------------------------------------------------------
// Address-type auto-detection
// ---------------------------------------------------------------------
// Four validators, checked in a specific order. EVM, Sui, and Solana are
// mutually exclusive by construction (see below); TRON needed one real
// tie-break decision: a 34-character, T-prefixed Solana address is
// theoretically possible but requires an ed25519 key with ~7 leading
// zero bytes — roughly 1-in-4×10^17 for a real generated key (verified
// by calculation, not assumed). TRON is checked first specifically to
// resolve that near-zero-probability overlap deterministically rather
// than leaving it to chance ordering.
//
// EVM requires exactly 40 hex chars after 0x with nothing following; Sui
// requires 0x + hex, but ONLY matches if '::' follows, which no valid EVM
// address contains; Solana's base58 alphabet excludes '0' entirely, so no
// Solana address can ever start with '0x' in the first place. These three
// remain genuinely non-overlapping, not just practically unlikely to
// collide.
function detectEcosystem(addr){
  const trimmed = String(addr || '').trim();
  if(!trimmed) return null;
  if(EvmAdapter.validateAddress(trimmed)) return 'evm';
  if(SuiAdapter.validateAddress(trimmed)) return 'sui';
  if(TronAdapter.validateAddress(trimmed)) return 'tron';
  if(SolanaAdapter.validateAddress(trimmed)) return 'solana';
  return null;
}

// Guarded export: in a browser <script> tag, `module` doesn't exist, so this
// block is skipped and every const/function above simply lives in script
// scope, same as before. In Node (the regression suite), this makes the
// exact same source file directly require()-able with no duplication.

// =====================================================================
// PACKAGE CHECK (npm)
// Reads public information ABOUT a package: the npm registry record, its
// usage, and OSV.dev's list of malicious and vulnerable versions. It never
// downloads or runs the package's code, and every result says so. Same
// evidence model as the address scans: each check is PASS, RISK or
// UNKNOWN, and VerdictEngine decides.
// =====================================================================
const NPM_REGISTRY_URL = 'https://registry.npmjs.org';
const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
const NPM_DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week/';

// Names attackers copy: widely used packages, the crypto libraries this
// site's visitors are most likely to install, and packages that have been
// hijacked or imitated before.
const POPULAR_NPM = [
  'react','react-dom','vue','svelte','next','nuxt','@angular/core','express','koa','fastify',
  'lodash','underscore','axios','request','node-fetch','cross-fetch','isomorphic-fetch','got','superagent',
  'chalk','debug','commander','yargs','minimist','meow','inquirer','ora','boxen','figlet',
  'moment','dayjs','date-fns','uuid','async','bluebird','rxjs','immer','zustand','mobx',
  'typescript','ts-node','tslib','webpack','vite','rollup','esbuild','@babel/core','babel-core',
  'eslint','prettier','jest','mocha','chai','sinon','jquery','bootstrap','tailwindcss','postcss',
  'autoprefixer','sass','less','dotenv','cross-env','rimraf','mkdirp','glob','minimatch','semver',
  'fs-extra','graceful-fs','colors','color','colorette','picocolors','kleur','supports-color','strip-ansi','ansi-regex',
  'ws','socket.io','mongoose','mongodb','mysql','mysql2','pg','sequelize','typeorm','knex','prisma','@prisma/client',
  'sqlite3','better-sqlite3','redis','ioredis','body-parser','cors','helmet','morgan','cookie-parser',
  'jsonwebtoken','bcrypt','bcryptjs','passport','nodemon','pm2','electron','puppeteer','playwright','cheerio',
  'classnames','prop-types','redux','react-redux','@reduxjs/toolkit','react-router','react-router-dom',
  'styled-components','@emotion/react','zod','yup','joi','execa','shelljs','cross-spawn','which','node-gyp','nan',
  'qs','form-data','formidable','multer','sharp','canvas','core-js','regenerator-runtime','@types/node','@types/react',
  'nodemailer','winston','pino','handlebars','ejs','pug','marked','highlight.js','three','d3','chart.js',
  'graphql','@apollo/client','xml2js','js-yaml','yaml','ini',
  'ethers','web3','viem','wagmi','@solana/web3.js','@solana/spl-token','@coral-xyz/anchor','bitcoinjs-lib',
  'bip39','bip32','ethereumjs-util','ethereum-cryptography','@ethersproject/providers','hardhat','truffle',
  '@openzeppelin/contracts','@metamask/sdk','@walletconnect/web3-provider','@web3-react/core',
  '@coinbase/wallet-sdk','@rainbow-me/rainbowkit','tweetnacl','bs58','elliptic','secp256k1','keccak',
  'crypto-js','@noble/hashes','@noble/curves','bn.js','big.js','bignumber.js','decimal.js',
  'event-stream','left-pad','ua-parser-js','coa','rc','node-ipc','@faker-js/faker',
];

// "lodash", "@scope/name", "name@1.2.3", or a pasted "npm install name".
function parsePackageSpec(input){
  const unquote = x => x.replace(/^[`'"\u2018\u2019\u201C\u201D]+|[`'"\u2018\u2019\u201C\u201D]+$/g, '');   // pasted with quotes
  let s = unquote(String(input || '').trim()).trim();
  s = s.replace(/^(?:npm|pnpm)\s+(?:i|install|add)\s+|^yarn\s+add\s+|^npx\s+/i, '');
  s = unquote(s.split(/\s+/)[0] || '');
  s = s.replace(/^npm:/i, '');
  let name = s, version = null;
  const at = s.lastIndexOf('@');
  if(at > 0){ name = s.slice(0, at); version = s.slice(at + 1); }
  if(!name || name.length > 214) return null;
  if(!/^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i.test(name)) return null;
  if(version !== null && !/^[\w.+~^-]{1,64}$/.test(version)) return null;
  return { name, version: version || null };
}

function osaDistance(a, b, cap){
  if(Math.abs(a.length - b.length) > cap) return cap + 1;
  const d = [];
  for(let i = 0; i <= a.length; i++){ d[i] = [i]; }
  for(let j = 0; j <= b.length; j++){ d[0][j] = j; }
  for(let i = 1; i <= a.length; i++){
    for(let j = 1; j <= b.length; j++){
      const cost = a[i-1] === b[j-1] ? 0 : 1;
      d[i][j] = Math.min(d[i-1][j] + 1, d[i][j-1] + 1, d[i-1][j-1] + cost);
      if(i > 1 && j > 1 && a[i-1] === b[j-2] && a[i-2] === b[j-1]) d[i][j] = Math.min(d[i][j], d[i-2][j-2] + 1);
    }
  }
  return d[a.length][b.length];
}

// The popular package this name imitates, if any.
function packageLookalike(name){
  const n = String(name).toLowerCase();
  if(POPULAR_NPM.includes(n)) return null;
  // Separators and the scope's @ and / removed: catches reactrouter for
  // react-router and solana-web3.js for @solana/web3.js.
  const squash = s => s.replace(/[-_.@/]/g, '');
  const scoped = s => s.charAt(0) === '@';
  const same = POPULAR_NPM.filter(p => squash(p) === squash(n))
    .sort((a, b) => (scoped(a) === scoped(n) ? 0 : 1) - (scoped(b) === scoped(n) ? 0 : 1))[0];
  if(same) return { target: same, how: scoped(same) && !scoped(n)
    ? 'copies a scoped package without its scope' : 'differs only in dashes, dots or underscores' };
  if(n.length < 5) return null;
  for(const p of POPULAR_NPM){
    if(p.length >= 5 && osaDistance(n, p, 1) === 1) return { target: p, how: 'is one character away' };
  }
  return null;
}

const PKG_INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];

// What an install-script LINE does, read as text. Only the line in
// package.json is available here: when it runs a file (node install.js)
// that file is never downloaded, and the result says so.
function installScriptSignals(text){
  const s = String(text || '');
  const out = [];
  if(/\|\s*(?:ba|z|da)?sh\b|\biex\b|Invoke-Expression/i.test(s))
    out.push({ what: 'pipes downloaded code into a shell', critical: true });
  if(/~\/\.(?:ssh|aws|npmrc|gnupg|config\/solana)|\bid_rsa\b|\.ethereum\/keystore|wallet\.dat|Login Data|Local State|keychain/i.test(s))
    out.push({ what: 'reaches for keys or saved credentials', critical: true });
  if(/\b(?:curl|wget|Invoke-WebRequest|iwr|certutil\s+-urlcache|bitsadmin)\b/i.test(s))
    out.push({ what: 'downloads something', critical: false });
  else if(/https?:\/\//i.test(s))
    out.push({ what: 'contacts a web address', critical: false });
  if(/base64|Buffer\.from\([^)]*['"](?:base64|hex)|\batob\(|(?:\\x[0-9a-f]{2}){4}|\beval\s*\(|new\s+Function\s*\(|powershell[^;&|]*\s-(?:enc|encodedcommand|e)\b|\bpython\d?\s+-c\b/i.test(s))
    out.push({ what: 'runs hidden or encoded code', critical: false });
  if(/process\.env\b|\$\{?(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_[A-Z_]+|[A-Z_]*SECRET[A-Z_]*|[A-Z_]*API_KEY)\b/.test(s))
    out.push({ what: 'reads secrets from the environment', critical: false });
  return out.sort((a, b) => (b.critical ? 1 : 0) - (a.critical ? 1 : 0));
}

function repoKey(u){
  let s = String(u || '').toLowerCase().trim();
  // npm's shorthands: "github:owner/repo", "gitlab:…", "bitbucket:…", or bare "owner/repo".
  s = s.replace(/^github:/, 'github.com/').replace(/^gitlab:/, 'gitlab.com/').replace(/^bitbucket:/, 'bitbucket.org/');
  if(/^[\w.-]+\/[\w.-]+$/.test(s) && !/^[\w-]+\.[\w.-]+\//.test(s)) s = 'github.com/' + s;
  return s.replace(/^git\+/, '').replace(/^[a-z]+:\/\//, '').replace(/^git@/, '')
    .replace(/^([^/:]+):/, '$1/').replace(/^www\./, '').replace(/\.git$/, '').replace(/\/+$/, '');
}
// Weekly downloads above which a similar name is an established package in
// its own right, not a trap.
const PKG_LOOKALIKE_ESTABLISHED = 50000;

function pkgClip(s, n){
  s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

// Pure: turns the evidence into checks. `ev` comes from fetchPackageEvidence.
function buildPackageChecks(ev, now){
  const t = typeof now === 'number' ? now : Date.now();
  const src = { npm: 'npm registry', osv: 'OSV.dev (open vulnerability database)',
                usage: 'npm download counts', local: 'SaveSaveSaveSave (name comparison)' };
  const checks = [];
  const add = (id, status, label, detail, source, weight, critical) =>
    checks.push({ id, category: 'package', status, critical: !!critical,
                  severityWeight: status === 'RISK' ? (weight || 1) : 0, label, detail, source });
  const meta = ev.version || {};
  const version = ev.resolvedVersion;
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  // 1. npm itself took the package down and left a placeholder.
  const holding = /-security$/.test(String(version || '')) || /^security holding package$/i.test(String(ev.description || ''));
  if(holding) add('pkg_removed', 'RISK', 'Removed by npm for security reasons',
    'npm replaced this package with an empty "security holding" placeholder, which it does when a package was malicious. Whatever you were told to install under this name was not safe.',
    src.npm, 3, true);
  else add('pkg_removed', 'PASS', 'Not removed by npm', 'npm has not replaced this package with a security placeholder.', src.npm, 0, true);

  // 2 + 3. OSV: reported malicious, reported vulnerable.
  if(!ev.osv || !ev.osv.ok){
    const why = 'OSV.dev could not be reached' + (ev.osv && ev.osv.error ? ' (' + pkgClip(ev.osv.error, 60) + ')' : '') + ', so this was not checked.';
    add('pkg_reported_malicious', 'UNKNOWN', 'Reported as malicious', why, src.osv, 1, true);
    add('pkg_known_vulns', 'UNKNOWN', 'Known vulnerabilities in this version', why, src.osv, 1);
  } else {
    const vulns = ev.osv.vulns || [];
    // Malicious, not merely vulnerable: OSV's own MAL- records, and GitHub
    // advisories filed as embedded malicious code (CWE-506) or titled as
    // malware, which is how hijacks like crossenv and ua-parser-js appear.
    const isMal = v => /^MAL-/.test(v.id || '')
      || ((v.database_specific && v.database_specific.cwe_ids) || []).includes('CWE-506')
      || /\b(?:malicious|malware)\b/i.test(v.summary || '');
    const mal = vulns.filter(isMal);
    const other = vulns.filter(v => !isMal(v));
    if(mal.length) add('pkg_reported_malicious', 'RISK', 'Reported as malicious',
      'OSV.dev lists this package as malicious (' + mal.slice(0, 3).map(v => pkgClip(v.id, 30)).join(', ') + '). Do not install it. If it is already installed, treat that computer as compromised.',
      src.osv, 3, true);
    else add('pkg_reported_malicious', 'PASS', 'Not reported as malicious',
      'OSV.dev has no malicious-package report for this version. A brand-new attack may not be reported yet.', src.osv, 0, true);
    if(other.length){
      const sev = other.map(v => String((v.database_specific && v.database_specific.severity) || '').toUpperCase());
      const serious = sev.some(s => s === 'HIGH' || s === 'CRITICAL');
      add('pkg_known_vulns', 'RISK', 'Known vulnerabilities in this version',
        plural(other.length, 'published vulnerability', 'published vulnerabilities') + (serious ? ', at least one rated high or critical' : '')
        + ': ' + other.slice(0, 3).map(v => pkgClip(v.id, 30)).join(', ') + (other.length > 3 ? ' and more' : '') + '. A newer version may fix them.',
        src.osv, serious ? 3 : 1);
    } else add('pkg_known_vulns', 'PASS', 'No known vulnerabilities in this version',
      'OSV.dev lists no vulnerability affecting ' + (version || 'this version') + '.', src.osv);
  }

  // 4. Code that runs during npm install, and what its script line does.
  const scripts = meta.scripts || {};
  const hooks = PKG_INSTALL_HOOKS.filter(h => typeof scripts[h] === 'string' && scripts[h].trim());
  const signals = hooks.length ? installScriptSignals(hooks.map(h => scripts[h]).join(' ; ')) : [];
  if(signals.length){
    const critical = signals.some(x => x.critical);
    add('pkg_install_scripts', 'RISK', 'Install script ' + signals[0].what,
      'The "' + hooks[0] + '" script reads: ' + pkgClip(scripts[hooks[0]], 90) + '. It ' + signals.map(x => x.what).join(', ')
      + ', and it runs on your computer during npm install, before you use the package at all. Honest packages almost never need this.',
      src.npm, critical ? 3 : 4, critical);
  } else if(hooks.length) add('pkg_install_scripts', 'RISK', 'Runs code automatically when installed',
    'This version has a "' + hooks[0] + '" script: ' + pkgClip(scripts[hooks[0]], 90) + '. It runs on your computer during npm install, before you use the package at all. Many honest packages do this to build native parts; it is also how most malicious packages strike. Only this line was read, not any file it runs.',
    src.npm, 2);
  else if(meta.gypfile) add('pkg_install_scripts', 'RISK', 'Runs code automatically when installed',
    'This version builds native code during npm install (binding.gyp). That runs on your computer before you use the package.', src.npm, 2);
  else add('pkg_install_scripts', 'PASS', 'No install scripts', 'Nothing in this version runs automatically during npm install.', src.npm);

  // 5. A name copied from a popular package.
  const like = packageLookalike(ev.name);
  const weekly = typeof ev.weekly === 'number' ? ev.weekly : null;
  if(like && !(weekly !== null && weekly >= PKG_LOOKALIKE_ESTABLISHED)) add('pkg_lookalike', 'RISK', 'Name looks like a popular package',
    'The name ' + like.how + ' from "' + like.target + '". Typo-squatters copy popular names to catch a mistyped install. If you meant ' + like.target + ', install that instead.',
    src.local, 3);
  else add('pkg_lookalike', 'PASS', 'Name does not imitate a popular package',
    like ? 'Similar to "' + like.target + '", but widely used in its own right.' : 'Not a near-copy of any name on our list of popular and often-imitated packages.', src.local);

  // 6. How old the package is.
  const created = ev.time && ev.time.created ? Date.parse(ev.time.created) : NaN;
  if(isNaN(created)) add('pkg_age', 'UNKNOWN', 'Package age', 'The registry did not say when this package was first published.', src.npm);
  else {
    const days = Math.max(0, Math.floor((t - created) / 86400000));
    if(days < 30) add('pkg_age', 'RISK', 'Brand-new package', 'First published ' + plural(days, 'day', 'days') + ' ago. Most malicious packages are young.', src.npm, 1);
    else add('pkg_age', 'PASS', 'Established package', 'First published ' + new Date(created).toISOString().slice(0, 10) + '.', src.npm);
  }

  // 7. How fresh this particular version is.
  const vtime = ev.time && version && ev.time[version] ? Date.parse(ev.time[version]) : NaN;
  if(isNaN(vtime)) add('pkg_fresh_version', 'UNKNOWN', 'Version age', 'The registry did not say when this version was published.', src.npm);
  else {
    const hours = Math.max(0, Math.floor((t - vtime) / 3600000));
    if(hours < 72) add('pkg_fresh_version', 'RISK', 'This version is very new',
      'Version ' + version + ' was published ' + (hours < 1 ? 'less than an hour' : plural(hours, 'hour', 'hours')) + ' ago. Hijacked versions of real packages are usually caught within days; waiting a few days before installing a brand-new version avoids most of them.',
      src.npm, 1);
    else add('pkg_fresh_version', 'PASS', 'Version is not brand-new', 'Version ' + version + ' was published ' + new Date(vtime).toISOString().slice(0, 10) + '.', src.npm);
  }

  // 8. Usage.
  if(weekly === null) add('pkg_usage', 'UNKNOWN', 'How widely it is used', 'Weekly downloads could not be read, so this was not checked.', src.usage);
  else if(weekly < 100) add('pkg_usage', 'RISK', 'Almost nobody uses it',
    plural(weekly, 'download', 'downloads') + ' last week. Widely used packages are not automatically safe, but far more people would notice a problem.', src.usage, 1);
  else add('pkg_usage', 'PASS', 'In real use', weekly.toLocaleString('en-US') + ' downloads last week.', src.usage);

  // 9. Source link.
  const repo = meta.repository ? (typeof meta.repository === 'string' ? meta.repository : meta.repository.url) : null;
  if(repo) add('pkg_source_link', 'PASS', 'Links to its source code',
    'The package points to ' + pkgClip(repo, 80) + '. That link is the author’s claim: nothing here checks that the published code matches it.', src.npm);
  else add('pkg_source_link', 'RISK', 'No link to its source code',
    'The package does not say where its source code lives, so nobody can easily read it before installing.', src.npm, 1);

  // 10. Deprecated.
  if(meta.deprecated) add('pkg_deprecated', 'RISK', 'Marked deprecated',
    'The maintainer marked this version deprecated: "' + pkgClip(meta.deprecated, 120) + '"', src.npm, 1);
  else add('pkg_deprecated', 'PASS', 'Not deprecated', 'The maintainer has not marked this version deprecated.', src.npm);

  // 11-15. Signs of a hijacked release, judged against this package's own
  // earlier versions. A first version has nothing to compare with, so these
  // are skipped and the result says why.
  const notes = [];
  const h = ev.history || null;
  if(holding){
    // npm's own placeholder is published by npm, not by a hijacker; the
    // comparisons below would only describe the takedown itself.
    notes.push('npm replaced this package with a security placeholder, so its release history was not compared for signs of a hijack.');
  } else if(!h || !h.count){
    notes.push('This is the first published version, so there was nothing earlier to compare it with for signs of a hijacked release.');
  } else {
    const who = meta.publisher;
    if(who && (h.earlierPublishers || []).length){
      // Weight 1: large projects change publishing accounts often, so on its
      // own this is a note; next to other signs it adds up.
      if(h.count >= 3 && !h.earlierPublishers.includes(who) && meta.provenance) add('pkg_publisher', 'PASS', 'New publishing account, with a build record',
        'Version ' + version + ' was published by "' + pkgClip(who, 40) + '", an account new to this package, but it carries a provenance record tying it to its source repository\u2019s build. Someone publishing from a stolen account could not easily produce that.', src.npm);
      else if(h.count >= 3 && !h.earlierPublishers.includes(who)) add('pkg_publisher', 'RISK', 'Published by a new account',
        'Version ' + version + ' was published by the npm account "' + pkgClip(who, 40) + '", which published none of the earlier versions. That happens when a project changes hands or moves its publishing, and it is also what a hijacked package looks like.', src.npm, 1);
      else if(h.earlierPublishers.includes(who)) add('pkg_publisher', 'PASS', 'Published by a familiar account',
        'Version ' + version + ' was published by "' + pkgClip(who, 40) + '", who also published earlier versions.', src.npm);
      else add('pkg_publisher', 'PASS', 'Too few earlier versions to judge the publisher',
        'Version ' + version + ' was published by "' + pkgClip(who, 40) + '", an account new to this package, but with only ' + h.count + ' earlier version' + (h.count === 1 ? '' : 's') + ' that is not unusual yet.', src.npm);
    }
    if(h.earlierProvenance && !meta.provenance) add('pkg_provenance', 'RISK', 'No build record, unlike earlier versions',
      'Recent earlier versions were published with a provenance record linking them to their source code and build. This one was not, which suggests it was published by hand from someone\u2019s account. Hijacked versions usually are.', src.npm, 3);
    else if(meta.provenance) add('pkg_provenance', 'PASS', 'Has a build record (provenance)',
      'npm holds a provenance record linking this version to its source repository and build. This check confirms the record exists; it does not verify its signature.', src.npm);
    else add('pkg_provenance', 'PASS', 'No build record, same as before',
      'Neither this version nor recent earlier ones carry a provenance record. Most packages do not; it is a warning sign only when it disappears.', src.npm);
    const prev = h.previous;
    const pt = prev && prev.time ? Date.parse(prev.time) : NaN;
    if(!isNaN(pt) && !isNaN(vtime)){
      const gap = Math.floor((vtime - pt) / 86400000), age = Math.floor((t - vtime) / 86400000);
      if(gap > 365 && age < 30 && meta.provenance) add('pkg_dormant', 'PASS', 'Back after a long silence, with a build record',
        'Version ' + version + ' came out after ' + plural(Math.floor(gap / 30), 'month', 'months') + ' with no release, but it carries a provenance record tying it to its source repository\u2019s build, which a hijacker publishing by hand would not have.', src.npm);
      else if(gap > 365 && age < 30) add('pkg_dormant', 'RISK', 'Sudden release after a long silence',
        'Version ' + version + ' came out ' + plural(age, 'day', 'days') + ' ago, after ' + plural(Math.floor(gap / 30), 'month', 'months') + ' with no release. Hijackers favour quiet packages whose owners are no longer watching.', src.npm, 2);
      else add('pkg_dormant', 'PASS', 'No sudden return from silence', 'The release before this one was ' + plural(gap, 'day', 'days') + ' earlier.', src.npm);
    }
    if(prev && prev.repository){
      const was = typeof prev.repository === 'string' ? prev.repository : prev.repository.url;
      const own = meta.ownRepository ? (typeof meta.ownRepository === 'string' ? meta.ownRepository : meta.ownRepository.url) : null;
      if(!own) add('pkg_repo_changed', 'RISK', 'Source link removed in this version',
        'The previous version pointed to ' + pkgClip(was, 70) + '. This one gives no source link at all.', src.npm, 2);
      else if(repoKey(own) !== repoKey(was)) add('pkg_repo_changed', 'RISK', 'Source link changed in this version',
        'The previous version pointed to ' + pkgClip(was, 60) + '; this one points to ' + pkgClip(own, 60) + '. Check that the new place really belongs to the same project.', src.npm, 2);
      else add('pkg_repo_changed', 'PASS', 'Same source link as the previous version', 'Both versions point to the same source repository.', src.npm);
    }
    if(meta.unpackedSize && prev && prev.unpackedSize){
      const mb = n => (n / 1048576).toFixed(n < 1048576 ? 2 : 1) + ' MB';
      if(meta.unpackedSize > prev.unpackedSize * 5 && meta.unpackedSize - prev.unpackedSize > 1048576) add('pkg_size_jump', 'RISK', 'Much bigger than the previous version',
        'This version unpacks to ' + mb(meta.unpackedSize) + ', against ' + mb(prev.unpackedSize) + ' for the previous one. A sudden jump can mean something extra was bundled in.', src.npm, 1);
      else add('pkg_size_jump', 'PASS', 'Size in line with the previous version', mb(meta.unpackedSize) + ' unpacked, against ' + mb(prev.unpackedSize) + ' before.', src.npm);
    }
  }

  return { checks, expected: checks.length, criticalTotal: checks.filter(c => c.critical).length, notes };
}

// Network: the registry record, weekly downloads and OSV. `fetchImpl` is
// injectable so the tests never touch the network.
async function fetchPackageEvidence(spec, fetchImpl, opts){
  const f = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  const o = opts || {};
  const get = async (url, init) => {
    const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctl ? setTimeout(() => ctl.abort(), o.timeoutMs || 15000) : null;
    try { return await f(url, Object.assign({}, init || {}, ctl ? { signal: ctl.signal } : {})); }
    finally { if(timer) clearTimeout(timer); }
  };
  const reg = await get(NPM_REGISTRY_URL + '/' + spec.name.replace('/', '%2F'), { headers: { Accept: 'application/json' } });
  if(reg.status === 404) return { notFound: true, name: spec.name };
  if(!reg.ok) throw new Error('The npm registry answered HTTP ' + reg.status + '.');
  const doc = await reg.json();
  const tags = doc['dist-tags'] || {};
  const resolvedVersion = spec.version ? (tags[spec.version] || spec.version) : tags.latest;
  const v = doc.versions && resolvedVersion ? doc.versions[resolvedVersion] : null;
  if(!v) return { versionMissing: true, name: spec.name, requested: spec.version || 'latest' };

  // Earlier versions, in publishing order, for the hijack comparisons.
  const times = doc.time || {};
  const ordered = Object.keys(doc.versions || {}).filter(k => times[k] && !isNaN(Date.parse(times[k])))
    .sort((a, b) => Date.parse(times[a]) - Date.parse(times[b]));
  const at = ordered.indexOf(resolvedVersion);
  const all = at > 0 ? ordered.slice(0, at) : [];
  // Compare a stable release with earlier stable releases: nightlies and
  // release candidates are often built by other accounts and pipelines.
  const pre = k => /-/.test(k);
  const stable = pre(resolvedVersion) ? all : all.filter(k => !pre(k));
  const earlier = (stable.length ? stable : all).map(k => doc.versions[k]);
  const hasProv = x => !!(x && x.dist && x.dist.attestations && x.dist.attestations.provenance);
  const who = x => x && x._npmUser && x._npmUser.name ? String(x._npmUser.name) : null;
  const last = earlier.length ? earlier[earlier.length - 1] : null;
  const history = {
    count: earlier.length,
    earlierPublishers: [...new Set(all.map(k => who(doc.versions[k])).filter(Boolean))],
    earlierProvenance: earlier.slice(-5).some(hasProv),
    previous: last ? { time: times[last.version] || null, repository: last.repository || null,
                       unpackedSize: (last.dist && last.dist.unpackedSize) || null } : null,
  };

  // Weekly downloads: npm's download counts, or its search index if that
  // is unavailable. Neither answering is reported as unknown, not as zero.
  const fromSearch = () => get(NPM_REGISTRY_URL + '/-/v1/search?text=' + encodeURIComponent(spec.name) + '&size=20')
    .then(r => r.ok ? r.json() : null)
    .then(j => {
      const hit = j && (j.objects || []).find(x => x && x.package && x.package.name === spec.name);
      return hit && hit.downloads && typeof hit.downloads.weekly === 'number' ? hit.downloads.weekly : null;
    })
    .catch(() => null);
  const usage = get(NPM_DOWNLOADS_URL + spec.name)
    .then(r => r.ok ? r.json() : null)
    .then(j => j && typeof j.downloads === 'number' ? j.downloads : null)
    .catch(() => null)
    .then(w => w !== null ? w : fromSearch());
  const osv = get(OSV_QUERY_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: spec.name, ecosystem: 'npm' }, version: resolvedVersion }) })
    .then(async r => r.ok ? { ok: true, vulns: ((await r.json()) || {}).vulns || [] } : { ok: false, error: 'HTTP ' + r.status })
    .catch(e => ({ ok: false, error: (e && e.name === 'AbortError') ? 'timed out' : 'no response' }));
  const [weekly, osvResult] = await Promise.all([usage, osv]);
  return {
    name: spec.name, resolvedVersion, description: doc.description || '', time: doc.time || {},
    version: { scripts: v.scripts || {}, gypfile: !!v.gypfile,
               repository: v.repository || doc.repository || null, ownRepository: v.repository || null,
               deprecated: v.deprecated || null, publisher: who(v), provenance: hasProv(v),
               unpackedSize: (v.dist && v.dist.unpackedSize) || null },
    history, weekly, osv: osvResult,
  };
}

if(typeof module !== 'undefined' && module.exports){
  module.exports = {
    escapeHtml, stripSpoofChars, getPath, flagState, buildCheck, VerdictEngine, fetchGoPlus,
    EVM_TOKEN_CHECK_DEFS, EVM_WALLET_CHECK_DEFS, EVM_CHAINS, normalizeEvmRecord, EvmAdapter,
    COUNTERPARTY_CHECK_SUPPORTED_CHAINS, fetchCounterpartyChecks,
    SOLANA_CHECK_DEFS, normalizeSolanaRecord, normalizeSolanaWalletRecord, SolanaAdapter,
    SOLANA_RPC_URL, solanaAccountKind, OFAC_SOLANA_ADDRESSES, OFAC_SOLANA_AS_OF,
    SUI_CHECK_DEFS, suiFlagState, normalizeSuiRecord, SuiAdapter, TronAdapter, Adapters, detectEcosystem,
    POPULAR_NPM, parsePackageSpec, packageLookalike, buildPackageChecks, fetchPackageEvidence, installScriptSignals, repoKey,
    NPM_REGISTRY_URL, NPM_DOWNLOADS_URL, OSV_QUERY_URL, SOLANA_PROXY_URL
  };
}
