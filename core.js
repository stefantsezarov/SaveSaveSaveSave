/* =====================================================================
   SAVESAVESAVESAVE CORE (formerly RiskPass)
   Layers 0-6 from the architecture: input validation, data acquisition,
   evidence normalization, chain adapters, verdict engine, confidence.
   This block has NO DOM dependency except an optional escapeHtml path,
   so it can be eval()'d in Node for regression testing, unmodified,
   exactly as it ships in the browser.
   ===================================================================== */

// ---------- Sanitization ----------
function escapeHtml(str){
  if(typeof document !== 'undefined'){
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function stripSpoofChars(str){
  return String(str).replace(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g, '');
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

    let score = 0;
    risks.forEach(c => { score += c.severityWeight; });
    score += unknowns.length; // each unreadable field nudges toward caution, doesn't force it alone

    const coverage = expectedChecks ? valid / expectedChecks : 0;
    const insufficientData = valid === 0 || coverage < 0.4;

    let verdict, label, sub;
    if(criticalHit){
      verdict = 'fail'; label = 'FAIL';
      sub = 'A confirmed high-severity indicator was detected';
    } else if(insufficientData){
      verdict = 'unknown'; label = 'INSUFFICIENT DATA';
      sub = `Only ${valid}/${expectedChecks} indicators returned usable data — too little to form a judgment. This is not a clean result.`;
    } else if(score >= 6){
      verdict = 'fail'; label = 'FAIL';
      sub = 'Significant risk indicators detected';
    } else if(score >= 2 || unknowns.length > 0){
      verdict = 'caution'; label = 'CAUTION';
      sub = (unknowns.length > 0 && score < 2)
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

const SolanaAdapter = {
  id: 'solana', name: 'Solana',
  // WALLET SCREENING IS OFF FOR SOLANA, and this time the reason is
  // measured rather than reasoned about.
  //
  // It was switched ON once before on the strength of GoPlus's public
  // announcement that chain_id: 'solana' is accepted by the Malicious
  // Address API. The announcement is real. The endpoint does not honour
  // it. Queried directly, 21 September 2026:
  //
  //   address_security/42RLPACwZPx3…?chain_id=solana
  //     -> {"code":5000,"message":"system error","result":null}
  //   address_security/EPjFWdd5…?chain_id=solana   (USDC's mint)
  //     -> {"code":5000,"message":"system error","result":null}
  //   address_security/0x098B716B…?chain_id=1      (a listed address)
  //     -> {"code":1, … "sanctioned":"1","data_source":"SlowMist,BlockSec"}
  //
  // So the route is healthy and the chain_id is what it refuses. Two
  // addresses, one of them the best-known mint on Solana, rule out "that
  // address simply has no record".
  //
  // This reached a user as "Scan failed: system error … the address has
  // no data yet", on an address he had brought from a sanctions list.
  // A security tool that answers a listed address with a shrug is worse
  // than one that says it does not cover the chain, because the shrug
  // reads as absence of evidence.
  //
  // DO NOT "FIX" THIS BY DROPPING chain_id. That was tested too:
  // address_security/<solana addr> with no chain_id returns code 1 with
  // every flag "0" and data_source "" — an empty record that this engine
  // would faithfully render as a clean PASS. The failure would stop being
  // visible and start being wrong, which is the only change that could
  // make this worse.
  //
  // Re-enable when a query like the ones above returns code 1 with a
  // populated data_source. Not before, and not on an announcement.
  capabilities: { tokenSecurity:true, walletScreening:false, txSimulation:false, liquidityAnalysis:true, contractAnalysis:false },
  // "not yet available" is the right phrase for something not built yet.
  // This one IS built; the provider will not answer. Different sentence.
  capabilityNotes: { walletScreening: 'not available on Solana — no provider data' },
  chains: { 'solana': 'Solana Mainnet' },
  validateAddress(addr){ return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(addr).trim()); },

  async fetchChecks(addr, assetType, chainId, fetchImpl){
    // The same guard the EVM adapter has. The UI disables the wallet tab
    // when walletScreening is false, but the UI is not the only caller and
    // a capability flag that only the interface respects is decoration.
    if(assetType === 'wallet' && !this.capabilities.walletScreening){
      throw new Error('Wallet screening is not available on Solana. The security provider\'s address library does not answer for this chain, so this scanner has no wallet reputation data here — this is a gap in coverage, not a clean result.');
    }
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
    if(data.code !== 1 || !data.result) throw new Error(data.message || data.error || 'No security data returned for this address.');
    const keys = Object.keys(data.result);
    if(keys.length === 0) throw new Error('This address does not appear to be a recognized token on Solana.');
    const record = data.result[keys[0]];
    const { checks, expected, criticalDefsTotal, liquiditySummary } = normalizeSolanaRecord(record);
    return { checks, expected, criticalDefsTotal, record, raw: data, liquiditySummary };
  },

  async _fetchWalletChecks(addr, fetchImpl){
    const directUrl = `https://api.gopluslabs.io/api/v1/address_security/${addr}?chain_id=solana`;
    let res;
    try{
      res = await fetchImpl(directUrl);
    } catch(directErr){
      if(SOLANA_PROXY_URL.includes('REPLACE-WITH-YOUR-WORKER-URL')){
        throw new Error('Solana wallet screening needs the CORS proxy deployed and updated first — see setup instructions.');
      }
      const proxyUrl = `${SOLANA_PROXY_URL}?wallet_address=${addr}`;
      res = await fetchImpl(proxyUrl);
    }
    if(!res.ok){
      let detail = '';
      try { const errBody = await res.json(); detail = errBody.error || errBody.message || errBody.detail || ''; }
      catch(_){ /* response wasn't JSON, or already consumed */ }
      throw new Error(`Network response was not OK (${res.status})${detail ? ': ' + detail : ''}`);
    }
    const data = await res.json();
    // code 5000 / "system error" is what this endpoint returns for every
    // Solana address (see the capability note above). Name it, rather than
    // passing the vendor's word up to a banner that will guess at a cause.
    if(data.code === 5000){
      throw new Error('the security provider\'s address library does not currently answer for Solana (it returned "system error" for this chain). This is a gap in coverage — it is not a statement that the address is clean');
    }
    if(data.code !== 1 || !data.result) throw new Error(data.message || data.error || 'No security data returned for this address.');
    // An all-zero record with no data_source is an EMPTY record, not a
    // clean one. Rendering it as a row of PASSes would manufacture
    // reassurance out of a provider having nothing to say.
    if(!String(data.result.data_source || '').trim()){
      throw new Error('the security provider returned no address record at all (no data source), so there is nothing to screen against. Absence of a record is not absence of risk');
    }
    const { checks, expected, criticalDefsTotal } = normalizeSolanaWalletRecord(data.result);
    return { checks, expected, criticalDefsTotal, record: data.result, raw: data, liquiditySummary: null };
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
if(typeof module !== 'undefined' && module.exports){
  module.exports = {
    escapeHtml, stripSpoofChars, getPath, flagState, buildCheck, VerdictEngine, fetchGoPlus,
    EVM_TOKEN_CHECK_DEFS, EVM_WALLET_CHECK_DEFS, EVM_CHAINS, normalizeEvmRecord, EvmAdapter,
    COUNTERPARTY_CHECK_SUPPORTED_CHAINS, fetchCounterpartyChecks,
    SOLANA_CHECK_DEFS, normalizeSolanaRecord, normalizeSolanaWalletRecord, SolanaAdapter,
    SUI_CHECK_DEFS, suiFlagState, normalizeSuiRecord, SuiAdapter, TronAdapter, Adapters, detectEcosystem
  };
}
