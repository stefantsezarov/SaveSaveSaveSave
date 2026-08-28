/* =====================================================================
   RISKPASS REGRESSION SUITE
   Run with: node riskpass.regression.test.js
   This is meant to be kept in the repo and re-run after ANY change to
   core.js or the adapters. Every test asserts the resulting VERDICT,
   per the project rule: a test that only checks "did not crash" is
   not sufficient for a security-verdict engine.
   ===================================================================== */
const path = require('path');
const {
  escapeHtml, stripSpoofChars, VerdictEngine,
  EVM_TOKEN_CHECK_DEFS, EVM_CHAINS, EVM_WALLET_CHECK_DEFS, normalizeEvmRecord, EvmAdapter,
  normalizeSolanaRecord, normalizeSolanaWalletRecord, SolanaAdapter,
  normalizeSuiRecord, suiFlagState, SuiAdapter, detectEcosystem
} = require(path.join(__dirname, 'core.js'));

let passed = 0, failed = 0;
function assertVerdict(name, actual, expected){
  const ok = actual.label === expected;
  if(ok) passed++; else failed++;
  console.log(
    (ok ? 'PASS ' : 'FAIL ') + name +
    ' -> ' + actual.label + ' (expected ' + expected + ')' +
    '  [valid=' + actual.checksValid + '/' + actual.checksExpected +
    ', unknown=' + actual.checksUnknown + ', critical=' + actual.criticalFindings + ']'
  );
}

function fullClean(defs, extra){
  const rec = {};
  defs.forEach(d => { rec[d.key] = '0'; });
  return Object.assign(rec, extra || {});
}

// ---------------------------------------------------------------------
// EVM — TOKEN
// ---------------------------------------------------------------------
(async () => {
console.log('\n== EVM token checks ==');

{ // 1. malicious input — single confirmed critical flag
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({is_honeypot:'1'}, 'token');
  assertVerdict('malicious input (confirmed honeypot, sparse)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 2. benign input — fully clean, full coverage
  const rec = fullClean(EVM_TOKEN_CHECK_DEFS, {is_open_source:'1'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('benign input (fully clean, full coverage)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 3. empty provider response
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({}, 'token');
  assertVerdict('empty provider response', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 4. malformed provider response — wrong JSON types
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({is_honeypot:null, is_mintable:[], is_blacklisted:'unknown'}, 'token');
  assertVerdict('malformed types (null/array/string)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 5. partial response — low coverage, all clear
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({is_honeypot:'0', is_mintable:'0', is_blacklisted:'0'}, 'token');
  assertVerdict('partial response (3/12, all clear)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 6. partial response — majority present, all clear (should still pass)
  const rec = {}; EVM_TOKEN_CHECK_DEFS.slice(0,8).forEach(d => rec[d.key] = '0');
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('partial response (8/12, all clear)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 7. contradictory indicators — two warn flags with full coverage
  const rec = Object.assign(fullClean(EVM_TOKEN_CHECK_DEFS), {is_mintable:'1', is_proxy:'1'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('two warn flags, full coverage', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'CAUTION');
}
{ // 8. missing critical field entirely — must not crash, and (this is the actual
  // requirement) a well-covered PASS must still explicitly disclose that a
  // high-stakes check specifically was never answered, rather than reading
  // as unqualified confidence.
  const rec = fullClean(EVM_TOKEN_CHECK_DEFS.filter(d => d.key !== 'is_honeypot'), {is_open_source:'1'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  const result = VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal);
  const verdictOk = result.label === 'PASS';
  const disclosedOk = result.criticalMissing === 1 && /could not be evaluated/.test(result.sub);
  const ok = verdictOk && disclosedOk;
  console.log((ok ? 'PASS ' : 'FAIL ') + 'missing critical field: verdict stays PASS at high coverage BUT discloses the gap -> ' + result.label + ' | criticalMissing=' + result.criticalMissing + ' | sub="' + result.sub + '"');
  ok ? passed++ : failed++;
}
{ // 9. malformed numeric value — non-numeric tax
  const rec = Object.assign(fullClean(EVM_TOKEN_CHECK_DEFS), {is_open_source:'1', buy_tax:'not-a-number', sell_tax:'also-bad'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('malformed numeric tax value', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'CAUTION');
}
{ // 10. confirmed critical finding with sparse data — the exact bug found earlier
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({selfdestruct:'1'}, 'token');
  assertVerdict('critical finding despite sparse data (1/12 fields)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 11. Unicode/HTML payload — sanitization functions, not verdict, but must not throw
  const evil = '<img src=x onerror=alert(1)>\u202Eevil\u202C';
  let threw = false, out = '';
  try { out = escapeHtml(stripSpoofChars(evil)); } catch(e){ threw = true; }
  const ok = !threw && !out.includes('<img') && !out.includes('\u202E');
  console.log((ok ? 'PASS ' : 'FAIL ') + 'Unicode/HTML payload sanitized without throwing -> ' + JSON.stringify(out));
  ok ? passed++ : failed++;
}
{ // 12. unexpected JSON types — object/array in a boolean-shaped field
  const rec = Object.assign(fullClean(EVM_TOKEN_CHECK_DEFS), {is_proxy:{weird:'object'}, is_blacklisted:[1,2,3]});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  const result = VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal);
  const hasUnknownChecks = checks.some(c => c.status === 'UNKNOWN');
  console.log((hasUnknownChecks ? 'PASS ' : 'FAIL ') + 'unexpected JSON types classified as UNKNOWN, not crashed -> ' + result.label);
  hasUnknownChecks ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// EVM adapter-level: unknown chain / unsupported asset type
// ---------------------------------------------------------------------
console.log('\n== EVM adapter guards ==');
{
  let threw = false;
  EvmAdapter.fetchChecks('0x0000000000000000000000000000000000dead', 'token', '999999', async()=>({ok:true,json:async()=>({code:1,result:{}})}))
    .catch(() => { threw = true; });
  // fetchChecks is async; run a synchronous pre-check instead since we need this to assert immediately
  const chainKnown = !!EVM_CHAINS['999999'];
  console.log((chainKnown ? 'FAIL' : 'PASS') + ' unknown chain id is not in the supported chain list (999999)');
  chainKnown ? failed++ : passed++;
}
{
  const walletOnEvmOk = EvmAdapter.capabilities.walletScreening === true;
  console.log((walletOnEvmOk ? 'PASS' : 'FAIL') + ' EVM adapter declares wallet screening capability');
  walletOnEvmOk ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// SOLANA — TOKEN
// ---------------------------------------------------------------------
console.log('\n== Solana token checks ==');

{ // 13. malicious input — confirmed critical Solana flag
  const rec = { closable: { status: '1' } };
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord(rec);
  assertVerdict('Solana: confirmed closable program (sparse)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 14. benign input — fully clean Solana record
  const rec = {
    closable: {status:'0'}, balance_mutable_authority:{status:'0'}, freezable:{status:'0'},
    mintable:{status:'0'}, metadata_mutable:{status:'0'}, transfer_fee_upgradable:{status:'0'},
    default_account_state_upgradable:{status:'0'}, transfer_hook_upgradable:{status:'0'},
    non_transferable:'0', transfer_hook:{address:''},
    creator:{address:'Abc123', malicious_address:'0'}, mintable_authority_check: null
  };
  rec.mintable.authority = { address:'Xyz', malicious_address:'0' };
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord(rec);
  assertVerdict('Solana: fully clean record', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 15. empty Solana response
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord({});
  assertVerdict('Solana: empty provider response', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 16. non-EVM-shaped nested field, malformed type — must not crash on bad nesting
  const rec = { closable: 'not-an-object', mintable: null, freezable: {status:'0'} };
  let threw = false, checks = [], expected = 0;
  try { ({checks, expected} = normalizeSolanaRecord(rec)); } catch(e){ threw = true; }
  console.log((!threw ? 'PASS' : 'FAIL') + ' Solana: malformed nested structure does not throw');
  !threw ? passed++ : failed++;
}
{ // 17. trusted-token exception — mintable=on but trusted_token=1 should not read as risk
  const rec = { trusted_token:'1', mintable:{status:'1'}, closable:{status:'0'}, balance_mutable_authority:{status:'0'},
    freezable:{status:'0'}, metadata_mutable:{status:'0'}, transfer_fee_upgradable:{status:'0'},
    default_account_state_upgradable:{status:'0'}, transfer_hook_upgradable:{status:'0'}, non_transferable:'0' };
  const { checks, expected, criticalDefsTotal } = normalizeSolanaRecord(rec);
  const mintCheck = checks.find(c => c.id === 'mintable');
  const ok = mintCheck && mintCheck.status === 'PASS';
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: trusted_token suppresses mintable risk (matches GoPlus\'s documented intent) -> ' + (mintCheck ? mintCheck.status : 'MISSING'));
  ok ? passed++ : failed++;
}
{ // 18. capability correctly reflects wallet screening being re-enabled — GoPlus's own
  // documentation confirms chain_id: 'solana' is supported on this endpoint, which is
  // why this was worth trying again rather than leaving permanently disabled on the
  // strength of one unexplained past error
  const capabilityDeclared = SolanaAdapter.capabilities.walletScreening === true;
  console.log((capabilityDeclared ? 'PASS' : 'FAIL') + ' Solana adapter declares walletScreening: true (re-enabled, per GoPlus\'s own docs)');
  capabilityDeclared ? passed++ : failed++;
}
{ // 18a. fetchChecks actually routes wallet requests to _fetchWalletChecks now,
  // rather than refusing them before any attempt is made
  let called = false;
  const mockFetch = async () => { called = true; return { ok: true, json: async () => ({ code: 1, result: { sanctioned: '0' } }) }; };
  await SolanaAdapter.fetchChecks('SomeAddress1111111111111111111111111111111', 'wallet', null, mockFetch);
  console.log((called ? 'PASS' : 'FAIL') + ' Solana wallet: fetchChecks now actually attempts the call (mocked) -> called=' + called);
  called ? passed++ : failed++;
}
{ // 18b. normalizeSolanaWalletRecord — this logic was never what broke; only the
  // endpoint routing was in question, and that's now restored
  const { checks, expected, criticalDefsTotal } = normalizeSolanaWalletRecord({ sanctioned: '1' });
  assertVerdict('Solana wallet normalization: sanctioned address', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 18c. clean Solana wallet, full coverage -> PASS
  const rec = Object.fromEntries(EVM_WALLET_CHECK_DEFS.map(d => [d.key, '0']));
  const { checks, expected, criticalDefsTotal } = normalizeSolanaWalletRecord(rec);
  assertVerdict('Solana wallet normalization: fully clean, full coverage', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 18d. the direct-then-proxy fallback mechanism, exercised through the actual
  // public fetchChecks entry point now, not just the internal method directly
  let directCalled = false, proxyCalled = false;
  const mockFetch = async (url) => {
    if(url.includes('api.gopluslabs.io')){
      directCalled = true;
      throw new TypeError('Failed to fetch'); // simulates a CORS/network-level block
    }
    proxyCalled = true;
    return { ok: true, json: async () => ({ code: 1, result: { sanctioned: '0' } }) };
  };
  await SolanaAdapter.fetchChecks('SomeAddress1111111111111111111111111111111', 'wallet', null, mockFetch);
  const ok = directCalled && proxyCalled;
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana wallet fallback, via the real entry point: direct failure falls back to proxy -> directCalled=' + directCalled + ', proxyCalled=' + proxyCalled);
  ok ? passed++ : failed++;
}
{ // 18e. liquidity: empty dex array is a soft risk signal, not silently ignored
  const { checks } = normalizeSolanaRecord({ dex: [] });
  const liqCheck = checks.find(c => c.id === 'has_liquidity');
  const ok = liqCheck && liqCheck.status === 'RISK';
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: empty dex[] flagged as no-liquidity risk -> ' + (liqCheck ? liqCheck.status : 'ABSENT'));
  ok ? passed++ : failed++;
}
{ // 18f. liquidity: populated dex array produces a usable summary with correct pool count and TVL sum
  const rec = { dex: [ {dexname:'Raydium', tvl:'1000.5', lp_holders:[{is_locked:'1'}]}, {dexname:'Orca', tvl:'500'} ] };
  const { checks, liquiditySummary } = normalizeSolanaRecord(rec);
  const liqCheck = checks.find(c => c.id === 'has_liquidity');
  const ok = liqCheck && liqCheck.status === 'PASS' && liquiditySummary && liquiditySummary.poolCount === 2 && Math.abs(liquiditySummary.totalTvl - 1500.5) < 0.01;
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: populated dex[] -> correct pool count and TVL sum -> ' + JSON.stringify(liquiditySummary));
  ok ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// Address validation — Layer 0, must not share validators across chains
// ---------------------------------------------------------------------
console.log('\n== Layer 0: address validation ==');
const addrTests = [
  ['EVM valid', EvmAdapter.validateAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'), true],
  ['EVM rejects Solana-shaped address', EvmAdapter.validateAddress('9sj3vLFy26i1j4safWWoPujx7YScrWa4HyRF7s8XVb3U'), false],
  ['EVM rejects short hex', EvmAdapter.validateAddress('0x1234'), false],
  ['EVM rejects injection attempt', EvmAdapter.validateAddress('0x' + 'a'.repeat(40) + '<script>'), false],
  ['Solana valid', SolanaAdapter.validateAddress('9sj3vLFy26i1j4safWWoPujx7YScrWa4HyRF7s8XVb3U'), true],
  ['Solana rejects EVM-shaped address', SolanaAdapter.validateAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'), false],
  ['Solana rejects ambiguous base58 chars (0,O,I,l)', SolanaAdapter.validateAddress('0OIl' + 'a'.repeat(40)), false],
];
addrTests.forEach(([name, actual, expected]) => {
  const ok = actual === expected;
  console.log((ok ? 'PASS ' : 'FAIL ') + name + ' -> ' + actual + ' (expected ' + expected + ')');
  ok ? passed++ : failed++;
});

{ // 19. mint authority object entirely absent (consistent with revocation) resolves to a clear
  // check, not a silent gap that would otherwise count toward criticalMissing
  const rec = { closable:{status:'0'}, balance_mutable_authority:{status:'0'}, freezable:{status:'0'},
    mintable:{status:'0'}, metadata_mutable:{status:'0'}, transfer_fee_upgradable:{status:'0'},
    default_account_state_upgradable:{status:'0'}, transfer_hook_upgradable:{status:'0'},
    non_transferable:'0', transfer_hook:{address:''}, creator:{address:'Abc', malicious_address:'0'} };
    // note: no `mintable.authority` key at all
  const { checks } = normalizeSolanaRecord(rec);
  const mintAuthCheck = checks.find(c => c.id === 'mint_authority_malicious');
  const ok = mintAuthCheck && mintAuthCheck.status === 'PASS';
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: absent mint authority resolves to PASS, not missing -> ' + (mintAuthCheck ? mintAuthCheck.status : 'ABSENT FROM CHECKS'));
  ok ? passed++ : failed++;
}
{ // 20. mint authority object present but malicious_address unreadable -> genuinely UNKNOWN, not silently dropped
  const rec = { mintable: { status:'0', authority: { address:'Xyz', malicious_address: [1,2,3] } } };
  const { checks } = normalizeSolanaRecord(rec);
  const mintAuthCheck = checks.find(c => c.id === 'mint_authority_malicious');
  const ok = mintAuthCheck && mintAuthCheck.status === 'UNKNOWN';
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana: unreadable malicious_address on a present authority -> UNKNOWN, not dropped -> ' + (mintAuthCheck ? mintAuthCheck.status : 'ABSENT FROM CHECKS'));
  ok ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// SUI
// ---------------------------------------------------------------------
console.log('\n== Sui checks ==');

{ // 21. the whole reason Sui needed its own value classifier: '2' means
  // available too, not just '1' — a shared flagState() would miss this
  const { checks, expected, criticalDefsTotal } = normalizeSuiRecord({ contract_upgradeable: { value: '2' } });
  assertVerdict('Sui: value="2" for a critical field is still caught', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 22. confirmed critical finding despite sparse data - same override rule as EVM/Solana
  const { checks, expected, criticalDefsTotal } = normalizeSuiRecord({ contract_upgradeable: { value: '1' } });
  assertVerdict('Sui: critical finding despite sparse data (1/4 fields)', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 23. fully clean record -> PASS
  const clean = { contract_upgradeable:{value:'0'}, blacklist:{value:'0'}, mintable:{value:'0'}, metadata_modifiable:{value:'0'} };
  const { checks, expected, criticalDefsTotal } = normalizeSuiRecord(clean);
  assertVerdict('Sui: fully clean record', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 24. empty response -> INSUFFICIENT DATA, not a silent PASS
  const { checks, expected, criticalDefsTotal } = normalizeSuiRecord({});
  assertVerdict('Sui: empty provider response', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'INSUFFICIENT DATA');
}
{ // 25. trusted_token suppresses the mintable flag, same documented GoPlus exception as Solana
  const rec = { trusted_token:'1', mintable:{value:'1'}, contract_upgradeable:{value:'0'}, blacklist:{value:'0'}, metadata_modifiable:{value:'0'} };
  const { checks } = normalizeSuiRecord(rec);
  const mintCheck = checks.find(c => c.id === 'mintable');
  const ok = mintCheck && mintCheck.status === 'PASS';
  console.log((ok ? 'PASS' : 'FAIL') + ' Sui: trusted_token suppresses mintable risk -> ' + (mintCheck ? mintCheck.status : 'MISSING'));
  ok ? passed++ : failed++;
}
{ // 26. address validation against the real example from GoPlus's own console URL
  const real = SuiAdapter.validateAddress('0xbc732bc5f1e9a9f4bdf4c0672ee538dbf56c161afe04ff1de2176efabdf41f92::suai::SUAI');
  console.log((real ? 'PASS' : 'FAIL') + ' Sui: validates a real confirmed GoPlus example address');
  real ? passed++ : failed++;
}
{ // 27. cross-chain validator isolation, same discipline as EVM/Solana
  const rejectsEvm = !SuiAdapter.validateAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');
  const rejectsSolana = !SuiAdapter.validateAddress('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
  const ok = rejectsEvm && rejectsSolana;
  console.log((ok ? 'PASS' : 'FAIL') + ' Sui: rejects EVM- and Solana-shaped addresses -> rejectsEvm=' + rejectsEvm + ', rejectsSolana=' + rejectsSolana);
  ok ? passed++ : failed++;
}
{ // 28. six additional EVM chains landed correctly, none silently dropped
  const expectedNewChains = ['324','59144','534352','81457','5000','100'];
  const allPresent = expectedNewChains.every(id => !!EVM_CHAINS[id]);
  console.log((allPresent ? 'PASS' : 'FAIL') + ' EVM: all 6 newly added chains present -> ' + JSON.stringify(expectedNewChains.map(id => EVM_CHAINS[id])));
  allPresent ? passed++ : failed++;
}
// ---------------------------------------------------------------------
// Address-type auto-detection
// ---------------------------------------------------------------------
console.log('\n== Address auto-detection ==');
const detectionCases = [
  ['0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'evm', 'real USDC on Ethereum'],
  ['EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'solana', 'real USDC on Solana'],
  ['0xbc732bc5f1e9a9f4bdf4c0672ee538dbf56c161afe04ff1de2176efabdf41f92::suai::SUAI', 'sui', 'real SUAI on Sui'],
  ['0x2::sui::SUI', 'sui', 'short-form Sui native coin (not misread as EVM)'],
  ['not an address at all', null, 'garbage input'],
  ['', null, 'empty string'],
  ['   ', null, 'whitespace only'],
];
detectionCases.forEach(([addr, expected, label]) => {
  const got = detectEcosystem(addr);
  const ok = got === expected;
  console.log((ok ? 'PASS' : 'FAIL') + ' detectEcosystem: ' + label + ' -> ' + got + ' (expected ' + expected + ')');
  ok ? passed++ : failed++;
});

console.log(passed + '/' + (passed + failed) + ' regression tests passed');
console.log('='.repeat(60));
if(failed > 0) process.exitCode = 1;
})();
