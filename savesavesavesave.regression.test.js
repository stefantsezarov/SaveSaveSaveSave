/* =====================================================================
   SAVESAVESAVESAVE REGRESSION SUITE
   Run with: node savesavesavesave.regression.test.js
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
  normalizeSuiRecord, suiFlagState, SuiAdapter, TronAdapter, detectEcosystem,
  fetchCounterpartyChecks, COUNTERPARTY_CHECK_SUPPORTED_CHAINS
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
// ---------------------------------------------------------------------
// 18–18f. SOLANA WALLET SCREENING IS OFF, and these tests exist to keep
// it off until someone has evidence rather than an announcement.
//
// It was switched on once on the strength of GoPlus's published statement
// that chain_id: 'solana' works on the Malicious Address API. Measured on
// 21 September 2026, that endpoint answers code 5000 "system error" for
// every Solana address tried, including USDC's mint — while answering
// correctly for chain_id=1. A user scanning an address he had taken from
// a sanctions list was told "system error … the address has no data yet".
// ---------------------------------------------------------------------
{ // 18. the capability is off, and says why in its own words
  const off = SolanaAdapter.capabilities.walletScreening === false;
  console.log((off ? 'PASS' : 'FAIL') + ' Solana adapter declares walletScreening: false (provider returns code 5000 for chain_id=solana)');
  off ? passed++ : failed++;

  const note = (SolanaAdapter.capabilityNotes || {}).walletScreening || '';
  const explained = /no provider data/i.test(note) && !/not yet available/i.test(note);
  console.log((explained ? 'PASS' : 'FAIL') + ' ...and the page says "no provider data", not "not yet available" -> "' + note + '"');
  explained ? passed++ : failed++;
}
{ // 18a. a wallet request is refused BEFORE any network call, and the
  // refusal says it is a coverage gap. The old version of this test
  // asserted the opposite; it was asserting a bug.
  let called = false;
  const mockFetch = async () => { called = true; return { ok: true, json: async () => ({ code: 1, result: { sanctioned: '0' } }) }; };
  let msg = '';
  try {
    await SolanaAdapter.fetchChecks('SomeAddress1111111111111111111111111111111', 'wallet', null, mockFetch);
  } catch(e){ msg = e.message; }
  const ok = !called && /gap in coverage/i.test(msg) && /not a clean result/i.test(msg);
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana wallet: refused without a network call, as a coverage gap -> fetched=' + called);
  ok ? passed++ : failed++;
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
{ // 18d. if the capability is ever restored, the live 5000 must still be
  // named as a coverage gap rather than handed up as the vendor's bare
  // phrase "system error". That phrase is what the banner then wrapped in
  // "the address has no data yet".
  const mockFetch = async () => ({ ok: true, json: async () => ({ code: 5000, message: 'system error', result: null }) });
  let msg = '';
  try { await SolanaAdapter._fetchWalletChecks('SomeAddress1111111111111111111111111111111', mockFetch); }
  catch(e){ msg = e.message; }
  const ok = /gap in coverage/i.test(msg) && !/^system error$/i.test(msg);
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana wallet: a live code 5000 is reported as a coverage gap -> "' + msg.slice(0, 60) + '…"');
  ok ? passed++ : failed++;
}
{ // 18e. THE DANGEROUS FIX. Dropping chain_id makes the endpoint return
  // code 1 with every flag "0" and data_source "" — an empty record that
  // the normalizer would turn into a full row of PASSes. An address with
  // no record must never be rendered as an address with a clean record.
  const mockFetch = async () => ({ ok: true, json: async () => ({
    code: 1, message: 'ok',
    result: Object.fromEntries([...EVM_WALLET_CHECK_DEFS.map(d => [d.key, '0']), ['data_source', '']]),
  })});
  let msg = '', threw = false;
  try { await SolanaAdapter._fetchWalletChecks('SomeAddress1111111111111111111111111111111', mockFetch); }
  catch(e){ threw = true; msg = e.message; }
  const ok = threw && /no address record at all/i.test(msg) && /not absence of risk/i.test(msg);
  console.log((ok ? 'PASS' : 'FAIL') + ' Solana wallet: an empty record (no data_source) is refused, never rendered as PASS');
  ok ? passed++ : failed++;
}
{ // 18f. and the adapter must never ask the address endpoint WITHOUT a
  // chain_id, which is the request that produces that empty record.
  const urls = [];
  const mockFetch = async (url) => { urls.push(url); return { ok: true, json: async () => ({ code: 5000, message: 'system error', result: null }) }; };
  try { await SolanaAdapter._fetchWalletChecks('SomeAddress1111111111111111111111111111111', mockFetch); } catch(_){}
  const bare = urls.filter(u => /address_security/.test(u) && !/chain_id=/.test(u));
  console.log((bare.length === 0 ? 'PASS' : 'FAIL') + ' Solana wallet: never queries address_security without chain_id -> ' + (bare[0] || 'none'));
  bare.length === 0 ? passed++ : failed++;
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

// ---------------------------------------------------------------------
// TRON
// ---------------------------------------------------------------------
console.log('\n== TRON checks ==');

{ // 29. TRON via the reused EVM normalizer - confirmed critical finding despite sparse data
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord({ is_honeypot: '1' }, 'token');
  assertVerdict('TRON (via shared EVM schema): confirmed honeypot, sparse data', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'FAIL');
}
{ // 30. fully clean, full coverage -> PASS
  const rec = fullClean(EVM_TOKEN_CHECK_DEFS, {is_open_source:'1'});
  const { checks, expected, criticalDefsTotal } = normalizeEvmRecord(rec, 'token');
  assertVerdict('TRON (via shared EVM schema): fully clean', VerdictEngine.evaluate(checks, expected, 'test', criticalDefsTotal), 'PASS');
}
{ // 31. address validation against real, well-known TRON contracts
  const usdt = TronAdapter.validateAddress('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t');
  const usdc = TronAdapter.validateAddress('TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8');
  console.log((usdt && usdc ? 'PASS' : 'FAIL') + ' TRON: validates real USDT and USDC-TRC20 contract addresses');
  (usdt && usdc) ? passed++ : failed++;
}
{ // 32. cross-chain validator isolation
  const rejectsEvm = !TronAdapter.validateAddress('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48');
  const rejectsSolana = !TronAdapter.validateAddress('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
  const rejectsSui = !TronAdapter.validateAddress('0x2::sui::SUI');
  const ok = rejectsEvm && rejectsSolana && rejectsSui;
  console.log((ok ? 'PASS' : 'FAIL') + ' TRON: rejects EVM-, Solana-, and Sui-shaped addresses');
  ok ? passed++ : failed++;
}
{ // 33. the actual reason TRON's check is ordered before Solana's in detectEcosystem —
  // confirms a real, valid Solana address is still classified correctly and NOT
  // swallowed by the new TRON check
  const stillSolana = detectEcosystem('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v') === 'solana';
  console.log((stillSolana ? 'PASS' : 'FAIL') + ' detectEcosystem: adding TRON does not break existing Solana detection');
  stillSolana ? passed++ : failed++;
}
{ // 34. detectEcosystem correctly classifies a real TRON address
  const isTron = detectEcosystem('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t') === 'tron';
  console.log((isTron ? 'PASS' : 'FAIL') + ' detectEcosystem: real USDT-TRON address -> tron');
  isTron ? passed++ : failed++;
}

// ---------------------------------------------------------------------
// Recent counterparty checking (direct_counterparty attribution)
// ---------------------------------------------------------------------
console.log('\n== Recent counterparty checking ==');

{ // 35. unsupported chain -> no attempt, no checks, no fetch call made
  const result = await fetchCounterpartyChecks('0x1111111111111111111111111111111111111111', '324', async () => { throw new Error('should not be called'); });
  const ok = result.attempted === false && result.checks.length === 0;
  console.log((ok ? 'PASS' : 'FAIL') + ' counterparty check: unsupported chain makes no attempt');
  ok ? passed++ : failed++;
}
{ // 36. one sanctioned counterparty found -> CAUTION, NOT an unconditional FAIL
  // (a direct designation on the wallet itself gets that override; a
  // counterparty being sanctioned is deliberately one tier less severe)
  const mockFetch = async () => ({ ok: true, json: async () => ({
    available: true, windowDescription: '~50 minutes (2000 blocks)', transferCount: 5, uniqueCounterpartyCount: 4,
    sanctionedCounterparties: [{ address: '0x7F367cC41522cE07553e823bf3be79A889DEbe1B', direction: 'received_from', txHash: '0xabc' }],
  })});
  const result = await fetchCounterpartyChecks('0x1111111111111111111111111111111111111111', '137', mockFetch);
  const cleanBase = EVM_WALLET_CHECK_DEFS.map(d => ({ id:d.key, category:'reputation', status:'PASS', critical:d.critical, severityWeight:0, label:d.label, detail:d.detail, source:'test' }));
  const combined = [...cleanBase, ...result.checks];
  const verdict = VerdictEngine.evaluate(combined, cleanBase.length + 1, 'test', EVM_WALLET_CHECK_DEFS.filter(d=>d.critical).length);
  const ok = result.checks[0].critical === false && result.checks[0].attributionType === 'direct_counterparty' && verdict.label === 'CAUTION';
  console.log((ok ? 'PASS' : 'FAIL') + ' counterparty check: one sanctioned counterparty -> CAUTION, not critical override -> ' + verdict.label);
  ok ? passed++ : failed++;
}
{ // 37. a genuine direct sanction on the wallet itself still forces FAIL
  // regardless of what a clean counterparty check says -- the actual
  // precedence hierarchy this feature was designed to protect
  const directSanction = { id:'sanctioned', category:'reputation', status:'RISK', critical:true, severityWeight:3, label:'x', detail:'x', source:'test' };
  const cleanCounterparty = { id:'recent_counterparty_check', category:'exposure', status:'PASS', critical:false, severityWeight:0, label:'x', detail:'x', source:'test' };
  const verdict = VerdictEngine.evaluate([directSanction, cleanCounterparty], 2, 'test', 1);
  const ok = verdict.label === 'FAIL';
  console.log((ok ? 'PASS' : 'FAIL') + ' counterparty check: direct wallet sanction overrides regardless of counterparty result');
  ok ? passed++ : failed++;
}
{ // 38. worker-side failure produces UNKNOWN, never silently PASS
  const mockFetch = async () => ({ ok: true, json: async () => ({ available: false, reason: 'RPC request timed out' }) });
  const result = await fetchCounterpartyChecks('0x1111111111111111111111111111111111111111', '10', mockFetch);
  const ok = result.attempted === true && result.checks.length === 1 && result.checks[0].status === 'UNKNOWN';
  console.log((ok ? 'PASS' : 'FAIL') + ' counterparty check: worker failure -> UNKNOWN, not silently dropped or PASS');
  ok ? passed++ : failed++;
}
{ // 39. supported-chain list matches the Worker's actual RPC coverage exactly
  const expected = ['1','10','137','43114','42161','56','81457','8453'].sort();
  const actual = [...COUNTERPARTY_CHECK_SUPPORTED_CHAINS].sort();
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log((ok ? 'PASS' : 'FAIL') + ' counterparty check: supported-chain list matches Worker RPC coverage -> ' + actual.join(','));
  ok ? passed++ : failed++;
}

console.log(passed + '/' + (passed + failed) + ' regression tests passed');
console.log('='.repeat(60));
if(failed > 0) process.exitCode = 1;
})();
