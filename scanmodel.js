/* =====================================================================
   SAVESAVESAVESAVE — UNIFIED SCAN RESULT MODEL

   One envelope every scan type returns, and one deterministic rule for
   combining several scans into a single piece of action guidance without
   ever averaging them.

   WHY THIS EXISTS SEPARATELY: a pasted scam message is not one thing. It
   is a message, plus some URLs, plus some addresses, and each of those
   gets a different kind of check with different coverage and different
   limitations. Flattening them into one number destroys exactly the
   information a person needs: WHICH part is dangerous. A message whose
   text is unremarkable but whose contract is a honeypot is not "mostly
   fine". It is a honeypot with a polite covering letter.

   THE COMBINATION RULE, stated once: the worst component controls the
   guidance, and nothing outvotes it. Two clean addresses do not dilute
   one failing address. An incomplete check never rounds down to PASS.

   Pure: no DOM, no network, no clock beyond a timestamp. Testable in
   isolation, which is the point of it being its own file.
   ===================================================================== */

const SCAN_TYPES = {
  CRYPTO_ADDRESS: 'crypto_address_scan',
  TOKEN: 'token_scan',
  WALLET: 'wallet_scan',
  PROMPT: 'prompt_scan',
  MESSAGE: 'message_scan',
  FILE: 'file_scan',
};

// Ordering for combination. Note where INSUFFICIENT DATA sits: worse than
// PASS, because not knowing is not the same as being clear; but not worse
// than CAUTION, because a specific observed problem outranks an absence of
// information. It can never mask a FAIL.
const VERDICT_RANK = { pass: 0, unknown: 1, caution: 2, fail: 3 };
const VERDICT_LABEL = { pass: 'PASS', unknown: 'INSUFFICIENT DATA', caution: 'CAUTION', fail: 'FAIL' };

const MODEL_VERSION = '1.0.0';

function nowIso() { return new Date().toISOString(); }

/* ------------------------------------------------------------------ core
   The envelope. Every scan type produces this shape, so the renderer and
   the tests only ever learn one structure. */
function makeScanResult(o) {
  if (!o || !o.scan_type) throw new Error('scan_type is required');
  if (!Object.values(SCAN_TYPES).includes(o.scan_type)) {
    throw new Error(`unknown scan_type: ${o.scan_type}`);
  }
  const verdict = o.verdict || 'unknown';
  if (!(verdict in VERDICT_RANK)) throw new Error(`unknown verdict: ${verdict}`);

  return {
    scan_type: o.scan_type,
    subject: o.subject || null,            // what was scanned: an address, "pasted text", a filename
    verdict,
    label: VERDICT_LABEL[verdict],
    summary: o.summary || '',
    confidence: o.confidence || 'medium',
    findings: o.findings || [],
    coverage: o.coverage || {},
    limitations: o.limitations || [],
    recommended_actions: o.recommended_actions || [],
    sections: o.sections || null,          // composite scans only
    scanner_version: o.scanner_version || 'unknown',
    model_version: MODEL_VERSION,
    timestamp: o.timestamp || nowIso(),
  };
}

/* ------------------------------------------------------------- actions
   Recommended actions are lifted from the findings that actually drove the
   verdict, most severe first, deduplicated. They are never invented here:
   an action a person is told to take must trace to a specific finding. */
const SEV_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function recommendedActions(findings, max) {
  const cap = max || 5;
  const seen = new Set();
  const out = [];
  const ranked = (findings || [])
    .filter(f => f && f.action && SEV_RANK[f.severity] >= SEV_RANK.MEDIUM)
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]);
  for (const f of ranked) {
    const key = f.action.trim().toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ action: f.action, because: f.title, severity: f.severity, ruleId: f.ruleId });
    if (out.length >= cap) break;
  }
  return out;
}

/* --------------------------------------------------------- combination
   The only place verdicts are merged. Deliberately small so it can be
   read in one sitting and tested exhaustively. */
function combineVerdicts(components) {
  const list = (components || []).filter(Boolean);
  if (!list.length) {
    return {
      verdict: 'unknown',
      driver: null,
      incomplete: true,
      reason: 'Nothing was scanned.',
    };
  }

  let worst = list[0];
  for (const c of list) {
    if (VERDICT_RANK[c.verdict] > VERDICT_RANK[worst.verdict]) worst = c;
  }

  // Tracked separately from the verdict: a CAUTION overall must still say
  // so when one of its components could not be checked at all.
  const incomplete = list.some(c => c.verdict === 'unknown');

  return {
    verdict: worst.verdict,
    driver: worst,
    incomplete,
    counts: list.reduce((acc, c) => { acc[c.verdict] = (acc[c.verdict] || 0) + 1; return acc; }, {}),
  };
}

/* Phrases the overall guidance so it names the part that caused it, rather
   than describing the whole message as if it were uniform. */
function describeOutcome(combined, total) {
  const { verdict, driver, incomplete, counts } = combined;
  const what = driver && driver.subject ? driver.subject : 'one of the checks';
  const kind = driver ? ({
    [SCAN_TYPES.PROMPT]: 'the message text',
    [SCAN_TYPES.MESSAGE]: 'the message text',
    [SCAN_TYPES.CRYPTO_ADDRESS]: 'an address in this message',
    [SCAN_TYPES.TOKEN]: 'a token in this message',
    [SCAN_TYPES.WALLET]: 'a wallet in this message',
    [SCAN_TYPES.FILE]: 'the file',
  })[driver.scan_type] || 'one of the checks' : 'one of the checks';

  let summary;
  if (verdict === 'fail') {
    summary = `${cap(kind)} has a confirmed serious finding. Treat the whole message as unsafe — the rest of it passing does not make this part safe.`;
  } else if (verdict === 'caution') {
    summary = `${cap(kind)} has warning signs worth reviewing before you act on any part of this.`;
  } else if (verdict === 'unknown') {
    summary = `Not enough of this could be checked to give you a reliable answer. This is not a clean result.`;
  } else {
    summary = `Nothing covered by these checks was found${total > 1 ? ` across all ${total} of them` : ''}. That is not a guarantee of safety.`;
  }

  if (incomplete && verdict !== 'unknown') {
    summary += ' At least one check could not be completed, so coverage here is incomplete.';
  }
  if (counts && counts.fail > 1) {
    summary = `${counts.fail} separate checks returned a serious finding. ` + summary;
  }
  return { summary, driverSubject: what, driverKind: kind };
}

function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

/* ----------------------------------------------------------- composite
   Builds a message_scan (or file_scan) from its parts, keeping every part
   intact and addressable. `sections` is what the UI renders; `components`
   is what the policy reads. They are the same objects — no copy drifts. */
function combineScans(opts) {
  const scanType = opts.scan_type || SCAN_TYPES.MESSAGE;
  const sections = opts.sections || [];
  const components = [];
  for (const s of sections) {
    if (s.scan) components.push(s.scan);
    if (s.scans) components.push(...s.scans);
  }

  const combined = combineVerdicts(components);
  const outcome = describeOutcome(combined, components.length);

  // Actions come from the components that actually reached the top
  // verdict, so a person is told what to do about the dangerous part
  // rather than a list averaged across everything.
  const worstRank = VERDICT_RANK[combined.verdict];
  const drivingFindings = components
    .filter(c => VERDICT_RANK[c.verdict] === worstRank)
    .flatMap(c => c.findings || []);

  const limitations = [];
  const seenLim = new Set();
  for (const c of components) {
    for (const l of (c.limitations || [])) {
      const k = (l.text || l).toString();
      if (seenLim.has(k)) continue;
      seenLim.add(k);
      limitations.push(l);
    }
  }

  // Coverage is reported per component, never collapsed: "urls: complete"
  // for the message says nothing about whether a token's liquidity data
  // came back.
  const coverage = {};
  components.forEach((c, i) => {
    if (c.coverage && Object.keys(c.coverage).length) {
      coverage[`${c.scan_type}#${i + 1}`] = c.coverage;
    }
  });

  return makeScanResult({
    scan_type: scanType,
    subject: opts.subject || null,
    verdict: combined.verdict,
    summary: outcome.summary,
    confidence: combined.incomplete ? 'low' : (combined.verdict === 'fail' ? 'high' : 'medium'),
    findings: [],   // deliberately empty: findings belong to their section
    sections,
    coverage,
    limitations,
    recommended_actions: recommendedActions(drivingFindings),
    scanner_version: opts.scanner_version || 'unknown',
  });
}

/* ------------------------------------------------------------ adapters
   Wrap the two engines that already exist. Neither is modified: the
   adapters read their output and produce the envelope, so the address
   engine stays exactly as tested. */

function fromPromptScan(r, subject) {
  return makeScanResult({
    scan_type: SCAN_TYPES.PROMPT,
    subject: subject || 'pasted text',
    verdict: r.verdict,
    summary: r.sub,
    confidence: r.confidence,
    findings: r.findings,
    coverage: r.coverage,
    limitations: r.limitations,
    recommended_actions: recommendedActions(r.findings),
    scanner_version: r.scannerVersion,
  });
}

// `result` is what core.js's VerdictEngine.evaluate() returns.
function fromAddressScan(result, address, chain, assetType) {
  const findings = (result.checks || [])
    .filter(c => c.status === 'RISK' || c.status === 'UNKNOWN')
    .map(c => ({
      ruleId: c.id,
      category: c.category || 'general',
      severity: c.status === 'UNKNOWN' ? 'LOW'
        : (c.critical ? 'CRITICAL' : (c.severityWeight >= 3 ? 'HIGH' : 'MEDIUM')),
      confidence: c.status === 'UNKNOWN' ? 0.4 : 0.85,
      title: c.label,
      plain: c.detail,
      technical: `${c.id} · ${c.status} · weight ${c.severityWeight} · ${c.source || 'unknown source'}`,
      evidence: null,
      action: c.status === 'UNKNOWN'
        ? 'This indicator returned no usable data. Treat it as unverified rather than clear.'
        : 'Do not send funds to, or approve spending for, this address until you have verified it independently.',
      source: c.source || 'chain scan',
      contributed: c.status === 'RISK',
    }));

  return makeScanResult({
    scan_type: assetType === 'wallet' ? SCAN_TYPES.WALLET : SCAN_TYPES.TOKEN,
    subject: address,
    verdict: result.verdict,
    summary: result.sub,
    confidence: result.confidence,
    findings,
    coverage: {
      indicators: result.checksExpected
        ? `${result.checksValid}/${result.checksExpected} returned usable data`
        : 'unknown',
      unreadable: String(result.checksUnknown || 0),
      chain: chain || 'unknown',
    },
    limitations: [
      { text: 'Chain data comes from a third-party provider. A clean result reflects the indicators that were checked, not every possible risk.', material: false },
      ...(result.criticalMissing
        ? [{ text: `${result.criticalMissing} high-severity check(s) returned no data — this result is incomplete on that point.`, material: true }]
        : []),
    ],
    scanner_version: result.source || 'chain engine',
  });
}

// A placeholder component for an address the user has not scanned yet.
// It exists so the composite can say "not checked" explicitly rather than
// leaving a silent hole that reads as fine.
function pendingAddressScan(address, chain) {
  return makeScanResult({
    scan_type: SCAN_TYPES.CRYPTO_ADDRESS,
    subject: address,
    verdict: 'unknown',
    summary: 'This address was found in the text but has not been checked yet.',
    confidence: 'low',
    findings: [],
    coverage: { chain: chain || 'unknown', status: 'not_checked' },
    limitations: [{ text: `The address ${address} was extracted but not scanned. Nothing is known about it either way.`, material: true }],
    recommended_actions: [],
    scanner_version: 'n/a',
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SCAN_TYPES, VERDICT_RANK, VERDICT_LABEL, SEV_RANK, MODEL_VERSION,
    makeScanResult, combineVerdicts, combineScans, describeOutcome,
    recommendedActions, fromPromptScan, fromAddressScan, pendingAddressScan,
  };
}
