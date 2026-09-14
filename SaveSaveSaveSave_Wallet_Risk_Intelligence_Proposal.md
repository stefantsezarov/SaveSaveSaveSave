# SaveSaveSaveSave Wallet-Risk Intelligence: Feasibility, Architecture, and Implementation Proposal

*Prepared as an architecture and feasibility review. Every provider claim below is tagged with a confidence level. Where I could not verify something against primary documentation, it says so — nothing here is invented.*

**Confidence key:** `VERIFIED` (confirmed via official docs/primary source, checked during this review) · `STRONGLY SUPPORTED` (authoritative secondary material, not independently confirmed) · `SECONDARY` (reputable third-party reporting) · `INFERRED` (reasonable technical inference, not documented) · `UNKNOWN` · `REQUIRES VENDOR CONFIRMATION`

---

## 1. Executive Summary

Three things need to be said before anything else, because they change the shape of every recommendation that follows.

**First: a real version of this feature already exists and is live.** SaveSaveSaveSave's EVM wallet-screening mode, built earlier in this project, already checks a submitted address against GoPlus Security's Malicious Address API and reports on sanctions, phishing, theft, money laundering, dark-web activity, cybercrime association, mixer exposure, and fake-KYC association — `VERIFIED`, this is the actual shipped `EVM_WALLET_CHECK_DEFS` list in `core.js`, tested and in production. This isn't a competing proposal to what's below; it's the true Phase 0/1 that's already done. The question this document actually answers is not "should SaveSaveSaveSave build wallet screening" — it's "what's the honest, realistic next increment beyond what's shipped, and where does the 56-point vision in the original brief stop being appropriate for what SaveSaveSaveSave currently is."

**Second: the enterprise AML providers named in the brief (Chainalysis, TRM Labs, Elliptic, Merkle Science, Crystal, Scorechain) are, without exception, sales-led enterprise products with no public self-serve pricing or API signup** — `VERIFIED` for Chainalysis/TRM/Elliptic via multiple 2026 buyer's-guide and pricing-benchmark sources; `STRONGLY SUPPORTED` for Merkle Science/Crystal/Scorechain by the same market pattern, not independently confirmed per-vendor. One real pricing data point surfaced: third-party procurement benchmarking cites roughly **€60,000–150,000/year for a mid-sized CASP** on TRM Labs — `SECONDARY`, not official pricing, but the only concrete number found. None of these are integrable by a solo-maintained free product without a sales conversation and a contract. This is worth saying plainly rather than writing around it.

**Third: the free/public sources that genuinely exist are narrower than they sound, but real and immediately useful.** OFAC's Sanctions List Service is free, requires no API key, and — confirmed directly against live treasury.gov designations — embeds actual blockchain addresses (`"Digital Currency Address - ETH 0x..."`) inside SDN entries, not just names. It's a raw file feed, not a matching API — SaveSaveSaveSave would need to build the parsing and matching itself, which is real but bounded engineering work. Chainabuse has a genuine public API (`docs.chainabuse.com`) for real-time address/URL lookup against community-reported scams, separate from its enterprise "Chainabuse Pro" tier.

**My recommendation, stated up front rather than buried at the end:** don't build the 56-point architecture. Extend what's already shipped along two concrete, boundable axes — a self-hosted OFAC digital-currency-address matcher, and a Chainabuse lookup as a second signal source — inside the existing `CHECK` evidence model and `VerdictEngine` SaveSaveSaveSave already has, tested and working across four chains. Everything past that (graph analysis, ML, multi-provider failover orchestration, continuous monitoring with webhooks, a dedicated compliance case-management system) is real, well-specified below, and *wrong for SaveSaveSaveSave's current stage* — it's the correct architecture for a funded compliance company with a legal team, not a free tool with one active maintainer. I say this explicitly because the brief invited intelligent disagreement, and this is the disagreement that matters most.

---

## 2. Problem Definition, Threat Model, and the Conceptual Hierarchy

### 2.1 What "wallet risk" actually means

The brief's hierarchy is correct and worth keeping exactly as specified, because collapsing it is the single most common mistake in this space:

```
ENTITY → ADDRESS → TRANSACTION → COUNTERPARTY → EXPOSURE → RISK SIGNAL → RISK ASSESSMENT → DECISION
```

An EVM address is a cryptographic identifier, not a person. A given address may be:
- **Directly designated** (appears by name on a sanctions list, or as a "Digital Currency Address" field within one — the strongest, most legally significant category)
- **Directly attributed** (a provider or community has linked it to a known entity — exchange, scammer, ransomware operator — with varying confidence)
- **Behaviorally suspicious** (transaction patterns suggest risk without a direct attribution)
- **Exposed** (has transacted with a risky address, without being risky itself)
- One of potentially **many addresses controlled by the same entity** (a person or organization rarely uses one address)
- **Shared infrastructure** used by many unrelated people (an exchange deposit address, a bridge contract, a DEX router)

SaveSaveSaveSave's existing `CHECK` model — `{id, category, status, critical, severityWeight, label, detail, source}` — already has the right shape to carry this distinction (`category: 'reputation'` vs. others, `critical` for direct designations), but it currently only represents **direct attribution**, not exposure/distance. That gap is the actual scope of "what's new" in this proposal, not a wholesale new system.

### 2.2 Threat taxonomy

Grouped as the brief requested, with a note on which of these SaveSaveSaveSave's existing GoPlus integration already covers (`VERIFIED` from the shipped check list) versus what would be new:

| Category | Already covered (GoPlus Malicious Address API) | Not covered — would need a new source |
|---|---|---|
| Sanctions | `sanctioned` flag — `VERIFIED`, shipped | Direct OFAC digital-currency-address match (more authoritative, legally specific) |
| Phishing / draining | `phishing_activities` — `VERIFIED`, shipped | — |
| Theft / hacks / exploits | `stealing_attack` — `VERIFIED`, shipped | Exploit-specific attribution (which hack, which protocol) |
| Money laundering | `money_laundering` — `VERIFIED`, shipped | — |
| Mixers/tumblers | `mixer` — `VERIFIED`, shipped | Mixer *exposure* (received funds that passed through a mixer) vs. *being* a mixer |
| Darknet | `darkweb_transactions` — `VERIFIED`, shipped | — |
| Cybercrime / ransomware | `cybercrime`, `blackmail_activities` — `VERIFIED`, shipped | Ransomware-family-specific attribution |
| Terrorist financing | Not a distinct field in the shipped schema | Would need a dedicated source — see §4 |
| Scam reports (community) | Not covered — GoPlus is provider-verified, not community | Chainabuse — see §4 |
| Rug pulls / Ponzi / malicious tokens | Out of scope for *wallet* screening — this is Token Security territory | SaveSaveSaveSave already has this, separately, for tokens |

That last row matters architecturally: **rug-pull and malicious-token detection already exists in SaveSaveSaveSave, in the Token Security engines, not the wallet engine.** This directly answers §52 of the brief (three engines) — see §9 below.

### 2.3 Why wallet risk and contract risk must stay separate

SaveSaveSaveSave's existing architecture already enforces this correctly without having named it: `EVM_TOKEN_CHECK_DEFS` (honeypot, mint function, blacklist) and `EVM_WALLET_CHECK_DEFS` (sanctioned, phishing, mixer) are already two distinct check-definition arrays, normalized and scored independently, sharing only the `VerdictEngine`. This is the right design and should stay exactly as-is — it's Engine 1 and Engine 3 from the brief's §52, already architecturally separated by accident of good design rather than deliberate three-engine planning. No change needed here; worth stating explicitly so it doesn't get "improved" into something more complicated later.

---

## 3. Data-Source Landscape

### 3.1 Tiered summary

| Tier | Sources | Public/self-serve? | EVM address-level data? |
|---|---|---|---|
| 1 — Government/sanctions | OFAC SDN/Consolidated, EU/UN/UK lists | OFAC: `VERIFIED` free, no key. EU/UN/UK: `UNKNOWN` — not independently checked this session, `REQUIRES SOURCE CONFIRMATION` | OFAC: `VERIFIED` yes, via Digital Currency Address fields |
| 2 — Institutional blockchain intelligence | Chainalysis, TRM Labs, Elliptic | No — enterprise sales only, `VERIFIED` | Yes, but inaccessible without a contract |
| 3 — Commercial AML/KYT | Merkle Science, Crystal, Scorechain | `STRONGLY SUPPORTED` same pattern as Tier 2, not individually verified | `REQUIRES VENDOR CONFIRMATION` |
| 4 — Public/community reporting | Chainabuse | `VERIFIED` — public API exists (`docs.chainabuse.com`) | `VERIFIED` — address/URL lookup is the core function |
| 5 — Blockchain infrastructure | Etherscan/block explorers, GoPlus (already integrated) | GoPlus: `VERIFIED`, already shipped | Yes, already in production use |
| 6 — OSINT/threat intel | Various security researchers, threat-intel accounts | Not a queryable API — editorial | N/A as a programmatic source |

### 3.2 Provider comparison matrix — the fields that could actually be verified

The brief asks for 40+ fields per provider. Rather than fabricate 40 fields across eight providers when most of that matrix would legitimately read "UNKNOWN — REQUIRES VENDOR CONFIRMATION" (which the brief explicitly says not to pad past), here is what's actually knowable without a sales call, and an honest statement about the rest:

| Field | GoPlus (already integrated) | OFAC SLS | Chainabuse | Chainalysis / TRM / Elliptic |
|---|---|---|---|---|
| Public API | `VERIFIED` yes | `VERIFIED` yes (file feed) | `VERIFIED` yes | `VERIFIED` no — sales-gated |
| Auth required | `VERIFIED` none (current usage) | `VERIFIED` none | `REQUIRES VENDOR CONFIRMATION` — public API page exists; self-serve signup process not independently confirmed | `VERIFIED` — contract + credentials |
| Pricing | `VERIFIED` free | `VERIFIED` free | `UNKNOWN` — full API vs. "Pro" tier boundary unclear from public docs | `SECONDARY` — ~€60–150k/yr for TRM (mid-market CASP, third-party benchmark, not official) |
| EVM address screening | `VERIFIED` yes | `VERIFIED` yes (SDN digital currency address field) | `VERIFIED` yes | `VERIFIED` yes, per marketing/product pages |
| Data type | Provider-verified (GoPlus's own analysis) | Government designation (authoritative) | Community-reported, confidence-scored, spam-filtered | Analyst-verified + proprietary clustering |
| Rate limits | `SECONDARY` — 30 req/min free tier, per earlier research this project | `VERIFIED` — none published | `UNKNOWN` — not published on the docs page reviewed | `REQUIRES VENDOR CONFIRMATION` |
| Redistribution rights | `UNKNOWN` — not reviewed in ToS this session | Public domain (US government work) — `STRONGLY SUPPORTED` | `UNKNOWN` — likely restricted, `REQUIRES VENDOR CONFIRMATION` | `VERIFIED` restricted — standard enterprise data-licensing terms |
| Historical/versioned data | `UNKNOWN` | `VERIFIED` — SLS publishes dated delta files | `UNKNOWN` | `REQUIRES VENDOR CONFIRMATION` |

For every cell not filled above, the honest answer is exactly what the brief asked for when evidence doesn't exist: **UNKNOWN — REQUIRES VENDOR CONFIRMATION.** Producing a fuller-looking table by inferring plausible values would fail the brief's own stated standard.

### 3.3 Sources not named in the brief worth flagging

- **Chainalysis's free, on-chain sanctions oracle** — a publicly deployed, queryable smart contract that flags OFAC-sanctioned addresses, distinct from Chainalysis's paid enterprise API. `SECONDARY` — referenced in this project's own earlier research when Solana wallet screening was first being scoped, not re-verified in this session. If confirmed, this is a meaningfully better MVP fit than the paid Chainalysis product: free, on-chain, no sales conversation required. **Flagged as the single highest-value follow-up verification task**, ahead of anything else in this document.
- **Etherscan's label/tag data** — some address labels (exchange, contract type) are visible via Etherscan's free API tier. `INFERRED` from general knowledge of the product, not verified this session. Lower value for illicit-activity screening specifically (Etherscan labels skew toward entity identification, not risk classification) but potentially useful for the false-positive mitigation work in §12.

---

## 4. Sanctions Subsystem — the One Piece Worth Building Now

This is the part of the 56-point brief that's genuinely appropriate to build immediately, because the data is free, authoritative, and legally distinct from every other signal type.

### 4.1 The three-tier distinction, made structural, not just conceptual

```
DIRECTLY DESIGNATED      (address itself is an SDN digital-currency-address entry)
        ≠
DIRECT COUNTERPARTY      (received funds from / sent funds to a designated address)
        ≠
INDIRECT EXPOSURE        (N hops from a designated address, via an intermediary)
```

These must never collapse into one field. Concretely: SaveSaveSaveSave's `CHECK` model needs a new field, `attributionType: 'direct_designation' | 'direct_counterparty' | 'indirect_exposure'`, and the `VerdictEngine`'s critical-override rule (a single confirmed critical finding forces `FAIL`, already built and tested) should apply **only** to `direct_designation`. Counterparty and exposure signals should score additively, the same way non-critical signals already do — not trigger the same hard override. This is a small, precise change to logic SaveSaveSaveSave already has, not a new engine.

### 4.2 Real evidence this matters: the Tornado Cash case

Confirmed directly against treasury.gov's own recent-actions archive: Tornado Cash was added to the SDN list on **August 8, 2022** with eight specific Ethereum addresses listed as `Digital Currency Address - ETH` entries, then **removed on March 21, 2025** (following the *Van Loon v. Treasury* litigation). This is `VERIFIED`, not hypothetical, and it's the exact scenario §21 of the brief asks about: a transaction with one of those addresses in September 2023 occurred while the designation was active; the same interaction today would not. A wallet-risk system that only stores "currently sanctioned: yes/no" cannot answer "was this risky at the time" — which is precisely the historical-state requirement in §20 of the brief, and precisely why SaveSaveSaveSave needs `effective_from` / `effective_to` timestamps on sanctions records, not just a current boolean.

### 4.3 Implementation shape

- **Ingest OFAC's SLS XML/CSV feed directly** (`VERIFIED` free, no key, published dated delta files). Parse out every `Digital Currency Address - ETH` entry (and other EVM-relevant symbols, though OFAC's symbol taxonomy predates most current EVM chains and doesn't distinguish Ethereum mainnet from other EVM chains at the address level — worth noting as a real data-quality gap, not glossed over).
- **This is a scheduled batch job, not a live per-request API call to OFAC** — SLS is a file feed. A new check run against SaveSaveSaveSave's own normalized copy is the only correct architecture; calling treasury.gov synchronously per user scan would be slow, unreliable, and unnecessary.
- **Store the raw designation date and delisting date**, not just current status — this is what makes §20/§21 (historical risk, temporal analysis) answerable without a bigger system.
- Explicitly **do not** attempt name-based fuzzy matching (the SLS's actual complexity, per the OFAC SLS API review found this session) — SaveSaveSaveSave only needs the address-field subset, which is exact-match, not fuzzy. This sidesteps the hardest part of building "our own OFAC screener" that commercial providers charge for.

---

## 5. EVM Address Model

The brief's default assumption — canonical key is `chain_id + normalized_address` — is correct, and SaveSaveSaveSave already implements exactly this, `VERIFIED` directly from the shipped code: `EvmAdapter.fetchChecks(addr, assetType, chainId, ...)` already threads `chainId` through every call, and the UI's `CHAIN_LABEL` map already treats `(chain, address)` as the unit of identity, not `address` alone. No architectural change needed here — this section exists mainly to confirm the brief's own assumption holds and explain why, for anyone reading this later:

The same `0x...` string is a genuinely different entity on Ethereum vs. Base vs. Arbitrum — different deployed contract, different owner, different history — even though nothing about the string itself reveals that. A screening result cached or displayed without the `chain_id` is, strictly, meaningless. SaveSaveSaveSave's existing multi-chain architecture (`EVM_CHAINS` map, per-adapter `chains` object) already made this decision correctly when it was built for token security; wallet screening should use the identical key, not a parallel one.

One gap worth naming: SaveSaveSaveSave validates address *format* (checksum-independent regex) but doesn't currently normalize checksummed vs. lowercase representations before using an address as a cache/storage key. `INFERRED` risk: two requests for the same address in different letter-casing would currently be treated as different cache entries. Small, concrete fix if a caching layer gets built (§6): lowercase-normalize before keying, `VERIFIED`-safe because EIP-55 checksums are case-only and don't change the underlying 20-byte address.

---

## 6. Architecture — What to Actually Add, Not a Parallel System

### 6.1 The brief's proposed pipeline, evaluated

```
Client → API Gateway → Screening Orchestrator → Provider Abstraction Layer → Normalization → Risk Signal Engine → Risk Scoring Engine → Decision Engine → Evidence Store → API
```

This is a reasonable architecture **for a multi-provider compliance platform**. SaveSaveSaveSave is not that today, and building toward it now — before there's a second real provider to abstract over — is exactly the kind of premature architecture the brief's own §51 asked me to flag. SaveSaveSaveSave's actual current pipeline is simpler and already works:

```
Client → runScan() → Adapter.fetchChecks() → normalize*Record() → VerdictEngine.evaluate() → renderPass()
```

The honest addition, scoped to what's actually being proposed (OFAC + Chainabuse as new signal sources), is:

```
Client → runScan() → [GoPlus check (existing) + OFAC local-index check (new) + Chainabuse check (new), fetched in parallel]
       → mergeChecks() → VerdictEngine.evaluate() (unchanged) → renderPass() (unchanged)
```

This is not the Provider Abstraction Layer from §9 of the brief — it doesn't need capability negotiation, health checks, or failover between providers, because the three sources aren't substitutes for each other, they're additive (sanctions, provider-verified reputation, and community reports are three different signal *types*, not three competing measurements of the same thing). A real Provider Abstraction Layer becomes justified the moment there are two providers that answer the *same* question and need reconciliation — which is §31's contradictory-results problem. That day may come; it hasn't yet with two additive, complementary sources.

### 6.2 Synchronous, asynchronous, or hybrid

**Synchronous, unchanged from today.** GoPlus's response and a local OFAC-index lookup are both sub-second. Chainabuse's public API, `UNKNOWN` latency (not benchmarked this session) but described as "real-time" in its own docs — `STRONGLY SUPPORTED` as synchronous-appropriate. SaveSaveSaveSave's existing 20-second timeout + one-retry pattern (already built, already tested) is the correct handling for all three; no async job queue is justified until continuous monitoring (§13 below) actually gets built, and even then, monitoring is a genuinely separate asynchronous concern from a live user-initiated scan, not a reason to make the scan itself async.

### 6.3 Should this screen only the submitted address, or counterparties/history too?

**Only the submitted address, for now — this is the single biggest scope-discipline recommendation in this document.** Counterparty analysis, transaction history, funding-source tracing, and cluster analysis are the actual product Chainalysis/TRM/Elliptic sell for five and six figures a year, built on years of proprietary clustering work. Attempting a lightweight version of this from RPC calls alone would produce a **worse, less defensible, more false-positive-prone result** than not having the feature — SaveSaveSaveSave would be making claims about "exposure" without the entity-resolution quality that makes such claims meaningful. This is exactly the "excessive false positives" case the brief's §51 invited me to flag. Recommend explicitly: **do not build transaction/counterparty analysis until there's a specific, verified, appropriately-licensed data source for it** — not before.

---

## 7. Normalized Intelligence Model

SaveSaveSaveSave's `CHECK` shape already has 80% of what's needed:

```js
{ id, category, status: 'PASS'|'RISK'|'UNKNOWN', critical, severityWeight, label, detail, source }
```

Extending it for wallet-risk signals specifically, additively (no breaking change to existing token-security checks, which don't need these fields):

```js
{
  id, category, status, critical, severityWeight, label, detail, source,   // existing, unchanged
  attributionType: 'direct_designation' | 'direct_counterparty' | 'community_report' | 'provider_verified' | null,
  confidence: 0.0-1.0 | null,        // present for probabilistic sources (Chainabuse), absent for deterministic ones (OFAC exact match)
  firstSeen: null,                   // ISO8601 string when known
  lastSeen: null,                    // ISO8601 string when known
  evidenceRef: null,                 // opaque reference to source's own record ID, not the evidence itself
}
```

Every new field is optional and defaults to `null`/absent for existing EVM/Solana/Sui/TRON checks that don't have this data — this is additive, not a rewrite of the evidence model, matching how `criticalDefsTotal` and `liquiditySummary` were added in earlier phases of this project without disturbing existing tests.

**On the taxonomy list itself** (SANCTIONS, SCAM, PHISHING, etc.): the brief's proposed list is reasonable but has one real problem — it mixes *category* (what kind of harm) with *attribution type* (how confident/direct the claim is) in a single flat enum. Recommend keeping category (`SANCTIONS`, `SCAM`, `PHISHING`, `MIXER_EXPOSURE`, etc.) as `check.category`, and attribution type as the new separate `attributionType` field above — this is a materially better model than one enum trying to carry two independent dimensions, and it's what allows the precedence rule in §8.2 to be written as one clean condition instead of a lookup table of 20 category-specific rules.

---

## 8. Risk Scoring — Extending What's Tested, Not Replacing It

### 8.1 What already exists and already works

SaveSaveSaveSave's `VerdictEngine.evaluate()` already implements exactly the layered model the brief asks for in §12-13, verified by 56 passing regression tests:

- **Hard-stop / critical override**: a single `critical: true` RISK check forces `FAIL` regardless of aggregate score — already built, already the mechanism that resolved the exact "20 weak signals shouldn't outvote 1 strong one" concern in §13 of the brief, for a different signal type (confirmed honeypots) but the identical mathematical problem.
- **Coverage-based `INSUFFICIENT DATA`**: below a coverage threshold, the engine refuses a confident-looking verdict rather than defaulting to PASS — already built, already the mechanism that answers §30 of the brief ("provider unavailable must never silently become LOW_RISK").
- **Additive scoring** for non-critical signals — already built.

### 8.2 What's genuinely new: attribution-type precedence

The one real gap for wallet-risk specifically: today, all `critical: true` checks are treated equally. Sanctions and community-reported scams should not be. Recommended precedence rule, as a small addition to `VerdictEngine.evaluate()`:

```
IF any check has attributionType === 'direct_designation' AND status === 'RISK':
    -> FAIL, unconditionally (unchanged critical-override behavior, now scoped explicitly to this case)
ELSE IF any check has attributionType === 'direct_counterparty' AND status === 'RISK':
    -> contributes high severityWeight (e.g. 3), same additive path non-critical EVM checks already use
ELSE IF any check has attributionType === 'community_report':
    -> contributes weight scaled by confidence (e.g. severityWeight * confidence), never alone sufficient for FAIL
    -> multiple independent community_report checks do NOT multiply into a critical override -- this is the explicit
       answer to the brief's "20 weak reports must not outvote 1 verified sanction" requirement
```

This is a genuine, bounded extension of tested logic — not a new scoring framework. It should ship with its own regression tests the same way every other verdict-engine change in this project has, including the specific adversarial case the brief names: a synthetic record with many `community_report` checks and zero `direct_designation` checks must resolve to at most `CAUTION`, never `FAIL`.

### 8.3 Risk levels vs. confidence vs. data completeness — the brief's own best idea

§14 of the brief suggests separating `risk_level` from `screening_confidence` from `data_completeness`, then immediately says "critically evaluate." I agree with the separation and recommend keeping it — SaveSaveSaveSave already has the `confidence` field (`'low'|'medium'|'high'`) in `VerdictEngine`'s output, computed from coverage and unknown-check count. It's a short step to also surface it explicitly in the UI rather than only internally, which is exactly the magic-score problem the brief's §53 warns against. Recommend: the badge stays `PASS`/`CAUTION`/`FAIL`/`INSUFFICIENT DATA` (unchanged, already well-tested and understood), and the existing coverage line ("17/18 checks completed") already partially does the job of surfacing data completeness — extending it to also show confidence explicitly is a UI-only change, not a scoring-model change.

---

## 9. Explainability

SaveSaveSaveSave already does more of this correctly than most tools in this space, by accident of its existing design philosophy: every `CHECK` already carries a human-readable `label` and `detail`, and the verdict `sub` text is already deliberately hedged language ("no major risk indicators... not a safety guarantee") rather than declarative certainty. The brief's language-guidance concern (§27) — never say "this person is a criminal," always say "this address has been associated with" — is already the house style established across every chain adapter's check `detail` text in this project (e.g., the existing `stealing_attack` check reads "Address has been associated with a stealing attack," not "this wallet stole funds"). No new writing-style work needed; the discipline already exists and should just be extended to whatever new checks get added, not reinvented.

---

## 10. API Design

Recommend **not** introducing a new versioned REST API (`/v1/wallet-screenings`, `/v1/watchlists`, etc.) at this stage. SaveSaveSaveSave is a client-side static site with a thin serverless proxy — it has no backend of its own to host such an API on, and building one would be a materially larger undertaking than everything shipped in this project so far combined (real auth, real database, real ops surface). The existing `SolanaAdapter`/`TronAdapter`/`SuiAdapter` pattern already *is* SaveSaveSaveSave's API, just expressed as an internal JS interface (`fetchChecks(addr, assetType, chainId, fetchImpl)`) rather than an HTTP one — and it's the correct level of abstraction for what SaveSaveSaveSave actually is right now.

If SaveSaveSaveSave later becomes a product with paying API customers (§45 of the brief, commercial strategy), a real HTTP API becomes justified — at that point, the endpoint shape the brief proposes (`GET /v1/addresses/{chain}/{address}/risk`) is reasonable and should explicitly require `chain` as a path segment, never inferred, for the exact reason §5 above confirms: address alone is not a unique key. That's a future-phase decision, not something to build speculatively now.

---

## 11. Database Design

Same reasoning as §10: SaveSaveSaveSave currently has **no database** — it's a static site with no server-side storage, by deliberate design (documented throughout `ARCHITECTURE.md` as a core security property: "SaveSaveSaveSave does not require an account to run a scan and does not log or store the addresses you check"). The brief's 20-table schema (`screenings`, `provider_results`, `risk_signals`, `evidence`, `watchlists`, `manual_reviews`, `audit_events`...) is well-designed **for a system that has decided to store screening history**, which is a significant product and privacy decision SaveSaveSaveSave hasn't made and shouldn't make implicitly by building out infrastructure for it.

If continuous monitoring (§13 below) is ever built, storage becomes unavoidable — a watchlist inherently requires remembering what's being watched. At that point, a much smaller schema than the brief's 20 tables is appropriate for what SaveSaveSaveSave would actually need:

```
watchlist_entries   (chain_id, address, added_at, user_ref -- minimal, no PII beyond what the address itself is)
rescreen_results    (watchlist_entry_id, checked_at, verdict, checks_json -- append-only, immutable)
```

Two tables, not twenty, until there's a demonstrated need for the rest — `entities`, `analyst_actions`, `appeals`, `manual_reviews` are compliance-case-management concepts that belong to a product with paying enterprise customers and a compliance team, not a free consumer tool's MVP monitoring feature.

---

## 12. False Positives, Attribution, and Limitations

This section deserves to be taken as seriously as the brief treats it, because it's where a wallet-risk feature can do real harm if built carelessly.

| Pattern | Why it misleads | Mitigation |
|---|---|---|
| CEX omnibus/deposit wallets | Thousands of unrelated users share one address; flagging it flags everyone | Cross-check against known-exchange label lists before surfacing as risky (GoPlus's own data may already carry exchange tags — `UNKNOWN`, worth checking the raw response) |
| Address poisoning / dust | Attacker sends a near-identical address (or trivial dust) to pollute a victim's transaction history, hoping for a copy-paste error later | SaveSaveSaveSave screens *the address the user pasted*, not their transaction history — this specific attack is largely out of scope for SaveSaveSaveSave's current model, which is a genuine advantage of *not* doing counterparty/history analysis (§6.3) |
| Bridges / DEX routers | Legitimate infrastructure interacting with huge transaction volumes, easily mistaken for suspicious "high-volume" behavior if a naive volume heuristic were added | Don't build volume-based heuristics without an allowlist of known infrastructure contracts first |
| Community reports without verification | A malicious actor can report a competitor's or an innocent address; Chainabuse itself documents spam-detection and confidence scoring for exactly this reason | This is precisely why `attributionType: 'community_report'` must never alone trigger `FAIL` (§8.2) |
| Stale labels | An address flagged in 2022 may have changed hands, or the original designation may have been reversed (Tornado Cash, §4.2) | Store `firstSeen`/`lastSeen` and, for sanctions, `effective_to` — surface recency in the explanation, not just a static flag |

**The clean-result caveat is load-bearing, not boilerplate.** SaveSaveSaveSave's existing footer language ("a PASS result is not a guarantee of safety") already covers this correctly for token security; the same discipline must extend to wallet screening verbatim — a clean wallet-screening result means *no known risk indicators were found among the sources checked*, never *this address is safe*.

---

## 13. Continuous Monitoring — Recommend Deferring, With a Specific Reason

The brief's monitoring architecture (watchlists → scheduled rescreen → change detection → alert) is well-specified and technically sound. The reason to defer it isn't technical difficulty — it's that it requires SaveSaveSaveSave to acquire exactly the thing its current architecture deliberately avoids: **persistent storage of what a specific user is watching**, which is the first genuine privacy/data-retention decision this product would make. That's a legitimate product direction, but it's a decision, not an engineering default, and it shouldn't get built as a side effect of implementing the rest of this brief. Recommend: explicitly scope this as its own future decision point, not Phase 3 of an assumed roadmap.

---

## 14. Cross-Chain Architecture

No new design needed here — SaveSaveSaveSave's adapter pattern (`EvmAdapter`, `SolanaAdapter`, `SuiAdapter`, `TronAdapter`, each implementing `{capabilities, chains, validateAddress, fetchChecks}`) is already exactly the `BlockchainAdapter` abstraction the brief asks for in §25, already proven across four genuinely different address formats and security models. Wallet-risk screening for Solana already exists (re-enabled earlier in this project after being verified against GoPlus's own documentation). Extending wallet risk to Sui or TRON would follow the identical, now well-worn pattern: verify the data source exists and what it actually returns before writing code — not, per this project's own hard-learned lesson, before.

---

## 15. Privacy and Legal Considerations

**Not legal advice; the following identifies what requires qualified counsel rather than attempting to answer it.**

- **GDPR / personal data**: a blockchain address is not inherently personal data, but a *report* about an address (especially one naming a specific person, as Chainabuse reports sometimes do) may constitute personal data under GDPR once combined with identifying context. `REQUIRES LEGAL REVIEW` before displaying any provider's free-text report content verbatim to end users.
- **Defamation/reputational risk**: this is the single highest-stakes legal question in the entire brief. Displaying "this address has been reported for fraud" based on an unverified community report, without adequate hedging, creates real exposure if the report is wrong. SaveSaveSaveSave's existing hedged-language discipline (§9) mitigates but does not eliminate this. `REQUIRES LEGAL REVIEW`, specifically: whether current footer/disclaimer language is sufficient once *third-party accusatory content* (not just SaveSaveSaveSave's own security-check results) is being surfaced.
- **Redistribution rights**: whether SaveSaveSaveSave can display Chainabuse report content (not just a yes/no flag) requires reading Chainabuse's actual API terms of service, which is `REQUIRES VENDOR CONFIRMATION` — not reviewed in this session beyond confirming the API's existence.
- **Sanctions data**: US government works (including OFAC's SDN list) are generally public domain and free of redistribution restriction — `STRONGLY SUPPORTED`, standard US government-works doctrine — but this is a general legal principle, not a substitute for confirming it applies cleanly to SaveSaveSaveSave's specific intended use.

---

## 16. Security Considerations

SaveSaveSaveSave already has a documented, tested security posture (`ARCHITECTURE.md`): no custody, no private keys, every external input treated as untrusted, escaped/sanitized before rendering. Extending to a Chainabuse integration inherits this automatically if built the same way as every existing adapter — the same `escapeHtml`/`stripSpoofChars` discipline already applied to GoPlus token names must apply to any free-text content surfaced from Chainabuse reports, since report text is even more directly attacker-influenced (a malicious reporter controls the report text) than a token's on-chain metadata already was. **This is not a new security concern — it's the same XSS lesson from the Solana token-name incident earlier in this project, applied to a new untrusted-text source.**

---

## 17. Cost Model

Per the brief's own instruction: where pricing isn't public, state that rather than invent a number.

| Volume | GoPlus (existing, free tier) | OFAC (self-hosted index) | Chainabuse |
|---|---|---|---|
| 1,000/mo | Free, within known 30/min limit if paced | Free (own infra: negligible compute for a small indexed file) | `UNKNOWN` — pricing not publicly disclosed for API tier beyond "free" |
| 10,000/mo | Free tier likely sufficient if traffic is spread; `UNKNOWN` at what volume GoPlus would require a paid key | Free | `UNKNOWN` |
| 100,000+/mo | `REQUIRES VENDOR CONFIRMATION` — GoPlus's paid tier terms not reviewed this session | Free (scales with storage, not requests, since it's a local index) | `UNKNOWN` |

**Formula for future estimation once real pricing is confirmed:** `monthly_cost = sum over providers of (requests_per_screening x screenings_per_month x cost_per_request)` — trivial once the unknowns are filled in, not worth padding with invented numbers now.

---

## 18. MVP Specification

Challenging the brief's own suggested MVP (§35: sanctions + one intelligence source + community reports + normalized signals + scoring + explanation) — this is close, but overstates what's actually new, since "one intelligence source" and "normalized signals + scoring + explanation" already exist and shouldn't be re-scoped as if starting over.

**Actual recommended MVP — the delta from today, only:**

1. Self-hosted OFAC digital-currency-address index (batch-ingested, address-exact-match only, no fuzzy name matching).
2. Chainabuse public API as a second EVM wallet-screening signal, added as a new `CHECK` alongside the existing GoPlus-derived ones.
3. The `attributionType` field and precedence rule from §8.2, with regression tests proving the "many weak reports can't outvote one sanction" property — the same discipline as every other verdict-engine change in this project.
4. UI: surface `attributionType`/source distinctly per check (already structurally possible — `checkRow()` already renders a `source` string per check; extending it to also show attribution type is a small, additive UI change).

Everything else in the original 56-point brief — provider abstraction layer, watchlists, graph analysis, ML, a formal API, a database — is Phase 2 or later, and several items (full transaction/counterparty tracing specifically) are recommended against outright per §6.3, not merely deferred.

---

## 19. Implementation Roadmap

| Phase | Scope | Complexity | Main dependency | Effort (rough order of magnitude) | Biggest risk |
|---|---|---|---|---|---|
| **0 — Verify** | Confirm Chainalysis's free sanctions oracle contract address/ABI; confirm Chainabuse's exact auth/rate-limit terms from live docs, not summary | Low | None | Hours, not days | Skipping this and building on assumption — exactly the mistake this project already made once with Solana wallet screening |
| **1 — MVP (§18)** | OFAC index + Chainabuse signal + attribution precedence | Medium | Phase 0 confirmed | Comparable to one chain adapter build (this project's Solana or Sui adapter is a reasonable reference point) | OFAC parsing edge cases (delisted addresses, alt-address entries like Tornado Cash's eight variants) |
| **2 — Monitoring (optional, separate decision)** | Watchlists, scheduled rescreen | Medium-High | A genuine product/privacy decision to start storing data, not just engineering | Meaningfully larger than Phase 1 — first persistent storage in the product's history | Privacy/retention policy must exist *before* code, not after |
| **3 — Second commercial provider** | Only if a specific verified, appropriately-priced source is found | Unknown until Phase 0-equivalent research is done for that specific provider | A sales conversation, realistically | `UNKNOWN` | Vendor lock-in, cost at scale, redistribution licensing |
| **4 — Graph/ML/cross-chain wallet risk** | Recommend against building independently — see §6.3, §22 | High | Would require licensed, entity-resolved data SaveSaveSaveSave doesn't have a path to | Large | Producing a worse, false-positive-prone imitation of what paid providers already do well |

---

## 20. Testing Strategy

Extends the existing 56-test regression suite pattern directly, not a new test framework:

- **Precedence rule**: the adversarial case from §8.2 (many weak community reports, zero direct designations → must not exceed `CAUTION`) as a named regression test, same style as the existing "critical hit despite sparse data" tests.
- **OFAC parsing**: a fixed corpus of real historical SDN entries (Tornado Cash's eight addresses, both as designated and as delisted) as literal test fixtures — this is public-domain government data, so no licensing concern in maintaining it as a permanent test corpus, unlike a commercial provider's data would be.
- **Chainabuse response shape**: mocked-fetch tests the same way the Solana wallet-screening fallback was tested (`mockFetch` returning canned JSON), not a live-API test in CI.

---

## 21. UX Recommendation

SaveSaveSaveSave's existing two-tier structure — plain-language verdict + collapsible raw evidence — already is the "simple view / advanced view" split the brief asks for in §39. No new UX pattern needed; extend the existing `checkRow()` rendering to include the new `attributionType`/`confidence` fields in the advanced (raw JSON) view, and fold the strongest new signal (a direct sanctions hit) into the existing plain-language verdict text exactly the way a confirmed honeypot already overrides everything else today.

---

## 22. AI/ML Assessment

**Recommend against ML for the scoring/decision path**, for a specific reason beyond general skepticism: SaveSaveSaveSave's core, hard-won architectural property across this entire project is that a verdict must be *reconstructable* — the same input produces the same output, traceable to specific rules. A trained model with continuous retraining breaks exactly that property, and reproducibility is what makes the "why was this HIGH_RISK" question (brief §54) answerable at all. Deterministic rules over a small number of well-understood signal types, which is what SaveSaveSaveSave has today and what this document proposes extending, remain the right choice until the signal count and complexity genuinely exceed what rules can express — which is not close to true yet.

**Where an LLM could help, safely, bounded exactly as the brief's §42 suggests**: turning an existing `CHECK` array into a plain-language summary for the advanced view, or answering a user's follow-up question about a result — *never* generating a risk score, never inventing a signal, never overriding the deterministic engine. This would be a presentation-layer feature, strictly downstream of the verdict engine, not a replacement for any part of it.

---

## 23. Competitive Positioning

SaveSaveSaveSave's actual differentiator, made concrete rather than asserted: **most consumer-facing "wallet checker" tools quietly resell one provider's opaque score.** SaveSaveSaveSave's existing architecture — every check individually labeled with its source and reasoning, a verdict engine whose precedence rules are documented and tested in the open, an explicit `INSUFFICIENT DATA` state instead of a false-confidence default — is a genuinely different product shape, already built, not aspirational. That's worth stating as the actual competitive position rather than a generic "multi-source intelligence" claim, because it's specific and already true.

---

## 24. Final Recommendation

### 24.1 Executive decision table

| Decision | Recommendation | Confidence | Reason |
|---|---|---:|---|
| Build this feature? | Already built (v1); extend, don't restart | High | `EVM_WALLET_CHECK_DEFS` is shipped and tested |
| MVP scope | OFAC address index + Chainabuse signal + attribution precedence | High | Both sources verified free/public; bounded engineering scope |
| Primary provider | GoPlus (already integrated) | High | Free, proven, already covers most of the threat taxonomy |
| Secondary provider | Chainabuse | Medium | Public API confirmed; exact rate limits/ToS need direct confirmation |
| Sanctions source | Self-hosted OFAC SLS index | High | Free, authoritative, address-level data confirmed |
| Community intelligence | Chainabuse, weighted low, never alone critical | Medium | Community reports are real signal but must never trigger a hard `FAIL` alone |
| Proprietary scoring | No — extend existing `VerdictEngine`, don't replace it | High | Already tested across 4 chains; replacing it discards proven work |
| Graph analysis | No, not now | High | Requires entity-resolution quality SaveSaveSaveSave has no path to without a paid provider |
| Continuous monitoring | Defer — separate product/privacy decision first | Medium | First persistent-storage decision in the product's history; shouldn't be a side effect |
| Human review | Required for any dispute/correction process, not for routine scans | High | Routine scans are deterministic rule application; disputes involve judgment |
| ML | No, for scoring | High | Breaks reproducibility, the project's core architectural property |
| LLM | Yes, presentation-layer only | Medium | Safe if strictly downstream of the deterministic engine |
| Cross-chain (wallet risk) | Follow existing adapter pattern when a verified source exists | High | Proven pattern, four times over |
| Own data | Yes, for OFAC (self-indexed) | High | Free, public-domain, no redistribution concern |
| Third-party data | Yes, for GoPlus/Chainabuse, referenced not redistributed | High | Display attribution, don't claim it as SaveSaveSaveSave's own finding |

### 24.2 The architecture I would actually build

1. User pastes an EVM address, same entry point as today.
2. `detectEcosystem()` + `validateAddress()` confirm it's EVM (unchanged, existing code).
3. `runScan()` fires the existing GoPlus wallet-screening call (unchanged) **in parallel with** a new local-index OFAC lookup and a new Chainabuse API call.
4. OFAC lookup: exact-match the address against a pre-ingested, address-only index built from the SLS feed — sub-millisecond, no network call at scan time.
5. Chainabuse call: real-time API request, same timeout/retry pattern already built for GoPlus.
6. Each source produces `CHECK` objects using the existing model, extended with `attributionType`/`confidence`/`firstSeen`/`lastSeen`.
7. A direct OFAC match sets `attributionType: 'direct_designation'`.
8. A GoPlus `sanctioned` flag — already existing — is treated the same way, since it's provider-verified, not community-sourced.
9. A Chainabuse hit sets `attributionType: 'community_report'`, with `confidence` populated from Chainabuse's own verification signal if the API exposes one.
10. All `CHECK`s merge into one array, same shape `VerdictEngine.evaluate()` already consumes.
11. `VerdictEngine` gains the precedence rule from §8.2 — one small, tested addition, not a rewrite.
12. A `direct_designation` RISK check triggers `FAIL`, unconditionally, same override mechanism already proven.
13. `community_report` checks contribute confidence-weighted score, capped so they can never alone reach `FAIL`.
14. If OFAC lookup or Chainabuse call fails, that source's coverage simply doesn't count toward `checksValid` — the existing `INSUFFICIENT DATA` machinery handles a failed source exactly like it already handles any missing check, no new failure-handling code needed.
15. `renderPass()` displays the verdict using existing badge/coverage-line rendering, with each check's `source` and (new) `attributionType` visible in the checklist, same pattern as today's `source: 'GoPlus Security (EVM)'` labels.
16. The raw-JSON "View raw API response" panel extends to include all three sources' raw responses, not just GoPlus's — same disclosure discipline already applied everywhere else in the product.
17. Regression suite gains: the precedence adversarial test, OFAC parsing tests against the real Tornado Cash fixture, and mocked-Chainabuse tests — extending the existing 56-test suite, not starting a new one.
18. `ARCHITECTURE.md` gains a section documenting this exactly the way every other addition in this project has been documented — what was verified, what wasn't, and why the design decisions were made.

Eighteen steps, almost all of them extending tested code that already exists, rather than the 10-component enterprise pipeline the original brief sketched. That's the actual disagreement this document is making: **the mature version of this feature is real and worth building, but it's an extension of SaveSaveSaveSave's existing, working architecture — not a parallel system next to it.**
