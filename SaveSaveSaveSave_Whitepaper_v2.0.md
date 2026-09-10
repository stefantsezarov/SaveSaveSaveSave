# SaveSaveSaveSave — A Transparent Risk Tool for Everyone in Crypto

**Verified. Constantly Improving.**

*Whitepaper v2.0 — September 2026*
*Formerly RiskPass*

> Four chains. Four data sources. Four reasons for the name: save your funds, save your time, save your trust, save the regret.

---

## 1. Executive Summary

Crypto is easy to get into and hard to get right. Anyone can send a transaction in thirty seconds. Almost no one gets a clear answer to the question that actually matters: *how risky is what I'm about to do?*

SaveSaveSaveSave answers that question. It checks a wallet or token against real security data — honeypot detection, mint authority, sanctions designations, malicious-address intelligence, and on-chain transfer patterns — and returns a plain verdict: **PASS, CAUTION, FAIL, or INSUFFICIENT DATA.** Not a price prediction. Not financial advice. A risk read, in seconds, before you act.

This edition documents a materially different product from the one the previous whitepaper described. What was a single-chain EVM tool is now a four-ecosystem screening engine — EVM (14 chains), Solana, Sui, and TRON — with wallet-risk intelligence that goes beyond a single vendor's opaque score: a free, independently-verified on-chain sanctions oracle, malicious-address screening across two ecosystems, and a bounded, honestly-labeled check for recent exposure to sanctioned counterparties. Every claim in this document is a claim about what is actually built and tested, not a roadmap dressed up as a feature list.

**Who it's for:**
- People new to crypto, who shouldn't need to know what a "honeypot" or "mint authority" is before their first transaction is safe.
- Retail traders and small merchants, who need a fast, trustworthy check before interacting with something unfamiliar.
- Institutions and funds, who need a transparent, auditable risk layer — one they can inspect, not one they have to trust blindly.

**How it works, in one line:** you give SaveSaveSaveSave an address, it checks that address against real, cited security data across as many relevant sources as are available for that chain, and it gives you a conservative, evidence-backed verdict — one that would rather say "we don't know" than guess wrong.

---

## 2. The Name

A name built from one word repeated four times invites a fair question: why? The honest answer is that it's a deliberate structural choice, not an accident of branding, and it maps onto four things the product actually does, not four abstractions invented to justify a word count.

**Save your funds.** The core function, unchanged since the first version: catch honeypots, malicious contracts, mint-authority abuse, and sanctioned or malicious-address exposure before a transaction is signed, not after.

**Save your time.** One scan, one interface, four blockchain ecosystems, and — where the chain supports it — multiple independent data sources queried in parallel rather than one search per explorer, per chain, per concern.

**Save your trust.** Every verdict shows its receipts. Each check states its source, and a PASS is never presented as a safety guarantee — it states plainly what was checked and what wasn't. Nothing here asks for blind confidence.

**Save the regret.** The two newest capabilities — the Chainalysis Sanctions Oracle integration and recent counterparty checking — exist specifically to catch the thing a user would otherwise only discover after the money has already moved: that a wallet transacted, recently, with an address the world now knows is sanctioned.

Four repetitions, four real pillars. The typographic treatment on the site reflects this directly — four instances of the word, each weighted differently, the last resolving into the brand's accent color, meant to read as a deliberate cascade rather than a repeated string.

---

## 3. The Problem: Why Crypto Risk Is Still Invisible by Default

### Where people actually get hurt

It's rarely the dramatic story. The common failure isn't "the market crashed" — it's smaller, quieter, and almost always preventable in hindsight:

- Someone buys a token and only later learns they can't sell it back — the contract was built that way from the start.
- Someone sends funds to an address that turns out, on public record, to be sanctioned — and finds out only when an exchange freezes the deposit.
- Someone connects their wallet to a project shared by a friend, without knowing what permissions they just granted.
- Someone holds a portfolio concentrated in one asset without realizing it, because no tool ever surfaced that number plainly.

None of these require bad luck. They require the absence of one thing: a clear, honest signal *before* the decision, not an explanation after.

### The tools that exist don't fill the gap

A person trying to check risk today has, broadly, two options. Price charts and trackers tell you what happened to a price — nothing about whether a contract can trap funds, whether an address carries a sanctions designation, or whether a wallet has recently moved funds through one that does. Institutional-grade compliance platforms exist and are often genuinely good, but they are priced, scoped, and sold for enterprise compliance teams — a sales conversation and a five- or six-figure annual contract stand between an ordinary user and that data, confirmed directly against how those vendors' own products are actually sold today, not assumed.

There is very little built for the space between those two — evidence-based and legible to someone without a compliance background. That gap is what this product exists to fill.

---

## 4. Architecture: What "Evidence-Based" Actually Means Here

SaveSaveSaveSave is built around a single, non-negotiable evidence model, applied identically whether the address is an Ethereum token, a Solana wallet, or a TRON contract:

- **Absence of evidence is never evidence of safety.** If a check couldn't be completed, that fact is surfaced — the result is `INSUFFICIENT DATA`, not a quiet PASS.
- **A single confirmed critical finding overrides everything else.** A confirmed honeypot, a direct sanctions match, or equivalent high-severity evidence forces a FAIL verdict regardless of how many other checks came back clean — accumulated positive signals cannot outvote one verified critical one.
- **Every chain is evaluated on its own native security model, not a shared template forced across ecosystems.** An EVM token's mint-authority check has no equivalent meaning on Solana, where authority revocation works differently; Sui's contract-function schema uses a genuinely different value encoding than EVM's; TRON's deployer risk reuses the EVM schema only because it verifiably shares the same underlying data provider, not because chains were assumed to be interchangeable.
- **A PASS is a statement about coverage, not a guarantee.** Every result states how many checks returned usable data out of how many were expected, and what confidence level that coverage supports.

This isn't a design aspiration — it's enforced by a permanent, versioned regression suite that runs against the actual evidence engine before any change ships, currently standing at 61 automated tests covering malicious input, benign input, malformed and partial provider responses, contradictory indicators, and — critically — adversarial cases designed specifically to try to break the "don't let weak evidence outvote strong evidence" rule.

---

## 5. Chain Coverage: What's Actually Supported, and Why Each Was Added the Way It Was

### EVM — 14 chains

Ethereum, BNB Smart Chain, Polygon, Arbitrum, Optimism, Base, Avalanche, Fantom, zkSync Era, Linea, Scroll, Blast, Mantle, and Gnosis. Token security (honeypot detection, mint authority, ownership and blacklist mechanics, tax structure) and wallet screening are both fully supported across this set.

### Solana

A genuinely different security model, not an EVM chain with a different name. Token security checks Solana's own mechanics — mint and freeze authority, metadata mutability, transfer-hook presence — and liquidity data (pool count, combined TVL, LP-lock status) is parsed directly from the same response, surfaced as context rather than folded into the risk score. Wallet screening reuses the same underlying malicious-address data source as EVM, because address reputation — is this a known phishing or laundering address — is not a chain-specific mechanic the way contract functions are.

### Sui

Token security only, and deliberately scoped that way: the underlying data provider does not yet return holder or liquidity data for Sui by its own admission, so this product doesn't claim to check what the data doesn't cover. Sui's contract-function schema uses a value encoding genuinely distinct from every other chain supported here — both `1` and `2` signal "available" for a given function, not just `1` — caught and handled by a purpose-built classifier, not an extension of the encoding used elsewhere.

### TRON

Token security, built on the same underlying data schema as EVM after confirming — not assuming — that TRON is served by the same general-purpose endpoint family rather than a dedicated one. TRON's address format (Base58Check, always 34 characters, always beginning with `T`) is distinct enough from every other supported chain that a real disambiguation question had to be resolved: a Solana address could theoretically collide with TRON's format. The actual odds were calculated, not waved away — on the order of one in 400 quadrillion for a genuine Solana key, low enough that a deterministic ordering rule in the detection logic resolves it with certainty rather than probability.

### Aptos — evaluated, not built

Aptos is named in the underlying data provider's own marketing material as a supported chain. No dedicated technical endpoint or verifiable schema could be found to confirm that claim against primary documentation, unlike every chain actually shipped here. Rather than build against a marketing page and discover the gap later, Aptos was left out. If that changes, it will be because a real endpoint was confirmed — not because the marketing claim was trusted a second time.

### Address type is detected automatically

Paste any address from any of the four supported ecosystems, and the correct chain is selected automatically — the four address formats (EVM's `0x` plus 40 hex characters, Solana's base58 without a leading `0`, Sui's Move-type identifier containing `::`, and TRON's `T`-prefixed Base58Check) are mutually exclusive by construction, not by convention, which makes automatic detection a matter of applying four independent, non-overlapping rules rather than a best-effort guess.

---

## 6. Wallet-Risk Intelligence: Beyond a Single Vendor's Score

This is the newest and, in a specific sense, the most significant part of the product — not because it does the most, but because of how it's built.

### The premise this section starts from

Commercial blockchain-intelligence platforms — the well-known names in this space — are real, sophisticated, and in most cases entirely reasonable for what they're built to do. They are also, without exception in the direct experience of building this product, sold through enterprise sales conversations with no public self-serve pricing. That's a legitimate business model. It's also not a foundation this product can build on. The wallet-risk intelligence in this product was built specifically around sources that are genuinely free, genuinely verifiable, and don't require a contract to use.

### Malicious-address screening

The first layer: an address is checked against a maintained database covering sanctions exposure, phishing and wallet-draining association, theft and exploit involvement, money-laundering and mixer exposure, dark-web transaction history, and cybercrime or extortion association. Available for EVM and Solana addresses today.

### The Chainalysis Sanctions Oracle

The second layer, and the one worth explaining in real technical detail, because the verification behind it is the actual point. This is a free, publicly callable smart contract — not a paid API, not a rate-limited trial — deployed by Chainalysis across nine chains, requiring no customer relationship or API key to query. Confirmed independently, not taken on faith from a single source: the Ethereum deployment address was cross-checked against Etherscan directly, and the exact function selector needed to call it (`isSanctioned(address)`) was computed with a cryptographic hashing method that was itself sanity-tested against a universally known reference value before being trusted, then confirmed to appear, byte for byte, inside the actual deployed contract's bytecode on Etherscan. Eight of the nine chains where the oracle is deployed are supported here today, each with its own independently verified free RPC endpoint — three of which turned out to require a specific, non-obvious sub-network address rather than the chain's default one, caught by checking each one directly rather than assuming a naming pattern from the two simplest chains would hold for the rest.

This data source carries one honestly-disclosed limitation, stated plainly because Chainalysis's own documentation states it plainly: the oracle is not always immediately current. An independent technical review found real gaps — in one case, over ninety days — between an OFAC designation taking effect and the oracle reflecting it. A match against this oracle is reported as exactly that: a match against this oracle, as of the check, not an unconditional, real-time guarantee.

### Recent counterparty checking

The third and newest layer, scoped narrowly and named honestly. Standard blockchain infrastructure has no method to retrieve "all transactions for an address" — that capability doesn't exist at the protocol level, which is why entire companies exist to provide it commercially. What this product checks instead, and states plainly that it checks: recent token-transfer activity — a bounded, disclosed window, different in real time span per chain since block production speed varies enormously between them — cross-referenced against the same sanctions oracle above. If a wallet sent or received tokens directly to or from a sanctioned address within that window, it's reported, with the transaction hash included as evidence.

This is deliberately not "transaction history" and doesn't claim to be. Native transfers of a chain's own base asset aren't visible to this method at all, and activity outside the checked window isn't covered. The verdict math reflects the same restraint: a single sanctioned counterparty moves the result to a cautionary state, not an automatic fail — that override is reserved for the wallet's own address being directly designated. Two or more counterparties escalate the result further, through the same ordinary scoring logic used everywhere else, not a special case written just for this feature.

---

## 7. Transparency by Design

Every result is built to answer a question a user should be allowed to ask: *why?*

- **Every check names its source.** A result never says "risky" without saying which provider, and for the newest checks, which specific on-chain contract, produced that finding.
- **Coverage is stated, not implied.** "17 of 18 checks completed" is shown plainly, not buried in fine print.
- **Confidence is separate from the verdict.** A clean result reached with full coverage reads differently from one reached with partial coverage, and the interface says so.
- **Raw provider responses are one click away.** Nothing is summarized in a way that can't be checked against the underlying data it came from.

---

## 8. Limitations, Stated Plainly

A tool built around honest evidence has to be honest about its own limits.

**A clean result is not a safety guarantee.** It means no flags were found among the indicators actually checked — not that none exist anywhere.

**Blockchain addresses are pseudonymous.** One entity may control many addresses; one address may be shared by many people or services. None of the checks here claim to resolve identity.

**Community and provider labels can be wrong, and can change.** A designation added today can be reversed tomorrow — the Chainalysis oracle's own real-world staleness gap is evidence of exactly this kind of lag, documented above rather than glossed over.

**Interaction with a flagged address is not proof of wrongdoing.** Funds can pass through an address without the recipient knowing their origin. This product reports exposure as exposure, and states explicitly that exposure is not the same claim as guilt.

**Coverage varies by chain, and that variance is disclosed, not hidden.** Wallet screening, liquidity data, and counterparty checking are not uniformly available across all four ecosystems, and the interface reflects exactly which chain supports which check rather than presenting a false uniform experience.

---

## 9. What's Next

Two categories of future work, kept honestly separate. The first is scoped, verified, and next in line: expanding counterparty checking's chain coverage as more RPC infrastructure is verified, and reconsidering Aptos if a real, documented data source is ever confirmed. The second is real, well-specified, and deliberately not yet started: continuous monitoring (watchlists, scheduled re-screening, alerting) has a complete architectural design already written, and was deliberately not built yet — because it requires this product to begin storing what a user is watching, the first genuine data-retention decision in its history, and that's a decision to make on purpose, not a side effect of building a feature.

---

## 10. Closing

Most tools in this space ask for trust. This one is built to need less of it — every verdict shows its sources, every limitation is stated instead of buried, and every technical claim in this document was verified against a primary source before being written down, not assumed because it sounded right. Four chains, several independently verified data sources, one evidence model applied consistently across all of them. Verified, because a security tool that asks to be trusted has an obligation to earn it. Constantly improving, because the risk landscape doesn't hold still, and neither should the tool built to read it.
