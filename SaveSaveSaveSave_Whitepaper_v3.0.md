# SaveSaveSaveSave — A Transparent Risk Tool for Everyone in Crypto

**Verified. Constantly Improving.**

*Whitepaper v3.0 — September 2026*

> Four chains. Two scanners. One rule that decides what a mixed result means: the worst part controls the answer, and nothing outvotes it.

---

## 1. Executive Summary

Crypto is easy to get into and hard to get right. Anyone can send a transaction in thirty seconds. Almost no one gets a clear answer to the question that actually matters: *how risky is what I'm about to do?*

SaveSaveSaveSave answers that question in two directions at once, because that is how the risk actually arrives.

**The address scanner** checks a wallet or token against real security data — honeypot detection, mint authority, sanctions designations, malicious-address intelligence, and on-chain transfer patterns — and returns a plain verdict: **PASS, CAUTION, FAIL, or INSUFFICIENT DATA.**

**The message scanner**, new in this edition, reads the thing that arrived *before* the address did: the Telegram message, the support-chat reply, the airdrop announcement, the prompt someone asks you to paste into an AI assistant. It looks for hidden instructions, invisible characters, disguised links, requests for secrets, and the pressure tactics that make people skip checking — and it does all of it inside your browser, without sending the text anywhere.

Neither is financial advice. Neither is a price prediction. Both are risk reads, in seconds, before you act.

This edition documents a materially wider product than v2.0 described. The previous edition documented a four-ecosystem address-screening engine. This one adds a second, independent detection engine for text, a bridge that carries addresses found in a message straight into the chain scanner, and — the part that matters most when a message contains several things at once — a formally specified model for combining separate scans without averaging them into a single misleading number.

**Who it's for:**

- People new to crypto, who shouldn't need to know what a "honeypot" or a "prompt injection" is before their first transaction is safe.
- Retail traders and small merchants, who need a fast, trustworthy check before interacting with something unfamiliar.
- Anyone who has been sent a message that felt slightly wrong and had no way to find out why.
- Institutions and funds, who need a transparent, auditable risk layer — one they can inspect, not one they have to trust blindly.

**How it works, in one line:** you give SaveSaveSaveSave an address or a message, it checks each part against real, cited evidence, and it gives you a conservative, evidence-backed verdict — one that would rather say "we don't know" than guess wrong.

**What this product is not:** the only tool in this space. Commercial blockchain-intelligence platforms, browser wallet warnings, security extensions and simulation tools all exist, and several of them are good. What is uncommon here is the combination — free, self-serve, evidence-first, honest about coverage, and covering both the address and the message that carried it — not the individual capability.

---

## 2. The Name

A name built from one word repeated four times invites a fair question: why? The honest answer is that it's a deliberate structural choice, not an accident of branding, and it maps onto four things the product actually does.

**Save your funds.** Catch honeypots, malicious contracts, mint-authority abuse, and sanctioned or malicious-address exposure before a transaction is signed, not after.

**Save your time.** One scan, one interface, four blockchain ecosystems, and — where the chain supports it — multiple independent data sources queried in parallel rather than one search per explorer, per chain, per concern.

**Save your trust.** Every verdict shows its receipts. Each check states its source, and a PASS is never presented as a safety guarantee — it states plainly what was checked and what wasn't.

**Save the regret.** The newest capabilities exist specifically to catch the thing a user would otherwise only discover after the money has already moved: that a wallet transacted with an address the world now knows is sanctioned, or that the "verification link" in a message was never going where it appeared to go.

Four repetitions, four real pillars. The wordmark reflects this directly — four instances of the word, each weighted differently, the last resolving into the brand's accent color, meant to read as a deliberate cascade rather than a repeated string.

---

## 3. The Problem: Why Crypto Risk Is Still Invisible by Default

### Where people actually get hurt

It's rarely the dramatic story. The common failure isn't "the market crashed" — it's smaller, quieter, and almost always preventable in hindsight:

- Someone buys a token and only later learns they can't sell it back — the contract was built that way from the start.
- Someone sends funds to an address that turns out, on public record, to be sanctioned — and finds out only when an exchange freezes the deposit.
- Someone connects their wallet to a project shared by a friend, without knowing what permissions they just granted.
- Someone receives a message from "support" that looks ordinary, follows a link whose real destination was hidden in plain sight, and signs something they never read.
- Someone pastes a block of text into an AI assistant because a stranger said it would help — and the text contains instructions aimed at the assistant, not at them.

None of these require bad luck. They require the absence of one thing: a clear, honest signal *before* the decision, not an explanation after.

### The attack arrives as text before it arrives as an address

Almost every loss in the list above has a document in front of it. A message, a post, a DM, a prompt. By the time a user has an address to check, they have usually already been persuaded — and a scanner that only reads addresses can only ever meet them at the last step.

That is why v3.0 adds a scanner for the step before. The techniques it looks for are not exotic: text hidden with characters that render as nothing, instructions addressed to an AI system rather than to the reader, a domain that carries a trusted brand name somewhere it has no authority, a request for a recovery phrase phrased as a routine verification. They work because they are invisible to a quick human read, not because they are sophisticated.

### The tools that exist don't fill the gap

Price charts and trackers tell you what happened to a price — nothing about whether a contract can trap funds or whether a wallet has recently moved funds through a sanctioned one. Institutional-grade compliance platforms exist and are often genuinely good, but they are priced, scoped, and sold for enterprise compliance teams. Text-safety tooling exists too, mostly aimed at platform operators and model providers rather than at the person holding the phone.

There is very little built for the space between those — evidence-based, self-serve, and legible to someone without a compliance background. That gap is what this product exists to fill. It is not the only attempt; it is a specific one, with its scope written down.

---

## 4. Architecture: What "Evidence-Based" Actually Means Here

SaveSaveSaveSave is built around a single, non-negotiable evidence model, applied identically whether the subject is an Ethereum token, a Solana wallet, a TRON contract, or a pasted message:

- **Absence of evidence is never evidence of safety.** If a check couldn't be completed, that fact is surfaced — the result is `INSUFFICIENT DATA`, not a quiet PASS.
- **A single confirmed critical finding overrides everything else.** A confirmed honeypot, a direct sanctions match, or a confirmed instruction-override payload forces a FAIL regardless of how many other checks came back clean. Accumulated positive signals cannot outvote one verified critical one.
- **Every subject is evaluated on its own model, not a shared template.** An EVM token's mint-authority check has no equivalent meaning on Solana. A message's rule set has no equivalent meaning on a contract. Nothing is forced to look uniform for presentational convenience.
- **A PASS is a statement about coverage, not a guarantee.** Every result states how much of what was expected actually returned usable data, and what confidence that coverage supports.

This isn't a design aspiration. It is enforced by a permanent, versioned test suite that runs against the real engines before any change ships — **308 automated assertions** at the time of writing, described in §9.

---

## 5. Chain Coverage: What's Actually Supported, and Why Each Was Added the Way It Was

### EVM — 14 chains

Ethereum, BNB Smart Chain, Polygon, Arbitrum, Optimism, Base, Avalanche, Fantom, zkSync Era, Linea, Scroll, Blast, Mantle, and Gnosis. Token security (honeypot detection, mint authority, ownership and blacklist mechanics, tax structure) and wallet screening are both fully supported across this set.

### Solana

A genuinely different security model, not an EVM chain with a different name. Token security checks Solana's own mechanics — mint and freeze authority, metadata mutability, transfer-hook presence — and liquidity data (pool count, combined TVL, LP-lock status) is parsed from the same response and surfaced as context rather than folded into the risk score. Wallet screening reuses the same malicious-address data source as EVM, because address reputation is not a chain-specific mechanic the way contract functions are.

### Sui

Token security only, and deliberately scoped that way: the underlying data provider does not yet return holder or liquidity data for Sui by its own admission. Sui's contract-function schema uses a value encoding genuinely distinct from every other chain supported here — both `1` and `2` signal "available" for a given function — caught and handled by a purpose-built classifier rather than an extension of the encoding used elsewhere.

### TRON

Token security, built on the same underlying data schema as EVM after confirming — not assuming — that TRON is served by the same general-purpose endpoint family. TRON's address format (Base58Check, 34 characters, always beginning with `T`) raised a real disambiguation question against Solana's base58 format. The odds of a genuine collision were calculated rather than waved away — on the order of one in 400 quadrillion — and resolved with a deterministic ordering rule rather than left to probability.

### Aptos — evaluated, not built

Aptos is named in the underlying data provider's own marketing material as a supported chain. No dedicated technical endpoint or verifiable schema could be found to confirm that claim against primary documentation. Rather than build against a marketing page and discover the gap later, Aptos was left out.

### Address type is detected automatically

Paste any address from any of the four supported ecosystems and the correct chain is selected automatically. The four formats — EVM's `0x` plus 40 hex characters, Solana's base58, Sui's Move-type identifier containing `::`, and TRON's `T`-prefixed Base58Check — are mutually exclusive by construction, not by convention.

---

## 6. Wallet-Risk Intelligence: Beyond a Single Vendor's Score

### The premise this section starts from

Commercial blockchain-intelligence platforms are real, sophisticated, and reasonable for what they're built to do. They are also, without exception in the direct experience of building this product, sold through enterprise sales conversations with no public self-serve pricing. That's a legitimate business model, and not a foundation this product can build on. The wallet-risk intelligence here was built specifically around sources that are free, verifiable, and require no contract to use.

### Malicious-address screening

An address is checked against a maintained database covering sanctions exposure, phishing and wallet-draining association, theft and exploit involvement, money-laundering and mixer exposure, dark-web transaction history, and cybercrime or extortion association. Available for EVM and Solana addresses today.

### The Chainalysis Sanctions Oracle

A free, publicly callable smart contract — not a paid API, not a rate-limited trial — deployed by Chainalysis across nine chains, requiring no customer relationship or API key. Verified independently rather than taken on faith: the Ethereum deployment address was cross-checked against Etherscan directly, and the function selector needed to call it (`isSanctioned(address)`) was computed with a hashing method that was itself sanity-tested against a known reference value, then confirmed byte for byte inside the deployed contract's bytecode. Eight of the nine deployed chains are supported here, each with its own independently verified free RPC endpoint — three of which required a specific, non-obvious sub-network address rather than the chain's default.

One limitation is disclosed plainly, because Chainalysis's own documentation discloses it: the oracle is not always immediately current. An independent technical review found real gaps — in one case over ninety days — between an OFAC designation taking effect and the oracle reflecting it. A match is reported as exactly that: a match against this oracle, as of the check, not an unconditional real-time guarantee.

### Recent counterparty checking

Standard blockchain infrastructure has no method to retrieve "all transactions for an address" — that capability doesn't exist at the protocol level, which is why entire companies exist to provide it commercially. What this product checks instead, and says plainly that it checks: recent token-transfer activity — a bounded, disclosed window, different in real time span per chain — cross-referenced against the same sanctions oracle. If a wallet sent or received tokens directly to or from a sanctioned address within that window, it is reported, with the transaction hash as evidence.

This is deliberately not "transaction history". Native transfers of a chain's base asset are not visible to this method at all, and activity outside the window isn't covered. The verdict math reflects the same restraint: a single sanctioned counterparty moves the result to caution, not an automatic fail — that override is reserved for the wallet's own address being directly designated.

---

## 7. The Message and Prompt Safety Scan

New in v3.0. A second detection engine, sharing the page with the address scanner but sharing none of its pipeline.

### What it is

Paste any text — a message, a DM, an email, a post, or a prompt someone wants you to give an AI assistant — and it is analysed for the techniques that are used to make people act against their own interest. It reads the text the way a spell-checker does. **It never executes anything, never sends the text anywhere, never calls a language model, and never stores it.** The analysis happens in your browser, and the text does not leave it.

That last property is not a convenience. A tool that asks people to paste suspicious messages, some of which contain their own private information, has no business collecting them.

### What it detects

Twenty-five deterministic rules across six families:

1. **Hidden and invisible characters.** Zero-width characters, bidirectional overrides that reorder what you see, and the Unicode Tags block — a range of codepoints that render as nothing at all and can carry an entire hidden instruction inside an innocuous sentence. Homoglyph substitution, where a Latin letter is replaced by an identical-looking character from another script, is detected in the same pass.
2. **Hidden markup.** Instructions concealed in HTML comments, in elements styled to be invisible, or in attributes that a reader never sees but a system might.
3. **Encoded payloads.** Base64 and similar encodings carrying text that is not meant to be read by the person pasting it.
4. **Instruction override.** The family usually called prompt injection: text addressed to an AI system rather than to the reader — cancel your previous instructions, ignore your rules, you are now a different assistant, do not mention this to the user. Including attempts aimed at this scanner itself, which are treated as the strongest finding in the report rather than as an error.
5. **Credential solicitation.** Requests for a seed phrase, recovery words, a private key, a password, or a two-factor code, in any of the phrasings that are used to make them sound routine.
6. **Link structure.** Addresses that hide their real destination before an `@` sign, bare IP hosts, punycode domains that display as a different name entirely, shorteners, brand names placed somewhere in a URL other than the part that actually determines ownership, and long encoded query payloads.

Every finding carries a rule identifier, a severity, a confidence, the exact character offsets where it matched, and a plain-English explanation of what the technique is and why it works.

### Education is not execution

The single hardest problem in this engine, and the one with the most tests behind it. "Never share your seed phrase with anyone" and "send me your seed phrase to verify your wallet" contain almost the same words. A scanner that flags the first one is worse than useless: it trains people to ignore it.

The engine separates them with a directive score — whether the text refers to a technique or instructs the reader to perform it — combined with explicit handling of advisory negation. This was not right the first time. An early version returned FAIL on a legitimate security article about seed-phrase safety, which is exactly the failure mode described above. It was caught by an adversarial review file that scores the engine against a careful human reading, and that file is now a permanent part of the test suite.

### What it does not do

Stated as plainly as the coverage, and shown on every result rather than only in this document:

- **No meaning-level analysis.** Detection is pattern-based. A technique phrased in an unusual way can pass unnoticed. This is a floor, not a ceiling.
- **Links are read, never visited.** No address in the text is opened and no reputation service is consulted, because visiting an address a stranger chose is itself a risk.
- **A harmless-looking prompt can still be dangerous.** Once an AI system has your files, your browser, a wallet, or the ability to act, the context supplies the danger that the text alone does not.
- **A clean result means no covered pattern matched.** It is not a statement that the message is safe.

---

## 8. From a Message to an Address: the Bridge, and How Mixed Results Are Handled

### The bridge

Crypto addresses found in a pasted message are extracted and offered directly to the chain scanner — EVM, Solana, Sui and TRON formats, each with its own validator — so a suspicious message and the token it is pushing can be checked in one place without the user retyping anything.

Two details matter more than they look:

- **An address lifted out of prose carries no chain.** A `0x` address could be on any of fourteen EVM chains. Rather than silently guessing, the row defaults to Ethereum, says "chain not stated in the text", and offers a chain picker. Changing it discards any previous result, because a result for Ethereum is not a result for BNB Chain.
- **Format collisions are resolved, not ignored.** A Bitcoin address and a Solana address are both base58. The extractor applies explicit structural guards so a Bitcoin address is not reported as a Solana one — a rule that exists because an adversarial review caught exactly that mistake.

### The combination rule

A pasted message is not one thing. It is text, plus links, plus addresses, and each gets a different check, with different coverage and different limitations. Flattening them into one score destroys exactly the information a person needs: *which part* is dangerous. A message whose wording is unremarkable but whose contract is a honeypot is not "mostly fine". It is a honeypot with a polite covering letter.

So the parts are never averaged. Every scan — address, token, wallet, prompt, message, file — returns the same envelope, and they are combined by one rule:

```
PASS (0)  <  INSUFFICIENT DATA (1)  <  CAUTION (2)  <  FAIL (3)
```

**The worst single component controls the guidance, and nothing outvotes it.** There is no score, no weighted average, no majority. Two clean addresses do not dilute one failing address.

Note where INSUFFICIENT DATA sits: worse than PASS, because not knowing is not the same as being clear — but not worse than CAUTION, because a specific observed problem outranks an absence of information. It can never mask a FAIL.

Three consequences are visible in the interface:

- An address that was found but not checked contributes an explicit *unknown* component. A message containing an unchecked address therefore cannot show PASS, and the row says "counted as INSUFFICIENT DATA, not as safe" rather than leaving a silent hole.
- A lookup that fails — network error, unsupported chain, rate limit — renders INSUFFICIENT DATA with the reason, never a clean row.
- Recommended actions are taken only from the components that actually reached the top verdict, and each one names the finding it came from. No action is invented by the combiner.

Coverage is reported per component rather than collapsed into one line, for the same reason: "links: complete" for the message text says nothing about whether a token's liquidity data came back.

---

## 9. Verification: What Is Actually Tested

A claim about rigour is worth exactly as much as the suite behind it.

| Suite | Assertions | What it holds down |
|---|---|---|
| Address engine regression | 61 | Verdict labels across malicious, benign, partial, contradictory and malformed provider data |
| Message engine | 96 | Each detection family, plus the education-versus-execution boundary |
| Scan model | 50 | The combination rule, exhaustively — including that one failing component is never diluted |
| UI / integration | 65 | The code actually embedded in the page, not the source modules, including a full XSS suite |
| Provider routing | 16 | Direct-then-proxy ordering per chain, and that a rate-limited call is not retried through a shared proxy |
| Adversarial review | 20 | Engine output scored against a careful human reading, benign cases included |
| **Total** | **308** | |

Two further guards run alongside them:

**Drift detection.** The page is a single self-contained file, which means each engine exists twice: once as its own module, once embedded in the page. Two copies of the same logic is a standing invitation to fix a bug in one and ship the other. A build check compares them and fails loudly if they disagree — added after exactly that happened once, shipping a broken chain-routing path for a week while the module's own tests kept passing.

**Cross-site scripting.** This feature takes hostile text from a stranger and prints it back onto the page. Every value is escaped, including the security provider's own response text, because a spoofed upstream response must not become markup either. The only inline handlers the interface emits are fixed literals plus an integer index, and a test asserts precisely that.

---

## 10. Transparency by Design

Every result is built to answer a question a user should be allowed to ask: *why?*

- **Every check names its source.** A result never says "risky" without saying which provider, or which on-chain contract, produced the finding.
- **Coverage is stated, not implied.** "12 of 14 checks returned usable data" is shown plainly, and for a multi-part message, per part.
- **Confidence is separate from the verdict.** A clean result reached with full coverage reads differently from one reached with partial coverage, and the interface says so.
- **Evidence is shown in place.** A finding in a message highlights the exact characters that matched, in the text you pasted, at the offset where they were found.
- **Raw provider responses are one click away.** Nothing is summarised in a way that can't be checked against the data it came from.

### Where your data goes

- **The message scan never leaves your browser.** No text is transmitted, stored, or logged by this product.
- **An address check is a network request.** Checking an address requires querying a third-party security data provider and, for sanctions checks, a public blockchain node — so those services receive the address being checked, as any lookup of this kind must. No account is required and nothing is retained by this product.

---

## 11. Limitations, Stated Plainly

**A clean result is not a safety guarantee.** It means no flags were found among the indicators actually checked — not that none exist anywhere.

**Message detection is pattern-based.** There is no meaning-level analysis. A novel or unusually phrased technique can pass unnoticed.

**Blockchain addresses are pseudonymous.** One entity may control many addresses; one address may be shared by many people or services. None of the checks here claim to resolve identity.

**Provider labels can be wrong, and can change.** A designation added today can be reversed tomorrow — the sanctions oracle's own documented staleness gap is evidence of exactly this kind of lag.

**Interaction with a flagged address is not proof of wrongdoing.** Funds can pass through an address without the recipient knowing their origin. Exposure is reported as exposure, which is not the same claim as guilt.

**Coverage varies by chain and by scan type, and that variance is disclosed rather than hidden.** Wallet screening, liquidity data and counterparty checking are not uniformly available across all four ecosystems, and the interface reflects which subject supports which check.

**A verdict is not advice.** Nothing here is financial, legal, or investment advice, and no output should be read as a recommendation to buy, sell, hold, or transact.

---

## 12. What's Next

Kept honestly separate, in the order they are actually queued.

**Scoped and next in line.** Message-level social-engineering findings — impersonation patterns, fake-support structures and payment-redirection phrasing — reported as their own findings with their own evidence rather than folded into the existing rules. Then static file scanning for documents a user is asked to open, beginning with Markdown and HTML, using the same scan envelope and the same combination rule.

**Specified, deliberately not started.** Continuous monitoring — watchlists, scheduled re-screening, alerting — has a complete architectural design written and has not been built, because it requires this product to begin storing what a user is watching. That is the first genuine data-retention decision in its history, and it is a decision to make on purpose rather than as a side effect of shipping a feature.

**Considered and rejected for now.** Automated JavaScript analysis of pasted or linked code. A regular-expression pass over source code produces confident-looking output with no reliable relationship to what the code does, and presenting that as a security audit would be worse than offering nothing. If it ships, it will be as a clearly-labelled triage aid, not an audit.

---

## 13. Closing

Most tools in this space ask for trust. This one is built to need less of it — every verdict shows its sources, every limitation is stated instead of buried, and every technical claim in this document was verified against a primary source before being written down.

Four chains. Two scanners. One rule for combining them that refuses to let a clean part speak for a dangerous one.

Verified, because a security tool that asks to be trusted has an obligation to earn it. Constantly improving, because the risk landscape doesn't hold still, and neither should the tool built to read it.
