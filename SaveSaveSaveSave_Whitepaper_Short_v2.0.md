# SaveSaveSaveSave — Short Edition

**Verified. Constantly Improving.**
*Whitepaper v2.0 — September 2026*

---

## What it is

SaveSaveSaveSave checks a wallet or token against real security data and returns a plain verdict — **PASS, CAUTION, FAIL, or INSUFFICIENT DATA** — before you act, not after. Not financial advice, not a price prediction. A risk read, in seconds, built on evidence you can inspect rather than a score you have to trust.

## The name

Four repetitions, four real product pillars, not four copies of the same idea:

- **Save your funds** — honeypot, mint-authority, and sanctions/malicious-address detection before you sign.
- **Save your time** — one scan across four blockchain ecosystems and, where available, multiple independent data sources at once.
- **Save your trust** — every check names its source; a PASS is never presented as a guarantee.
- **Save the regret** — the newest checks exist to catch exposure a user would otherwise only discover after the money has moved.

## What's covered

**EVM — 14 chains:** Ethereum, BNB Smart Chain, Polygon, Arbitrum, Optimism, Base, Avalanche, Fantom, zkSync Era, Linea, Scroll, Blast, Mantle, Gnosis. Full token and wallet screening.

**Solana:** its own native security model — mint/freeze authority, metadata mutability, transfer hooks — plus liquidity data (pool count, TVL, LP-lock status) shown as context, not folded into the score. Wallet screening included.

**Sui:** token security only, because the underlying data provider doesn't yet return liquidity or holder data for Sui — scope matches what's actually available, not what would look complete.

**TRON:** token security, verified to share the same data schema as EVM rather than assumed to. Its address format was checked carefully enough to calculate — not guess at — the odds of confusing it with a Solana address (about one in 400 quadrillion), resolved with a deterministic rule rather than left to chance.

**Aptos:** evaluated and deliberately not built. It's named in the data provider's marketing material, but no verifiable technical endpoint could be confirmed — so it isn't claimed as supported.

Address type is detected automatically across all four ecosystems — the four formats don't overlap by construction, not by convention.

## Wallet-risk intelligence, in three layers

1. **Malicious-address screening** (EVM, Solana) — sanctions, phishing, theft, money laundering, mixer exposure, dark-web and cybercrime association.
2. **The Chainalysis Sanctions Oracle** — a free, on-chain smart contract, independently verified (contract address cross-checked on Etherscan; function selector computed and confirmed against the real deployed bytecode, not assumed). Live on 8 of its 9 deployed chains here. Its one honest limitation: an independent review found real gaps — over 90 days in one case — between a designation taking effect and the oracle reflecting it. Reported as a match against the oracle, not an unconditional real-time guarantee.
3. **Recent counterparty checking** — a bounded, disclosed window of recent token transfers cross-checked against the same oracle. Not transaction history (that capability doesn't exist at the protocol level for any chain), doesn't see native-asset transfers, and says so. One sanctioned counterparty moves the result to caution, not an automatic fail — that override stays reserved for the wallet's own address being directly designated.

## Why it can be trusted a little more than most

Absence of evidence is never treated as evidence of safety — an incomplete check produces `INSUFFICIENT DATA`, not a quiet pass. One confirmed critical finding overrides everything else; accumulated weak signals can never outvote it. Every chain is evaluated on its own native security model, not a template forced across ecosystems. All of this is enforced by a 61-test automated regression suite, including tests written specifically to try to break the "weak evidence can't outvote strong evidence" rule.

## What it isn't

A clean result isn't a safety guarantee — it means nothing was found among what was actually checked. Addresses are pseudonymous, and interacting with a flagged one is not proof of wrongdoing. Coverage differs by chain, and the interface says which chain supports which check rather than pretending otherwise.

## Closing

Verified, because a tool asking to be trusted has to earn it. Constantly improving, because the risk landscape doesn't hold still.
