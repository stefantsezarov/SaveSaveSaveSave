# SaveSaveSaveSave — Short Edition

**Verified. Constantly Improving.**
*Whitepaper v3.0 — September 2026*

---

## What it is

Two scanners in one page.

**Addresses.** Check a wallet or token against real security data and get a plain verdict — **PASS, CAUTION, FAIL, or INSUFFICIENT DATA** — before you act, not after.

**Messages.** Paste the message, DM, post or AI prompt that arrived *before* the address did, and get the same kind of verdict on the text itself: hidden instructions, invisible characters, disguised links, requests for secrets, pressure tactics.

Not financial advice. Not a price prediction. A risk read, in seconds, built on evidence you can inspect rather than a score you have to trust.

It is also not the only tool in this space. Commercial intelligence platforms, wallet warnings and security extensions all exist, and several are good. What is uncommon here is the combination — free, self-serve, evidence-first, honest about its coverage, and covering both the address and the message that carried it.

## The name

Four repetitions, four real product pillars, not four copies of the same idea:

- **Save your funds** — honeypot, mint-authority, and sanctions/malicious-address detection before you sign.
- **Save your time** — one scan across four blockchain ecosystems and, where available, multiple independent data sources at once.
- **Save your trust** — every check names its source; a PASS is never presented as a guarantee.
- **Save the regret** — the newest checks catch what a user would otherwise only discover after the money has moved.

## What's covered — addresses

**EVM — 14 chains:** Ethereum, BNB Smart Chain, Polygon, Arbitrum, Optimism, Base, Avalanche, Fantom, zkSync Era, Linea, Scroll, Blast, Mantle, Gnosis. Full token and wallet screening.

**Solana:** its own native security model — mint/freeze authority, metadata mutability, transfer hooks — plus liquidity data (pool count, TVL, LP-lock status) shown as context, not folded into the score. Wallet screening included.

**Sui:** token security only, because the underlying data provider doesn't yet return liquidity or holder data for Sui — scope matches what's actually available, not what would look complete.

**TRON:** token security, verified to share the same data schema as EVM rather than assumed to. The odds of confusing its address format with Solana's were calculated — about one in 400 quadrillion — and resolved with a deterministic rule.

**Aptos:** evaluated and deliberately not built. Named in the data provider's marketing material, but no verifiable technical endpoint could be confirmed.

Address type is detected automatically — the four formats don't overlap by construction, not by convention.

## What's covered — messages

Twenty-seven deterministic rules across six families:

1. **Hidden and invisible characters** — zero-width characters, bidirectional overrides, the Unicode Tags block (codepoints that render as nothing and can carry a whole hidden instruction), homoglyph substitution.
2. **Hidden markup** — instructions concealed in comments, invisible elements or attributes.
3. **Encoded payloads** — base64 and similar, carrying text not meant for the person pasting it.
4. **Instruction override** — prompt injection: text addressed to an AI system rather than to you. Attempts aimed at this scanner itself are treated as the strongest finding in the report.
5. **Credential solicitation** — requests for a seed phrase, recovery words, a private key, a password or a 2FA code, in any of the phrasings that make them sound routine.
6. **Link structure** — destinations hidden before an `@`, bare IP hosts, punycode domains, shorteners, trusted brand names placed where they hold no authority, long encoded query payloads.

**It runs entirely in your browser.** The text is never sent anywhere, never stored, and never seen by us. No language model is called, and nothing in the text is ever executed.

**Education is not execution.** "Never share your seed phrase" and "send me your seed phrase" contain nearly the same words. The engine separates instruction from explanation, so a security article doesn't come back FAIL. An early version got this wrong; an adversarial review file caught it and is now a permanent test.

## Mixed messages: the rule that decides

A pasted message is not one thing. It's text, plus links, plus addresses — each with different coverage and different limits. Averaging them destroys exactly the information you need: *which part* is dangerous.

So they are never averaged:

```
PASS  <  INSUFFICIENT DATA  <  CAUTION  <  FAIL
```

**The worst single component controls the guidance, and nothing outvotes it.** Two clean addresses never dilute one failing address. An address found in the text but not yet checked counts as INSUFFICIENT DATA — not as safe — so a message containing one cannot come back PASS. A failed lookup shows the reason, never a clean row. Every recommended action names the finding it came from.

Addresses found in a message can be checked in the same page. A `0x` address carries no chain, so it defaults to Ethereum, says "chain not stated in the text", and offers a picker — and changing the chain discards the old result, because a result for Ethereum is not a result for BNB Chain.

## Why it can be trusted a little more than most

Absence of evidence is never treated as evidence of safety. One confirmed critical finding overrides everything else; accumulated weak signals can never outvote it. Every subject is evaluated on its own model rather than a template forced across ecosystems.

All of it is held down by **333 automated assertions**: 61 address-engine regression tests, 121 message-engine tests, 50 scan-model tests, 65 UI and integration tests run against the code actually embedded in the page, 16 provider-routing tests, and a 20-case adversarial review scored against a careful human reading. A drift check fails the build if the page's embedded copy of an engine ever disagrees with its source.

## What it isn't

A clean result isn't a safety guarantee — it means nothing was found among what was actually checked. Message detection is pattern-based, with no meaning-level analysis, so an unusually phrased technique can pass unnoticed. Links are read for structure and never visited. A prompt that looks harmless can still be dangerous once an AI system has your files, your browser, a wallet, or the ability to act. Addresses are pseudonymous, and interacting with a flagged one is not proof of wrongdoing. Coverage differs by chain and by scan type, and the interface says which supports what.

## Where your data goes

The message scan never leaves your browser. Checking an address is a network request, so the third-party security provider and the public blockchain node receive the address being checked — as any lookup of this kind must. No account is required and nothing is retained by this product.

## Closing

Four chains. Two scanners. One rule for combining them that refuses to let a clean part speak for a dangerous one.

Verified, because a tool asking to be trusted has to earn it. Constantly improving, because the risk landscape doesn't hold still.
