# RiskPass Architecture

## Philosophy

- RiskPass never treats absence of evidence as evidence of safety.
- RiskPass never claims more coverage than it actually obtained.
- RiskPass treats external data as untrusted, always.
- Critical evidence overrides uncertainty.
- Uncertainty overrides PASS.
- Every blockchain is analyzed according to its own native security model.
- The user interface stays simple even when the underlying security model is sophisticated.

## Layers

```
RiskPass Core
│
├── Input validation        (Layer 0 — per-chain address validators)
├── Data acquisition        (Layer 1 — adapters treat provider responses as hostile)
├── Evidence normalization  (Layer 2 — the CHECK model)
├── Verdict engine          (Layer 5 — provider- and chain-agnostic)
├── Confidence engine       (Layer 6 — coverage, critical-check tracking)
└── UI                      (Layer 7 — thin, DOM-only, knows nothing security-specific)
        │
        ├── EVM adapter     (Layer 3) ──────────────► GoPlus EVM API
        │                                              (direct browser call, CORS-enabled)
        │
        ├── Solana adapter  (Layer 3) ──► CORS proxy ──► GoPlus Solana API (Beta)
        │                                  (used as fallback only —
        │                                   token security always proxied,
        │                                   wallet screening tries direct first)
        │
        ├── Sui adapter     (Layer 3) ──► CORS proxy ──► GoPlus Sui Token Security API
        │                                  (proxied unconditionally — see below for why
        │                                   this adapter didn't get the "try direct first"
        │                                   treatment Solana wallet screening did)
        │
        └── TRON adapter    (Layer 3) ──► CORS proxy ──► GoPlus Token Security API
                                            (chain_id="tron", same endpoint family as EVM —
                                             schema reused from EvmAdapter, not rebuilt)
```

**All decision logic — validation, normalization, the verdict engine — runs
entirely client-side for every chain, no exception.** The one thing that
differs per chain is the *network path* to the data provider. EVM's GoPlus
endpoint sends proper CORS headers, so the browser calls it directly. As of
this writing, GoPlus's Solana token-security endpoint does not send those
headers — confirmed directly, not assumed — so that adapter routes through
a small proxy. Sui's endpoint is routed through the same proxy from the
start, on the strength of the pattern rather than direct confirmation —
see "The Sui adapter" below for why that's a reasonable bet and not a
guess pretending to be a fact.


Layer 4 (cross-provider correlation) is not yet implemented — GoPlus remains
the sole provider per chain. The adapter interface is shaped so a second
provider can be added to `fetchChecks()` per adapter without changing the
verdict engine.

### Layer 0 — Input validation

Each adapter owns its own `validateAddress()`. EVM and Solana never share a
validator: `/^0x[a-fA-F0-9]{40}$/` vs base58 with excluded ambiguous
characters (`0`, `O`, `I`, `l`). No cross-chain guessing.

### Layer 1 — Data acquisition

Every HTTP response is checked for `res.ok`, then for the provider's own
success code, then for the presence of `result`, before any field is read.
Network failure and HTTP errors both throw and are surfaced as an explicit
error state — never as a verdict.

This layer is also where the EVM and Solana adapters diverge in practice.
`EvmAdapter.fetchChecks()` calls `api.gopluslabs.io` directly from the
browser. `SolanaAdapter.fetchChecks()` calls a Cloudflare Worker instead,
because GoPlus's Solana endpoint does not return an
`Access-Control-Allow-Origin` header — confirmed directly in the browser
console (`"...has been blocked by CORS policy: No 'Access-Control-Allow-Origin'
header is present..."`), not inferred. Every scan, regardless of chain,
still goes through the same fetch-timeout-catch handling in `runScan()` —
only the URL each adapter builds differs.

### Layer 2 — Evidence normalization

Every raw provider field becomes at most one `CHECK`:

```
CHECK
  id           string
  category     string   (control | supply | liquidity | economics | reputation | transparency)
  status       'PASS' | 'RISK' | 'UNKNOWN'
  critical     boolean  (can this check alone force a FAIL?)
  severityWeight number (contribution to the caution/fail score)
  label        string
  detail       string
  source       string   (which provider/adapter produced this)
```

A field that is simply absent from the response never becomes a CHECK at
all — its absence is accounted for via `checksExpected` vs `checksValid`,
never silently folded into "clear." A field that IS present but not in a
recognized shape (null, an array, an unexpected string) becomes a CHECK
with `status: 'UNKNOWN'`, not a guessed PASS.

The verdict engine (Layer 5) only ever reads this CHECK shape. It has no
knowledge of GoPlus, EVM, or Solana field names.

### Layer 3 — Chain adapters

`EvmAdapter` and `SolanaAdapter` each expose the same interface:
`{ id, name, capabilities, chains, validateAddress(addr), fetchChecks(addr, assetType, chainId, fetchImpl) }`.
Adding a chain means writing a new adapter against this interface — it does
not mean touching the verdict engine. Solana's checks are read from a
nested `{status}` object shape; EVM's are flat `"1"/"0"` fields. The
adapters absorb that difference; nothing above them needs to know it exists.

### The Solana CORS proxy

**What happened:** early Solana scans hung for roughly 80 seconds and then
failed with a generic "Failed to fetch." The first fix attempt (a 20-second
client-side timeout) treated this as a slow-provider problem — a reasonable
guess, since a hard CORS rejection normally fails in a second or two, not
80. It was wrong. A browser console check settled it directly:

```
Access to fetch at 'https://api.gopluslabs.io/api/v1/solana/token_security?...'
from origin 'https://stefantsezarov.github.io' has been blocked by CORS
policy: No 'Access-Control-Allow-Origin' header is present on the
requested resource.
```

That's a hard block — no client-side code change can fix a missing
response header, no matter how the timeout or retry logic is written. The
console also showed a `504 Gateway Timeout` from GoPlus's own backend
alongside the CORS error, meaning there were two separate problems stacked
on each other: the browser was never going to be allowed to read the
response, and GoPlus's Solana endpoint (documented by GoPlus as Beta) is
also, separately, sometimes slow to answer.

**The fix:** `riskpass-solana-proxy-worker.js`, deployed on Cloudflare
Workers. It receives the request in place of GoPlus, forwards it
server-to-server (CORS is a browser-enforced restriction — it does not
apply between two servers), and returns the response with an
`Access-Control-Allow-Origin` header the browser will accept.

**What the proxy does:**
- Accepts `GET ?contract_addresses=<address>`, nothing else.
- Re-validates the address against the same base58 pattern the client
  already checked, before forwarding anything — a public endpoint
  shouldn't blindly relay arbitrary input just because the browser-side
  check already ran once.
- Restricts `Access-Control-Allow-Origin` to the site's own origin, not `*`.
- Applies its own 15-second timeout against GoPlus, returning a clear `504`
  JSON error rather than hanging, so a slow upstream fails predictably on
  both sides of the proxy.

**What the proxy explicitly does not do:**
- Store, log, or cache any address or response beyond Cloudflare's own
  default platform-level request logs.
- Touch EVM traffic at all — that adapter's direct-to-GoPlus path is
  unchanged, because that endpoint's CORS support was never the problem.
- Add any authentication, custody, or state. It is a stateless relay with
  one job.

**The honest architectural consequence:** the claim "every check runs
entirely in the browser, no backend" is no longer 100% true — it's true
for EVM, and true for Solana's *decision logic*, but Solana's *network
path* now depends on one small, separately-hosted component. If GoPlus
adds proper CORS support to their Solana API — plausible, since it's
still labeled Beta — this proxy becomes removable and the Solana adapter
can call GoPlus directly, exactly like the EVM adapter already does.

### Layer 5/6 — Verdict engine and confidence

Four states, in strict priority order:

1. **FAIL** — any `critical: true` check has `status: 'RISK'`. This fires
   regardless of how sparse the rest of the response is — a confirmed
   honeypot with only 1 of 12 fields returned is still FAIL, not
   "insufficient data." (This exact interaction was a real bug caught by
   the regression suite during development — see the test named
   `critical hit even with sparse data`.)
2. **INSUFFICIENT DATA** — fewer than 40% of expected checks returned
   usable (PASS/RISK) data. Never collapses into PASS.
3. **FAIL** (score-based) / **CAUTION** — accumulated severity score from
   non-critical RISK and UNKNOWN checks.
4. **PASS** — only when coverage is adequate and nothing scored.

Separately, a well-covered PASS or CAUTION result still checks whether any
`critical`-tier check specifically went unanswered (`criticalMissing`) and
appends an explicit note if so — a scan can have 79% overall coverage and
still be silently missing the single most decisive check (e.g. honeypot
detection). This is deliberately additive to the main classification, not
folded into the coverage threshold, because "most things checked out, but
we couldn't check the one that matters most" is a different, more targeted
kind of uncertainty than "most of the response was empty."

### Layer 7 — Presentation

The badge, the one-line verdict subtext, and a coverage line
(`N/M checks completed`) are the only things a casual user needs to read.
The full per-check list and raw API response are present but not
foregrounded.

## Capability declarations

Each adapter declares what it actually implements, not what the upstream
provider theoretically supports:

| Capability | EVM | Solana | Sui | TRON |
|---|---|---|---|---|
| Token security | yes (14 chains) | yes | yes | yes |
| Wallet screening | yes | yes — re-enabled; see below | no — GoPlus's Sui API doesn't return this data yet | no — not verified; see below |
| Transaction simulation | no | no | no | no |
| Liquidity analysis | no | yes — see below | no — GoPlus has stated holder/DEX data for Sui is "awaiting ecosystem infra" | no |
| Contract/source analysis | yes | n/a (different security model) | n/a (different security model) | yes — inherited from the reused EVM schema; see below |

The UI reads this table directly (`renderCapabilityNote()`) rather than
having a hardcoded list duplicated in markup, so flipping a capability flag
is sufficient to both enable and correctly describe a capability — or, as
below, to honestly retract one.

### Solana wallet screening — attempted, reverted, re-enabled

The hypothesis was reasonable: GoPlus's Malicious Address API — the same
endpoint the EVM adapter already uses (`address_security/{address}`) —
was announced by GoPlus as supporting Solana via `chain_id=solana`. That's
a mature, general endpoint already proven to send proper CORS headers for
EVM traffic, unlike the newer Beta Solana Token Security endpoint that
needed the proxy. There was a real chance this would work directly from
the browser with no proxy at all.

It didn't, on first attempt. Deployed and tested live, the endpoint
returned a generic **"system error"** — not a CORS block (the request
reached GoPlus and got a response), not a clean validation error, a
backend exception. The suspected explanation at the time: GoPlus's classic
`address_security` endpoint might expect a numeric EVM-style `chain_id`,
with real Solana wallet support instead living behind a separate, newer
"Address Scan API" — a materially different, async submit-then-poll
integration, not a parameter change. `capabilities.walletScreening` was
reverted to `false` on that basis, and `fetchChecks()` refused wallet
requests immediately rather than repeat an unverified guess.

That suspected explanation was never actually confirmed against GoPlus's
docs — it was a plausible theory written down at the time, not a verified
fact. Revisiting it: GoPlus's own public announcement is unambiguous that
`chain_id: 'solana'` is supported on the same `address_security` endpoint
already in use, for exactly this purpose. That directly contradicts the
theory the revert was based on. Trusting an unconfirmed hypothesis over
the vendor's own stated behavior indefinitely isn't the more conservative
choice here — it's just the first guess left unquestioned.

**What changed as a result:** `capabilities.walletScreening` is back to
`true`, and `fetchChecks()` routes wallet requests to `_fetchWalletChecks()`
again — the direct-then-proxy fallback mechanism and the schema-reuse
logic (Solana wallet reputation data uses the same field names as EVM's,
since address reputation isn't a chain-specific mechanic) were never
actually wrong; they were only disconnected. Both were already
regression-tested in isolation throughout, and are now additionally
tested through the real `fetchChecks()` entry point rather than only the
internal method directly.

**What this section deliberately does not claim:** that the earlier
"system error" is understood, resolved, or won't recur. It might. The
honest position is that the theory used to justify leaving the feature
off doesn't hold up against GoPlus's own documentation, which is a good
enough reason to try again with full error-detail surfacing already in
place — not a good enough reason to declare the matter closed. If it
fails again, the error banner itself will show GoPlus's actual response
text this time, which is a real, checkable data point the original
"system error" report apparently wasn't specific enough to leave behind.

### Liquidity analysis

The `dex[]` array (DEX name, TVL, LP holder/lock info) was already present
in every Solana Token Security response this adapter was already fetching —
confirmed against GoPlus's documented response schema, field by field,
before writing any code. Enabling this was pure parsing work: no new
endpoint, no proxy change. Two things were added:

- A derived `has_liquidity` check: an empty `dex[]` is a soft (non-critical)
  risk signal — a token with no tracked liquidity pool may not be
  meaningfully tradable — while a populated one contributes a summary, not
  a score.
- A separate, non-scored "Liquidity" panel in the UI (`renderLiquidityPanel()`)
  showing pool count, combined TVL, and top-LP-holder lock status per pool.
  This is explicitly informational, not part of the verdict — TVL and lock
  status are context for a human to weigh, not a pass/fail signal RiskPass
  is confident enough to score on its own.

Note the Solana wallet-scan tab is no longer disabled in the UI — it was,
prior to this update, precisely because the capability was honestly false.
Now that it's genuinely implemented, the same UI logic that disabled it
automatically re-enables it; no separate UI change was needed for that part.

## Permanent regression suite

`riskpass.regression.test.js` requires `core.js` directly and asserts the
resulting **verdict label** for each case, not merely that nothing threw.
It should be run after any change to `core.js`, and `core.js` is the
source of truth — the copy embedded in `riskpass.html`'s `<script>` tag
must be pasted from `core.js` verbatim after any edit. `verify_embedded.js`
exists to catch drift between the two if that discipline slips.

Current coverage: 56 assertions across malicious input, benign input,
empty/malformed/partial provider responses, contradictory indicators,
missing critical fields, malformed numeric values, a confirmed critical
finding under sparse data, Unicode/HTML payloads, unexpected JSON types,
unknown chain IDs, per-chain address-validator isolation (now across four
address formats: EVM hex, Solana base58, Sui Move-type identifiers, TRON
Base58Check), Solana wallet screening (both verdict paths, plus the
direct-then-proxy fallback verified with mocked fetch rather than
asserted by inspection), liquidity summary parsing, Sui's distinct
value-encoding (`"1"`/`"2"` both meaning "available" — the specific edge
case that motivated writing a separate classifier instead of reusing
`flagState()`), TRON's reused EVM schema producing correct verdicts
without a duplicate normalizer, and address auto-detection across all
four ecosystems — including a specific test that adding TRON's detector
didn't break existing, working Solana detection.

## The Sui adapter

Built in the same session as the EVM chain expansion, on request, following
the same discipline as Solana: verify the real schema before writing code,
not after.

Two genuine differences from EVM and Solana surfaced during that
verification, not assumed in advance:

**The value encoding is different.** EVM and Solana both use a simple
on/off convention (`"1"`/`"0"`, or a nested `{status: "1"/"0"}`). Sui's
schema documents `"0"` as unavailable, but **both** `"1"` and `"2"` as
available — the distinction between 1 and 2 isn't specified at the field
level GoPlus exposes. Reusing `flagState()` here would have silently
misread `"2"` as neither on nor off (since it isn't `'1'`, `1`, or `true`,
`flagState` would classify it as `'unrecognized'`, and a naive read might
have ended up treating a real risk indicator as unreadable data rather
than a confirmed finding). This is exactly the kind of thing the hostile
test matrix exists to catch, so a dedicated `suiFlagState()` was written
instead, with a specific regression test asserting that `value: "2"` on a
critical field still produces FAIL.

**The address isn't an address in the EVM/Solana sense.** Sui's
`contract_addresses` parameter, per a real example pulled from GoPlus's
own console URL, is a Move type identifier: `0x<hex>::module::TypeName`
— not a flat account address. The validator is deliberately permissive on
hex length (`{1,64}` rather than a fixed `{64}`), because well-known
system packages are commonly referenced in short form in real Sui tooling
(e.g. the native coin type `0x2::sui::SUI`) — a strict fixed-length
requirement, discovered only after writing it, would have silently
rejected valid addresses. This was caught and fixed before shipping, not
after a user report.

**Scope is honestly limited by what GoPlus actually returns for Sui
today**, not by what RiskPass chose to build: GoPlus's own announcement
states holder and DEX data for Sui are "awaiting ecosystem infra." No
liquidity panel exists for Sui, and wallet screening isn't offered for
it, because that data doesn't exist upstream yet — the capability table
reflects an actual provider limitation, not an unfinished feature.

**Routing:** unlike Solana wallet screening, which tries a direct call
first because it reuses a *mature* endpoint with existing EVM precedent,
Sui's Token Security API is a newly added, chain-specific endpoint —
structurally the same situation Solana's token security was in before its
CORS gap was discovered. Rather than repeat that discovery process, Sui
is routed through the proxy unconditionally from the start. This is a
reasoned bet based on the pattern, explicitly not a confirmed fact —
if Sui's endpoint turns out to support CORS fine, the proxy hop is an
unnecessary but harmless extra network round-trip, not a correctness bug.

## The TRON adapter

Verified before building, same discipline as Sui: TRON turned out to be a
genuinely different case from Sui, not just "another non-EVM chain,"
which shaped a different design decision.

**The schema is inherited, not rebuilt.** Unlike Solana and Sui, GoPlus's
docs don't show a dedicated Token Security endpoint or schema page for
TRON — it appears as just another `chain_id` value (`"tron"`, a string)
on the *same* generic `token_security/{chain_id}` endpoint EVM chains
already use. Combined with TVM being documented as broadly
Solidity-compatible, `TronAdapter.fetchChecks()` calls
`normalizeEvmRecord()` directly rather than writing a parallel, near-
duplicate normalizer. This is a well-justified inference from endpoint
structure, explicitly **not** a confirmed field-by-field schema the way
Solana and Sui's dedicated docs pages provided — worth re-checking
against a real response if TRON scans ever return something unexpected.
It's also why TRON shows `contractAnalysis: yes` in the capability table:
that's an inherited consequence of reusing the EVM schema wholesale, not
a separately verified TRON-specific claim.

**A real disambiguation problem, not a hypothetical one.** TRON addresses
are base58, 34 characters, always starting with `T`. Solana addresses are
also base58, 32-44 characters, with no fixed prefix — meaning a 34-
character Solana address starting with `T` would satisfy both formats.
Before deciding this was safe to ignore, the actual probability was
calculated, not assumed: a Solana address that short requires an ed25519
public key with roughly 7 leading zero bytes, which happens for a real
generated key on the order of 1 in 4×10¹⁷. `detectEcosystem()` checks
TRON's stricter pattern before Solana's broader one specifically to
resolve this deterministically, and the regression suite includes a test
confirming a real Solana address still classifies correctly after TRON's
check was added — not just a test that TRON itself works.

**Routed through the proxy from day one**, for the same reason Sui was:
CORS support has only actually been confirmed for numeric EVM `chain_id`
values on this endpoint family, not for the non-standard string
`"tron"`. The Worker gained a fourth route, `?tron_contract_addresses=`.

**Wallet screening was deliberately left off**, not attempted and
reverted this time — unlike Solana, no equivalent GoPlus announcement
confirming TRON support on the Malicious Address API was found. Rather
than repeat the Solana wallet-screening cycle (build on an assumption,
discover it fails, revert, re-verify, re-enable), this one simply wasn't
built until that confirmation exists.

## Deliberately deferred

Aptos was evaluated alongside TRON and specifically **not** built. It
appears in GoPlus's own marketing chain lists ("Ethereum, BNB Chain,
Solana, Tezos, NEAR, Polygon, Cosmos, Polkadot, Optimism, Avalanche,
Arbitrum, Aptos, Tron...") and GoPlus operates across 40+ blockchains by
their own account — but unlike Solana, Sui, and (with the caveats above)
TRON, no dedicated technical endpoint or response schema for Aptos could
be found to verify against. Building an adapter on a marketing mention
alone is exactly the mistake already made once with Solana wallet
screening, on a much smaller scope than a full adapter. Not repeating it
here. If GoPlus's docs surface a confirmable Aptos endpoint later, the
adapter interface is already shaped to add it as a scoped, testable
addition — the same template Solana, Sui, and TRON all followed.

Two data points now exist on the CORS question: Solana's token security
endpoint lacked CORS (confirmed via console), and both Sui's and TRON's
newer or non-standard endpoints were routed through the proxy
preemptively on the same suspicion, without confirmation either way yet
for either. If that holds up once tested, that's a real pattern — newer
or non-standard `chain_id` values on GoPlus's endpoints, as a category —
not a Solana-specific one-off. The next chain added, if any, is still
what actually settles it.
