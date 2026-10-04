# SaveSaveSaveSave

**A free checker for suspicious messages, links, crypto addresses and npm packages.** Paste a message, an address, a token or an npm package and get an honest verdict: what was found, and what was *not* checked.

**Live:** https://savesavesavesave.xyz · No account · Open source (AGPL-3.0)

---

## What it does

| Tool | What you give it | What it checks | Where it runs |
|---|---|---|---|
| **Message scan** | A DM, email, "support" message or AI prompt | Requests for a recovery phrase, keys or logins; disguised links; invisible and look-alike characters; hidden markup; prompt injection aimed at AI assistants; addresses inside the text | **Entirely in your browser.** The text is never sent anywhere. |
| **Address / token scan** | A wallet or token address | Honeypot patterns, owner powers (minting, balance edits, blacklists), sell restrictions and similar flags from public security data; sanctions screening for EVM wallets (Chainalysis oracle) and Solana wallets (US Treasury OFAC list); for Solana wallets, also what kind of account the address is | Your browser asks [GoPlus Security](https://gopluslabs.io) directly; some chains and the sanctions checks go through our Cloudflare Worker |
| **Package check** | An npm package name (optionally a version) | Removed by npm for security reasons; reported malicious or vulnerable in OSV.dev; code that runs during `npm install`; a name imitating a popular package; age, usage, source link, deprecation. The package's code is never downloaded | Your browser asks the npm registry and OSV.dev directly; only the name and version are sent |
| **Compare two addresses** | The address you meant and the one you're about to pay | Every character, grouped in fours, to catch address poisoning | Entirely in your browser |

Coverage: 14 EVM chains, Solana, Sui and TRON for token and address data. EVM wallets are also screened against the Chainalysis sanctions oracle, and their recent counterparties are screened on 8 chains.

After a FAIL or CAUTION result you can **share the warning as an image**. It's drawn on your device, carries the date and "not a guarantee", and never contains the message text.

## For AI agents

An **MCP server**, **CLI** and **Node library** in [`agent/`](agent/) give agents the same four checks as read-only tools: `scan_message`, `check_package`, `scan_address`, `compare_addresses`. Zero dependencies, a hard-coded network allowlist, and CI keeps it identical to the site's engine. [`llms.txt`](https://savesavesavesave.xyz/llms.txt) describes the site for AI assistants.

- **Install the MCP server:** `claude mcp add savesavesavesave -- npx -y savesavesavesave mcp` (other clients: see [savesavesavesave.xyz/agents](https://savesavesavesave.xyz/agents)).
- **GitHub Action** for your npm dependencies: `uses: stefantsezarov/SaveSaveSaveSave@v0.1.3` ([setup](https://savesavesavesave.xyz/tools)).
- **Scan selected text** on any web page with a one-click bookmark ([install](https://savesavesavesave.xyz/tools)).

## The rules it keeps

- **It never says "safe".** Verdicts are PASS, CAUTION, FAIL or INSUFFICIENT DATA.
- **Every result lists what was not checked.** A clean result on thin data is reported as INSUFFICIENT DATA, not PASS.
- **Only confirmed findings produce FAIL.** One confirmed high-severity finding always means FAIL. Unreadable data leads to CAUTION, and the result says so.
- **The live scan console shows real steps only.** No invented progress.

## Privacy

- **Message text** never leaves the browser.
- **Addresses** go from your browser to GoPlus, or through our Worker for some chains and checks. We don't store them.
- **Usage** is counted only as anonymous daily totals (scan kind, chain, verdict). There is no cookie, ID or IP address, and Global Privacy Control is respected. The totals are public: [`?stats=week`](https://cool-sound-6db2riskpass.stefan-tsezarov82.workers.dev/?stats=week).
- **Ads** appear in the side columns on wide screens, on the scanner and a few guides. They never appear on the high-harm guides and never receive anything you scan. Details are on the [privacy page](https://savesavesavesave.xyz/privacy).

## How it's built

- **Static site, no build step.** `index.html` is the whole scanner. The engine inside it is copied verbatim from `core.js`, and a test fails if the two drift apart.
- **`goplus-proxy-worker.js`** is the Cloudflare Worker. It relays requests for chains that browsers can't reach directly, runs the sanctions checks, and keeps the anonymous daily totals in D1.
- **Guides** are plain HTML pages (`*.html`, styled by `paper.css`). `guide-examples.test.js` ties every factual claim in a guide to what the engine actually does.
- **Generators:**
  - `seo.js` writes the SEO blocks.
  - `apply-ads.js` holds the per-page ad policy and security policy (CSP).
  - `build-sitemap.js` writes the sitemap.

## Tests

Over 1,000 checks across 10 suites. They run on every push (`.github/workflows/tests.yml`), followed by a check of the live site after each deploy.

```
node verify_embedded.js              # page engine == core.js
node savesavesavesave.regression.test.js
node scanmodel.test.js
node goplus-routing.test.js
node promptscan.test.js
node promptscan.ui.test.js           # includes XSS tests
node scanconsole.test.js
node redteam.js                      # adversarial prompts
node guide-examples.test.js
node seo.test.js
```

No dependencies: Node 20 (the version CI uses) is enough.

## Found a miss or a false alarm?

Open an issue with the example, and remove anything personal first. Misses are the most useful thing you can send.

## Licence and support

- **Code:** GNU AGPL-3.0-only ([LICENSE](LICENSE)).
- **The SaveSaveSaveSave name, logo, visual identity and guide text:** all rights reserved ([LICENSE.md](LICENSE.md)). Forks must use their own name.
- **Supporting the project:** [SUPPORT.md](SUPPORT.md). We never message anyone asking for crypto.

The original vision document is kept in [VISION.md](VISION.md).

*Not financial, legal or investment advice. An automated check can be wrong; use it as one input, not the only one.*
