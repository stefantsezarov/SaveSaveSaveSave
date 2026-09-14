# SaveSaveSaveSave — upload notes

Everything in this zip goes in the repo root.

## Order

**1. `index.html` — do this first.**
The TRON/Sui rate-limit fix was only ever in `core.js`, which the page never
loads. This copy has it embedded. Uploading this file is what actually fixes
the bug.

**2. `goplus-proxy-worker.js` — paste into the Cloudflare Worker editor, Deploy.**
Adds edge caching and turns the CORS origin into an allowlist that already
includes `savesavesavesave.pages.dev`, so the Pages move needs no second deploy.

Check it worked — run twice, the second should say `HIT`:

    curl -si "https://cool-sound-6db2riskpass.stefan-tsezarov82.workers.dev/?tron_contract_addresses=TGBfBt6Y2Dm3RHdNpZAdqywBsvfdysf834" | grep -i x-proxy-cache

**3. Everything else** — the renamed docs and tests. No urgency.

## Do not rename the Cloudflare Worker

Its URL contains `riskpass`:

    cool-sound-6db2riskpass.stefan-tsezarov82.workers.dev

That looks like something the rebrand missed. It is not. It is the live
endpoint, hardcoded in `core.js` and `index.html`. Renaming it in the
Cloudflare dashboard breaks every fallback scan until both copies are
updated to match.

## Delete these four after uploading

GitHub's web upload adds files but never removes them, so the old names
survive unless you delete them by hand (open the file → trash icon):

- `riskpass-solana-proxy-worker.js`  → replaced by `goplus-proxy-worker.js`
- `riskpass.regression.test.js`      → replaced by `savesavesavesave.regression.test.js`
- `RiskPass_Wallet_Risk_Intelligence_Proposal.md` → replaced by the SaveSaveSaveSave name
- `RiskPass-Whitepaper.pdf`          → superseded by `SaveSaveSaveSave-Whitepaper.pdf`

## Files

| File | What it is |
|---|---|
| `index.html` | The site. Contains the embedded core **with** the direct-first fix. |
| `core.js` | Source of truth for the engine. Re-paste into `index.html` after any edit. |
| `goplus-proxy-worker.js` | Cloudflare Worker: cached, CORS allowlist. Renamed. |
| `whitepaper.html` | Dropped the visible "Formerly RiskPass" line. |
| `ARCHITECTURE.md` | Filename refs fixed; removed a pointer to `riskpass.html`, which never existed. |
| `SaveSaveSaveSave_Whitepaper_v2.0.md` | Dropped "Formerly RiskPass". |
| `SaveSaveSaveSave_Whitepaper_Short_v2.0.md` | Same. |
| `SaveSaveSaveSave_Wallet_Risk_Intelligence_Proposal.md` | Renamed file, 55 in-text references. |
| `savesavesavesave.regression.test.js` | The 61-test suite, renamed. |
| `goplus-routing.test.js` | **New.** Asserts which URL each chain calls first. |
| `verify_embedded.js` | **New.** Catches `core.js` / `index.html` drift — the bug above. |
| `_headers` | Cloudflare Pages response headers. Inert on GitHub Pages. |
| `switch-domain.sh` | Rewrites every public URL once the new domain is live. |

## Tests

Run from the repo root:

    node savesavesavesave.regression.test.js   # 61 assertions on the engine
    node goplus-routing.test.js                # 16 assertions on call routing
    node verify_embedded.js                    # index.html still matches core.js

The third one is the important habit. Run it after every `core.js` edit —
it is the check that would have caught this bug months earlier.

## When Pages is live

Name the project exactly `savesavesavesave`, then:

    ./switch-domain.sh https://savesavesavesave.pages.dev

It rewrites `index.html`, `sitemap.xml` and `robots.txt`, and deliberately
leaves the Worker URL alone. Run it only after the new site is serving — a
canonical tag pointing at a 404 tells Google the real page does not exist.
