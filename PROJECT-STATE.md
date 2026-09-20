# SaveSaveSaveSave — project state

**Written 20 September 2026, at the end of a three-day session, for whoever
picks this up next.** Read this before changing anything. It is not a
tutorial; it is the set of things that are true now, the decisions behind
them, and the mistakes that have already been made once.

Owner: **Stefan Tsezarov** — sole decision-maker on this project. He is not
a programmer. He is a careful editor with good instincts about trust and
tone, and he is right more often than not about what the site should say.
Explain things in plain words. Do not send him hunting for a button
without checking it exists.

---

## 1. The working agreement

Agreed explicitly on 20 September:

> Push routine work without asking — fixes, guides he has approved, tests,
> copy corrections. **Stop and ask before anything that changes money,
> privacy, or what the site promises its users.**

That second half is the whole point. Things that need his decision:

- turning advertising on or off for any page (see §5),
- anything that alters the privacy policy's factual claims,
- anything that changes what a verdict means or what the scanner says it can do,
- adding a third-party service that receives any data,
- publishing a new guide's content (he edits every one himself).

Things to just do: bug fixes, test coverage, accessibility, copy typos,
build-script improvements, refactors that keep behaviour identical.

**When you publish, say so plainly.** "Push origin" reads like plumbing.
Say *this publishes to savesavesavesave.xyz* so the moment he is approving
is unmistakable. A real misunderstanding happened over exactly this.

---

## 2. How this gets deployed

The site is a static repo deployed by Cloudflare Workers on push to `main`.
**Pushing to `main` publishes immediately.** There is no staging.

- Repository: `https://github.com/stefantsezarov/SaveSaveSaveSave.git`
- Live: `https://savesavesavesave.xyz`
- Working clone on his machine: `C:\Users\stefa\Downloads\SaveSaveSaveSave-pages_1\SaveSaveSaveSave`

This session was created from that folder, so it has push access directly.
Earlier sessions did not, and used a slower loop: write files into the
clone, hand Stefan the commit text, he clicks Commit and Push. If you find
yourself without push access, that fallback still works — but say clearly
that *his* click is what publishes.

`git` in the connected folder needs delete permission to remove its own
lock files. If a command fails with `Operation not permitted` on
`.git/index.lock`, request delete permission for the folder root, then
`rm -f .git/index.lock`.

### Before any push

```
node embed.js               # copy engine modules into index.html
node verify_embedded.js     # prove the copy took
node apply-ads.js           # apply the advertising route policy
node build-sitemap.js       # regenerate sitemap.xml
```

then every suite in §4. All green, or do not push.

---

## 3. Architecture, and the one trap in it

`index.html` is a **single self-contained file**. The scanner engine exists
twice: as its own module, and copied verbatim inside the page. This is
deliberate — the page works with no build step and no extra requests.

**The trap:** fix a bug in `promptscan.js`, run the tests against the
module, watch them pass, and ship a page that still contains the old code.
This has happened. A broken chain-routing path shipped for a week while its
own tests were green.

Two scripts exist because of it:

- `embed.js` — copies `core.js`, `scanmodel.js` and `promptscan.js` into
  `index.html`. Refuses to write anything if a landmark banner is missing;
  a half-embedded page is worse than a stale one, because a stale one runs.
- `verify_embedded.js` — compares the two copies and fails loudly if they
  disagree. Run it after `embed.js`, every time.

Other build scripts:

- `apply-ads.js` — the advertising route policy (§5). One source, eleven
  outputs. Also the only thing that should edit the ad hosts in any page's
  Content-Security-Policy.
- `build-sitemap.js` — regenerates `sitemap.xml`. Uses git dates; a file
  not yet committed gets today's date and says so.
- `build-suffixes.js` — regenerates the public-suffix table from the
  upstream Public Suffix List (§6). Refuses to write a table it could not
  fetch or that fails its own sanity checks.

---

## 4. The test suites — 484 checks

Run every one of them. Each protects something different.

| File | Checks | What it holds down |
|---|---|---|
| `promptscan.test.js` | 176 | Every detection family, the education-versus-execution boundary, address extraction, public-suffix boundaries |
| `promptscan.ui.test.js` | 82 | The code actually embedded in the page, a full XSS suite, and the advertising isolation checks |
| `guide-examples.test.js` | 72 | The published guides: examples still reach their stated verdict, capability claims match the engine, no resolvable addresses, the ad route policy, the home link |
| `savesavesavesave.regression.test.js` | 61 | Address-engine verdicts across malicious, benign, partial and malformed provider data |
| `scanmodel.test.js` | 57 | The combination policy — one failing component is never diluted |
| `redteam.js` | 20 | Engine output against a careful human reading, benign cases included |
| `goplus-routing.test.js` | 16 | Direct-then-proxy ordering per chain |

`guide-examples.test.js` is the unusual one: it reads the **published
HTML**, not a fixture. The guides invite readers to paste their examples
into the scanner. If the engine drifts and an example stops being detected,
the article becomes a live demonstration that the tool does not work — on
the exact case it claims to catch.

---

## 5. Advertising — read this before touching an ad

Google AdSense, publisher `ca-pub-7192453271158919`. `ads.txt` is verified.
Account was still in review as of 20 September, so slots are often empty.

**The policy lives in `AD_POLICY` at the top of `apply-ads.js`**, with a
written reason for every page. Currently five pages carry advertising and
six deliberately do not.

Ad-free, and why: the four guides about message-based deception
(`seed-phrase-phishing`, `disguised-links`, `prompt-injection`,
`invisible-characters`) plus `privacy` and `terms`. Someone may be reading
the seed-phrase guide *while being defrauded*. An unreviewed commercial
link beside that warning can read as our recommendation, and no disclaimer
undoes it.

**"Off" is four things, not a comment:** no loader script, no ad units, no
reveal script, and the Google ad hosts **removed from that page's own
Content-Security-Policy**. That last one is the enforcement. A browser
applies the *intersection* of a page's meta policy and the response header,
so an ad-free page cannot load an ad even though the site-wide header in
`_headers` still permits those hosts for the pages that serve. Deleting
markup alone would leave a page one careless paste away from serving.

Other standing rules, from Stefan:

- No advertiser influences a verdict. No payment removes or downgrades a finding.
- No sponsorship from any project the scanner would reasonably need to assess.
- Scan content is never sold, shared, or sent to an advertising system.
- **Do not optimise for impressions.** Optimise for long-term public trust,
  useful coverage, sustainable economics and honest communication.

Between 18 and 20 September every page carried the ad loader, including the
scanner and the phishing guides. That was a default nobody chose. It has
been corrected, and the correction is recorded in the privacy policy rather
than quietly made.

Each rail now has its own ad unit — `1457626247` left, `8189344100` right —
so the two placements report separately. A test fails if they collapse back
to one id.

---

## 6. The public-suffix rule

Deciding where a public suffix ends is what tells the brand checks who owns
a domain. Get it wrong and the tool accuses real websites.

**It already did.** With a last-two-labels rule, the owner of
`coinbase.co.uk` read as `co.uk`, and an ordinary legitimate link earned a
HIGH brand-impersonation finding. A security tool that cries wolf at real
sites gets switched off, and then it protects nobody.

What is true now:

- `MULTI_LABEL_SUFFIXES` in `promptscan.js` is a **dated subset** of the
  Public Suffix List, labelled as such. `build-suffixes.js` regenerates it.
- **An unresolvable boundary is never guessed.** When a host ends in a
  suffix the table does not carry and has the shape of a country-code
  registry, the boundary is reported as unknown, every brand judgement is
  withheld, and the reader is told ownership could not be determined.

Never reintroduce "take the last two labels, except for these three
suffixes". It is wrong, and the guide that teaches readers about domains
says so in public.

---

## 7. The guides

Published: honeypot tokens · invisible characters · prompt injection ·
seed-phrase phishing · disguised links.

Next: **token approvals** (needs a screenshot of a wallet approval prompt
from Stefan) and **sanctioned addresses** (can be written unaided).

House rules, learned the hard way:

- Stefan edits every guide himself. Draft it, send it, take his pass almost
  wholesale — his prose is better than the draft's. Push back only where
  something is factually wrong.
- Every address that demonstrates a trick must be a **reserved
  documentation name** and must not be a clickable link. The one live
  domain printed anywhere is `metamask.io`, in the links guide, as the
  example of where a name belongs — and the closing note names it as the
  exception. The tests enforce both.
- Every capability the guide claims must be one the engine actually
  performs. `guide-examples.test.js` probes the engine for each claimed row.
- State the limits. "Structure is not reputation." A clean structural
  result is not a safety verdict, and the guides say so.
- No test-suite detail in the article itself; that belongs in Technical
  Transparency.

---

## 8. Naming

The public documents were renamed on 20 September. **Filenames unchanged**
so nothing breaks:

| File | Called |
|---|---|
| `whitepaper.html` | Before You Act |
| `technical-appendix.html` | Technical Transparency |

---

## 9. Open items

1. **The scanner's footer has no Technical Transparency link.** Every other
   page's does. Small, safe, routine — just fix it.
2. **Consent verification.** Google's consent dialogue is enabled in the
   AdSense account, but nobody has confirmed it *behaves* correctly on the
   live site: that it appears, that declining genuinely stops personalised
   ads, that accepting is recorded. Needs a network capture against the
   live pages under each answer. Do this before personalised advertising is
   relied on for revenue. Stefan does nothing; this is a check to run.
3. **Guides 6 and 7** (§7).
4. **Two stale markdown whitepapers** — `SaveSaveSaveSave_Whitepaper_v3.0.md`
   and `_Short_v3.0.md` — are unlinked but publicly fetchable and now
   contradict the HTML. Deleting them was recommended, not yet approved.
5. **Punycode is identified, not translated.** The engine flags an `xn--`
   host but cannot say which name it renders as. A real gap, published as
   such in the links guide.
6. **Plain misspellings** (`metamsk.io`) are not detected. There is a test
   asserting they are not, so the gap stays a known quantity.
7. **Traffic is small** — roughly 32 real visits a day as of mid-September.
   Do not build revenue models on optimistic numbers; that mistake was
   already made and corrected six-fold downward.

---

## 10. Mistakes already made — do not repeat them

- **Inventing a click path.** Stefan was told to use a control in a
  settings screen that does not exist, and separately was assumed to have
  an app installed that he did not. If a step involves a button, verify it
  exists or say plainly that you are unsure. When it is a third-party
  interface, read the vendor's current documentation rather than recalling
  it.
- **Claiming something is verified when it was only reasoned about.** The
  ad isolation was asserted in a comment long before anyone watched the
  network. Comments are not enforcement. Tests are better. A live capture
  is better still.
- **Letting a default become a decision.** Ads on every page happened
  because the installer added them everywhere and nobody chose otherwise.
  Defaults need reasons written next to them.
- **Shipping a fix to a module the page does not load.** See §3.
