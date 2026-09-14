# Moving to Cloudflare Pages

## Do this in two passes, not one

The files in this folder point every public URL at `savesavesavesave.pages.dev`.
**Do not upload them until that site is actually serving.** A canonical tag
pointing at a URL that 404s tells Google the real version of the page does not
exist, which is worse than leaving it on GitHub Pages.

So: get Pages live first with the files you already have, confirm it works,
*then* upload these three.

---

## Pass 1 — create the project

In the Cloudflare dashboard: **Workers & Pages → Create → Pages →
Connect to Git**.

Connect to Git, not Direct Upload. Your workflow is uploading files through
the GitHub web interface; with Git connected, every one of those uploads
deploys to Pages automatically. Direct Upload would mean doing the work twice,
forever.

Pick the `SaveSaveSaveSave` repo, then:

| Setting | Value |
|---|---|
| Project name | `savesavesavesave` — this is what makes the URL |
| Production branch | `main` |
| Framework preset | **None** |
| Build command | **leave empty** |
| Build output directory | `/` |

The build settings are where this usually goes wrong. The site is plain HTML
with no build step; if a framework preset is selected, Cloudflare will look for
a build that does not exist and fail.

Deploy, wait for the green tick, then open `https://savesavesavesave.pages.dev`
and run one real scan to confirm the engine works.

### If the project name is taken

Cloudflare will tell you, and the URL will be something else. Send me the
actual URL and I will regenerate these three files — do not hand-edit them,
there are 16 URLs across the three and missing one is silent.

---

## Pass 2 — point the URLs at the new home

Once the Pages site is serving, upload these three files to GitHub:

- `index.html`
- `sitemap.xml`
- `robots.txt`

Pages redeploys on its own. GitHub Pages stays live and now carries a canonical
tag pointing at the Pages URL, which tells Google to consolidate on the new
address instead of treating the two as duplicates.

---

## Two things that break silently

**The Worker's CORS allowlist.** `goplus-proxy-worker.js` in the update zip
already lists `savesavesavesave.pages.dev`. If you have not deployed that
version yet, the fallback path will fail CORS on the Pages site — invisibly,
and only for the visitors whose browser blocks GoPlus directly, which is
exactly who the fallback exists for. Deploy the Worker before or with this move.

**`robots.txt` starts working now.** On GitHub Pages it sat at
`/SaveSaveSaveSave/robots.txt`, which crawlers ignore — only a domain root
counts. On Pages the site *is* the root, so the file takes effect and the
sitemap reference in it is finally read.

---

## Worth doing once it is live

Add the site to **Google Search Console** and submit
`https://savesavesavesave.pages.dev/sitemap.xml` directly. Verification is a
DNS record or an HTML file; on Pages the file method works without a custom
domain. Without this, a brand-new site with no inbound links can sit
undiscovered for weeks.

## A real domain later

`savesavesavesave.com` is roughly $10–15/year and is the version worth having
when there is money for it — a `.pages.dev` address reads as a staging URL to
anyone evaluating whether to trust a security tool. Nothing about this move
blocks it: when the domain exists, add it in the Pages project under Custom
Domains, add it to the Worker's `ALLOWED_ORIGINS`, and run

    ./switch-domain.sh https://savesavesavesave.com

The migration path is the same one you are running now.
