#!/usr/bin/env bash
# Point every public URL at a new home.
#
# RUN THIS ONLY AFTER the new site is actually live and serving. A canonical
# tag pointing at a 404 is worse than no canonical tag: it tells Google the
# real version of this page does not exist.
#
#   ./switch-domain.sh https://savesavesavesave.pages.dev
#   ./switch-domain.sh https://savesavesavesave.com
#
# Deliberately does NOT touch the Worker URL in index.html or core.js. That
# hostname happens to contain "riskpass", which looks like something the
# rebrand missed. It is not. It is the live endpoint every fallback scan
# depends on, and renaming the Worker in Cloudflare breaks the site until
# both copies of SOLANA_PROXY_URL are updated to match. Leave it alone.

set -euo pipefail

NEW="${1:-}"
if [[ -z "$NEW" ]]; then
  echo "usage: $0 https://your-new-domain" >&2
  exit 1
fi
NEW="${NEW%/}"   # strip any trailing slash

OLD="https://stefantsezarov.github.io/SaveSaveSaveSave"

FILES=(index.html sitemap.xml robots.txt)
for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || { echo "missing: $f" >&2; exit 1; }
done

echo "  from: $OLD"
echo "    to: $NEW"
echo

before=0
for f in "${FILES[@]}"; do
  n=$(grep -c "$OLD" "$f" || true)
  before=$((before + n))
  printf '  %-14s %2d occurrence(s)\n' "$f" "$n"
done

if [[ "$before" -eq 0 ]]; then
  echo
  echo "Nothing to change -- already switched, or run from the wrong directory."
  exit 0
fi

for f in "${FILES[@]}"; do
  sed -i.bak "s|${OLD}|${NEW}|g" "$f"
  rm -f "$f.bak"
done

echo
after=0
for f in "${FILES[@]}"; do
  n=$(grep -c "$OLD" "$f" || true)
  after=$((after + n))
done

if [[ "$after" -ne 0 ]]; then
  echo "WARNING: $after occurrence(s) of the old URL survived. Check manually." >&2
  exit 1
fi

echo "Rewrote $before URL(s) across ${#FILES[@]} files."
echo
echo "Worker URL left untouched (correct):"
grep -o 'https://[a-z0-9.-]*workers\.dev' index.html | sort -u | sed 's/^/  /'
echo
echo "NEXT: add \"$NEW\" to ALLOWED_ORIGINS in goplus-proxy-worker.js and"
echo "      redeploy the Worker, or the fallback path will fail CORS."
