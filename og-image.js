// Renders og-image.html to og-image.png (1200x630), the link-preview card.
// Usage: node og-image.js
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
  await page.goto('file://' + path.join(__dirname, 'og-image.html'));
  await page.evaluate(() => document.fonts.ready);
  const missing = await page.evaluate(() =>
    ['700 10px "Space Grotesk"', '400 10px "IBM Plex Sans"', '600 10px "IBM Plex Mono"']
      .filter(f => !document.fonts.check(f)));
  if (missing.length) throw new Error('Fonts not loaded: ' + missing.join(', '));
  await page.screenshot({ path: path.join(__dirname, 'og-image.png'), clip: { x: 0, y: 0, width: 1200, height: 630 } });
  await browser.close();
  console.log('wrote og-image.png');
})().catch(e => { console.error(e); process.exit(1); });
