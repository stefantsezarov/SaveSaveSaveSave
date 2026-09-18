// Generate SaveSaveSaveSave-Whitepaper.pdf by printing whitepaper.html.
//
// One source, two editions: the PDF linked from the site is this page's
// print stylesheet, so the download can never quietly describe an older
// product than the page does.
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto('file://' + path.join(__dirname, 'whitepaper.html'), { waitUntil: 'load' });
  await page.emulateMedia({ media: 'print' });
  await page.pdf({
    path: path.join(__dirname, 'SaveSaveSaveSave-Whitepaper.pdf'),
    format: 'A4',
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate:
      '<div style="width:100%; font-size:8pt; color:#5B677D; padding:0 16mm; ' +
      'font-family:sans-serif; display:flex; justify-content:space-between;">' +
      '<span>SaveSaveSaveSave — Whitepaper · September 2026 · savesavesavesave.xyz</span>' +
      '<span class="pageNumber"></span></div>',
    margin: { top: '18mm', right: '16mm', bottom: '20mm', left: '16mm' },
  });
  await browser.close();
  console.log('wrote SaveSaveSaveSave-Whitepaper.pdf');
})();
