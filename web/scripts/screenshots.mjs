// Capture the dashboard for docs/images, in both themes.
//
// Run against a pool that already has traffic, or every chart is empty and the
// screenshots undersell the thing. From the repo root:
//
//   docker compose up -d --build
//   # drive some requests through the SOCKS port, then:
//   docker run --rm --add-host=host.docker.internal:host-gateway \
//     -v "$PWD/web/scripts":/work -v "$PWD/docs/images":/out -w /work \
//     mcr.microsoft.com/playwright:v1.49.1-noble \
//     sh -c "npm i playwright@1.49.1 --silent && node screenshots.mjs"
//
// Playwright is not a project dependency: it is only needed to refresh the
// screenshots, and pulling a browser into every install is not worth it.
//
// Note: waitUntil is 'domcontentloaded', never 'networkidle' — the dashboard
// holds an SSE connection open for its whole life, so the network never idles.

import { chromium } from 'playwright';

const base = process.env.BASE ?? 'http://host.docker.internal:8080';
const errors = [];

const browser = await chromium.launch();
for (const theme of ['light', 'dark']) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on('console', (m) => { if (m.type() === 'error') errors.push(`[${theme}] ${m.text()}`); });
  page.on('pageerror', (e) => errors.push(`[${theme}] pageerror: ${e.message}`));

  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.evaluate((t) => localStorage.setItem('torpool.theme', t), theme);
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForSelector('text=Routable instances', { timeout: 15000 });
  await page.waitForTimeout(2500);

  const title = await page.textContent('h4');
  const live = await page.textContent('.ant-badge-status-text');
  console.log(`${theme}: title=${title} status=${live}`);
  await page.screenshot({ path: `/out/overview-${theme}.png` });

  for (const [tab, name] of [['Instances','instances'],['Sessions','sessions'],['Events','events']]) {
    await page.click(`.ant-tabs-tab:has-text("${tab}")`);
    await page.waitForTimeout(1200);
    await page.screenshot({ path: `/out/${name}-${theme}.png` });
  }
  await page.close();
}
await browser.close();

if (errors.length) { console.log('CONSOLE ERRORS:'); errors.forEach(e => console.log('  ' + e)); process.exit(1); }
console.log('no console errors');
