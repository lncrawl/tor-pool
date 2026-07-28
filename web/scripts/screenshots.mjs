// Capture the dashboard for docs/images, in both themes.
//
// Run against a pool that already has traffic, or every chart is empty and the
// screenshots undersell the thing. From the repo root:
//
//   docker compose up -d --build
//   # drive some requests through the SOCKS port, then:
//   docker run --rm --add-host=host.docker.internal:host-gateway \
//     -e ADMIN_PASSWORD=... \
//     -v "$PWD/web/scripts":/work -v "$PWD/docs/images":/out -w /work \
//     mcr.microsoft.com/playwright:v1.49.1-noble \
//     sh -c "npm i playwright@1.49.1 --silent && node screenshots.mjs"
//
// ADMIN_PASSWORD is required: the dashboard is behind a sign-in screen, and on a
// first run the password is generated and printed to the container log.
//
// Playwright is not a project dependency: it is only needed to refresh the
// screenshots, and pulling a browser into every install is not worth it.
//
// Note: waitUntil is 'domcontentloaded', never 'networkidle' — the dashboard
// holds an SSE connection open for its whole life, so the network never idles.

import { chromium } from 'playwright';

const base = process.env.BASE ?? 'http://host.docker.internal:8080';
const user = process.env.ADMIN_USER ?? 'admin';
const password = process.env.ADMIN_PASSWORD;
const errors = [];

if (!password) {
  console.error('set ADMIN_PASSWORD: the dashboard requires a sign-in');
  process.exit(2);
}

// signIn seeds the session the way the app itself stores it, so the run starts on
// the dashboard rather than the sign-in screen. Going through the login form
// would work too, but this keeps the theme seeding and the credential in one
// reload instead of two.
async function signIn(page) {
  const res = await page.request.post(`${base}/api/auth/login`, {
    data: { user, password },
  });
  if (!res.ok()) {
    throw new Error(`login failed: ${res.status()} ${(await res.text()).trim()}`);
  }
  return res.json();
}

const browser = await chromium.launch();
for (const theme of ['light', 'dark']) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on('console', (m) => { if (m.type() === 'error') errors.push(`[${theme}] ${m.text()}`); });
  page.on('pageerror', (e) => errors.push(`[${theme}] pageerror: ${e.message}`));

  await page.goto(base, { waitUntil: 'domcontentloaded' });

  // The sign-in screen is worth a shot of its own, once.
  if (theme === 'light') {
    await page.waitForSelector('text=Sign in to manage the pool', { timeout: 15000 });
    await page.screenshot({ path: '/out/signin-light.png' });
  }

  const session = await signIn(page);
  await page.evaluate(
    ([t, token, name]) => {
      localStorage.setItem('torpool.theme', t);
      localStorage.setItem('torpool.token', token);
      localStorage.setItem('torpool.user', name);
    },
    [theme, session.token, session.user],
  );
  await page.reload({ waitUntil: 'domcontentloaded' });
  await page.waitForSelector('text=Routable instances', { timeout: 15000 });
  await page.waitForTimeout(2500);

  const title = await page.textContent('h4');
  const live = await page.textContent('.ant-badge-status-text');
  console.log(`${theme}: title=${title} status=${live}`);
  await page.screenshot({ path: `/out/overview-${theme}.png` });

  for (const [tab, name] of [['Instances','instances'],['Sessions','sessions'],['Tokens','tokens'],['Events','events']]) {
    await page.click(`.ant-tabs-tab:has-text("${tab}")`);
    await page.waitForTimeout(1200);
    await page.screenshot({ path: `/out/${name}-${theme}.png` });
  }
  await page.close();
}
await browser.close();

if (errors.length) { console.log('CONSOLE ERRORS:'); errors.forEach(e => console.log('  ' + e)); process.exit(1); }
console.log('no console errors');
