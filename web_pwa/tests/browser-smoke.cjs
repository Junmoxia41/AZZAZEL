// Browser smoke test against the real public deployment.
// Install Playwright (and Chromium) separately; NODE_PATH may point to its install.
// Supabase discovery is explicitly mocked to [] to avoid connecting to the user's PC.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const base = process.env.PWA_TEST_URL || 'https://azzazel-vpn.vercel.app';
  const origin = new URL(base).origin;
  const evidence = path.resolve(__dirname, '../../docs/deployments');
  fs.mkdirSync(evidence, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const report = { base_url: base, tested_at: new Date().toISOString(),
    scope: 'Real React/CSS over HTTPS, no Vercel session; login form rendering only. Supabase discovery mocked, no account login or PC operations.',
    tests: [] };
  try {
    for (const testCase of [
      { name: 'mobile', viewport: { width: 390, height: 844 }, route: '/' },
      { name: 'desktop-spa-route', viewport: { width: 1440, height: 900 }, route: '/ajustes/conexion' },
    ]) {
      const context = await browser.newContext({ viewport: testCase.viewport });
      await context.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.origin === origin) return route.continue();
        // No credentials or PC endpoint is used by this test.
        if (url.hostname.endsWith('.supabase.co')) {
          return route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
        }
        if (['fonts.googleapis.com', 'fonts.gstatic.com'].includes(url.hostname)) return route.continue();
        return route.abort();
      });
      const page = await context.newPage();
      const errors = [], resources = [];
      page.on('pageerror', error => errors.push(error.message));
      page.on('console', msg => {
        if (msg.type() === 'error' && /MIME|module script|stylesheet/i.test(msg.text())) errors.push(msg.text());
      });
      page.on('response', response => {
        const request = response.request();
        if (new URL(response.url()).origin === origin && ['script', 'stylesheet'].includes(request.resourceType())) {
          resources.push({ type: request.resourceType(), status: response.status(), url: response.url(), mime: response.headers()['content-type'] });
        }
      });
      const response = await page.goto(base + testCase.route, { waitUntil: 'networkidle', timeout: 45000 });
      assert.equal(response.status(), 200);
      assert.equal(new URL(page.url()).origin, origin, 'Must not redirect to Vercel login');
      await page.locator('input[type="email"]').waitFor({ state: 'visible', timeout: 15000 });
      await page.waitForFunction(() => !document.body.textContent.includes('Comprobando enlace seguro con tu PC...'), { timeout: 15000 });
      const rootChildren = await page.locator('#root').evaluate(root => root.childElementCount);
      assert.ok(rootChildren > 0, 'React did not mount');
      const background = await page.locator('body').evaluate(body => getComputedStyle(body).backgroundColor);
      assert.equal(background, 'rgb(7, 10, 19)', 'Stylesheet did not apply');
      assert.ok(resources.some(r => r.type === 'script' && r.status === 200 && /javascript/.test(r.mime)));
      assert.ok(resources.some(r => r.type === 'stylesheet' && r.status === 200 && /text\/css/.test(r.mime)));
      assert.deepEqual(errors, [], 'Browser runtime / MIME errors');
      await page.screenshot({ path: path.join(evidence, `mime-fix-${testCase.name}.png`), fullPage: true });
      report.tests.push({ name: testCase.name, passed: true, react_mounted: true, login_form_visible: true,
        body_background: background, errors, resources });
      console.log('PASS', testCase.name, '— React mounted, CSS applied, login visible, no module/MIME errors');
      await context.close();
    }
    report.passed = true;
  } catch (error) {
    report.passed = false;
    report.error = error.message;
    console.error(error);
    process.exitCode = 1;
  } finally {
    fs.writeFileSync(path.join(evidence, 'mime-browser-verification.json'), JSON.stringify(report, null, 2) + '\n');
    await browser.close();
  }
})();
