// 実行例: IDOBATA_PLAYWRIGHT=/path/to/playwright node scripts/verify-site.cjs
const { chromium } = require(process.env.IDOBATA_PLAYWRIGHT || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const base = process.env.IDOBATA_SITE_URL || 'http://127.0.0.1:19168';
const output = process.env.IDOBATA_SITE_EVIDENCE || '/tmp/idobata-site-qa';

(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true,
    ...(process.env.IDOBATA_CHROME ? { executablePath: process.env.IDOBATA_CHROME } : {}),
    args: ['--no-sandbox'] });
  const checks = [];
  try {
    for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844], ['narrow', 320, 780]]) {
      const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1 });
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(base + '/', { waitUntil: 'networkidle' });
      await page.locator('.post').first().waitFor();
      assert.equal(await page.locator('h1').count(), 1);
      assert.equal(await page.locator('.post').count(), 3);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      assert.equal(await page.locator('.hero-icon').evaluate(e => e.complete && e.naturalWidth > 0), true);
      await page.screenshot({ path: output + '/' + name + '.png', fullPage: true });
      await page.getByRole('link', { name: '使い方', exact: true }).click();
      await page.waitForURL('**/docs/');
      assert.match(await page.title(), /使い方/);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      assert.deepEqual(errors, []);
      checks.push(name + ': rendering, posts, navigation, overflow, no page errors');
      await page.close();
    }
    const page = await browser.newPage();
    const actual = await (await page.request.get(base + '/posts.json')).json();
    let response = { status: 503, contentType: 'application/json', body: '{}' };
    await page.route('**/posts.json', route => route.fulfill(response));
    await page.goto(base + '/');
    await page.getByText('公開投稿を取得できませんでした。', { exact: false }).waitFor();
    assert.equal(await page.locator('.post').count(), 0);
    response = { status: 200, contentType: 'application/json', body: JSON.stringify(actual) };
    await page.getByRole('button', { name: '投稿を再取得' }).click();
    await page.locator('.post').first().waitFor();
    assert.equal(await page.locator('.post').count(), 3);
    response = { status: 500, contentType: 'application/json', body: '{}' };
    await page.getByRole('button', { name: '投稿を再取得' }).click();
    await page.getByText('前回取得した内容を表示しています。', { exact: false }).waitFor();
    assert.equal(await page.locator('.post').count(), 3);
    checks.push('feed failure, retry recovery, previous snapshot on refresh failure');
    response = { status: 200, contentType: 'application/json',
      body: JSON.stringify({ version: 1, updated_at: actual.updated_at, posts: [] }) };
    await page.getByRole('button', { name: '投稿を再取得' }).click();
    await page.getByText('公開投稿はまだありません。', { exact: true }).waitFor();
    assert.equal(await page.locator('.post').count(), 0);
    checks.push('empty feed distinguished from errors');
    const injected = structuredClone(actual);
    injected.posts[0].signed.content.title = '<img src=x onerror="window.injected=true">';
    injected.posts[0].signed.content.body = '<script>window.injected=true</script>';
    response.body = JSON.stringify(injected);
    await page.getByRole('button', { name: '投稿を再取得' }).click();
    await page.getByText(injected.posts[0].signed.content.title, { exact: true }).waitFor();
    assert.equal(await page.locator('.post h3 img, .post-body script').count(), 0);
    assert.equal(await page.evaluate(() => window.injected), undefined);
    checks.push('untrusted title and body rendered as text');
    injected.posts[0].signed.content.references = ['javascript:alert(1)'];
    response.body = JSON.stringify(injected);
    await page.getByRole('button', { name: '投稿を再取得' }).click();
    await page.locator('.feed-error').waitFor();
    checks.push('invalid reference URL fails closed');
    const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    const copyPage = await context.newPage();
    await copyPage.goto(base + '/');
    await copyPage.getByRole('button', { name: 'コピー', exact: true }).click();
    await copyPage.getByText('ビルド手順をコピーしました。', { exact: true }).waitFor();
    assert.match(await copyPage.evaluate(() => navigator.clipboard.readText()), /cargo build --locked --release/);
    checks.push('copy install commands');
    const result = { version: 1, checked_at: new Date().toISOString(), base, checks, outcome: 'passed' };
    fs.writeFileSync(output + '/result.json', JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
