// Isolated synthetic records only; does not contact or modify an installed backend.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const frontend = path.resolve(__dirname, '../frontend');
  const now = new Date().toISOString();
  const fixture = index => ({
    task_id: 'fixture-' + index, task_key: 'fixture-' + index, goal: '测试任务 ' + index,
    source_kind: index % 3 === 0 ? 'test' : 'live', status: 'completed', started_at: now, ended_at: now,
    events: [
      { event_type: 'input_event', task_id: 'fixture-' + index, timestamp: now, user_goal: 'Synthetic fixture' },
      { event_type: 'risk_decision_event', event_id: 'risk-' + index, timestamp: now, risk_score: 12, gate_action: 'allow', tool_name: 'read' },
      { event_type: 'result_event', event_id: 'result-' + index, timestamp: now, status: 'success' }
    ]
  });
  let tasks = Array.from({ length: 1200 }, (_, i) => fixture(i));
  let revision = 1, historyReads = 0, conditionalReads = 0;
  const errors = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      const history = url.searchParams.get('scope') === 'history';
      const window = { monitoring_scope: history ? 'history' : 'current', monitoring_started_at: history ? null : '2026-09-12T00:00:00Z' };
      res.setHeader('Content-Type', 'application/json');
      if (url.pathname === '/api/live/tasks') {
        if (history) historyReads++;
        const etag = '"' + revision + '-' + history + '"';
        res.setHeader('ETag', etag);
        if (req.headers['if-none-match'] === etag) { conditionalReads++; res.writeHead(304); res.end(); return; }
        const rows = history ? tasks : tasks.slice(0, 2);
        res.end(JSON.stringify({ ...window, tasks: rows, task_count: rows.length,
          ...(url.searchParams.get('format') === 'compact' ? {
            transport: 'task-events-v1', event_defaults: {}, decision_refs: rows.map(() => [1, 1])
          } : {}) }));
      } else res.end(JSON.stringify({ ...window, server: { status: 'healthy' }, rules: { rules_version: 'fixture', weights: {}, thresholds: [] } }));
      return;
    }
    const relative = url.pathname.replace(/^\//, '');
    const file = path.resolve(frontend, relative);
    if (!file.startsWith(frontend + path.sep) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
    res.setHeader('Content-Type', file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.jpg') ? 'image/jpeg' : 'text/html');
    res.end(fs.readFileSync(file));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true, ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}) });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/security-layer.html`);
    const ready = () => page.waitForFunction(() => !document.querySelector('#refreshButton').disabled);
    await ready();
    assert.equal(await page.inputValue('#monitoringScope'), 'current');
    await page.selectOption('#monitoringScope', 'history');
    await ready();
    await page.click('[data-page="tasks"]');
    assert.match(await page.locator('.scope-count').innerText(), /1200/);
    assert.equal(await page.locator('.selection-item').count(), 50);
    assert.equal(await page.locator('.advanced-filters').count(), 0);
    await page.selectOption('#advancedSourceFilter', 'test');
    assert.equal(await page.inputValue('#advancedSourceFilter'), 'test');
    assert.match(await page.locator('.scope-count').innerText(), /400/);
    await page.selectOption('#advancedSourceFilter', 'all');
    assert.match(await page.locator('.scope-count').innerText(), /1200/);
    await page.selectOption('#timeFilter', 'unknown');
    assert.equal(await page.locator('.selection-item').count(), 0);
    assert.equal(await page.inputValue('#timeFilter'), 'unknown');
    await page.selectOption('#timeFilter', 'all');
    await page.fill('#searchInput', '测试任务 1199');
    await page.waitForFunction(() => document.querySelectorAll('.selection-item').length === 1);
    assert.match(await page.locator('.detail-heading h2').innerText(), /1199/);
    await page.fill('#searchInput', '');
    await page.waitForFunction(() => document.querySelectorAll('.selection-item').length === 50);
    await page.locator('.selection-list').evaluate(list => { list.scrollTop = list.scrollHeight; });
    await page.waitForFunction(() => document.querySelectorAll('.selection-item').length > 50);
    await page.locator('.selection-item').nth(55).click();
    const scroll = await page.locator('.selection-list').evaluate(list => list.scrollTop);
    await page.locator('summary').filter({ hasText: '技术详情' }).first().click();
    await page.click('#refreshButton');
    await ready();
    assert.equal(await page.locator('details').filter({ has: page.locator('summary').filter({ hasText: '技术详情' }) }).first().getAttribute('open'), '');
    assert.equal(await page.locator('.selection-list').evaluate(list => list.scrollTop), scroll);
    assert(conditionalReads > 0);
    const reads = historyReads;
    await page.selectOption('#monitoringScope', 'current');
    await ready();
    await page.selectOption('#monitoringScope', 'history');
    await ready();
    assert.equal(historyReads, reads);
    await page.click('[data-page="evidence"]');
    await page.locator('[data-evidence-key]').first().check();
    const filePromise = page.waitForEvent('download');
    await page.click('[data-action="download-selected"]');
    const file = await filePromise;
    const snapshot = JSON.parse(fs.readFileSync(await file.path(), 'utf8'));
    assert.equal(snapshot.tasks.length, 1);
    await page.click('[data-action="select-all"]');
    assert.match(await page.locator('.section-heading h2').innerText(), /1200 \/ 1200/);
    assert.equal(await page.locator('[data-report-content] .report-section').count(), 0);
    const allPromise = page.waitForEvent('download');
    await page.click('[data-action="download-selected"]');
    const all = await allPromise;
    assert.equal(JSON.parse(fs.readFileSync(await all.path(), 'utf8')).tasks.length, 1200);
    await page.click('[data-action="clear-selection"]');
    await page.locator('[data-evidence-key]').first().check();
    await page.locator('[data-lazy-report] summary').click();
    await page.waitForFunction(() => document.querySelectorAll('[data-report-content] .report-section').length > 0);
    assert.equal(await page.locator('[data-report-content] .report-section').count(), 2);
    await page.evaluate(() => { window.print = () => {}; });
    await page.click('[data-action="print"]');
    assert.equal(await page.locator('#printReport .report-section').count(), 2);
    revision++; tasks = [fixture(1201), ...tasks];
    await page.click('#refreshButton');
    await ready();
    await page.click('[data-page="tasks"]');
    assert.match(await page.locator('.scope-count').innerText(), /1201/);
    await page.selectOption('#monitoringScope', 'current');
    await ready();
    await page.click('[data-page="tasks"]');
    await page.locator('summary').filter({ hasText: '技术详情' }).first().click();
    const content = await page.locator('#pageContent').elementHandle();
    await page.waitForTimeout(5500);
    assert(await content.evaluate(node => node.isConnected));
    assert.equal(await page.locator('details').filter({ has: page.locator('summary').filter({ hasText: '技术详情' }) }).first().getAttribute('open'), '');
    for (const width of [390, 820, 900, 1024, 1280, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const section of ['overview', 'tasks', 'risks', 'reviews', 'evidence', 'rules']) {
        await page.evaluate(section => { location.hash = section; }, section);
        await page.waitForFunction(section => document.querySelector('#pageContent').dataset.renderedPage === section, section);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
        assert(!overflow, `${section} overflow at ${width}`);
      }
    }
    await page.setViewportSize({ width: 1440, height: 1000 });
    assert.equal(await page.locator('body').evaluate(node => getComputedStyle(node).fontSize), '15px');
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed: true, records: 1201, conditionalReads, checks: ['direct filters', 'all-record search', 'incremental lists', 'scope cache', 'stable disclosures', 'selected export and print', 'unrendered-record full export', 'live polling preserves DOM', 'six-page responsive typography'] }));
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
