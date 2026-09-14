// Run with Node and Playwright available via NODE_PATH.
// Uses an isolated HTTP fixture; never writes events to a user's backend.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');

(async () => {
  const frontend = path.resolve(__dirname, '../frontend');
  const now = new Date().toISOString();
  const fixtureTask = (id, adapter, status = 'awaiting_review') => ({
    task_id: id, task_origin: 'openclaw_user_message', session_key: 'private-session-secret',
    goal: '核对项目变更审批 private-business-text', status, started_at: now, ended_at: now,
    event_count: 3, review_count: 1, decision_count: 1, max_risk_score: 58,
    events: [
      { event_type: 'input_event', timestamp: now, adapter, task_id: id, user_goal: 'private-user-prompt' },
      { event_type: 'pending_review_event', timestamp: now, adapter, task_id: id, gate_action: 'human_review', review_id: 'AGR-001', approval_id: 'AGR-001', risk_score: 58, tool_name: 'edit', triggered_rules: ['POL-001'], evidence: 'private-evidence-text' },
      { event_type: 'tool_event', timestamp: now, adapter, task_id: id, tool_name: 'read', status: 'failed', sensitivity: 'sensitive', parameters: { token: 'private-api-token', email: 'private@example.com', mobile: '13800138000' } }
    ]
  });
  const state = {
    failures: {}, tasks: [], boot: new Date(Date.now()-3600000).toISOString(),
    health: { server: { status: 'healthy' }, plugin: { activity_state: 'never_seen' }, guard: { effective_state: 'awaiting_plugin_activity' }, audit: { event_count: 0 }, rules: { rules_version: '2.1', policy_version: '1.3', thresholds: { block: 75 } } }
  };
  const requests = [], errors = [], passed = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      requests.push({ method: req.method, path: url.pathname });
      const failure = state.failures[url.pathname];
      if (failure === 'network') { req.socket.destroy(); return; }
      if (failure === 'timeout') { setTimeout(() => res.end('{}'), 9000).unref(); return; }
      res.setHeader('Content-Type', 'application/json');
      if (typeof failure === 'number') { res.writeHead(failure); res.end('{}'); return; }
      if (failure === 'invalid-json') { res.end('<html>not JSON</html>'); return; }
      if (failure === 'missing') { res.end('{}'); return; }
      const payloads = {
        '/api/live/tasks': { tasks: state.tasks }, '/api/health': state.health,
        '/api/live/summary': { window: { decision_count: 2, high_risk_count: 5 } },
        '/api/supply-chain/samples': { items: [{ label: 'bundled historical example', source: 'sample_clean.json', component: { name: 'fixture-plugin', version: '1' }, risk_score: 0, recommendation: 'allow' }] }
      };
      const payload=payloads[url.pathname]||{};
      if(url.pathname!=='/api/supply-chain/samples')Object.assign(payload,{monitoring_scope:url.searchParams.get('scope')==='current'?'current':'history',monitoring_window_kind:'boot',monitoring_started_at:state.boot});
      res.end(JSON.stringify(payload)); return;
    }
    const files = { '/security-layer.html': ['security-layer.html', 'text/html'], '/security-layer.js': ['security-layer.js', 'text/javascript'], '/security-layer.css': ['security-layer.css', 'text/css'] };
    const entry = files[url.pathname];
    if (!entry) { res.writeHead(204); res.end(); return; }
    res.setHeader('Content-Type', entry[1] + '; charset=utf-8');
    res.end(fs.readFileSync(path.join(frontend, entry[0])));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true, ...(process.env.EDGE_PATH ? { executablePath: process.env.EDGE_PATH } : {}), args: ['--no-proxy-server'] });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    async function waitText(selector, pattern) {
      await page.waitForFunction(({ selector, source }) => new RegExp(source).test(document.querySelector(selector)?.textContent || ''), { selector, source: pattern.source });
    }
    async function open(module) {
      await page.goto(`${base}/security-layer.html?module=${module}`, { waitUntil: 'domcontentloaded' });
      await waitText('#connectionTitle', /监控接口已连接/);
    }
    async function refresh() {
      await page.locator('#retryConnection').click();
      await page.waitForFunction(() => !document.querySelector('#retryConnection').disabled);
    }
    async function download(selector) {
      const event = page.waitForEvent('download');
      await page.locator(selector).click();
      const file = await event;
      assert.match(file.suggestedFilename(), /^AgentMeter-monitoring-.*\.json$/);
      return JSON.parse(fs.readFileSync(await file.path(), 'utf8'));
    }
    await open('live');
    assert.match(await page.locator('#protectStateText').innerText(), /尚未收到插件活动/);
    assert.doesNotMatch(await page.locator('#protectStateText').innerText(), /防护正常/);
    await page.locator('[data-home]').first().click();
    assert.match(await page.locator('#statusData').innerText(), /高风险记录 5 项（非阻断数）/);
    passed.push('无插件不显示防护正常；高风险数不充当阻断数');

    state.health.plugin = { activity_state: 'recent' };
    state.health.guard = { effective_state: 'active' };
    await refresh();
    assert.match(await page.locator('#protectStateText').innerText(), /近期有审计活动.*待验证/);
    state.health.guard.enabled = false;
    await refresh();
    assert.equal(await page.locator('#protectStateText').innerText(), '防护未启用');
    delete state.health.guard.enabled;
    state.health.plugin.activity_state = 'stale';
    await refresh();
    assert.match(await page.locator('#protectStateText').innerText(), /活动已过期/);
    passed.push('近期活动、停用和陈旧插件状态均如实展示');

    state.tasks = [fixtureTask('fixture-001', 'review_synthetic_fixture'), fixtureTask('unknown-001', ''), fixtureTask('runtime-001', 'openclaw', 'running')];
    await open('approvals');
    assert.match(await page.locator('#records').innerText(), /测试 \/ 合成数据/);
    assert.match(await page.locator('#records').innerText(), /来源未知/);
    await page.locator('#records .record').first().click();
    assert.equal(await page.locator('#reportButton').isVisible(), false);
    await page.locator('#approveButton').click();
    assert.equal(await page.locator('#openClawCommand').innerText(), '审批通过 AGR-001');
    assert.equal(await page.locator('#confirmDecision').count(), 0);
    await page.evaluate(() => { Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async value => { window.copiedCommand = value; } } }); });
    const before = JSON.stringify(state.tasks);
    await page.locator('#copyCommandButton').click();
    await waitText('#toast strong', /审批尚未提交/);
    assert.match(await page.locator('#decisionFeedback').innerText(), /审批尚未提交/);
    assert.equal(await page.evaluate(() => window.copiedCommand), '审批通过 AGR-001');
    assert.equal(JSON.stringify(state.tasks), before);
    await page.locator('#cancelDecision').click();
    await page.locator('#rejectButton').click();
    assert.equal(await page.locator('#openClawCommand').innerText(), '审批拒绝 AGR-001');
    await page.evaluate(() => { navigator.clipboard.writeText = async () => { throw Error('denied'); }; document.execCommand = () => false; });
    await page.locator('#copyCommandButton').click();
    await waitText('#toast strong', /复制失败/);
    assert.match(await page.locator('#decisionFeedback').innerText(), /复制失败/);
    assert.equal(requests.filter(req => req.method !== 'GET').length, 0);
    // A backend status update invalidates an already open approval command.
    state.tasks[0].status = 'allowed';
    await waitText('#openClawCommand', /指令不可用/);
    assert.equal(await page.locator('#copyCommandButton').isDisabled(), true);
    await page.locator('#cancelDecision').click();
    await page.locator('#closeDrawer').click();
    assert.equal(await page.locator('#records .record').count(), 1);
    state.tasks[1].events[1].risk_score = 66;
    await refresh();
    assert.match(await page.locator('#records').textContent(), /66 \/ 100/);
    passed.push('审批仅复制；失败不报成功；后端更新后旧指令失效');

    await open('live');
    await page.locator('#liveTaskSelect').selectOption('runtime-001');
    assert.match(await page.locator('#sourceNotice').innerText(), /OpenClaw 上报.*本次开机.*运行中/);
    await page.locator('#liveTaskSelect').selectOption('unknown-001');
    assert.match(await page.locator('#sourceNotice').innerText(), /来源未知.*本次开机.*已记录/);
    passed.push('实时视图与历史视图分开标识，不以 task_origin 伪造真实来源');

    await open('reports');
    await page.locator('#records .record').first().click();
    const selected = await download('#reportButton');
    assert.equal(selected.tasks[0].task_id, 'fixture-001');
    assert.equal(selected.task_count, 1);
    assert.equal(selected.signed, false);
    assert.equal(selected.stale, false);
    assert.equal(selected.tasks[0].source.kind, 'test');
    for (const secret of ['private-api-token', 'private-business-text', 'private-user-prompt', 'private-evidence-text', 'private-session-secret', 'private@example.com', '13800138000']) assert.ok(!JSON.stringify(selected).includes(secret), secret);
    await page.locator('#closeDrawer').click();
    const all = await download('#moduleAction');
    assert.equal(all.task_count, 3);
    passed.push('真实下载单任务 / 已载入任务 JSON；标注未签名；敏感原文不导出');

    state.failures['/api/live/tasks'] = 'network';
    await refresh();
    assert.match(await page.locator('#connectionDetails').innerText(), /网络连接失败.*最近成功/);
    assert.match(await page.locator('#toast strong').textContent(), /刷新未全部成功/);
    assert.equal(await page.locator('#records .record').count(), 3);
    const stale = await download('#moduleAction');
    assert.equal(stale.stale, true);
    assert.equal(stale.task_data_stale, true);
    state.failures = { '/api/health': 401 };
    await refresh();
    assert.match(await page.locator('#connectionDetails').innerText(), /身份验证失败（401）/);
    assert.match(await page.locator('#protectStateText').innerText(), /已过期/);
    assert.doesNotMatch(await page.locator('body').innerText(), /演示模式/);
    state.failures = { '/api/supply-chain/samples': 503 };
    await refresh();
    assert.match(await page.locator('#connectionDetails').innerText(), /扫描记录.*HTTP 503/);
    state.failures = { '/api/live/summary': 'invalid-json' };
    await refresh();
    assert.match(await page.locator('#connectionDetails').innerText(), /有效 JSON/);
    state.failures = { '/api/health': 'missing' };
    await refresh();
    assert.match(await page.locator('#connectionDetails').innerText(), /缺少必要字段/);
    state.failures = { '/api/live/tasks': 'timeout' };
    await refresh();
    assert.match(await page.locator('#connectionDetails').innerText(), /连接超时/);
    state.failures = {};
    await refresh();
    await waitText('#connectionTitle', /监控接口已连接/);
    state.tasks[1].events[1].triggered_rules = 'invalid-array';
    await refresh();
    assert.match(await page.locator('#connectionDetails').textContent(), /缺少必要字段或格式异常/);
    state.tasks[1].events[1].triggered_rules = ['POL-001'];
    await refresh();
    passed.push('断网、401、503、无效 JSON、缺字段、8 秒超时、缓存导出和恢复');

    await open('components');
    assert.equal(await page.locator('#moduleAction').innerText(), '刷新扫描记录');
    assert.match(await page.locator('#sourceNotice').innerText(), /历史样例/);
    await page.locator('#moduleAction').click();
    await page.waitForFunction(() => !document.querySelector('#retryConnection').disabled);
    assert.equal(requests.filter(req => req.path.includes('/scan') || req.method !== 'GET').length, 0);
    await open('tools');
    await page.locator('#searchInput').fill('不存在的工具');
    await page.locator('#moduleAction').click();
    assert.equal(await page.locator('#toast strong').textContent(), '暂无可导出的记录');
    await page.locator('#searchInput').fill('');
    const tools = await download('#moduleAction');
    assert.ok(tools.tasks.every(task => task.events.every(event => event.event_type === 'tool_event')));
    await open('data');
    assert.equal((await download('#moduleAction')).scope, 'filtered_data');
    passed.push('按钮名称匹配刷新 / 下载；筛选导出只包含可见记录');

    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(300); // Let the responsive sidebar transition finish.
    assert.equal(await page.locator('#protectState').isVisible(), true);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    const artifacts = process.env.FRONTEND_TEST_ARTIFACTS;
    if (artifacts) { fs.mkdirSync(artifacts, { recursive: true }); await page.screenshot({ path: path.join(artifacts, 'priority-one-mobile.png'), fullPage: true }); }
    await page.setViewportSize({ width: 1440, height: 1000 });
    await open('approvals');
    if (artifacts) await page.screenshot({ path: path.join(artifacts, 'priority-one-approvals.png'), fullPage: true });
    assert.deepEqual(errors, []);
    passed.push('390px / 桌面布局无横向溢出；无 JavaScript 异常');
    await open('live');
    assert.equal(await page.locator('#historyButton').count(),0);
    assert.equal(await page.locator('#monitoringScope').count(),0);
    assert.equal(await page.locator('#liveTaskSelect option[value]:not([value=""])').count(),3);
    await page.locator('#liveTaskSelect').selectOption('fixture-001');
    assert.equal(await page.locator('#selectedTaskStatus').textContent(),'已允许');
    assert.equal(await page.locator('#moduleSummary article:first-child strong').textContent(),'1');
    assert.match(await page.locator('#taskRangeHint').textContent(),/已完成的也可回看.*关机重启后清零/);
    // Reload retains this boot's tasks in the same selector, including finished tasks.
    await page.reload({waitUntil:'domcontentloaded'});
    await waitText('#connectionTitle', /监控接口已连接/);
    assert.equal(await page.locator('#liveTaskSelect option[value]:not([value=""])').count(),3);
    state.boot=new Date().toISOString();state.tasks=[];
    await refresh();
    assert.equal(await page.locator('#records .record').count(),0);
    assert.equal(await page.locator('#sidePendingCount').textContent(),'0');
    assert.equal(await page.locator('#sideRiskCount').textContent(),'0');
    assert.equal(await page.locator('#liveTaskSelect option[value]:not([value=""])').count(),0);
    assert.equal(await page.locator('#moduleSummary article:first-child strong').textContent(),'0');
    passed.push('无独立历史入口；同次开机任务在下拉框回看；新开机后任务、风险和待审清零');
    console.log(JSON.stringify({ passed: passed.length, checks: passed }, null, 2));
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
