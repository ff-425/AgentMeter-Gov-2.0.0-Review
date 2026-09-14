// Run with Node and Playwright available via NODE_PATH; EDGE_PATH is optional.
// All API responses come from an isolated fixture. Never writes to a user backend.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { execFileSync } = require('node:child_process');
const { chromium } = require('playwright');

(async () => {
  const frontend = path.resolve(__dirname, '../frontend');
  const boot = new Date(Date.now() - 3600000).toISOString();
  const state = { tasks: [] };
  const errors = [], requests = [], passed = [];
  const event = (type, values = {}) => ({
    event_type: type, task_id: 'task-a', timestamp: new Date().toISOString(),
    adapter: 'openclaw', ...values
  });
  const task = (events, values = {}) => ({
    task_id: 'task-a', goal: '读取多个业务文件并核对变更', status: 'running',
    started_at: new Date().toISOString(), ended_at: new Date().toISOString(),
    tools: ['read'], events, event_count: events.length,
    decision_count: events.filter(item => item.event_type === 'risk_decision_event').length,
    max_risk_score: Math.max(0, ...events.map(item => Number(item.risk_score) || 0)),
    ...values
  });
  const decision = values => event('risk_decision_event', { tool_name: 'read', gate_action: 'human_review', risk_score: 70, ...values });
  const pending = values => event('pending_review_event', { tool_name: 'read', gate_action: 'human_review', risk_score: 70, ...values });
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
      requests.push({ method: req.method, path: url.pathname });
      const meta = { monitoring_scope: 'current', monitoring_window_kind: 'boot', monitoring_started_at: boot };
      const payloads = {
        '/api/live/tasks': { ...meta, tasks: state.tasks },
        '/api/health': { ...meta, server: { status: 'healthy' }, plugin: { activity_state: 'recent' }, guard: { effective_state: 'active' }, audit: { event_count: state.tasks.reduce((sum, item) => sum + item.events.length, 0) }, rules: { thresholds: { block: 75 } } },
        '/api/live/summary': { ...meta, window: { decision_count: 0, high_risk_count: 0 } },
        '/api/supply-chain/samples': { items: [] }
      };
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(payloads[url.pathname] || {}));
      return;
    }
    const files = {
      '/security-layer.html': ['security-layer.html', 'text/html'],
      '/security-layer.js': ['security-layer.js', 'text/javascript'],
      '/security-layer.css': ['security-layer.css', 'text/css'],
      '/assets/cjlu-logo.jpg': ['assets/cjlu-logo.jpg', 'image/jpeg'],
      '/assets/desktop-pet-audit-fox-web.png': ['assets/desktop-pet-audit-fox-web.png', 'image/png']
    };
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
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.on('pageerror', error => errors.push(error.message));
    async function open(module) {
      await page.goto(`${base}/security-layer.html?module=${module}`, { waitUntil: 'domcontentloaded' });
      await page.waitForFunction(() => document.querySelector('#connectionTitle').textContent === '监控接口已连接');
      // Control polling deterministically; every refresh below still uses the real
      // public button, fetch path and rendering code.
      await page.evaluate(() => clearInterval(realtimeTimer));
    }
    async function refresh() {
      await page.locator('#retryConnection').click();
      await page.waitForFunction(() => !document.querySelector('#retryConnection').disabled);
      assert.equal(await page.locator('#connectionTitle').innerText(), '监控接口已连接');
    }
    async function assertRiskCount(count, label) {
      assert.equal(await page.locator('#homeRiskCount').innerText(), String(count), `${label}: home`);
      assert.equal(await page.locator('#sideRiskCount').innerText(), String(count), `${label}: side`);
      assert.equal(await page.locator('#moduleSummary article').nth(0).locator('strong').innerText(), String(count), `${label}: risk summary`);
      assert.equal(await page.locator('#records .record').count(), count, `${label}: risk records`);
    }

    const python = process.env.AGENTMETER_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');
    const fixtures = JSON.parse(execFileSync(python, [path.join(__dirname, 'test_risk_display_context.py'), '--fixtures'], { encoding: 'utf8', env: { ...process.env, PYTHONIOENCODING: 'utf-8' } }));
    const reviewTask = review => task([review], {
      task_id: review.task_id, goal: review.user_goal, status: 'awaiting_review',
      max_risk_score: review.risk_score ?? null,
      reviews: [{ review_id: review.review_id, state: 'pending', request_event: review }]
    });
    state.tasks = [reviewTask(fixtures.public)];
    await open('approvals');
    assert.equal(await page.locator('#moduleSummary article').nth(1).locator('strong').innerText(), '0');
    await page.locator('#records .record').first().click();
    assert.equal(await page.locator('#drawerType').innerText(), '中风险 · 人工复核');
    const publicContext = await page.locator('#reviewReasonGrid').innerText();
    assert.match(publicContext, /send_email/);
    assert.match(publicContext, /outbox\/reply.md/);
    assert.match(publicContext, /wa\*\*\*@abc-tech.com/);
    assert.match(publicContext, /R-03A/);
    assert.match(publicContext, /D-01/);
    assert.doesNotMatch(publicContext, /读取内部人员|staff_sensitive|wangjl@/);
    assert.doesNotMatch(await page.locator('#drawerAdvice').innerText(), /拒绝|脱敏摘要/);
    assert.match(await page.locator('#reviewRecommendation').innerText(), /核对收件地址与正文范围/);
    if (process.env.SCREENSHOT_DIR) {
      fs.mkdirSync(process.env.SCREENSHOT_DIR, { recursive: true });
      await page.waitForFunction(() => [...document.images].every(img => img.complete && img.naturalWidth > 0));
      for (const [name, width, height] of [['desktop', 1440, 1000], ['mobile', 390, 844]]) {
        await page.setViewportSize({ width, height });
        await page.waitForTimeout(300);
        await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, `release-1.1.15-approval-${name}.png`), fullPage: true });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        assert.equal(await page.locator('#reviewReasonGrid').evaluate(el => el.scrollWidth <= el.clientWidth), true);
      }
      await page.setViewportSize({ width: 1440, height: 1000 });
    }
    await open('live');
    assert.equal(await page.locator('#selectedTaskRisk').innerText(), '中风险 · 40 / 100');
    assert.doesNotMatch(await page.locator('#storyAction').innerText(), /读取文件|人员数据/);
    await open('risks');
    assert.equal(await page.locator('#radarLevel').innerText(), '中风险');
    assert.match(await page.locator('#radarSubtitle').innerText(), /复核/);
    passed.push('真实 1.1.14 引擎公开邮件输出经后端脱敏后，显示中风险、真实操作及用户指定来源，不虚构敏感外发');

    for (const [score, label] of [[null, '未判定'], [0, '低风险'], [39, '低风险'], [40, '中风险'], [74, '中风险'], [75, '高风险'], [100, '高风险']]) {
      state.tasks = [reviewTask({ ...fixtures.public, risk_score: score })];
      await open('approvals');
      assert.equal(await page.locator('#moduleSummary article').nth(1).locator('strong').innerText(), score >= 75 ? '1' : '0');
      await page.locator('#records .record').first().click();
      assert.equal(await page.locator('#drawerType').innerText(), `${label} · 人工复核`);
      await open('live');
      assert.equal(await page.locator('#selectedTaskRisk').innerText(), `${label} · ${score === null ? '未评分' : score + ' / 100'}`);
      assert.equal(await page.locator('#selectedTaskRisk').getAttribute('class'), score >= 75 ? 'risk' : score === null || score >= 40 ? 'pending' : 'safe');
      await open('risks');
      assert.equal(await page.locator('#radarLevel').innerText(), label);
    }
    passed.push('风险分数边界、零分与缺失评分独立于复核状态；任务、审批与雷达口径一致');

    state.tasks = [reviewTask(fixtures.unnamed)];
    await open('approvals');
    await page.locator('#records .record').first().click();
    assert.match(await page.locator('#reviewReasonGrid').innerText(), /R-03B/);
    assert.match(await page.locator('#reviewRecommendation').innerText(), /非用户指定/);
    assert.doesNotMatch(await page.locator('#drawerAdvice').innerText(), /拒绝原文外发/);
    const sensitiveContext = await page.evaluate(event => taskRiskContext({ events: [event] }, event), fixtures.sensitive);
    assert.match(sensitiveContext.recommendation, /敏感数据证据.*拒绝原文外发/);
    passed.push('实际引擎的非用户指定收件人与敏感外发规则产生不同建议');

    const prior = { ...fixtures.sensitive, task_id: fixtures.public.task_id, review_id: 'AGR-prior', tool_name: 'read_sensitive_file', target: 'staff_sensitive.csv', proposed_tool_call: { name: 'read_sensitive_file', params: { path: 'staff_sensitive.csv' } } };
    const current = reviewTask(fixtures.public);
    current.events.unshift(prior);
    current.reviews.unshift({ review_id: prior.review_id, state: 'approved', request_event: prior });
    state.tasks = [current];
    await open('approvals');
    await page.locator('#records .record').first().click();
    assert.doesNotMatch(await page.locator('#reviewReasonGrid').innerText(), /staff_sensitive|R-02|读取内部人员/);
    assert.doesNotMatch(await page.locator('#drawerAdvice').innerText(), /拒绝/);
    await open('live');
    const stage = await page.evaluate(() => taskStageDetails(selectedAuditTask)[4]);
    assert.equal(stage.reviewId, fixtures.public.review_id);
    assert.doesNotMatch(JSON.stringify(stage.reviewContext), /staff_sensitive|R-02/);
    const matched = { ...fixtures.public, event_type: 'risk_decision_event' };
    const envelope = { ...fixtures.public, triggered_rules: [], recipients: [] };
    const enriched = await page.evaluate(({ matched, envelope }) => taskRiskContext({ events: [matched, envelope] }, envelope), { matched, envelope });
    assert.match(JSON.stringify(enriched), /R-03A/);
    assert.match(JSON.stringify(enriched), /wa\*\*\*@abc-tech.com/);
    passed.push('不同操作证据互不污染，默认选择当前待复核操作，只按明确同操作标识补充证据');

    state.tasks = [task([
      decision({ call_id: 'read-a', target: 'file-A.txt', gate_action: 'block', risk_score: 80 }),
      decision({ call_id: 'read-b', target: 'file-B.txt' })
    ])];
    await open('risks');
    await assertRiskCount(2, 'different calls and dispositions');
    assert.equal(await page.locator('#moduleSummary article').nth(1).locator('strong').innerText(), '1');
    assert.equal(await page.locator('#moduleSummary article').nth(2).locator('strong').innerText(), '1');
    assert.match(await page.locator('#records').innerText(), /风险 80/);
    assert.match(await page.locator('#records').innerText(), /风险 70/);
    state.tasks = [task([
      decision({ call_id: 'read-a', gate_action: 'block', risk_score: 80 }),
      decision({ call_id: 'read-b', gate_action: 'block', risk_score: 90 }),
      decision({ gate_action: 'block', risk_score: 95 })
    ])];
    await refresh();
    await assertRiskCount(3, 'same tool and disposition, separate calls');
    passed.push('不同调用及无标识判定均保留，首页、侧栏和风险页数量一致');

    const associations = [
      ['same call ID', { call_id: 'call-a' }, { call_id: 'call-a' }, 1],
      ['call ID aliases', { call_id: 'call-a' }, { tool_call_id: 'call-a' }, 1],
      ['same operation ID', { operation_id: 'operation-a' }, { operation_id: 'operation-a' }, 1],
      ['same review ID', { review_id: 'AGR-a' }, { review_id: 'AGR-a' }, 1],
      ['same approval ID', { approval_id: 'APP-a' }, { approval_id: 'APP-a' }, 1],
      ['different ID namespaces', { approval_id: 'shared-text' }, { review_id: 'shared-text' }, 2],
      ['conflicting call IDs', { call_id: 'call-a', review_id: 'AGR-a' }, { call_id: 'call-b', review_id: 'AGR-a' }, 2],
      ['conflicting targets', { target: 'file-A.txt', review_id: 'AGR-a' }, { target: 'file-B.txt', review_id: 'AGR-a' }, 2],
      ['conflicting nested file paths', { proposed_tool_call: { name: 'read', params: { path: 'file-A.txt' } }, review_id: 'AGR-a' }, { proposed_tool_call: { name: 'read', params: { path: 'file-B.txt' } }, review_id: 'AGR-a' }, 2],
      ['blocked decision and new pending review', { call_id: 'shared-call', gate_action: 'block' }, { call_id: 'shared-call' }, 2],
      ['no IDs', { target: 'same-file.txt' }, { target: 'same-file.txt' }, 2],
      ['different review IDs', { review_id: 'AGR-a' }, { review_id: 'AGR-b' }, 2],
      ['different task IDs', { task_id: 'task-a', call_id: 'call-a' }, { task_id: 'task-b', call_id: 'call-a' }, 2],
      ['missing task IDs', { task_id: '', call_id: 'call-a' }, { task_id: '', call_id: 'call-a' }, 2]
    ];
    for (const [label, a, b, count] of associations) {
      state.tasks = [task([decision(a), pending(b)])];
      await refresh();
      await assertRiskCount(count, label);
    }
    passed.push(associations.length + ' 种操作/复核标识场景，仅明确同操作的判定与待审事件合并');

    const oldReview = pending({ review_id: 'AGR-OLD', target: 'file-A.txt' });
    const newReview = pending({ review_id: 'AGR-NEW', approval_id: 'APP-NOT-A-REQUEST', target: 'file-B.txt' });
    const thirdReview = pending({ review_id: 'AGR-THIRD', target: 'file-C.txt' });
    state.tasks = [task([oldReview, newReview, thirdReview], { status: 'awaiting_review', review_count: 3, pending_review_count: 2, reviews: [
      { review_id: 'AGR-OLD', state: 'rejected', request_event: oldReview },
      { review_id: 'AGR-NEW', state: 'pending', request_event: newReview },
      { review_id: 'AGR-THIRD', state: 'pending', request_event: thirdReview }
    ] })];
    await open('approvals');
    assert.equal(await page.locator('#records .record').count(), 2);
    assert.equal(await page.locator('#moduleSummary article').nth(2).locator('strong').innerText(), '2');
    assert.match(await page.locator('#records').innerText(), /file-B.txt/);
    assert.doesNotMatch(await page.locator('#records').innerText(), /file-A.txt/);
    await page.locator('#records .record').first().click();
    await page.evaluate(() => openDecision('approve'));
    assert.equal(await page.locator('#openClawCommand').innerText(), '审批通过 AGR-NEW');
    state.tasks[0].reviews[1].state = 'approved';
    state.tasks[0].pending_review_count = 1;
    await page.evaluate(async () => { await loadLiveOpenClawTask(); updateOpenClawCommand('approve'); });
    assert.equal(await page.locator('#copyCommandButton').isDisabled(), true);
    assert.equal(await page.locator('#records .record').count(), 1);
    await page.evaluate(() => { document.querySelector('#decisionDialog').close(); closeDrawer(); });
    state.tasks[0].reviews[2].state = 'rejected';
    state.tasks[0].pending_review_count = 0;
    state.tasks[0].status = 'review_rejected';
    await refresh();
    assert.equal(await page.locator('#records .record').count(), 0);
    await page.locator('[data-module="live"]').first().click();
    assert.equal(await page.locator('#selectedTaskStatus').innerText(), '复核已拒绝');
    assert.equal(await page.locator('.flow-step.review').count(), 0);
    state.tasks[0].status = 'approved_awaiting_retry';
    await refresh();
    assert.equal(await page.locator('#selectedTaskStatus').innerText(), '已批准，待重试');
    passed.push('按待处理复核逐项显示，拒绝与批准状态准确，过期编号不能继续复制');

    // Reproduce the lost-update failure: the final response arrives while the
    // flow is playing, then the backend remains unchanged after playback ends.
    state.tasks = [task([event('input_event', { user_goal: '处理业务文件' })])];
    await open('live');
    await page.locator('#playFlowButton').click();
    state.tasks[0].events.push(event('result_event', { status: 'completed' }));
    state.tasks[0].status = 'completed';
    state.tasks[0].event_count = 2;
    await refresh();
    await page.waitForFunction(() => !document.querySelector('#playFlowButton').disabled);
    assert.equal(await page.locator('#selectedTaskStatus').innerText(), '已完成');
    assert.equal(await page.locator('#records .record').count(), 2);
    assert.equal(await page.locator('#moduleSummary article').nth(0).locator('strong').innerText(), '0');
    assert.equal(await page.locator('#moduleSummary article').nth(3).locator('strong').innerText(), '2');
    assert.match(await page.locator('#flowMessage').innerText(), /当前任务：已完成/);
    await refresh();
    assert.equal(await page.locator('#selectedTaskStatus').innerText(), '已完成');
    assert.equal(await page.locator('#moduleSummary article').nth(0).locator('strong').innerText(), '0');
    if (process.env.SCREENSHOT_DIR) {
      fs.mkdirSync(process.env.SCREENSHOT_DIR, { recursive: true });
      await page.waitForFunction(() => [...document.images].every(img => img.complete && img.naturalWidth > 0));
      await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'monitor-desktop.png'), fullPage: true });
      await page.setViewportSize({ width: 390, height: 844 });
      await page.waitForTimeout(300);
      await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'monitor-mobile.png'), fullPage: true });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.setViewportSize({ width: 1440, height: 1000 });
    }
    passed.push('播放期间完成任务，结束后状态、运行数量和新增事件即时更新');

    state.tasks = [task([event('input_event')])];
    await refresh();
    await page.locator('#playFlowButton').click();
    state.tasks = [];
    await refresh();
    assert.equal(await page.locator('#playFlowButton').isDisabled(), false);
    assert.equal(await page.locator('#records .record').count(), 0);
    assert.equal(await page.locator('#liveTaskSelect option').count(), 1);
    await page.waitForTimeout(6200);
    assert.equal(await page.locator('#records .record').count(), 0);
    assert.doesNotMatch(await page.locator('#flowMessage').innerText(), /流程播放完成/);
    passed.push('播放任务消失时安全取消，旧计时器不会恢复旧记录或抛异常');

    const taskA = task([event('input_event')]);
    const taskB = task([event('result_event', { task_id: 'task-b', status: 'completed' })], { task_id: 'task-b', goal: '第二项业务任务', status: 'completed' });
    state.tasks = [taskA, taskB];
    await refresh();
    await page.locator('#liveTaskSelect').selectOption('task-a');
    await page.locator('#playFlowButton').click();
    await page.locator('#liveTaskSelect').selectOption('task-b');
    assert.equal(await page.locator('#playFlowButton').isDisabled(), false);
    assert.equal(await page.locator('#selectedTaskStatus').innerText(), '已完成');
    assert.match(await page.locator('#selectedTaskGoal').innerText(), /第二项业务任务/);
    await page.locator('#playFlowButton').click();
    await page.locator('[data-home]').first().click();
    assert.equal(await page.locator('#modulePage').isHidden(), true);
    await page.waitForTimeout(6200);
    assert.doesNotMatch(await page.locator('#toast strong').textContent(), /流程播放完成/);
    await page.locator('[data-module="live"]').first().click();
    assert.equal(await page.locator('#playFlowButton').isDisabled(), false);
    assert.equal(await page.locator('#selectedTaskStatus').innerText(), '已完成');
    passed.push('切换任务与返回工作台取消播放，重新进入实时审计仍为最新记录');

    assert.equal(requests.filter(request => request.method !== 'GET').length, 0);
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ passed, browser_errors: errors, non_read_requests: 0 }, null, 2));
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
