(function () {
  'use strict';
  const M = window.MonitorModel;
  const $ = selector => document.querySelector(selector);
  const $$ = selector => [...document.querySelectorAll(selector)];
  const h = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const value = item => item === null || item === undefined || item === '' ? '未提供' : String(item);
  const safe = item => h(M.redact(value(item)));
  const icon = name => '<i data-lucide="' + name + '"></i>';
  const badge = (text, tone = 'neutral') => '<span class="badge ' + tone + '">' + h(text) + '</span>';
  const tone = state => ({warning:'amber',danger:'red',success:'teal',info:'blue'}[state] || state || 'neutral');
  const validDate = input => Boolean(input) && Number.isFinite(Date.parse(input));
  const REFRESH_INTERVAL_MS = 5000;
  const dateFormatter=new Intl.DateTimeFormat('zh-CN',{hour12:false,dateStyle:'short',timeStyle:'medium'});
  const shortDateFormatter=new Intl.DateTimeFormat('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
  const date = input => validDate(input) ? dateFormatter.format(new Date(input)) : '未提供';
  const shortDate = input => validDate(input) ? shortDateFormatter.format(new Date(input)) : '时间未提供';
  function cachedTaskRead(read) {
    const cache=new WeakMap();
    return task=>{if(!cache.has(task))cache.set(task,read(task));return cache.get(task);};
  }
  const riskEvents=cachedTaskRead(M.riskEvents),taskReviews=cachedTaskRead(M.reviews),taskExecution=cachedTaskRead(M.execution);
  // Status depends on time; reuse it only within the current rendering pass.
  let taskStates=new WeakMap();
  const taskState=task=>{if(!taskStates.has(task))taskStates.set(task,M.taskState(task));return taskStates.get(task);};
  const label = {overview:['审计总览','先看当前风险和处理结果'],tasks:['审计任务','查看每项任务做了什么、如何处理、最终结果'],risks:['风险计量','查看每次调用的风险分、五维分析和处理原因'],reviews:['复核与整改','处理需要人工确认的事项，并核对后续执行结果'],evidence:['审计档案','按任务整理证据，用于核查、留档和导出'],rules:['规则与标准','了解系统如何判断风险']};
  const sameOriginBackend = ['http:','https:'].includes(location.protocol) ? location.origin : 'http://127.0.0.1:8765';
  const state = {page:'overview',mode:'backend',tasks:[],health:null,total:null,lastSuccess:null,error:'',healthError:'',loading:false,attempted:false,backend:sameOriginBackend,token:'',query:'',statusFilter:'all',sourceFilter:'live',timeFilter:'all',taskKey:null,riskKey:null,reviewKey:null,selected:new Set(),timer:null};
  state.tasks.forEach(task => state.selected.add(task.task_key));
  state.requestId=0;
  state.monitoringScope='current';
  state.scopeCache=new Map();
  state.endpointCache=new Map();state.rawTasksPayload=null;state.dataRevision=0;
  state.listLimit=50;state.activeList=null;state.listObserver=null;state.searchTimer=null;
  const viewingHistory = () => state.mode==='backend'&&state.monitoringScope==='history';
  const scopeLabel = () => viewingHistory()?'历史记录':'本次开机累计';
  state.runData=null;state.runIndex=0;state.scopeTaskKey=null;
  const taskRiskRows=cachedTaskRead(task=>riskEvents(task).map((event,index)=>({task,event,key:task.task_key+':'+index})));
  const taskReviewRows=cachedTaskRead(task=>taskReviews(task).map((review,index)=>({task,review,key:task.task_key+':'+index})));
  const allRisks = tasks => tasks.flatMap(taskRiskRows);
  const allReviews = tasks => tasks.flatMap(taskReviewRows);
  const sources = (task,event) => {const source=M.source(task,event);return '<span title="'+h(source.detail)+'">'+badge(source.label,source.kind==='test'?'amber':source.kind==='live'?'teal':'neutral')+'</span>';};
  const taskStatusText = current => ({awaiting_review:'待人工确认',review_unconfirmed:'复核情况待确认',approved_awaiting_retry:'已批准，等待执行',review_rejected:'已拒绝',blocked:'已阻止风险操作',block_recommendation:'建议阻止，待核对',failed:'执行失败',not_executed:'未执行',running:'正在运行',incomplete:'记录可能不完整',model_refused:'未执行目标操作',unknown:'结果待确认'}[current.code]||current.label);
  const statusBadge = task => {const current=taskState(task),text=state.mode==='run'&&current.code==='running'?'采集中':taskStatusText(current);return '<span title="'+h(current.detail)+'">'+badge(text,tone(current.tone))+'</span>';};
  const executionText = task => {const result=taskExecution(task);return ({success:result.label==='办理产物已生成'?'办理结果已生成':'已完成',failed:'执行失败',agent_completed:'任务已结束，结果待核对',not_executed:'未执行',awaiting_review:'等待人工确认',model_refused:'未执行目标操作',unprovided:'结果待确认'}[result.status]||result.label);};
  const actionOf = event => event?.gate_action || event?.decision || event?.action || '';
  const actionLabel = event => ({block:event?.summary_only?'建议阻止':'已阻止操作',deny:event?.summary_only?'建议阻止':'已阻止操作',human_review:'需要人工确认',human_review_approved:'人工确认后允许',allow:'允许调用'}[actionOf(event)] || '处理结果待确认');
  const actionTone = event => ['block','deny'].includes(actionOf(event))?'red':actionOf(event)==='human_review'?'amber':['allow','human_review_approved'].includes(actionOf(event))?'teal':'neutral';
  const actionReason = (event,task) => {
    const recorded=event?.evidence||task?.safe_summary?.risk;
    if(recorded)return recorded;
    return ({allow:'本次操作风险较低，系统允许继续。',human_review:'本次操作需要工作人员确认后才能继续。',human_review_approved:'本次操作已经工作人员确认，可以继续。',block:'本次操作风险较高，系统已阻止执行。',deny:'本次操作风险较高，系统已阻止执行。'}[actionOf(event)]||'本次处理依据可在技术详情中核对。');
  };
  const rulesOf = event => (event.triggered_rules || event.matched_rules || []).map(rule => {if(typeof rule==='string')return rule;const id=M.ruleId?.(rule)||rule.rule_id||rule.code,description=rule.description||rule.name||'未提供';return id&&!description.includes(id)?id+'：'+description:description;});
  const rawToolOf = event => event?.proposed_tool_call?.name || event?.tool_name || event?.control_plan?.current_tool || '';
  const toolOf = event => {const name=rawToolOf(event);return ({read:'读取材料',read_document:'读取材料',read_file:'读取文件',write:'保存文件',write_file:'保存文件',write_document:'保存文档',edit:'修改文件',edit_document:'修改文档',apply_patch:'修改文件',exec:'执行本地操作',run_shell:'执行本地操作',send_email:'发送邮件'}[name]||name||'操作类型未记录');};
  const paramsOf = event => event?.proposed_tool_call?.params || event?.parameters || event?.control_plan?.redacted_proposed_params || null;
  const targetOf = event => event?.data_object || event?.target || paramsOf(event)?.path || paramsOf(event)?.attachment || '';
  const fact = (name, item) => '<div class="fact"><span>'+h(name)+'</span><strong>'+safe(item)+'</strong></div>';
  const factHtml = (name, item) => '<div class="fact"><span>'+h(name)+'</span><strong>'+item+'</strong></div>';
  const button = (text,action,iconName='arrow-up-right',extra='') => '<button class="button subtle" data-action="'+action+'" '+extra+'>'+h(text)+icon(iconName)+'</button>';
  const empty = text => '<div class="empty-state">'+icon('inbox')+'<strong>'+h(text)+'</strong><span>当前筛选范围内没有可展示记录</span></div>';
  const runConfirmed = run => run?.execution_mode==='actual_local_openclaw'&&run?.confirmed===true;
  const runList = () => state.runData ? Array.isArray(state.runData.runs)&&state.runData.runs.length ? state.runData.runs : [state.runData] : [];
  const currentRun = () => runList()[state.runIndex] || null;
  const runForTask = task => runList().find(run=>run.task_id===task?.task_id||(run.tasks||[]).some(item=>item.task_id===task?.task_id)) || null;
  const runName = (run,index) => run.scenario_label||run.label||(typeof run.scenario==='string'?run.scenario:run.scenario?.title)||run.title||run.tasks?.[0]?.title||'办理任务 '+(index+1);
  function businessTask(run,index) {
    const original=run.tasks?.find(task=>task.task_id===run.task_id)||run.tasks?.[0]||{};
    const supplied=Array.isArray(run.reviews)?run.reviews:(run.tasks||[]).flatMap(task=>task.reviews||[]);
    const reviews=new Map(supplied.map((review,i)=>[review.review_id||review.review_key||'unidentified-'+i,review]));
    return {...original,task_id:run.task_id,task_key:run.task_id,title:runName(run,index),goal:run.business_goal||run.goal,
      events:run.events||[],reviews:[...reviews.values()],related_task_ids:(run.tasks||[]).map(task=>task.task_id),
      started_at:run.started_at,ended_at:run.ended_at,status:run.status,source_kind:run.source_kind,is_test:run.is_test,
      business_outcome:run.outcome,safe_summary:run.safe_summary||original.safe_summary,
      enforcement_layer:run.outcome?.model_refusal===true?'model_refusal_before_target_tool':original.enforcement_layer};
  }
  function selectRun(index) {
    state.runIndex=Math.max(0,Math.min(index,runList().length-1));
    const run=currentRun(),task=state.tasks.find(task=>task.task_id===(run?.current_task_id||run?.task_id))||state.tasks.find(task=>(run?.tasks||[]).some(item=>item.task_id===task.task_id));
    state.taskKey=task?.task_key||null;state.scopeTaskKey=state.taskKey;state.riskKey=null;state.reviewKey=null;state.query='';state.statusFilter='all';state.sourceFilter='all';state.timeFilter='all';state.selected=new Set(task?[task.task_key]:[]);
  }
  function setTaskScope(key) {
    state.taskKey=key;
    if(state.mode!=='run')return;
    state.scopeTaskKey=key;state.selected=new Set(key?[key]:[]);
    const task=state.tasks.find(task=>task.task_key===key),index=runList().findIndex(run=>run===runForTask(task));
    if(index>=0)state.runIndex=index;
  }
  function datasetUrl(mode) {
    const url=new URL(location.href);mode==='archive'?url.searchParams.delete('dataset'):url.searchParams.set('dataset',mode);history.replaceState(null,'',url);
  }
  function activateRunMode() {
    if(state.mode!=='run'){state.requestId++;state.loading=false;clearInterval(state.timer);state.timer=null;state.mode='run';state.tasks=[];state.selected.clear();state.health=null;state.healthError='';state.lastSuccess=null;state.total=null;state.error='';state.runData=null;state.scopeTaskKey=null;}
    state.sourceFilter='all';state.timeFilter='all';datasetUrl('run');loadRun();
  }
  async function loadRun() {
    if(state.loading)return;
    const requestId=++state.requestId,controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),10000);
    state.loading=true;renderChrome();
    try{
      let response=await fetch('live-runs.json',{cache:'no-store',signal:controller.signal});
      if(response.status===404)response=await fetch('live-run.json',{cache:'no-store',signal:controller.signal});
      if(!response.ok)throw new Error('实际运行记录读取失败（HTTP '+response.status+'）');
      const payload=await response.json();
      if(!payload||typeof payload!=='object'||Array.isArray(payload)||(payload.runs!==undefined&&!Array.isArray(payload.runs)))throw new Error('实际运行记录格式异常');
      const entries=Array.isArray(payload.runs)&&payload.runs.length?payload.runs:[payload];
      const validRecord=run=>run&&typeof run==='object'&&!Array.isArray(run)&&(!run.tasks||Array.isArray(run.tasks)&&run.tasks.every(task=>task&&typeof task.task_id==='string'&&Array.isArray(task.events)&&task.events.every(event=>event&&typeof event==='object'&&!Array.isArray(event))))&&(!run.events||Array.isArray(run.events)&&run.events.every(event=>event&&typeof event==='object'&&!Array.isArray(event)));
      if(!entries.every(entry=>entry&&typeof entry==='object'&&!Array.isArray(entry)))throw new Error('运行索引格式异常');
      const results=await Promise.allSettled(entries.map(async entry=>{
        if(!entry.href){if(!validRecord(entry))throw new Error('运行任务或事件格式异常');return entry;}
        const url=new URL(entry.href,location.href);
        if(url.origin!==location.origin||!/^\/live-artifacts\/[A-Za-z0-9._-]+\.json$/.test(url.pathname)||url.search||url.hash)throw new Error('运行记录地址不在本地证据目录');
        const file=await fetch(url,{cache:'no-store',signal:controller.signal});
        if(!file.ok)throw new Error('场景记录读取失败（HTTP '+file.status+'）');
        const run=await file.json();if(!validRecord(run))throw new Error('场景任务或事件格式异常');
        if(entry.session_key&&run.session_key!==entry.session_key)throw new Error('场景索引与运行会话不一致');
        return {...run,label:entry.label||run.label};
      }));
      const runs=results.map((result,index)=>result.status==='fulfilled'?result.value:{...entries[index],confirmed:false,error:result.reason?.message||'场景记录读取失败',tasks:[],events:[],outcome:{}});
      if(requestId!==state.requestId||state.mode!=='run')return;
      const previousId=currentRun()?.run_id,rows=runs.filter(runConfirmed).map(businessTask);
      const unique=new Map(rows.filter(task=>task&&typeof task.task_id==='string'&&Array.isArray(task.events)).map(task=>[task.task_id,task]));
      state.runData={...payload,runs};state.tasks=M.normalizeTasks([...unique.values()]);state.total=state.tasks.length;state.lastSuccess=new Date().toISOString();state.error=results.some(result=>result.status==='rejected')?results.filter(result=>result.status==='rejected').length+' 项场景记录读取失败，请在办理任务中查看具体错误':'';
      const index=previousId?runs.findIndex(run=>run.run_id===previousId):runs.findIndex(run=>run.run_id===(payload.default_run_id||payload.run_id));
      selectRun(index>=0?index:0);
    }catch(error){if(requestId===state.requestId&&state.mode==='run')state.error=error.name==='AbortError'?'实际运行记录读取超时（10 秒）':error instanceof TypeError?'无法读取本地运行记录，请确认预览服务已启动':error.message;}
    finally{clearTimeout(timeout);if(requestId===state.requestId&&state.mode==='run'){state.loading=false;render();}}
  }
  function renderDemonstration() {
    if(state.mode!=='run')return empty('请选择本次 OpenClaw 实跑记录');
    const runs=runList(),run=currentRun();
    const chooser=runs.length>1?'<div class="run-selector"><label for="liveRunSelect">办理任务</label><select id="liveRunSelect">'+runs.map((item,index)=>'<option value="'+index+'"'+(index===state.runIndex?' selected':'')+'>'+h(runName(item,index))+'</option>').join('')+'</select>'+badge('本地测试材料','amber')+'</div>':'';
    const detail=run?{...run,tasks:state.tasks.filter(task=>(run.tasks||[]).some(item=>item.task_id===task.task_id)||task.task_id===run.task_id)}:null;
    return chooser+(window.LiveDemo?window.LiveDemo.render(detail):empty('办理结果组件未加载'));
  }
  function businessSummary(task) {
    if(state.mode!=='run')return '';
    const run=runForTask(task),confirmed=runConfirmed(run),provided=task.business_outcome;
    const outcome=confirmed?(provided&&typeof provided==='object'?provided:run.outcome||{}):{};
    const summary=confirmed&&typeof provided==='string'?provided:outcome.model_refusal===true?'模型自行拒绝':typeof outcome.business_result==='string'?outcome.business_result:outcome.summary_created===true?'办理摘要已生成':run?.artifacts?.length?'已提供办理产物':'办理结果待确认';
    const original=outcome.original_unchanged===true?'原文核验一致':outcome.original_unchanged===false?'原文发生变化':'原文核验待确认';
    const disposition=Number.isInteger(outcome.guard_block_count)?outcome.guard_block_count>0?outcome.guard_block_count+' 次阻断判定':'未记录阻断判定':'安全层处置待确认';
    return '<div class="business-outcome"><span>本次办理结果</span><h3>'+safe(summary)+'</h3><p>'+safe(original)+' · '+safe(disposition)+'</p>'+button('查看材料与产物','open-demonstration','file-check-2')+'</div>';
  }
  function taskScopeBar() {
    if(state.mode!=='run'||!state.scopeTaskKey||!['risks','reviews','evidence'].includes(state.page))return '';
    const task=state.tasks.find(task=>task.task_key===state.scopeTaskKey);
    return '<div class="task-scope-bar"><span>当前任务：<strong>'+safe(task?.title)+'</strong></span>'+button('查看全部运行任务','clear-task-scope','list')+'</div>';
  }
  const identifierLine = task => state.mode==='run'?'<details class="technical-detail"><summary>任务编号</summary><span class="cell-secondary mono">'+safe(task.task_id)+'</span></details>':'<span class="cell-secondary mono">'+safe(task.task_id)+'</span>';
  function scopedTasks() {
    return state.tasks.filter(task => {
      if(state.mode==='run'&&state.scopeTaskKey&&['risks','reviews','evidence'].includes(state.page)&&task.task_key!==state.scopeTaskKey)return false;
      if(!['overview','tasks'].includes(state.page))return true;
      if(state.sourceFilter!=='all' && M.source(task).kind!==state.sourceFilter) return false;
      const timestamp=task.ended_at || task.started_at;
      if(state.timeFilter==='unknown') return !validDate(timestamp);
      if(state.timeFilter==='all') return true;
      const age=Date.now()-Date.parse(timestamp);
      return Number.isFinite(age)&&age>=0&&age<=(state.timeFilter==='24h'?86400000:604800000);
    });
  }
  function pageScopeControls(tasks) {
    if(!['overview','tasks'].includes(state.page))return '';
    const option=(key,text,current)=>'<option value="'+key+'"'+(current===key?' selected':'')+'>'+h(text)+'</option>';
    const available=new Set(state.tasks.map(task=>M.source(task).kind));
    const sourceOptions=[['all','全部来源'],['live','实际运行记录'],['history','历史回放数据'],['test','测试数据'],['unknown','来源未注明']]
      .filter(([key])=>key==='all'||key==='live'||available.has(key)||key===state.sourceFilter);
    const countText='符合条件 '+tasks.filter(matches).length+' / 当前范围 '+state.tasks.length+' 项';
    return '<div class="page-scope-controls"><div class="scope-primary"><label class="direct-filter">记录来源<select id="advancedSourceFilter" aria-label="记录来源">'+sourceOptions.map(item=>option(item[0],item[1],state.sourceFilter)).join('')+'</select></label><label class="direct-filter">记录时间<select id="timeFilter" aria-label="记录时间">'+[['all','不限时间'],['24h','最近 24 小时'],['7d','最近 7 天'],['unknown','未记录时间']].map(item=>option(item[0],item[1],state.timeFilter)).join('')+'</select></label></div><span class="scope-count" aria-live="polite">'+countText+'</span></div>';
  }
  function matches(task) {
    const query=state.query.trim().toLowerCase();
    if(query && ![task.title,task.goal,task.task_id,task.run_id,...task.tools].join(' ').toLowerCase().includes(query))return false;
    if(state.statusFilter==='all')return true;
    const code=taskState(task).code;
    if(state.statusFilter==='review')return ['awaiting_review','review_unconfirmed','approved_awaiting_retry'].includes(code);
    if(state.statusFilter==='blocked')return ['blocked','block_recommendation'].includes(code);
    if(state.statusFilter==='abnormal')return ['failed','model_refused','incomplete','unknown'].includes(code);
    return code===state.statusFilter;
  }
  function range(tasks=scopedTasks()) {
    const times=tasks.flatMap(task=>[task.started_at,task.ended_at]).filter(validDate).map(Date.parse);
    return {since:times.length?new Date(Math.min(...times)).toISOString():null,until:times.length?new Date(Math.max(...times)).toISOString():null,missing:tasks.filter(task=>!validDate(task.started_at)).length};
  }
  const tasksStale = () => state.mode==='backend' && (Boolean(state.error)||!state.lastSuccess||(!viewingHistory()&&Date.now()-Date.parse(state.lastSuccess)>30000));
  function context(tasks=scopedTasks()) {const r=range(tasks);return {...r,baseVersion:'2.0.0',includeReviewedArchiveSummaries:false,rangeLabel:viewingHistory()?'历史记录（全部已保存，含本次开机）':'本次开机累计记录',total:state.total,stale:tasksStale(),lastSuccess:state.lastSuccess};}
  function mountIcons() {if(window.lucide)lucide.createIcons();}
  function notify(message) {$('#toast').textContent=message;$('#toast').hidden=false;clearTimeout(state.toastTimer);state.toastTimer=setTimeout(()=>{$('#toast').hidden=true;},4200);}
  function selectPage(page) {
    if(!label[page])page='overview';
    if(state.page!==page){state.query='';state.statusFilter='all';state.listLimit=50;clearTimeout(state.searchTimer);}
    state.page=page;document.body.classList.remove('nav-open');$('#menuButton').setAttribute('aria-expanded','false');
    if(location.hash.slice(1)!==page)location.hash=page;
    render();
  }
  function renderChrome() {
    taskStates=new WeakMap();
    const tasks=scopedTasks(),r=range(tasks),archived=state.mode==='archive',recorded=state.mode==='run';
    $('#breadcrumb').textContent=label[state.page][0];$('#pageTitle').textContent=label[state.page][0];$('#pageSubtitle').textContent=label[state.page][1];
    $('#monitoringScope').value=state.monitoringScope;
    $('#monitoringScope').closest('label').hidden=state.mode!=='backend';
    if(viewingHistory())$('#pageSubtitle').textContent+=' · 历史只读，包含本次开机及此前保存的记录';
    document.title='AgentMeter-Gov | '+label[state.page][0];
    document.body.classList.remove('demonstration-page');
    $$('[data-page]').forEach(item=>{if(item.dataset.page===state.page)item.setAttribute('aria-current','page');else item.removeAttribute('aria-current');});
    $('#navTasks').textContent=tasks.length;$('#navRisks').textContent=allRisks(tasks).length;$('#navReviews').textContent=allReviews(tasks).filter(item=>!['rejected','released','closed'].includes(item.review.status)).length;
    $('#navRisks').classList.add('red');$('#navReviews').classList.add('amber');
    const auth=/401|403/.test(state.error+' '+state.healthError);
    const status=recorded?state.loading?'读取运行记录':state.error?'记录读取失败':runConfirmed(currentRun())?'本次运行记录':'执行记录待确认':archived?'未连接实时后端':state.loading?'连接中':auth?'身份验证失败':state.error||state.healthError?'连接中断':state.lastSuccess?tasksStale()?'记录待更新':'后端已连接':'等待连接';
    $('#headerStatus').className='badge '+(!archived&&(state.error||state.healthError)?'red':'neutral');$('#headerStatus').innerHTML='<span class="dot"></span>'+h(viewingHistory()&&!state.loading&&!state.error&&!state.healthError&&state.lastSuccess?'历史记录 · 只读':status);
    $('#refreshButton').disabled=state.loading;$('#refreshButton span').textContent=state.loading?'正在读取':recorded?'重新读取运行记录':archived?'重新载入记录':'刷新监控记录';
    if(viewingHistory())$('#refreshButton span').textContent=state.loading?'正在读取历史':'刷新历史记录';
    $('#footerRange').textContent=(r.since?'事件范围：'+shortDate(r.since)+' 至 '+shortDate(r.until):'事件统计时间未提供')+' · '+(archived?'历史文件':state.error?'历史缓存':recorded?'本次运行采集记录':'当前接口返回');
    if(viewingHistory())$('#footerRange').textContent+=' · 历史记录按需读取，点击刷新更新';
  }
  function overviewConnection() {
    const archived=state.mode==='archive',recorded=state.mode==='run';
    if(recorded)return '<div class="connection-strip"><p>'+icon('file-clock')+' <strong>'+h(state.error?'记录读取失败':runConfirmed(currentRun())?'本次实际运行记录':'实际执行待确认')+'</strong> <span>'+h(state.error||'采集时间：'+date(state.runData?.collected_at||state.runData?.generated_at||currentRun()?.collected_at||currentRun()?.generated_at))+'</span></p>'+button(state.error?'重试读取':'重新读取记录','refresh','refresh-cw')+'</div>';
    if(archived)return '<div class="connection-strip"><p>'+icon('archive')+' <strong>历史测试记录</strong> <span>不代表当前业务状态</span></p>'+button('连接后端','settings','plug')+'</div>';
    if(!state.error&&!state.healthError)return '';
    const message=state.error||state.healthError||(state.lastSuccess?'最近更新：'+date(state.lastSuccess):'尚未成功读取任务');
    return '<div class="connection-strip connection-error"><p><strong>数据暂时无法更新</strong> '+h(message)+(tasksStale()&&state.tasks.length?' · 当前保留上次读取的内容':'')+'</p>'+button('重试','refresh','refresh-cw')+'</div>';
  }
  function systemStatuses() {
    const health=state.health,offline=state.mode!=='backend',bad=Boolean(state.healthError),unknown=offline||bad||!health||!state.healthAt||Date.now()-Date.parse(state.healthAt)>30000;
    const plugin=health?.plugin||{},audit=health?.audit||{},activity=plugin.activity_state;
    const activityLabel=unknown?'状态待更新':activity==='recent'?'刚刚有调用':activity==='idle'?'当前无调用':activity==='stale'?'长时间无调用':activity==='never_seen'?'尚无活动记录':'活动状态未知';
    const activityDetail=unknown?'未读取插件事件状态':validDate(plugin.last_seen)?'最近审计活动：'+date(plugin.last_seen):'尚未记录插件审计活动';
    const rows=[
      ['server','后端服务',offline?'未连接':bad?/401|403/.test(state.healthError)?'身份验证失败':'连接中断':unknown?'状态待更新':health?.server?.status==='healthy'?'后端已连接':health?'服务状态异常':'状态未知',offline?'尚未读取运行状态':bad?'健康接口读取失败':'监控接口可达',!offline&&(bad||health&&health.server?.status!=='healthy')?'red':!unknown?'teal':'neutral'],
      ['activity','插件审计活动',activityLabel,activityDetail,!unknown&&activity==='recent'?'teal':'neutral'],
      ['database','审计存储',unknown?'存储状态未知':audit.writable===true?'可写状态已确认':audit.writable===false?'存储不可写':Number.isFinite(audit.event_count)?'记录可读':'存储状态未知',unknown?'可写性与完整性未核验':Number.isFinite(audit.event_count)?'接口返回 '+audit.event_count+' 条 · 完整性未核验':'可写回执未提供',!unknown&&audit.writable===false?'red':'neutral']
    ];
    return '<section class="status-strip" aria-label="独立系统状态">'+rows.map(([symbol,name,current,detail,color])=>'<div class="system-status"><span class="status-icon '+color+'">'+icon(symbol)+'</span><div class="status-copy"><span>'+name+'</span><strong class="text-'+color+'"><span class="dot"></span>'+current+'</strong><small>'+h(detail)+'</small></div></div>').join('')+'</section>';
  }
  function taskTable(tasks,limit,compact=false) {
    if(!tasks.length)return empty('没有符合条件的任务');
    return '<div class="table-wrap"><table><thead><tr><th>任务</th>'+(compact?'':'<th>记录来源</th>')+'<th>处理结果</th><th>风险分</th><th>更新时间</th><th></th></tr></thead><tbody>'+tasks.slice(0,limit||tasks.length).map(task=>'<tr><td><button class="task-title text-button" data-action="open-task" data-key="'+h(task.task_key)+'">'+safe(task.title)+'</button>'+(compact?'':identifierLine(task))+'</td>'+(compact?'':'<td>'+sources(task)+'</td>')+'<td>'+statusBadge(task)+'</td><td><span class="score-inline '+(task.max_risk_score>=40?'text-red':'')+'">'+(Number.isFinite(task.max_risk_score)?task.max_risk_score:'未评分')+'</span></td><td class="cell-secondary">'+h(shortDate(task.ended_at))+'</td><td><button class="icon-button" data-action="open-task" data-key="'+h(task.task_key)+'" aria-label="查看任务" title="查看任务">'+icon('arrow-up-right')+'</button></td></tr>').join('')+'</tbody></table></div>';
  }
  function auditCoverage(task) {
    const events=task.events||[],risk=riskEvents(task),execution=taskExecution(task);
    const checks=[Boolean(task.task_id||task.run_id||task.case_id),Boolean(task.goal||events.some(event=>event.event_type==='input_event')),Boolean(risk.length||events.some(event=>event.event_type==='risk_decision_event')||task.enforcement_layer),Boolean(execution.receipts?.length||task.business_outcome)];
    return {complete:checks.every(Boolean),count:checks.filter(Boolean).length,total:checks.length};
  }
  function auditHero(tasks,risks) {
    if(!tasks.length){state.overviewRiskKey=null;return '<section class="audit-command audit-empty"><div class="overview-radar"><div class="radar-heading"><div><span class="eyebrow">核心计量结果</span><h2>五维风险计量</h2></div>'+badge('等待记录','neutral')+'</div><canvas id="overviewRadar" width="580" height="520" aria-label="等待调用记录的五维风险计量图"></canvas><p class="radar-caption">数据安全 · 内容安全 · 执行安全 · 供应链安全 · 合规风险</p></div><div class="audit-focus"><span class="eyebrow">当前审计任务</span><h2>等待审计任务接入</h2><p>收到工具调用判定后，这里将立即展示风险总分、五维明细、处置结论和证据完整度。</p><div class="empty-guidance"><div>'+icon('radar')+'<strong>九因子计算</strong><span>保留评分依据</span></div><div>'+icon('pentagon')+'<strong>五维展示</strong><span>形成计量结果</span></div><div>'+icon('folder-search')+'<strong>一任务一档</strong><span>关联审计证据</span></div></div></div></section>';}
    const ranked=[...tasks].sort((a,b)=>(Number(b.max_risk_score)||-1)-(Number(a.max_risk_score)||-1));
    const row=[...risks].sort((a,b)=>(Date.parse(b.event.timestamp)||0)-(Date.parse(a.event.timestamp)||0)||(Number(b.event.risk_score)||-1)-(Number(a.event.risk_score)||-1))[0]||null;
    state.overviewRiskKey=row?.key||null;
    const task=row?.task||ranked[0],risk=row?.event||null,current=taskState(task),coverage=auditCoverage(task),execution=taskExecution(task),dimensions=risk?M.dimensions(risk):[];
    const dimensionCount=dimensions.filter(item=>item.complete).length,score=risk?.risk_score??task.max_risk_score;
    const dimensionNote=!risk?'尚未收到风险评估':dimensionCount===5?'五项风险数据已齐全':'已有总分 '+value(score)+'，但五维详情只收集到 '+dimensionCount+' 项';
    return '<section class="audit-command"><div class="overview-radar"><div class="radar-heading"><div><span class="eyebrow">当前风险</span><h2>五维风险图</h2></div>'+badge(risk?actionLabel(risk):'暂无判定',risk?actionTone(risk):'neutral')+'</div><canvas id="overviewRadar" width="580" height="520" aria-label="当前调用的五维风险图"></canvas><p class="radar-caption">'+h(dimensionNote)+'</p></div><div class="audit-focus"><div class="audit-kicker"><span class="eyebrow">最新任务</span>'+statusBadge(task)+'</div><h2>'+safe(task.title)+'</h2><p>'+safe(task.goal||'任务内容未记录')+'</p><div class="headline-score"><div><span>风险分</span><strong>'+(Number.isFinite(score)?score:'—')+'<small> / 100</small></strong></div><div><span>处理结果</span><strong>'+h(risk?actionLabel(risk):current.label)+'</strong></div></div><div class="audit-ledger">'+fact('执行结果',executionText(task))+fact('证据完整度',coverage.count+' / '+coverage.total)+fact('更新时间',shortDate(task.ended_at))+'</div><div class="coverage-track" title="证据完整度 '+coverage.count+' / '+coverage.total+'"><i style="width:'+(coverage.count/coverage.total*100)+'%"></i></div><div class="audit-actions">'+button('查看任务','open-task','folder-search','data-key="'+h(task.task_key)+'"')+(row?button('查看风险详情','open-risk','radar','data-key="'+h(row.key)+'"'):'')+'</div><div class="metrology-principles"><span>可计量</span><span>可解释</span><span>可追溯</span><span>可复核</span></div></div></section>';
  }
  function renderOverview(tasks) {
    const risks=allRisks(tasks),reviews=allReviews(tasks);
    const states=tasks.map(task=>taskState(task));
    const pending=reviews.filter(row=>['pending','unprovided'].includes(row.review.status)).length,blocked=states.filter(s=>['blocked','block_recommendation'].includes(s.code)).length,incomplete=tasks.filter(task=>!auditCoverage(task).complete).length;
    const count=value=>state.mode==='backend'&&!state.lastSuccess?'—':value;
    const attention=pending||blocked||incomplete?'<div class="attention-summary">'+icon('bell-ring')+'<span><strong>需要关注：</strong>'+(pending?pending+' 项待人工确认；':'')+(blocked?blocked+' 项已阻止风险操作；':'')+(incomplete?incomplete+' 项证据待补充。':'')+'</span></div>':'';
    return auditHero(tasks,risks)+overviewConnection()+pageScopeControls(tasks)+'<section class="overview-summary" aria-label="当前概况"><button data-action="metric" data-filter="all"><span>审计任务</span><strong>'+count(tasks.length)+'</strong></button><button data-action="metric" data-filter="review"><span>待人工确认</span><strong class="text-amber">'+count(pending)+'</strong></button><button data-action="metric" data-filter="blocked"><span>已阻止风险操作</span><strong class="text-red">'+count(blocked)+'</strong></button><button data-action="evidence"><span>证据待补充</span><strong>'+count(incomplete)+'</strong></button></section>'+attention+'<section class="section overview-task-list"><div class="section-heading"><h2>近期审计任务 <span>共 '+tasks.length+' 项</span></h2>'+button('查看全部任务','tasks','arrow-right')+'</div>'+taskTable(tasks,6,true)+'</section>';
  }
  function toolbar(placeholder='搜索任务名称或内容',showStatus=true) {return '<div class="toolbar"><div class="search-field">'+icon('search')+'<input id="searchInput" type="search" placeholder="'+placeholder+'" aria-label="'+placeholder+'" value="'+h(state.query)+'"></div>'+(showStatus?'<div class="filter-group"><select id="localStatusFilter" aria-label="筛选任务处理结果">'+[['all','全部处理结果'],['completed','已完成'],['review','待人工处理'],['blocked','已阻止风险操作'],['abnormal','异常或记录不完整'],['running','正在运行']].map(([key,text])=>'<option value="'+key+'"'+(key===state.statusFilter?' selected':'')+'>'+text+'</option>').join('')+'</select></div>':'')+'</div>';}
  function listRows(rows,markup) {
    state.activeList={rows,markup,count:Math.min(state.listLimit,rows.length)};
    return rows.slice(0,state.activeList.count).map(markup).join('');
  }
  function observeRecordList() {
    const list=state.activeList,root=$('#pageContent');
    if(!list)return;
    list.element=root.querySelector(state.page==='evidence'?'.evidence-selector':'.selection-list');
    if(!list.element||list.count>=list.rows.length)return;
    const more=document.createElement('button');more.type='button';more.className='record-list-more';more.dataset.action='load-more-records';
    more.textContent='已显示 '+list.count+' / '+list.rows.length+' 项 · 继续加载';
    list.more=more;list.element.append(more);
    if(window.IntersectionObserver){
      state.listObserver=new IntersectionObserver(entries=>{if(entries.some(entry=>entry.isIntersecting))loadMoreRecords();},{root:state.page==='evidence'?null:list.element,rootMargin:'160px'});
      state.listObserver.observe(more);
    }
  }
  function loadMoreRecords() {
    const list=state.activeList;if(!list?.more||list.loading||list.count>=list.rows.length)return;
    list.loading=true;state.listObserver?.disconnect();
    requestAnimationFrame(()=>{
      if(state.activeList!==list||!list.element.isConnected)return;
      const end=Math.min(list.count+50,list.rows.length),holder=document.createElement('div');
      holder.innerHTML=list.rows.slice(list.count,end).map(list.markup).join('');
      const nodes=[...holder.children];list.more.before(...nodes);
      list.count=end;state.listLimit=end;list.loading=false;
      if(window.lucide)lucide.createIcons({root:list.element});
      if(end===list.rows.length){list.more.remove();list.more=null;}
      else{list.more.textContent='已显示 '+end+' / '+list.rows.length+' 项 · 继续加载';state.listObserver?.observe(list.more);}
    });
  }
  function selectionList(tasks,selected) {return '<div class="selection-list" aria-label="任务列表">'+listRows(tasks,task=>'<button class="selection-item '+(task.task_key===selected?'selected':'')+'" data-action="select-task" data-key="'+h(task.task_key)+'"><span class="selection-top">'+statusBadge(task)+'<small>'+h(shortDate(task.ended_at))+'</small></span><strong>'+safe(task.title)+'</strong><span class="selection-bottom"><small>任务最高风险分：'+(M.taskRisk(task).score??'未评分')+'</small><small>'+task.events.length+' 条系统记录</small></span></button>')+'</div>';}
  function reviewLabel(status) {return ({pending:'待复核',approved:'已批准，等待执行',approved_waiting_retry:'已批准，等待重试',released:'审批后已放行',released_once:'已放行一次',rejected:'已拒绝',expired:'已过期',approval_expired:'已过期',closed:'后端已关闭',unprovided:'未提供'}[status]||'未提供（'+status+'）');}
  function chain(task) {
    const events=task.events,risks=riskEvents(task),source=task.input_sources?.[0],execution=taskExecution(task);
    const steps=[
      ['用户目标',task.goal||'未提供',events.find(event=>event.event_type==='input_event')?.timestamp,'file-text',''],
      ['来源内容',source?source.name+'：'+source.content:'未提供来源内容与可信度',null,'file-input',source?.trust==='low'?'risk':''],
      ...(risks.length?risks.map((risk,index)=>[
        (risk.summary_only?'判定摘要':'第 '+(index+1)+' 次调用')+' · '+(risk.tool_name||toolOf(risk)||'工具未提供'),
        (risk.risk_score??'未评分')+' 分 · '+actionLabel(risk)+(risk.summary_only?'（执行回执未提供）':'')+(rulesOf(risk).length?' · '+rulesOf(risk).slice(0,2).join('；'):''),
        risk.timestamp,'shield-check',['block','deny'].includes(actionOf(risk))?'risk':''
      ]):[['调用判定','未提供工具请求或风险判定',null,'shield-check','']]),
      ['实际执行结果',execution.label+'。'+execution.detail,events.filter(event=>event.event_type==='result_event').at(-1)?.timestamp,'flag','']
    ];
    return '<ol class="task-chain">'+steps.map(([title,text,time,symbol,color],index)=>'<li class="chain-step '+color+'" data-step="'+index+'"><span class="step-index">'+icon(symbol)+'</span><div class="step-body"><h3><span class="step-number">'+String(index+1).padStart(2,'0')+'</span>'+title+'</h3><p>'+safe(text)+'</p><small>'+(time?'事件时间：'+h(date(time)):index===1?'来源：'+safe(source?.trust):'本阶段独立时间：未提供')+'</small></div></li>').join('')+'</ol>';
  }
  function eventKind(event) {return ({input_event:'用户目标上报',risk_decision_event:'工具调用前判定',pending_review_event:'申请人工复核',approval_event:'审批状态上报',tool_event:'工具活动回执',result_event:'任务结束回执'}[event.event_type]||event.event_type||'事件类型未提供');}
  function eventResult(event) {if(event.event_type==='risk_decision_event')return actionLabel(event)+' · 申请阶段';if(event.event_type==='tool_event')return ({success:'工具报告成功',failed:'工具报告失败',blocked:'工具报告被阻断',pending:'工具结果待确认'}[event.status]||'工具状态：'+value(event.status));if(event.event_type==='result_event'){const outcome=event.execution_result||event.status;return ({completed:'任务结束，业务结果需核对',success:'结果回执报告成功',failed:'结果回执报告失败',error:'结果回执报告失败',pending:'结果待确认'}[outcome]||value(outcome));}return value(event.review_decision||event.content_source);}
  function renderTasks(tasks) {
    const filtered=tasks.filter(matches),selected=filtered.find(task=>task.task_key===state.taskKey)||filtered[0];if(selected)state.taskKey=selected.task_key;
    if(!selected)return pageScopeControls(tasks)+toolbar()+empty('没有符合条件的任务');
    const recorded=state.mode==='run';
    const taskRisk=M.taskRisk(selected),risk=taskRisk.decision,execution=taskExecution(selected),coverage=auditCoverage(selected);
    const timeline=selected.events.length?'<ol class="timeline">'+selected.events.map((event,index)=>'<li class="timeline-item"><time class="timeline-time">'+h(shortDate(event.timestamp))+'</time><div class="timeline-content"><strong>'+h(eventKind(event))+'</strong><p>'+safe(toolOf(event))+' · '+h(eventResult(event))+'</p></div><button class="icon-button" title="查看事件证据" aria-label="查看事件证据" data-action="event" data-task="'+h(selected.task_key)+'" data-index="'+index+'">'+icon('file-search')+'</button></li>').join('')+'</ol>':'<div class="notice info">此记录仅含摘要，未提供逐事件时间线。</div>';
    const result='<section class="plain-result"><div><span>任务内容</span><strong>'+safe(selected.goal||'未记录')+'</strong></div><div><span>任务最高风险分</span><strong>'+h(taskRisk.score===null?'未评分':taskRisk.score+' 分')+'</strong><p>本任务最高处置：'+h(risk?actionLabel(risk):'暂无调用判定')+'</p></div><div><span>执行结果</span><strong>'+h(executionText(selected))+'</strong></div><div><span>证据情况</span><strong>'+coverage.count+' / '+coverage.total+' 项已齐全</strong></div></section>';
    const process='<details class="detail-disclosure"><summary>'+icon('route')+' 查看办理过程</summary><div class="section-heading chain-heading"><h2>办理过程 <span>目标 → 请求 → 判断 → 结果</span></h2></div>'+chain(selected)+'</details>';
    const technical='<details class="technical-detail technical-box"><summary>'+icon('wrench')+' 技术详情（供专业人员核对）</summary><div class="facts-grid">'+fact('任务编号',selected.task_id)+fact('开始时间',date(selected.started_at))+fact('最后更新',date(selected.ended_at))+fact('系统记录',selected.events.length+' 条')+fact('规则版本',selected.rules_version||selected.rule_version)+fact('记录来源',M.source(selected).label)+'</div><h3>系统记录时间线</h3>'+timeline+'<p class="muted">'+safe(selected.completeness_note||'缺失的技术字段按“未提供”展示，不作推测。')+'</p></details>';
    return pageScopeControls(tasks)+toolbar('搜索任务名称或内容')+'<div class="split-view">'+selectionList(filtered,selected.task_key)+'<section class="detail-panel"><header class="detail-heading"><div><div class="detail-meta">'+statusBadge(selected)+'</div><h2>'+safe(selected.title)+'</h2></div>'+button('打开审计档案','task-evidence','archive','data-key="'+h(selected.task_key)+'"')+'</header>'+businessSummary(selected)+result+process+technical+'</section></div>';
  }
  function renderRiskDetail(row) {
    const {task,event}=row,score=event.risk_score,factors=M.factors(event),dimensions=M.dimensions(event),received=factors.filter(f=>f.score!==null).length,dimensionCount=dimensions.filter(item=>item.complete).length;
    const list=value=>Array.isArray(value)?value:[],overrides=event.scoring_details?.overrides||{};
    const hard=[...new Set([...rulesOf(event).filter(rule=>/HARD-BLOCK|硬阻断/.test(rule)),...list(event.security_control?.hard_blocks),...list(event.control_plan?.hard_blocks),...list(overrides.hard_blocks)])];
    const forced=[...new Set([...list(event.security_control?.review_required),...list(event.control_plan?.review_required),...list(overrides.review_required)])];
    const hardApplied=hard.length>0||overrides.hard_block_floor_applied===true,reviewApplied=forced.length>0||overrides.forced_review_floor_applied===true;
    const params=paramsOf(event),weighted=event.scoring_details?.weighted_score;
    const scoreExplanation=hardApplied?'本次操作命中必须阻止的规则，因此系统直接阻止，不只看总分。':reviewApplied?'本次操作需要人工确认，确认前不会继续执行。':'系统根据本次记录给出处理结果；实际是否执行成功，仍以执行结果为准。';
    const dimensionExplanation=dimensionCount===5?'五维明细由本次记录的九因子分值与权重形成。':Number.isFinite(score)?'本次调用总风险分为 '+score+'；旧记录未完整采集九因子明细，因此五维明细不可计算。':'本次记录未提供总风险分，也未完整采集九因子明细。';
    const overrideDetail=forced.length?'<details class="technical-detail"><summary>查看后端强制复核依据</summary><ul>'+forced.map(reason=>'<li>'+safe(reason)+'</li>').join('')+'</ul></details>':'';
    const ids=fact('事件编号',event.event_id)+fact('工具请求 ID',event.tool_request_id||event.call_id||event.tool_call_id);
    const idMarkup=state.mode==='run'?'<details class="technical-detail"><summary>事件与工具请求编号</summary><div class="facts-grid">'+ids+'</div></details>':'';
    return '<section class="detail-panel risk-detail"><header class="detail-heading"><div><div class="detail-meta">'+badge(event.summary_only?'历史判定摘要':'已记录','neutral')+'</div><h2>'+safe(task.title)+'</h2><p>'+safe(toolOf(event))+' · '+h(shortDate(event.timestamp))+'</p></div>'+button('查看任务','open-task','arrow-up-right','data-key="'+h(task.task_key)+'"')+'</header>'+
      '<div class="risk-summary '+actionTone(event)+'"><div><span class="eyebrow">处理结果</span><h3>'+h(actionLabel(event))+'</h3><p>'+safe(actionReason(event,task))+'</p></div><div class="score-block"><span class="score">'+(Number.isFinite(score)?score:'—')+'</span><small>/ 100 · 本次评分</small></div></div>'+
      '<div class="section-heading"><h2>五维风险 <span>'+dimensionCount+' / 5 项数据已齐全</span></h2></div><div class="risk-factors"><div class="radar-wrap"><canvas id="riskRadar" width="580" height="520" aria-label="五维风险图；缺失数值不绘制风险面积"></canvas></div><div class="dimension-ledger">'+dimensions.map(item=>'<div class="dimension-row"><span><b>'+h(item.name)+'</b></span><strong>'+(item.score===null?'未采集':item.score)+'</strong></div>').join('')+'<p class="plain-help">'+h(dimensionExplanation)+'</p></div></div>'+
      '<section class="decision-reason"><h2>为什么这样处理</h2><p>'+h(scoreExplanation)+'</p></section>'+
      '<details class="technical-detail technical-box"><summary>'+icon('wrench')+' 技术详情（规则、证据与计算过程）</summary><div class="facts-grid">'+fact('涉及对象',targetOf(event))+(state.mode==='run'?'':ids)+fact('执行结果',event.summary_only?'未提供执行记录':taskExecution(task).label)+fact('规则版本',event.rules_version||task.rules_version)+'</div>'+idMarkup+'<h3>命中规则</h3><div class="rule-list">'+(rulesOf(event).map(rule=>'<div class="rule-item"><span class="rule-code">'+h(M.ruleId?.(rule)||rule.match(/^(?:HARD-BLOCK|[A-Z]+(?:-[A-Z]+)*-\d+)/)?.[0]||'RULE')+'</span><p>'+safe(rule)+'</p></div>').join('')||'<p class="muted">未记录命中规则</p>')+'</div>'+overrideDetail+'<div class="two-column evidence-columns"><section><h3>证据片段</h3><blockquote class="evidence-quote">'+safe(event.evidence||task.input_sources?.[0]?.content)+'</blockquote></section><section><h3>调用参数</h3><pre class="parameter-summary">'+(params?safe(JSON.stringify(params,null,2)):'未提供')+'</pre></section></div><details class="factor-disclosure"><summary>九因子计算明细 · '+received+' / 9 项数值</summary><div class="table-wrap"><table class="factor-table"><thead><tr><th>因子</th><th>分值</th><th>权重</th><th>贡献</th></tr></thead><tbody>'+factors.map(f=>'<tr><td><b>'+f.code+'</b> '+h(f.name)+'</td><td>'+(f.score===null?'未提供':f.score)+'</td><td>'+(f.weight===null?'未提供':f.weight)+'</td><td>'+(f.contribution===null?'未提供':f.contribution)+'</td></tr>').join('')+'</tbody></table></div></details><p class="muted">'+(Number.isFinite(weighted)?'九因子加权分为 '+weighted+'。':'')+(received<9?'缺失数值不补零、不推算。':'数值来自本次记录。')+'</p></details></section>';
  }
  function renderRisks(tasks) {
    const rows=allRisks(tasks.filter(matches));const selected=rows.find(row=>row.key===state.riskKey)||rows[0];if(selected)state.riskKey=selected.key;
    return toolbar()+(selected?'<div class="split-view"><div class="selection-list" aria-label="调用计量记录列表">'+listRows(rows,row=>'<button class="selection-item '+(row.key===selected.key?'selected':'')+'" data-action="select-risk" data-key="'+h(row.key)+'"><span class="selection-top">'+badge(actionLabel(row.event),actionTone(row.event))+'<small>'+h(row.event.risk_score??'未提供')+' 分</small></span><strong>'+safe(row.task.title)+'</strong><span class="cell-secondary">'+safe(toolOf(row.event))+'</span><span class="selection-bottom">'+sources(row.task)+'<small>'+h(shortDate(row.event.timestamp))+'</small></span></button>')+'</div>'+renderRiskDetail(selected)+'</div>':empty('没有符合条件的调用计量记录'));
  }
  function renderReviews(tasks) {
    const rows=allReviews(tasks.filter(matches)),selected=rows.find(row=>row.key===state.reviewKey)||rows[0];if(selected)state.reviewKey=selected.key;
    if(!selected)return toolbar()+empty('没有可展示的复核事项');
    const {task,review}=selected,expired=validDate(review.expires_at)&&Date.parse(review.expires_at)<Date.now();
    const canCopy=state.mode==='backend'&&!viewingHistory()&&!state.error&&Boolean(state.lastSuccess)&&Date.now()-Date.parse(state.lastSuccess)<30000&&review.status==='pending'&&!expired&&/^AGR-[A-Za-z0-9_-]+$/.test(review.review_id||'');
    const execution=taskExecution(task),needsAction=review.status==='pending';
    const actionPanel='<section class="review-action '+(needsAction?'needs-action':'')+'"><div><span class="eyebrow">'+(needsAction?'待办事项':'复核结果')+'</span><h3>'+(needsAction?'请决定是否允许本次操作':h(reviewLabel(review.status)))+'</h3><p>'+(needsAction?'批准只代表允许继续，最终是否执行成功还要看后续结果。':h(execution.detail))+'</p></div>'+badge(reviewLabel(review.status),needsAction?'amber':'neutral')+'</section>';
    const command='<div class="command-section"><div class="filter-group"><label for="decisionMode">处理意见</label><select id="decisionMode"><option value="approve">批准</option><option value="reject">拒绝</option></select></div><div class="command-line"><code id="reviewCommand">'+(canCopy?'审批通过 '+h(review.review_id):'当前事项不可操作')+'</code><button class="button primary" id="copyReview" data-action="copy-review" '+(canCopy?'':'disabled')+'>'+icon('copy')+'复制处理口令</button></div><p class="plain-help">'+(canCopy?'复制后，请将口令发送到原任务会话。系统收到后会记录处理结果。':state.mode==='archive'||viewingHistory()?'这是历史记录，只能查看；处理当前事项请切回本次开机。':'该事项已处理、已过期或记录需要刷新。')+'</p></div>';
    const technical='<details class="technical-detail technical-box"><summary>'+icon('wrench')+' 技术详情（编号、时间与系统状态）</summary><div class="facts-grid">'+fact('审批编号',review.review_id)+fact('申请时间',date(review.requested_at))+fact('影响范围',review.impact?typeof review.impact==='number'?review.impact+' 条记录':review.impact:task.affected_record_count?task.affected_record_count+' 条记录':null)+fact('申请工具',review.tool_name)+fact('工具请求 ID',review.tool_request_id)+fact('审批人',review.reviewer)+fact('审批意见',review.comment)+fact('有效期',date(review.expires_at))+'</div></details>';
    return toolbar('搜索需要复核的任务',false)+'<div class="split-view"><div class="selection-list" aria-label="复核事项列表">'+listRows(rows,row=>'<button class="selection-item '+(row.key===selected.key?'selected':'')+'" data-action="select-review" data-key="'+h(row.key)+'"><span class="selection-top">'+badge(reviewLabel(row.review.status),row.review.status==='pending'?'amber':'neutral')+'<small>'+h(shortDate(row.review.requested_at))+'</small></span><strong>'+safe(row.task.title)+'</strong><span class="selection-bottom"><small>'+safe(toolOf({tool_name:row.review.tool_name}))+'</small><small>'+h(row.review.status==='pending'?'待处理':'已有结果')+'</small></span></button>')+'</div><section class="detail-panel"><header class="detail-heading"><div><h2>'+safe(task.title)+'</h2></div>'+button('查看任务','open-task','arrow-up-right','data-key="'+h(task.task_key)+'"')+'</header>'+actionPanel+'<div class="review-stages">'+[['申请','已记录'],['人工处理',reviewLabel(review.status)],['执行结果',execution.confirmed?executionText(task):'待确认']].map(([name,detail],index)=>'<div><span>0'+(index+1)+' · '+name+'</span><strong>'+h(detail)+'</strong></div>').join('')+'</div>'+command+technical+'</section></div>';
  }
  function reportMarkup(tasks) {
    const snap=M.snapshot(tasks,context(tasks));
    const rows=snap.tasks.map((task,index)=>'<section class="report-section"><h3>'+String(index+1).padStart(2,'0')+' / '+safe(task.title)+'</h3><div class="facts-grid">'+fact('任务编号',task.task_id)+fact('数据来源',task.source.label+(state.mode==='archive'?' · 历史归档':''))+fact('用户目标摘要',task.goal)+fact('风险原因',task.risk_reason)+fact('系统处置',task.system_disposition.label)+fact('实际执行结果',task.execution_result.label)+fact('规则版本',task.rules_version)+fact('原始事件',task.events.length+' 条')+'</div></section>').join('');
    return '<div class="report-body"><div class="report-header"><div><span class="eyebrow">AGENTMETER-GOV / AUDIT DOSSIER</span><h2>智能体行为审计档案</h2><p>基于 2.0.0 · '+tasks.length+' 项审计任务</p></div>'+badge('档案预览 · 未签名','neutral')+'</div><div class="facts-grid">'+fact('生成时间',date(snap.generated_at))+fact('统计口径',snap.statistics_window.label)+fact('事件范围起点',date(snap.statistics_window.since))+fact('事件范围终点',date(snap.statistics_window.until))+'</div>'+rows+'<section class="report-section"><h3>完整性与使用范围</h3><ul class="integrity-list"><li>仅含当前选择的 '+tasks.length+' 项任务，不代表全部历史记录。</li><li>缺失字段保持为空；摘要记录不补造事件时间、编号与执行回执。</li><li>JSON 导出采用结构字段白名单，原始业务内容和工具参数默认省略。</li><li>当前档案未经后端签名，适用于核对与留档，不作为已验签的正式审计报告。</li></ul></section></div>';
  }
  function renderEvidence(tasks) {
    const filtered=tasks.filter(matches),selected=filtered.filter(task=>state.selected.has(task.task_key));
    const complete=selected.filter(task=>auditCoverage(task).complete).length,eventCount=selected.reduce((sum,task)=>sum+task.events.length,0);
    const intro='<section class="dossier-workspace"><div><span class="eyebrow">一项任务，一份档案</span><h2>选择要留档的任务</h2><p>档案会整理任务内容、风险判断和执行结果。</p></div><div class="dossier-stats"><div><span>已选择</span><strong>'+selected.length+'</strong></div><div><span>证据齐全</span><strong>'+complete+' / '+selected.length+'</strong></div><div><span>系统记录</span><strong>'+eventCount+'</strong></div></div><div class="dossier-output"><div class="dossier-actions"><button class="button" data-action="print" '+(selected.length?'':'disabled')+'>'+icon('printer')+'打印所选档案</button><button class="button primary" data-action="download-selected" '+(selected.length?'':'disabled')+'>'+icon('download')+'导出所选档案</button></div><p>打印会打开系统打印窗口，只包含已勾选任务；可打印到纸张或另存为 PDF。导出会生成所选任务的脱敏 JSON 数据。</p></div></section>';
    const choices='<section class="section"><div class="section-heading"><h2>任务列表 <span>'+selected.length+' / '+filtered.length+' 项已选</span></h2><div class="section-actions">'+button('全选','select-all','list-checks')+button('清空','clear-selection','list-x')+'</div></div><div class="evidence-selector">'+listRows(filtered,task=>{const coverage=auditCoverage(task);return '<label class="evidence-choice"><input type="checkbox" data-evidence-key="'+h(task.task_key)+'" '+(state.selected.has(task.task_key)?'checked':'')+'><span><strong>'+safe(task.title)+'</strong><small>证据 '+coverage.count+'/'+coverage.total+' · '+task.events.length+' 条系统记录</small></span>'+statusBadge(task)+'<button type="button" class="icon-button" data-action="open-task" data-key="'+h(task.task_key)+'" title="查看任务" aria-label="查看任务">'+icon('arrow-up-right')+'</button></label>';})+'</div></section>';
    const preview=selected.length?'<details class="report-preview" data-lazy-report><summary>'+icon('file-search')+' 预览档案内容 <span>专业人员可在此核对字段</span></summary>'+'<div data-report-content></div></details>':empty('请选择需要留档的任务');
    return intro+toolbar('搜索要留档的任务',false)+choices+'<p class="archive-note">'+icon('info')+' 只会打印或导出已勾选的任务；文件会自动隐去敏感内容，当前未加签，适合核对和留档。</p>'+preview;
  }
  function renderRules() {
    const rules=state.health?.rules||{},weights=rules.weights||{},thresholds=Array.isArray(rules.thresholds)?rules.thresholds:[];
    const dimensionHelp={data:'关注敏感信息、数据外发和存储范围',content:'关注输入输出是否安全、准确且符合要求',execution:'关注操作权限、影响范围和是否难以恢复',supply_chain:'关注插件、脚本和外部依赖是否可信',compliance:'关注是否符合制度、审批和留痕要求'};
    const dimensions=M.dimensionDefinitions.map((item,index)=>'<article class="standard-card"><span class="standard-index">'+String(index+1).padStart(2,'0')+'</span><h3>'+h(item.name)+'</h3><p>'+h(dimensionHelp[item.code]||'按当前规则进行评估')+'</p></article>').join('');
    const factors=M.factorDefinitions.map(item=>'<tr><td><b>'+h(item.code)+'</b></td><td>'+h(item.name)+'</td><td>'+(Number.isFinite(weights[item.code])?weights[item.code]:'未提供')+'</td></tr>').join('');
    const thresholdRows=thresholds.length?thresholds.map(item=>'<div class="threshold-band '+h(item.level||'')+'"><span>'+h(item.min)+'–'+h(item.max)+'</span><strong>'+h(({allow:'允许调用',human_review:'人工复核',block:'阻断'}[item.action]||item.action||'处置未提供'))+'</strong></div>').join(''):'<div class="notice info">实时后端未提供阈值；页面不采用内置数字替代。</div>';
    const mapping=M.dimensionDefinitions.map(item=>'<li><strong>'+h(item.name)+'：</strong>'+item.factor_codes.map(code=>h(code)+' '+h(M.factorDefinitions.find(f=>f.code===code)?.name||'')).join('、')+'</li>').join('');
    return '<section class="standards-intro"><div><span class="eyebrow">中国计量大学 · 风险计量</span><h2>系统如何判断风险</h2><p>系统从五个方面检查每次操作，再结合必须阻止或人工确认的规则，给出处理结果。</p></div><div class="version-seal"><span>当前规则</span><strong>v'+safe(rules.rules_version||'未提供')+'</strong></div></section><section class="section standards-section"><div class="section-heading"><h2>五类风险看什么</h2></div><div class="standard-grid">'+dimensions+'</div></section><section class="section standards-section"><div class="section-heading"><h2>分数对应的处理方式</h2></div><div class="thresholds">'+thresholdRows+'</div><p class="plain-help">如果触发“必须阻止”或“必须人工确认”的规则，系统会优先按规则处理，不会只看总分。</p></section><details class="technical-detail technical-box"><summary>'+icon('wrench')+' 技术详情（九因子、权重与维度对应关系）</summary><ul class="mapping-list">'+mapping+'</ul><div class="table-wrap"><table class="factor-table"><thead><tr><th>编码</th><th>风险因子</th><th>当前权重</th></tr></thead><tbody>'+factors+'</tbody></table></div><p class="muted">缺失的分值不补零、不从总分反推。</p></details>';
  }
  function detailStates(root) {
    const counts=new Map();
    return [...root.querySelectorAll('details')].map(detail=>{
      const label=detail.querySelector(':scope > summary')?.textContent.trim()||'详情';
      const count=counts.get(label)||0;counts.set(label,count+1);
      return {key:label+'::'+count,open:detail.open};
    });
  }
  function render() {
    const root=$('#pageContent'),samePage=root.dataset.renderedPage===state.page;
    clearTimeout(state.searchTimer);
    state.listObserver?.disconnect();state.activeList=null;
    const listScroll=samePage?root.querySelector('.selection-list')?.scrollTop:0;
    const expanded=new Set((samePage?detailStates(root):[]).filter(item=>item.open).map(item=>item.key));
    const active=samePage&&root.contains(document.activeElement)?{id:document.activeElement.id,start:document.activeElement.selectionStart,end:document.activeElement.selectionEnd}:null;
    const scroll=samePage?{x:window.scrollX,y:window.scrollY}:null;
    renderChrome();const tasks=scopedTasks();
    root.innerHTML=taskScopeBar()+({overview:renderOverview,tasks:renderTasks,risks:renderRisks,reviews:renderReviews,evidence:renderEvidence,rules:renderRules,demonstration:renderDemonstration}[state.page])(tasks);
    root.dataset.renderedPage=state.page;
    if(samePage){const details=root.querySelectorAll('details');detailStates(root).forEach((item,index)=>{if(expanded.has(item.key))details[index].open=true;});}
    mountIcons();
    if(listScroll)root.querySelector('.selection-list')?.scrollTo(0,listScroll);
    observeRecordList();
    if(state.page==='overview')drawRadar('overviewRadar',allRisks(tasks).find(item=>item.key===state.overviewRiskKey));
    if(state.page==='risks')drawRadar('riskRadar',allRisks(tasks).find(item=>item.key===state.riskKey));
    if(active?.id){const field=document.getElementById(active.id);if(field){field.focus({preventScroll:true});if(Number.isInteger(active.start)&&field.setSelectionRange)field.setSelectionRange(active.start,active.end);}}
    if(scroll)window.scrollTo(scroll.x,scroll.y);
  }
  function drawRadar(canvasId,row) {
    const canvas=$('#'+canvasId);if(!canvas)return;const ctx=canvas.getContext('2d');
    const defs=row?M.dimensions(row.event):M.dimensionDefinitions.map(item=>({...item,score:null,complete:false})),count=defs.length;
    const x=290,y=245,r=148,point=(i,scale)=>[x+Math.cos(-Math.PI/2+i*Math.PI*2/count)*r*scale,y+Math.sin(-Math.PI/2+i*Math.PI*2/count)*r*scale];
    ctx.clearRect(0,0,580,520);ctx.lineWidth=1;ctx.strokeStyle='#cbd6df';
    for(let level=1;level<=5;level++){ctx.beginPath();for(let i=0;i<count;i++){const p=point(i,level/5);i?ctx.lineTo(...p):ctx.moveTo(...p);}ctx.closePath();ctx.stroke();}
    ctx.strokeStyle='#b9c8d4';
    for(let i=0;i<count;i++){ctx.beginPath();ctx.moveTo(x,y);ctx.lineTo(...point(i,1));ctx.stroke();}
    ctx.fillStyle='#7a8b99';ctx.font='11px ui-monospace,Consolas,monospace';ctx.textAlign='left';
    for(let level=1;level<=5;level++)ctx.fillText(String(level*20),x+5,y-r*level/5+4);
    ctx.strokeStyle='#71899d';ctx.beginPath();ctx.moveTo(x-5,y);ctx.lineTo(x+5,y);ctx.moveTo(x,y-5);ctx.lineTo(x,y+5);ctx.stroke();
    ctx.font='17px "Microsoft YaHei",sans-serif';ctx.fillStyle='#40576a';ctx.textAlign='center';
    defs.forEach((def,i)=>{const [px,py]=point(i,1.28);ctx.fillText(def.name,px,py);ctx.font='15px ui-monospace,Consolas,monospace';ctx.fillStyle='#677b8d';ctx.fillText(def.score===null?'未提供':String(def.score),px,py+23);ctx.font='17px "Microsoft YaHei",sans-serif';ctx.fillStyle='#40576a';});
    if(defs.every(def=>def.score!==null)){ctx.beginPath();defs.forEach((def,i)=>{const p=point(i,Math.max(0,Math.min(100,def.score))/100);i?ctx.lineTo(...p):ctx.moveTo(...p);});ctx.closePath();ctx.fillStyle='rgba(180,35,47,.10)';ctx.fill();ctx.strokeStyle='#b4232f';ctx.lineWidth=2.5;ctx.stroke();}
    else{ctx.fillStyle='#65798a';ctx.font='18px "Microsoft YaHei",sans-serif';ctx.fillText(row?'五维明细未完整采集':'等待计量记录',x,y+6);}
  }
  function download(tasks) {
    if(!tasks.length){notify('没有可导出的记录');return;}
    const blob=new Blob([JSON.stringify(M.snapshot(tasks,context(tasks)),null,2)],{type:'application/json;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='AgentMeter-Gov-审计档案-'+tasks.length+'项-'+new Date().toISOString().replace(/[:.]/g,'-')+'.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);notify('已导出 '+tasks.length+' 项档案；文件内任务数：'+tasks.length+'（JSON，未签名）');
  }
  function downloadRun(run) {
    if(!runConfirmed(run)){notify('实际运行证据尚未确认，无法导出');return;}
    const record={...run,report_type:'OpenClaw 实际运行证据',signed:false,exported_at:new Date().toISOString()};
    const blob=new Blob([JSON.stringify(record,null,2)],{type:'application/json;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');
    a.href=url;a.download='AgentMeter-Gov-实际运行证据-'+String(run.run_id||'record').replace(/[^A-Za-z0-9_-]/g,'_')+'.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);notify('已下载本场景完整运行证据，含各轮任务与原始事件，未签名');
  }
  function eventDialog(task,index) {
    const event=task?.events[index];if(!event)return;
    $('#eventDialogTitle').textContent=eventKind(event);$('#eventDialogBody').innerHTML='<div class="detail-meta">'+sources(task)+badge(eventResult(event),'neutral')+'</div><div class="facts-grid">'+fact('任务编号',task.task_id)+fact('事件编号',event.event_id)+fact('事件时间',date(event.timestamp))+fact('工具请求 ID',event.tool_request_id||event.call_id||event.tool_call_id)+fact('工具',toolOf(event))+fact('状态',eventResult(event))+'</div><h3>证据片段</h3><blockquote class="evidence-quote">'+safe(event.evidence)+'</blockquote><h3>参数摘要</h3><pre class="parameter-summary">'+safe(paramsOf(event)?JSON.stringify(paramsOf(event),null,2):null)+'</pre><p class="muted">任务结束、审批放行和工具执行成功属于不同状态。</p>';mountIcons();$('#eventDialog').showModal();
  }
  async function readEndpoint(key) {
    const historyScope=viewingHistory(),timeoutSeconds=historyScope?60:10;
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),timeoutSeconds*1000);
    try{
      const headers={};if(state.token)headers.Authorization='Bearer '+state.token;
      const route=(key==='tasks'?'/api/live/tasks':'/api/health')+'?scope='+state.monitoringScope+(key==='tasks'?'&format=compact':'');
      const url=new URL(route,state.backend),endpointCache=state.endpointCache,cached=endpointCache.get(url.href);
      if(key==='tasks'&&cached?.etag)headers['If-None-Match']=cached.etag;
      const response=await fetch(url,{headers,cache:'no-store',signal:controller.signal});
      if(response.status===304&&cached)return cached.payload;
      if(!response.ok){let detail='';try{detail=(await response.json()).error||'';}catch{}throw new Error(response.status===401?'身份验证失败（HTTP 401）':response.status===403?'访问被拒绝（HTTP 403）':'接口返回 HTTP '+response.status+(detail?'：'+detail:''));}
      let payload=await response.json();if(payload.error)throw new Error(payload.error);
      if(key==='tasks')payload=M.expandTaskPayload(payload);
      if(key==='tasks'&&(!Array.isArray(payload.tasks)||!payload.tasks.every(task=>task&&typeof task.task_id==='string'&&typeof task.status==='string'&&Array.isArray(task.events)&&task.events.every(event=>event&&typeof event==='object'))))throw new Error('任务响应格式异常');
      if(key==='health'&&(!payload.server||typeof payload.server.status!=='string'))throw new Error('健康状态响应格式异常');
      if(payload.monitoring_error)throw new Error(payload.monitoring_error);
      if(key==='tasks'&&response.headers.get('ETag'))endpointCache.set(url.href,{etag:response.headers.get('ETag'),payload});
      return payload;
    }catch(error){throw new Error(error.name==='AbortError'?'读取超时（'+timeoutSeconds+' 秒）':error instanceof TypeError?'无法连接本机监控后端':error.message);}
    finally{clearTimeout(timeout);}
  }
  const pageDataSignature = () => JSON.stringify({revision:state.dataRevision,rules:state.health?.rules||null,error:state.error,healthError:state.healthError});
  async function refresh(forceRender=false) {
    if(viewingHistory()&&!forceRender)return;
    if(state.loading)return;
    if(location.protocol==='file:'){state.error='本地文件模式无法连接后端，请通过预览服务地址打开';render();return;}
    const previousSignature=pageDataSignature();
    const requestId=++state.requestId;
    state.loading=true;state.attempted=true;renderChrome();
    const [tasks,health]=await Promise.allSettled([readEndpoint('tasks'),readEndpoint('health')]);
    if(requestId!==state.requestId||state.mode!=='backend')return;
    if(tasks.status==='fulfilled'){
      const data=tasks.value;
      if(health.status==='fulfilled'&&data.monitoring_started_at&&health.value.monitoring_started_at&&data.monitoring_started_at!==health.value.monitoring_started_at){state.error='后端开机轮次不一致，请重新读取';}
      else{
        if(data!==state.rawTasksPayload){const nextTasks=M.normalizeTasks(data).map(task=>{delete task.safe_summary;return task;});const available=new Set(nextTasks.map(task=>task.task_key));state.tasks=nextTasks;state.selected=new Set([...state.selected].filter(key=>available.has(key)));state.rawTasksPayload=data;state.dataRevision++;}
        state.total=Number.isFinite(data.task_count)?data.task_count:null;state.lastSuccess=new Date().toISOString();state.error='';
      }
    }else state.error=tasks.reason.message;
    if(health.status==='fulfilled'){state.health=health.value;state.healthAt=new Date().toISOString();state.healthError='';}else{state.healthError=health.reason.message;state.health=null;state.healthAt=null;}
    if(!state.error&&!state.healthError&&tasks.status==='fulfilled'&&health.status==='fulfilled')state.scopeCache.set(state.monitoringScope,{tasks:state.tasks,rawTasksPayload:state.rawTasksPayload,health:state.health,healthAt:state.healthAt,lastSuccess:state.lastSuccess,total:state.total});
    state.loading=false;$('#connectionFeedback').textContent=state.error||state.healthError||'监控数据读取成功';
    if(forceRender||previousSignature!==pageDataSignature())render();else renderChrome();
  }
  function localBackendOrigin(input) {
    try {const url=new URL(input);if(!['http:','https:'].includes(url.protocol)||!['localhost','127.0.0.1','[::1]'].includes(url.hostname)||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw Error();return url.origin;} catch{return null;}
  }
  function connectBackend(origin,token='',autoRefresh=true) {
    const changed=state.mode!=='backend'||state.backend!==origin||state.token!==token;
    state.backend=origin;state.token=token;state.mode='backend';state.scopeTaskKey=null;datasetUrl('backend');
    if(changed){state.requestId++;state.loading=false;state.tasks=[];state.health=null;state.lastSuccess=null;state.total=null;state.error='';state.healthError='';state.selected.clear();state.scopeCache.clear();state.endpointCache=new Map();state.rawTasksPayload=null;}
    clearInterval(state.timer);$('#autoRefresh').checked=autoRefresh;if(autoRefresh)state.timer=setInterval(()=>refresh(false),REFRESH_INTERVAL_MS);
    refresh(true);
  }
  function openSettings() {$('#backendUrl').value=state.backend;$('#connectionDialog').showModal();}
  function setMonitoringScope(scope) {
    if(!['current','history'].includes(scope)||state.monitoringScope===scope)return;
    state.monitoringScope=scope;state.requestId++;state.loading=false;
    state.tasks=[];state.health=null;state.healthAt=null;state.lastSuccess=null;state.total=null;state.error='';state.healthError='';
    state.query='';state.statusFilter='all';state.sourceFilter=scope==='history'?'all':'live';state.timeFilter='all';
    state.taskKey=null;state.riskKey=null;state.reviewKey=null;state.selected.clear();
    state.listLimit=50;
    state.rawTasksPayload=null;
    const cached=state.scopeCache.get(scope);
    if(cached)Object.assign(state,cached);
    $('#eventDialog').close();$('#printReport').replaceChildren();
    render();if(scope==='current'||!cached||Date.now()-Date.parse(cached.lastSuccess)>60000)refresh(true);
  }
  async function copyReview() {
    const row=allReviews(scopedTasks()).find(row=>row.key===state.reviewKey);if(!row)return;
    if(state.mode!=='backend'||viewingHistory()||state.error||!state.lastSuccess||Date.now()-Date.parse(state.lastSuccess)>30000||row.review.status!=='pending'||!/^AGR-[A-Za-z0-9_-]+$/.test(row.review.review_id||'')||(validDate(row.review.expires_at)&&Date.parse(row.review.expires_at)<Date.now())){notify('历史记录只读，或审批已不可操作，请切回本次开机刷新核对');render();return;}
    const command=($('#decisionMode').value==='reject'?'审批拒绝 ':'审批通过 ')+row.review.review_id;
    try{await navigator.clipboard.writeText(command);notify('指令已复制，尚未提交审批；等待后端确认');}catch{notify('复制失败，可选中指令手动复制');}
  }
  document.addEventListener('click',event=>{
    const liveTarget=event.target.closest('[data-live-action]');
    if(liveTarget){
      const key=liveTarget.dataset.key,action=liveTarget.dataset.liveAction,task=state.tasks.find(task=>task.task_key===key||task.task_id===key);
      if(!task){notify('该次实际运行尚未提供可关联的任务记录');return;}
      setTaskScope(task.task_key);state.query='';state.statusFilter='all';state.sourceFilter='all';state.timeFilter='all';
      if(action==='download'){downloadRun(runForTask(task)||currentRun());return;}
      if(action==='risks')state.riskKey=allRisks([task])[0]?.key||null;
      if(['tasks','risks','reviews','evidence'].includes(action))selectPage(action);
      return;
    }
    const target=event.target.closest('[data-action]');if(!target)return;
    const action=target.dataset.action,key=target.dataset.key;
    if(action==='load-more-records'){loadMoreRecords();return;}
    if(label[action]){selectPage(action);return;}
    if(action==='clear-task-scope'){state.scopeTaskKey=null;state.query='';state.statusFilter='all';render();return;}
    if(action==='settings')openSettings();
    if(action==='refresh')refresh(true);
    if(action==='open-task'){setTaskScope(key);selectPage('tasks');}
    if(action==='open-risk'){const row=allRisks(state.tasks).find(row=>row.key===key);if(row)setTaskScope(row.task.task_key);state.riskKey=key;selectPage('risks');}
    if(action==='select-task'){setTaskScope(key);render();}
    if(action==='select-risk'){const row=allRisks(state.tasks).find(row=>row.key===key);if(row)setTaskScope(row.task.task_key);state.riskKey=key;render();}
    if(action==='select-review'){const row=allReviews(state.tasks).find(row=>row.key===key);if(row)setTaskScope(row.task.task_key);state.reviewKey=key;render();}
    if(action==='metric'){state.query='';selectPage('tasks');state.statusFilter=target.dataset.filter;render();}
    if(action==='task-evidence'){setTaskScope(key);state.selected=new Set([key]);selectPage('evidence');}
    if(action==='event')eventDialog(state.tasks.find(task=>task.task_key===target.dataset.task),Number(target.dataset.index));
    if(action==='select-all'){scopedTasks().filter(matches).forEach(task=>state.selected.add(task.task_key));render();}
    if(action==='clear-selection'){state.selected.clear();render();}
    if(action==='download-selected')download(scopedTasks().filter(matches).filter(task=>state.selected.has(task.task_key)));
    if(action==='print'){const selected=scopedTasks().filter(matches).filter(task=>state.selected.has(task.task_key));if(!selected.length){notify('请先勾选需要打印的任务');return;}$('#printReport').innerHTML=reportMarkup(selected);window.print();}
    if(action==='copy-review')copyReview();
  });
  document.addEventListener('input',event=>{if(event.target.id==='searchInput'){state.query=event.target.value;state.listLimit=50;clearTimeout(state.searchTimer);state.searchTimer=setTimeout(render,120);}});
  document.addEventListener('change',event=>{
    if(event.target.id==='monitoringScope'){setMonitoringScope(event.target.value);return;}
    if(event.target.id==='liveRunSelect'){selectRun(Number(event.target.value));render();}
    if(event.target.id==='localStatusFilter'){state.statusFilter=event.target.value;state.listLimit=50;render();}
    if(event.target.id==='advancedSourceFilter'){state.sourceFilter=event.target.value;state.listLimit=50;render();}
    if(event.target.id==='timeFilter'){state.timeFilter=event.target.value;state.listLimit=50;render();}
    if(event.target.dataset.evidenceKey){event.target.checked?state.selected.add(event.target.dataset.evidenceKey):state.selected.delete(event.target.dataset.evidenceKey);render();}
    if(event.target.id==='decisionMode'){const row=allReviews(scopedTasks()).find(row=>row.key===state.reviewKey);if(row&&$('#copyReview')&&!$('#copyReview').disabled)$('#reviewCommand').textContent=(event.target.value==='reject'?'审批拒绝 ':'审批通过 ')+row.review.review_id;}
  });
  document.addEventListener('toggle',event=>{
    const detail=event.target;
    if(detail.matches?.('[data-lazy-report]')&&detail.open){
      const content=detail.querySelector('[data-report-content]');
      if(content&&!content.childNodes.length){content.innerHTML=reportMarkup(scopedTasks().filter(matches).filter(task=>state.selected.has(task.task_key)));mountIcons();}
    }
  },true);
  $('#settingsButton').onclick=openSettings;$('#refreshButton').onclick=()=>refresh(true);
  $('#connectionForm').onsubmit=event=>{
    event.preventDefault();const origin=localBackendOrigin($('#backendUrl').value);if(!origin){$('#connectionFeedback').textContent='请输入本机服务地址，如 http://127.0.0.1:8765';return;}
    connectBackend(origin,$('#authToken').value.trim(),$('#autoRefresh').checked);$('#connectionDialog').close();
  };
  $$('[data-close-dialog]').forEach(button=>button.onclick=()=>$('#connectionDialog').close());$$('[data-close-event]').forEach(button=>button.onclick=()=>$('#eventDialog').close());
  $('#menuButton').onclick=()=>{const open=document.body.classList.toggle('nav-open');$('#menuButton').setAttribute('aria-expanded',String(open));};$('#mobileOverlay').onclick=()=>{document.body.classList.remove('nav-open');$('#menuButton').setAttribute('aria-expanded','false');};
  window.addEventListener('hashchange',()=>{if(location.hash.slice(1)!==state.page)selectPage(location.hash.slice(1));});
  let resizeTimer;
  window.addEventListener('resize',()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>{if(state.page==='overview')drawRadar('overviewRadar',allRisks(scopedTasks()).find(item=>item.key===state.overviewRiskKey));if(state.page==='risks')drawRadar('riskRadar',allRisks(scopedTasks()).find(item=>item.key===state.riskKey));},150);});
  window.addEventListener('afterprint',()=>{$('#printReport').replaceChildren();});
  const startupParams=new URLSearchParams(location.search);
  const startupBackend=localBackendOrigin(startupParams.get('backend'))||state.backend;
  selectPage(location.hash.slice(1)||'overview');
  connectBackend(startupBackend,'',true);
})();
