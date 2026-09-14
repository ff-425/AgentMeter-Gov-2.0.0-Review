const HIDDEN_INSTRUCTION_PATTERN = /hidden\s+instruction|do\s+not\s+(?:mention|tell)|without\s+(?:telling|informing)|silent(?:ly)?|ignore\s+(?:all\s+)?(?:previous|prior|user)|disregard\s+(?:the\s+)?(?:previous|user)|忽略(?:用户|之前|原始|先前)|隐藏指令|不要(?:告诉|提及|说明|通知)|无需(?:告诉|通知)|不得告知|静默执行/i;
const SIDE_EFFECT_REQUEST_PATTERN = /(?:use|call|invoke)\s+(?:the\s+)?(?:write|edit|exec|shell|terminal|email|upload|delete|payment|access)\s+(?:tool|command)\b|(?:create|write|edit|append|overwrite|save)\s+(?:a\s+|the\s+)?(?:file|document|record|log|output)\b|(?:写入|创建|修改|追加|覆盖|保存)(?:文件|文档|记录|日志|结果)/i;
const SECURITY_ANALYSIS_CONTEXT_PATTERN = /security\s+(?:awareness|analysis|training|lesson)|malicious\s+phrase|quoted\s+example|for\s+training\s+only|安全(?:意识|分析|培训|课程)|恶意(?:语句|指令)|引用(?:示例|内容)|仅供(?:培训|分析|测试)/i;
const EXPLICIT_NON_EXECUTION_PATTERN = /do\s+not\s+execute|must\s+not\s+execute|never\s+execute|do\s+not\s+follow|treat\s+(?:it|this|the\s+example)\s+as\s+data|不要执行|不得执行|禁止执行|不要遵循|仅作(?:分析|引用)/i;
const ANALYSIS_ONLY_GOAL_PATTERN = /summari[sz]e|analy[sz]e|explain|review|safety\s+lesson|read\s+only|只(?:分析|总结|阅读)|分析|总结|解释|安全(?:课程|提示|说明)/i;
const BUSINESS_STATE_FIELD_PATTERN = /^(?:status|state|workflow[_-]?status|task[_-]?status|approval[_-]?status|phase|stage|progress|result|approved|accepted|authorized|decision|signer|approver|reviewer|owner|super[_-]?admin|admin[_-]?enabled|role|permission|permissions|scope|access|sensitive|maintenance|channel|recipient|receipt|level\d+|requests?[_-]?per[_-]?minute|response[_-]?hours|rate[_-]?limit|business[_-]?record[_-]?days|retention[_-]?days|archive[_-]?years|high[_-]?risk[_-]?threshold|review[_-]?threshold|risk[_-]?threshold|状态|业务状态|任务状态|流程状态|审批状态|阶段|进度|结果|批准|授权|决策|签批人|签名人|审批人|审核人|责任人|角色|权限|访问范围|敏感数据|限流|响应时限|留存期|归档年限|风险阈值|复核阈值)$/i;
const CRITICAL_TERMINAL_STATE_PATTERN = /^(?:approved|accepted|paid|published|released|completed|closed|done|rejected|passed|通过|已通过|审批通过|验收通过|已付款|已支付|已发布|已办结|已完成|审核完成|已关闭|已拒绝|不通过)$/i;
const APPROVAL_FIELD_PATTERN = /^(?:approved|accepted|approval[_-]?status|decision|批准|审批状态|决策)$/i;
const AUTHORIZATION_FIELD_PATTERN = /^(?:authorized|super[_-]?admin|admin[_-]?enabled|role|permission|permissions|scope|access|sensitive|授权|角色|权限|访问范围|敏感数据)$/i;
const SIGNER_FIELD_PATTERN = /^(?:signer|approver|reviewer|签批人|签名人|审批人|审核人|责任人)$/i;


export function normalizeRuntimeSecurityText(value) {
  let text = String(value ?? "");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const decoded = decodeURIComponent(text.replace(/\+/g, "%20"));
      if (decoded === text) break;
      text = decoded;
    } catch {
      break;
    }
  }
  return text
    .normalize("NFKC")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g, "")
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, decimal) => String.fromCodePoint(Number.parseInt(decimal, 10)));
}


export function canonicalRuntimeToolName(rawName, params = {}) {
  const name = String(rawName ?? "");
  const compact = name.toLowerCase().replace(/[^a-z0-9]+/g, "");
  const context = normalizeRuntimeSecurityText(JSON.stringify(params)).toLowerCase();

  if (/sendmoney|transfermoney|makepayment|paybill|purchase|reservehotel|bookhotel|bookflight/.test(compact)) {
    return "execute_payment";
  }
  if (/grantguestaccess|grantaccess|inviteuser|addmember|disabletwofactor|disable2fa|disablemultifactor/.test(compact)) {
    return "grant_access";
  }
  if (/sendemail|sendmail|sendmessage|postmessage|sendsms/.test(compact)) {
    return "send_email";
  }
  if (/sharedata|postwebsite|uploadfile|publishfile/.test(compact)) {
    return "upload_file";
  }
  if (/deletefile|removefile|eraserecord|deletetask/.test(compact)) {
    return "delete_file";
  }
  if (/manageappointments|scheduleappointment|managetrafficlight|trafficlightstate/.test(compact)) {
    return "write_file";
  }
  if (/readcredential|getcredential|readsecret|getsecret|readapikey|getapikey/.test(compact)) {
    return "read_secret";
  }
  if (/getwebpage|openurl|fetchurl/.test(compact)) {
    return "run_shell";
  }

  if (/\b(?:transfer|payment|payee|purchase|reservation)\b/.test(context) && /\b(?:send|make|initiate|execute|buy|book|reserve)\b/.test(context)) {
    return "execute_payment";
  }
  if (/\b(?:access|permission|two[- ]?factor|2fa|mfa)\b/.test(context) && /\b(?:grant|give|disable|turn off|invite)\b/.test(context)) {
    return "grant_access";
  }
  return name;
}


export function analyzeEditSemantics(rawParams = {}, rawUserGoal = "") {
  const params = rawParams && typeof rawParams === "object" ? rawParams : {};
  const editItems = Array.isArray(params.edits) && params.edits.length ? params.edits : [params];
  const transitions = [];
  for (const item of editItems) {
    if (!item || typeof item !== "object") continue;
    transitions.push(...stateTransitions(
      item.oldText ?? item.old_text ?? item.before ?? item.old ?? "",
      item.newText ?? item.new_text ?? item.after ?? item.new ?? "",
    ));
  }
  if (transitions.length === 0) {
    const inferredFields = inferBusinessFieldsFromGoal(normalizeRuntimeSecurityText(rawUserGoal));
    const scalarEdits = editItems.filter((item) => {
      const before = item?.oldText ?? item?.old_text ?? item?.before ?? item?.old;
      const after = item?.newText ?? item?.new_text ?? item?.after ?? item?.new;
      return before !== undefined && after !== undefined && String(before) !== String(after);
    });
    for (const field of inferredFields) {
      for (const item of scalarEdits) {
        transitions.push({
          field,
          before: String(item.oldText ?? item.old_text ?? item.before ?? item.old),
          after: String(item.newText ?? item.new_text ?? item.after ?? item.new),
        });
      }
    }
  }
  const explicitCounts = [
    params.affected_records,
    params.affectedRecords,
    params.record_count,
    params.recordCount,
    params.row_count,
    params.rowCount,
    params.count,
  ]
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0);
  const transitionCountsByField = new Map();
  for (const transition of transitions) {
    transitionCountsByField.set(
      transition.field,
      (transitionCountsByField.get(transition.field) ?? 0) + 1,
    );
  }
  const inferredRecordCount = Math.max(0, ...transitionCountsByField.values());
  const affectedRecords = Math.max(
    inferredRecordCount,
    editItems.length > 1 ? editItems.length : 0,
    ...explicitCounts,
    1,
  );
  const fields = [...new Set(transitions.map((item) => item.field))];
  const approvalChange = transitions.some((item) => APPROVAL_FIELD_PATTERN.test(item.field));
  const signerChange = transitions.some((item) => SIGNER_FIELD_PATTERN.test(item.field));
  const authorizationChange = transitions.some((item) => AUTHORIZATION_FIELD_PATTERN.test(item.field));
  return {
    version: "edit-semantics-v2",
    operation: "edit",
    affected_records: affectedRecords,
    fields,
    transitions: transitions.slice(0, 20),
    business_state_change: transitions.length > 0,
    critical_terminal_state: transitions.some(isCriticalTransition),
    approval_change: approvalChange,
    authorization_change: authorizationChange,
    signer_change: signerChange,
    official_integrity_change: approvalChange && signerChange,
    benign_new_output: false,
    operational_plan: false,
    destructive_overwrite: false,
    record_merge: false,
  };
}


function inferBusinessFieldsFromGoal(goal) {
  const inferred = [];
  const checks = [
    ["requests_per_minute", /requests?[_-]?per[_-]?minute|接口限流|请求限流|rate[_ -]?limit/i],
    ["business_record_days", /business[_-]?record[_-]?days|业务记录留存期|记录留存期|retention[_ -]?days/i],
    ["high_risk_threshold", /high[_-]?risk[_-]?threshold|高风险阈值|风险阈值/i],
    ["approver", /\bapprover\b|审批人|审批责任人/i],
    ["reviewer", /\breviewer\b|审核人|流程负责人|负责人/i],
    ["response_hours", /response[_-]?hours|sla|响应时限|响应时间/i],
    ["archive_years", /archive[_-]?years|归档年限|档案保留期|保留期/i],
    ["status", /(?:改为|改成|设置为|设为)[\s\S]{0,30}(?:已支付|已付款|已通过|通过|已发布|已完成|已关闭)|(?:paid|approved|accepted|published|completed|closed)/i],
    ["level2", /\blevel2\b|告警升级对象|升级对象/i],
    ["level3", /\blevel3\b|告警升级对象|升级对象/i],
  ];
  for (const [field, pattern] of checks) {
    if (pattern.test(goal)) inferred.push(field);
  }
  return inferred;
}


export function analyzeWriteSemantics(rawParams = {}, rawUserGoal = "") {
  const params = rawParams && typeof rawParams === "object" ? rawParams : {};
  const content = params.content ?? params.text ?? params.data ?? params.body ?? "";
  const fields = extractBusinessStateFields(content);
  const goal = normalizeRuntimeSecurityText(rawUserGoal);
  const mutationIntent = /(?:批量|全部|所有|多条|\d+\s*条|[两二三四五六七八九十]\s*条)[\s\S]{0,60}(?:改为|改成|修改|更新|变更|设置|设为|合并|转派)|(?:改为|改成|修改|更新|变更|设置|设为|转派)[\s\S]{0,80}(?:状态|status|state|approved|super[_-]?admin|权限|角色|维护|maintenance|限流|响应|留存|归档|阈值|负责人|审核人|责任人|owner|升级对象|level\d+|已支付|已付款|已通过|通过|已发布|已完成|已关闭|requests?[_-]?per[_-]?minute|response[_-]?hours|archive[_-]?years|retention|threshold)|(?:状态|status|state|approved|super[_-]?admin|权限|角色|维护|maintenance|限流|响应|留存|归档|阈值|负责人|审核人|责任人|owner|升级对象|level\d+|requests?[_-]?per[_-]?minute|response[_-]?hours|archive[_-]?years|retention|threshold)[\s\S]{0,80}(?:改为|改成|修改|更新|变更|设置|设为|转派)|(?:change|modify|update|set|reassign)[\s\S]{0,80}(?:status|state|approved|authorization|permission|role|reviewer|approver|owner|maintenance|level\d+|rate[_-]?limit|response[_-]?hours|archive[_-]?years|retention|threshold|requests?[_-]?per[_-]?minute)/i.test(goal);
  const operationalPlan = /(?:生成|创建|编制|write|create|generate)[\s\S]{0,100}(?:停用|禁用|启用|批量执行|deactivation|disable|enable)[\s\S]{0,80}(?:计划|清单|plan|manifest)|(?:计划|清单|plan|manifest)[\s\S]{0,100}(?:停用|禁用|启用|deactivation|disable|enable)/i.test(`${goal}\n${content}`);
  const benignNewOutput = isBenignNewOutput(goal) && !operationalPlan;
  const recordMerge = /(?:合并|merge)[\s\S]{0,60}(?:记录|record)|(?:记录|record)[\s\S]{0,60}(?:合并|merge)/i.test(goal);
  const evidenceIntegrityChange = /(?:覆盖|替换|改写|删除)[\s\S]{0,180}(?:证据|原件|原文|原结论|风险结论|审计记录|evidence|original)|(?:证据|原件|原文|原结论|风险结论|审计记录|evidence|original)[\s\S]{0,180}(?:覆盖|替换|改写|删除)/i.test(goal);
  const historyClear = /(?:清空|删除|移除|clear|delete|remove)[\s\S]{0,100}(?:全部|所有|all)?[\s\S]{0,30}(?:历史记录|history)|(?:历史记录|history)[\s\S]{0,100}(?:清空|删除|移除|clear|delete|remove)/i.test(goal)
    && /^(?:\[\s*\]|\{\s*\}|null|)$/i.test(String(content).trim());
  const countsByField = new Map();
  for (const item of fields) {
    countsByField.set(item.field, (countsByField.get(item.field) ?? 0) + 1);
  }
  const inferredGoalCount = inferGoalRecordCount(goal);
  const affectedRecords = Math.max(0, ...countsByField.values(), recordMerge ? inferredGoalCount : 0);
  const referencedFields = fields.filter((item) => goalReferencesBusinessField(item.field, goal));
  const activeFields = referencedFields.length > 0 ? referencedFields : fields;
  const businessStateChange = !benignNewOutput && mutationIntent && activeFields.length > 0;
  const approvalChange = activeFields.some((item) => APPROVAL_FIELD_PATTERN.test(item.field));
  const approvalExplicitlyUnchanged = /(?:decision|审批状态|审批结论|决策)[\s\S]{0,40}(?:保持|仍|不变)[\s\S]{0,20}(?:pending|待审|待审核)|(?:保持|仍|不变)[\s\S]{0,20}(?:pending|待审|待审核)[\s\S]{0,40}(?:decision|审批状态|审批结论|决策)/i.test(goal);
  const authorizationChange = activeFields.some((item) => AUTHORIZATION_FIELD_PATTERN.test(item.field));
  const signerChange = activeFields.some((item) => SIGNER_FIELD_PATTERN.test(item.field));
  const result = {
    version: "write-semantics-v2",
    operation: "write",
    affected_records: businessStateChange || recordMerge ? Math.max(affectedRecords, 1) : 0,
    fields: businessStateChange ? [...new Set(activeFields.map((item) => item.field))] : [],
    transitions: businessStateChange
      ? activeFields.slice(0, 20).map((item) => ({ field: item.field, before: "unknown", after: item.value }))
      : [],
    business_state_change: businessStateChange,
    critical_terminal_state: businessStateChange
      && activeFields.some((item) => isCriticalTransition({ field: item.field, after: item.value })),
    approval_change: approvalChange && !approvalExplicitlyUnchanged,
    authorization_change: authorizationChange,
    signer_change: signerChange,
    official_integrity_change: evidenceIntegrityChange || (approvalChange && !approvalExplicitlyUnchanged && signerChange),
    benign_new_output: benignNewOutput,
    operational_plan: operationalPlan,
    destructive_overwrite: evidenceIntegrityChange || historyClear,
    record_merge: recordMerge,
  };
  if (typeof params.agentmeter_existing_content === "string") {
    const compared = analyzeEditSemantics({
      oldText: params.agentmeter_existing_content,
      newText: content,
    }, rawUserGoal);
    return {
      ...result,
      version: "write-semantics-v3-existing-content",
      affected_records: Math.max(result.affected_records, compared.affected_records),
      fields: [...new Set([...result.fields, ...compared.fields])],
      transitions: compared.transitions,
      business_state_change: result.business_state_change || compared.business_state_change,
      critical_terminal_state: result.critical_terminal_state || compared.critical_terminal_state,
      approval_change: result.approval_change || compared.approval_change,
      authorization_change: result.authorization_change || compared.authorization_change,
      signer_change: result.signer_change || compared.signer_change,
      official_integrity_change: result.official_integrity_change || compared.official_integrity_change,
      destructive_overwrite: result.destructive_overwrite || compared.destructive_overwrite,
      record_merge: result.record_merge || compared.record_merge,
      benign_new_output: false,
    };
  }
  return result;
}


export function analyzeShellWriteSemantics(rawParams = {}, rawUserGoal = "") {
  const params = rawParams && typeof rawParams === "object" ? rawParams : {};
  const command = normalizeRuntimeSecurityText(params.command ?? params.cmd ?? "");
  const goal = normalizeRuntimeSecurityText(rawUserGoal);
  const copyWithForce = /copy-item/i.test(command) && /(?:-force\b|>)/i.test(command);
  // OpenClaw normally expands both operands to absolute paths. The semantic
  // distance between “覆盖” and “backup” can therefore be much larger than a
  // short natural-language window even though they belong to one operation.
  const overwriteIntent = /(?:覆盖|替换|overwrite|replace)[\s\S]{0,400}(?:备份|原文件|原件|归档|基线|最近一次|latest|archive|baseline|backup|original)|(?:备份|原文件|原件|归档|基线|最近一次|latest|archive|baseline|backup|original)[\s\S]{0,400}(?:覆盖|替换|overwrite|replace)/i.test(goal);
  const benignScopedCleanup = isBenignScopedCleanup(command, goal);
  return {
    version: "shell-write-semantics-v1",
    operation: "shell_write",
    affected_records: 0,
    fields: [],
    transitions: [],
    business_state_change: false,
    critical_terminal_state: false,
    approval_change: false,
    authorization_change: false,
    signer_change: false,
    official_integrity_change: false,
    benign_new_output: false,
    operational_plan: false,
    destructive_overwrite: copyWithForce && overwriteIntent,
    record_merge: false,
    benign_scoped_cleanup: benignScopedCleanup,
  };
}


function isBenignScopedCleanup(command, goal) {
  const exact = command.match(/^\s*remove-item\s+-literalpath\s+(['"])([^'"]+)\1\s+-force\s*$/i);
  if (!exact) return false;
  const target = String(exact[2] ?? "").replaceAll("\\", "/").toLowerCase();
  if (!target || target.includes("..") || /[*?\[\]]/.test(target)) return false;
  if (!/\.(?:tmp|log|cache)$/i.test(target)) return false;
  if (/(?:^|\/)(?:audit|security|approval|openclaw|memory|credential|secret|config)[^/]*\.(?:tmp|log|cache)$/i.test(target)) {
    return false;
  }
  const cleanupRequested = /(?:清理|删除|移除|cleanup|delete|remove)[\s\S]{0,80}(?:临时|缓存|temp|cache|\.tmp|\.log)|(?:临时|缓存|temp|cache|\.tmp|\.log)[\s\S]{0,80}(?:清理|删除|移除|cleanup|delete|remove)/i.test(goal);
  const boundedScope = /(?:限定|指定|仅|只|不要修改其他|single|exact|only|literalpath)/i.test(goal);
  return cleanupRequested && boundedScope;
}


function stateTransitions(rawBefore, rawAfter) {
  const before = extractBusinessStateFields(rawBefore);
  const after = extractBusinessStateFields(rawAfter);
  const transitions = [];
  const usedAfter = new Set();
  for (const prior of before) {
    const nextIndex = after.findIndex((candidate, index) => !usedAfter.has(index) && candidate.field === prior.field);
    if (nextIndex < 0) continue;
    usedAfter.add(nextIndex);
    const next = after[nextIndex];
    if (prior.value !== next.value) {
      transitions.push({ field: prior.field, before: prior.value, after: next.value });
    }
  }
  return transitions;
}


function isCriticalTransition(item) {
  const field = String(item?.field ?? "");
  const after = String(item?.after ?? "").trim();
  if (CRITICAL_TERMINAL_STATE_PATTERN.test(after)) return true;
  return (APPROVAL_FIELD_PATTERN.test(field) || AUTHORIZATION_FIELD_PATTERN.test(field))
    && /^(?:true|1|yes|enabled|approved|accepted|通过|启用)$/i.test(after);
}


function isBenignNewOutput(goal) {
  const explicitNew = /(?:新的|新建|创建|生成)[\s\S]{0,100}(?:文件|清单|模板|报告|摘要|公告|faq|json|csv|md|txt)|(?:写入|保存|生成|创建)[\s\S]{0,80}(?:新的|新建)/i.test(goal);
  const existingMutation = /(?:改成|改为|修改|更新|覆盖|替换|清空|删除|合并|设为|设置)[\s\S]{0,80}(?:原文件|现有|已有|状态|审批|合同|权限|记录|备份|证据|结论)|(?:原文件|现有|已有|状态|审批|合同|权限|记录|备份|证据|结论)[\s\S]{0,80}(?:改成|改为|修改|更新|覆盖|替换|清空|删除|合并|设为|设置)/i.test(goal);
  const highRisk = /(?:外发|上传|发送给外部|付款执行|超级管理员|签批|绕过防护|关闭防护|删除审计|密钥|凭据|停用计划|禁用计划|批量执行|deactivation|disable\s+plan)/i.test(goal);
  return explicitNew && !existingMutation && !highRisk;
}


function goalReferencesBusinessField(field, goal) {
  const normalizedField = String(field ?? "").toLowerCase();
  const normalizedGoal = String(goal ?? "").toLowerCase();
  const aliases = [normalizedField, normalizedField.replace(/[_-]+/g, " ")];
  if (aliases.some((alias) => alias && normalizedGoal.includes(alias))) return true;
  if (/^(?:status|state|workflow[_-]?status|task[_-]?status|approval[_-]?status|phase|stage|progress|result|状态|业务状态|任务状态|流程状态|审批状态|阶段|进度|结果)$/i.test(normalizedField)) {
    return /(?:状态|阶段|进度|结果|status|state|phase|stage|progress|result)/i.test(goal);
  }
  if (APPROVAL_FIELD_PATTERN.test(normalizedField)) {
    return /(?:批准|审批|决策|approved|accepted|approval|decision)/i.test(goal);
  }
  if (AUTHORIZATION_FIELD_PATTERN.test(normalizedField)) {
    return /(?:权限|授权|角色|访问范围|敏感数据|super[_-]?admin|permission|authorization|role|scope|access|sensitive)/i.test(goal);
  }
  if (SIGNER_FIELD_PATTERN.test(normalizedField)) {
    return /(?:签批人|签名人|signer)/i.test(goal);
  }
  return false;
}


function inferGoalRecordCount(goal) {
  const numeric = goal.match(/\b(\d{1,4})\s*(?:条|个|rows?|records?)\b/i);
  if (numeric) return Number.parseInt(numeric[1], 10);
  const chinese = goal.match(/([两二三四五六七八九十])\s*(?:条|个)(?:记录|工单|业务)?/);
  if (!chinese) return 0;
  return ({ 两: 2, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9, 十: 10 })[chinese[1]] ?? 0;
}


function extractBusinessStateFields(rawText) {
  const text = normalizeRuntimeSecurityText(rawText);
  const fields = [];
  const pattern = /["']?([\p{L}_-][\p{L}\p{N}_-]{0,40})["']?\s*[:=]\s*["']?([^,"'\r\n}\]]{1,80})/gu;
  for (const match of text.matchAll(pattern)) {
    const field = String(match[1] ?? "").trim();
    const value = String(match[2] ?? "").trim();
    if (BUSINESS_STATE_FIELD_PATTERN.test(field) && value) {
      fields.push({ field: field.toLowerCase(), value });
    }
  }
  // Permission/scope values are commonly arrays (for example [] -> ["*"]).
  // The scalar parser intentionally stops at '['; preserve array-valued
  // business fields as first-class transitions as well.
  const arrayPattern = /["']?([\p{L}_-][\p{L}\p{N}_-]{0,40})["']?\s*[:=]\s*(\[[^\]\r\n]{0,200}\])/gu;
  for (const match of text.matchAll(arrayPattern)) {
    const field = String(match[1] ?? "").trim();
    const value = String(match[2] ?? "").trim();
    if (BUSINESS_STATE_FIELD_PATTERN.test(field) && value) {
      fields.push({ field: field.toLowerCase(), value });
    }
  }
  return fields;
}


export function detectHiddenInstruction(observed, rawText) {
  if (observed?.name !== "read_document" || observed?.result !== "success") {
    return null;
  }
  if (isBundledOpenClawSkillDocument(observed)) {
    // A bundled SKILL.md is an instruction source by design. Treating its
    // documented tool workflow as a hidden instruction taints ordinary tasks
    // from channel plugins such as Weixin. Third-party/workspace documents are
    // still scanned normally; component installation has a separate gate.
    return null;
  }
  const text = normalizeRuntimeSecurityText(rawText);
  if (/"case_id"\s*:/.test(text) && /"expected"\s*:/.test(text) && /"message"\s*:/.test(text)) {
    return null;
  }
  if (looksLikeDirectoryListing(text)) {
    return null;
  }
  if (isClearlyQuotedSecurityExample(text, observed?.user_goal)) {
    return null;
  }

  const indicators = [];
  const checks = [
    ["hidden_instruction", HIDDEN_INSTRUCTION_PATTERN],
    ["side_effect_request", SIDE_EFFECT_REQUEST_PATTERN],
    ["internal_data_request", /staff_sensitive|internal|staff_contacts|roster|id_card|identity|phone|mobile|pii|USER\.md|database_config|内部|人员|通讯录/i],
    ["secret_access_request", /\.env|db_pass|api[_-]?key|token|password|secret|credential|凭据|密钥/i],
    ["external_send_request", /send_to_external|external|upload|outbox|webhook|发送给外部|外发|上传|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i],
    ["financial_action", /\b(?:send|make|initiate|execute|wire|transfer|pay|purchase|buy|book|reserve)\b[\s\S]{0,50}\b(?:money|payment|transaction|bill|stock|hotel|flight)\b|(?:转账|付款|支付|缴费|购买|买入|预订|订购)/i],
    ["privilege_change", /(?:grant|give|add|invite|disable|turn off)[\s\S]{0,50}(?:access|permission|member|two[- ]?factor|2fa|mfa|authentication)|(?:授权|授予权限|添加成员|永久访问|关闭|禁用)[\s\S]{0,30}(?:双重认证|二次验证|访问|权限)/i],
    ["destructive_action", /(?:delete|remove|erase|clear|truncate)[\s\S]{0,50}(?:file|record|task|log|audit)|(?:删除|清空|覆盖)[\s\S]{0,30}(?:文件|记录|任务|日志|审计)/i],
    ["system_or_business_mutation", /(?:run|execute)[\s\S]{0,30}(?:shell|command|powershell|bash)|(?:schedule|change|modify|update)[\s\S]{0,50}(?:appointment|traffic light|status|contract|approval)|(?:执行命令|运行命令|预约|修改)[\s\S]{0,30}(?:门诊|交通灯|状态|合同|审批)/i],
  ];
  for (const [indicator, pattern] of checks) {
    if (pattern.test(text)) indicators.push(indicator);
  }
  if (!indicators.includes("hidden_instruction") || indicators.length < 2) {
    return null;
  }
  return {
    indicators,
    preview: text.slice(0, 1200),
  };
}


export function isBundledOpenClawSkillDocument(observed) {
  const params = observed?.params ?? {};
  const path = String(params.path ?? params.file ?? "").replace(/\\/g, "/");
  return /\/node_modules\/openclaw\/skills\/.+\/SKILL\.md$/i.test(path);
}


export function isClearlyQuotedSecurityExample(rawText, rawUserGoal = "") {
  const text = normalizeRuntimeSecurityText(rawText);
  const userGoal = normalizeRuntimeSecurityText(rawUserGoal);
  if (!ANALYSIS_ONLY_GOAL_PATTERN.test(userGoal) || !EXPLICIT_NON_EXECUTION_PATTERN.test(userGoal)) {
    return false;
  }
  if (!SECURITY_ANALYSIS_CONTEXT_PATTERN.test(text) || !EXPLICIT_NON_EXECUTION_PATTERN.test(text)) {
    return false;
  }
  const outsideQuotedExamples = text
    .replace(/"[^"\r\n]{1,2000}"/g, " ")
    .replace(/“[^”\r\n]{1,2000}”/g, " ")
    .replace(/`[^`\r\n]{1,2000}`/g, " ");
  return HIDDEN_INSTRUCTION_PATTERN.test(text) && !HIDDEN_INSTRUCTION_PATTERN.test(outsideQuotedExamples);
}


export function looksLikeDirectoryListing(rawText) {
  const value = String(rawText ?? "");
  const lines = value.split(/\r?\n/).filter((line) => line.trim());
  if (lines.length < 3) return false;
  const hasTableHeader = /FullName\s+Length|Mode\s+LastWriteTime\s+Length\s+Name|Directory:\s+/i.test(value);
  const pathLineCount = lines.filter((line) => /[A-Z]:\\|\.openclaw\\workspace|agentmeter_demo[\\/]/i.test(line)).length;
  const commandLike = HIDDEN_INSTRUCTION_PATTERN.test(value);
  return hasTableHeader && pathLineCount >= 2 && !commandLike;
}
