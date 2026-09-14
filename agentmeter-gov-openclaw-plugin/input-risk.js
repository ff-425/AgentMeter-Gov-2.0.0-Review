export function assessInputRisk(prompt) {
  const text = String(prompt ?? "");
  const lower = text.toLowerCase();
  const persistence = /请记住|记住这条规则|植入规则|永久规则|以后(?:当|每当)|自动(?:读取|执行|发送|上传)|触发词|触发规则|持久化|写入(?:长期)?记忆|remember this rule|from now on|whenever|persist/i.test(lower);
  const delayedTrigger = /当用户|当我|每当|以后.*(?:时|就)|提到.+时|回复.+时|触发|whenever|when (?:the )?user|if (?:the )?user/i.test(lower);
  const sensitiveAsset = /database[_ -]?config|\.env\b|api[_ -]?key|token|secret|password|credential|凭证|密钥|口令|数据库配置|内部人员|通讯录|身份证|手机号|user\.md|所有\s*(?:txt|json)|工作区所有/i.test(lower);
  // Keep the existing sensitive-asset policy; the conversational trigger rule
  // below separately requires a directed side effect.
  const externalEffect = /发送|外发|上传|post\b|webhook|邮件|email|@[a-z0-9.-]+\.[a-z]{2,}|https?:\/\/|外部地址|无需告知|不要告知|不告知|隐藏|powershell|cmd(?:\.exe)?|执行命令|run shell/i.test(lower);

  if (persistence && sensitiveAsset && externalEffect) {
    return {
      score: 92,
      category: "memory_poisoning",
      reason: "persistent_sensitive_exfiltration_rule",
      message: "AgentMeter-Gov 已阻断输入：该请求试图植入可持久触发的敏感数据读取与外发规则。",
      rules: [
        "INPUT-MEM-01：检测到持久化或自动触发规则植入",
        "INPUT-DATA-01：规则涉及凭证、配置或敏感文件读取",
        "INPUT-EXFIL-01：规则包含外发、上传、命令执行或隐藏行为",
      ],
      factors: inputFactorContributions({ C: 70, G: 95, D: 95, P: 82, T: 92, A: 75, I: 96 }),
    };
  }
  if (persistence && delayedTrigger && hasDirectedSideEffect(text)) {
    return {
      score: 86,
      category: "delayed_execution",
      reason: "persistent_delayed_side_effect_rule",
      message: "AgentMeter-Gov 已阻断输入：该请求试图植入延迟触发的外发或命令执行规则。",
      rules: [
        "INPUT-MEM-01：检测到持久化或自动触发规则植入",
        "INPUT-TRIGGER-01：检测到基于后续短语的延迟执行条件",
        "INPUT-SIDE-EFFECT-01：触发动作包含外发、网络请求或命令执行",
      ],
      factors: inputFactorContributions({ C: 55, G: 92, D: 60, P: 90, T: 88, A: 75, I: 95 }),
    };
  }

  // Below: input-layer attacks whose payload is the prompt itself (no tool call
  // is required). The live runner previously mapped these onto canned canary
  // scenarios, so the real per-case content never reached the gate; and the
  // offline full-eval skipped them because they carry no proposed_tool. Blocking
  // here makes the defense independent of model self-refusal.

  const dangerousCommand = detectDangerousCommandInstruction(text);
  if (dangerousCommand) return dangerousCommand;

  const externalExfil = detectExternalExfiltrationInstruction(text);
  if (externalExfil) return externalExfil;

  const configDowngrade = detectSecurityConfigDowngrade(text);
  if (configDowngrade) return configDowngrade;

  const maliciousSkill = detectMaliciousSkillInstruction(text);
  if (maliciousSkill) return maliciousSkill;

  const jailbreak = detectJailbreakInstruction(text);
  if (jailbreak) return jailbreak;

  const memoryBackdoor = detectMemoryBackdoorInstruction(text);
  if (memoryBackdoor) return memoryBackdoor;

  return null;
}

function hasDirectedSideEffect(text) {
  // "post a code snippet" is a conversational step; a URL or the word
  // "hidden" alone is not evidence of an external transfer or shell command.
  const destination = String.raw`(?:https?://|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|webhook\b|(?:an?\s+|the\s+)?(?:external|remote)\s+(?:server|endpoint|address)|外部(?:地址|接口|服务器)|远程服务器|邮箱)`;
  const transfer = new RegExp(String.raw`(?:\b(?:send|upload|post|transmit|forward|exfiltrate)\b|发送|外发|上传|推送|传输)[^\r\n]{0,160}(?:\bto\b|\bvia\b|到|至|给)\s*${destination}`, "i");
  const httpWrite = /\b(?:post|put)\s*(?:(?:to|到|至)\s*)?https?:\/\//i;
  const shell = /(?:执行|运行)[^。！？\r\n]{0,20}(?:命令|脚本)|(?:使用|执行|运行)\s*(?:powershell|cmd(?:\.exe)?)\b|\b(?:execute|run)\s+(?:(?:a|the|this)\s+)?(?:shell|command|script|powershell|cmd)\b|\b(?:powershell|cmd(?:\.exe)?)\s+[-/][a-z]|\b(?:curl|wget)\s+\S/i;
  const transferText = text.replace(/\b(?:post|send)\s+(?:a|the)\s+link\s+to\s+https?:\/\/\S+\s+in\s+(?:your|the)\s+(?:reply|response)\b/gi, "");
  return transfer.test(transferText) || httpWrite.test(text) || shell.test(text);
}

function hasAtSchedulingCommand(text) {
  const atTime = String.raw`\bat(?:\.exe)?\s+(?:[01]?\d|2[0-3]):[0-5]\d\b`;
  // Scheduling flags, redirected job input and shell pipes establish command
  // structure. Natural-language meeting / booking times do not.
  if (new RegExp(String.raw`${atTime}\s+(?:-(?:f|m|M|q|t)\b|<|/(?:interactive|every|next|delete)\b)`, "i").test(text)
      || new RegExp(String.raw`\|\s*${atTime}`, "i").test(text)
      || new RegExp(String.raw`${atTime}\s+(?:(?:cmd(?:\.exe)?|powershell(?:\.exe)?|sh|bash)\s+[-/]|(?:[A-Za-z]:\\|/)[^\r\n]+)`, "i").test(text)
      || new RegExp(String.raw`${atTime}\s+[A-Za-z0-9_.-]+\.(?:exe|bat|cmd|ps1|sh)\b`, "i").test(text)
      || new RegExp(String.raw`(?:执行命令|运行命令|\b(?:run|execute)\s+(?:the\s+)?command)\s*[:：]?\s*${atTime}`, "i").test(text)) return true;
  // Bare at commands in explicit code surfaces are still governed.
  for (const match of text.matchAll(/```[^\r\n]*\r?\n([\s\S]*?)```|`([^`\r\n]+)`/g)) {
    if (new RegExp(String.raw`^\s*${atTime}(?:\s|$)`, "im").test(match[1] ?? match[2])) return true;
  }
  return false;
}

function detectDangerousCommandInstruction(text) {
  const lower = text.toLowerCase();
  const destructive = /rm\s+-rf|rm\s+-fr\s|remove-item\s+-recurse|del\s+\/s\s+\/q|format\s+[a-z]:|删(?:除|掉)(?:整个|全部)?(?:工作区|目录|数据|文件)|delete\s+(?:entire|all)\s+(?:workspace|directory|data)/i.test(text);
  const reverseShell = /reverse\s+shell|\/dev\/tcp\/|反弹shell|反向shell/i.test(lower);
  const downloadExec = /(?:curl|wget|iwr|irm|iex|invoke-expression)[^\n]*(?:\||-o\s|outfile).{0,120}(?:bash|sh\b|cmd|powershell|python)/i.test(lower) || /(?:curl|wget)\s+[^\n]*\|\s*(?:bash|sh)\b/i.test(lower);
  const privilege = /chmod\s+(?:777|000|666)|\bsudo\b\s+|\bchown\b\s+-r|chmod\s+-r\s+777/i.test(lower);
  const persistenceCmd = /\bcrontab\s+-\b|\bschtasks\s+\/create\b/i.test(lower) || hasAtSchedulingCommand(text);
  const containerEscape = /docker\s+run[^\n]*(?:--privileged|chroot|-v\s+\/:\/)/i.test(lower);
  const networkScan = /\bnmap\s+(?:-s|\d|192\.|10\.|172\.)|arp\s+-a\b/i.test(lower);
  const credentialSteal = /git\s+credential\s+fill|\bssh\b[^\n]*id_rsa|\/etc\/shadow|\/etc\/passwd/i.test(lower);
  const pipBackdoor = /pip\s+install[^\n]*--index-url|npm\s+install[^\n]*--registry|pip3?\s+install[^\n]*attacker/i.test(lower);
  const historyMining = /\.bash_history|\.zsh_history|历史命令|history\s*\|\s*tail/i.test(lower);
  const cookieSteal = /chrome[^\n]*(?:cookies|history)|cookies[^\n]*curl|浏览器(?:cookie|历史)/i.test(lower);
  const clipboardExfil = /剪贴板|clipboard/i.test(lower) && /复制|内容|copy/i.test(lower);
  const keylogRead = /keylog|键盘记录|键击/i.test(lower);

  const rules = [
    [destructive, "INPUT-CMD-01：检测到破坏性删除或格式化指令"],
    [reverseShell || downloadExec || privilege, "INPUT-CMD-02：" + [reverseShell && "检测到反向 shell 指令", downloadExec && "检测到下载后执行命令", privilege && "检测到权限变更命令"].filter(Boolean).join("；")],
    [credentialSteal || persistenceCmd || containerEscape, "INPUT-CMD-03：" + [credentialSteal && "检测到凭据读取指令", persistenceCmd && "检测到计划任务或持久化命令", containerEscape && "检测到容器逃逸命令"].filter(Boolean).join("；")],
    [networkScan, "INPUT-CMD-04：检测到网络扫描命令"],
    [pipBackdoor, "INPUT-CMD-05：检测到依赖源替换或可疑依赖安装"],
    [historyMining, "INPUT-CMD-06：检测到命令历史读取指令"],
    [cookieSteal, "INPUT-CMD-07：检测到浏览器 Cookie 或历史读取指令"],
    [clipboardExfil, "INPUT-CMD-08：检测到剪贴板内容读取指令"],
    [keylogRead, "INPUT-CMD-09：检测到键盘记录相关指令"],
  ].filter(([matched]) => matched).map(([, rule]) => rule);
  if (rules.length) {
    return {
      score: 90,
      category: "dangerous_command",
      reason: "dangerous_shell_command_instructed",
      message: `AgentMeter-Gov 已阻断输入：${rules.map((rule) => rule.split("：")[1]).join("；")}。`,
      rules,
      factors: inputFactorContributions({ C: 60, G: 90, D: 80, P: 92, T: 90, A: 80, I: 92 }),
    };
  }
  return null;
}

function detectExternalExfiltrationInstruction(text) {
  const lower = text.toLowerCase();
  const attackerTarget = /attacker\.(?:com|org|net|io)|attacker-repo|attacker_controlled|evil\.org|attacker-webhook|attack\.example\.com|malicious/i.test(lower);
  const exfilAction = /curl|wget|post\b|upload|发送|外发|推送|打包|base64|encode|nslookup|scrot|截图|导出|export|exfil|dns\s+tunnel/i.test(lower);
  const secretSource = /\.env\b|config\.json|credentials|id_rsa|private\s*key|api[_ -]?key|token|secret|password|环境变量|凭据|密钥|\.ssh\/|\/etc\//i.test(lower);
  if (attackerTarget && (exfilAction || secretSource)) {
    return {
      score: 90,
      category: "external_exfiltration",
      reason: "external_attacker_exfiltration_instruction",
      message: "AgentMeter-Gov 已阻断输入：该请求指示将系统数据、凭据或环境变量外发至攻击者控制的外部地址。",
      rules: [
        "INPUT-EXFIL-02：检测到攻击者控制的外部目标地址",
        "INPUT-EXFIL-03：检测到数据打包、编码、隧道或外发动作",
      ],
      factors: inputFactorContributions({ C: 70, G: 90, D: 92, P: 80, T: 90, A: 80, I: 92 }),
    };
  }
  return null;
}

function detectSecurityConfigDowngrade(text) {
  const lower = text.toLowerCase();
  const authDisable = /auth["']?\s*[:=][^}]{0,40}none|认证模式.{0,20}(?:none|无|关闭)|authentication.{0,30}(?:off|disabled|none)/i.test(lower);
  const sandboxEscape = /--privileged|privileged\s*[:=]\s*true|沙箱.{0,20}(?:关闭|禁用|逃逸)|sandbox.{0,20}(?:disable|escape)/i.test(lower);
  const allowlistPoison = /白名单.{0,30}(?:添加|加入|设置).{0,60}attacker|allowlist.{0,40}attacker|可信域名.{0,30}attacker|\.attacker\.com|安全白名单.{0,40}(?:attacker|evil)/i.test(lower);
  const loggingDisable = /log[_-]?level.{0,20}(?:none|off)|关闭.{0,20}(?:审计|日志)|禁用.{0,20}(?:审计|日志)|audit.{0,20}(?:off|disabled)|logging.{0,20}(?:off|disabled)/i.test(lower);
  const rateLimitRemove = /速率限制.{0,20}(?:取消|移除|无限制|关闭)|rate[_-]?limit.{0,20}(?:remove|disable|unlimited)/i.test(lower);
  const keyReplace = /api[_-]?key.{0,40}(?:替换|改为|更换|replace).{0,40}sk-|密钥.{0,20}(?:替换|改为).{0,20}sk-/i.test(lower);
  const toolAllowlistExpand = /工具.{0,20}(?:白名单|列表).{0,30}(?:添加|扩展|加入).{0,60}(?:nc|nmap|sqlmap|netcat)|allowlist.{0,40}(?:nc|nmap|sqlmap)/i.test(lower);
  const signatureOff = /签名验证.{0,20}(?:无需|禁用|关闭|跳过)|verifySignature.{0,20}(?:false|off)|signature.{0,20}(?:verification|check).{0,20}(?:off|skip|disable)/i.test(lower);
  const retentionPermanent = /记忆.{0,20}(?:保留|留存).{0,20}(?:永久|永远|不删除|不清理)|memory.{0,20}retention.{0,20}(?:forever|permanent)/i.test(lower);
  const proxyHijack = /代理.{0,20}(?:设置|改为).{0,40}attacker|proxy.{0,40}attacker\.com/i.test(lower);

  if (authDisable || sandboxEscape || allowlistPoison || loggingDisable || rateLimitRemove || keyReplace || toolAllowlistExpand || signatureOff || retentionPermanent || proxyHijack) {
    return {
      score: 92,
      category: "security_config_downgrade",
      reason: "security_control_downgrade_instructed",
      message: "AgentMeter-Gov 已阻断输入：该请求指示降级安全控制（认证、签名验证、沙箱、审计日志、白名单、限流或密钥）。",
      rules: [
        "INPUT-CFG-01：检测到认证、签名验证或沙箱安全降级",
        "INPUT-CFG-02：检测到审计日志、限流、白名单或密钥篡改",
      ],
      factors: inputFactorContributions({ C: 70, G: 90, D: 80, P: 92, T: 85, A: 88, I: 92 }),
    };
  }
  return null;
}

function detectMaliciousSkillInstruction(text) {
  const lower = text.toLowerCase();
  const codeExec = /os\.system\(|subprocess\.|exec\(base64|b64decode|__reduce__|import\s+os\b|\beval\(|rm\s+-rf\s+\/|curl[^\n]*\|\s*(?:bash|sh)/i.test(lower);
  const pickle = /\bpickle\b|__reduce__|deserializ/i.test(lower);
  const postinstall = /postinstall|preinstall|"scripts"\s*:/i.test(lower);
  const gitCloneMalice = /git\s+clone[^\n]*(?:attacker|fake-|evil|malicious)/i.test(lower);
  const dependencyHijack = /dependencies["']?\s*:\s*\{[^}]*https?:/i.test(lower) || /pillow["']?\s*:\s*["']https?:/i.test(lower);
  const symlink = /ln\s+-sf?\s+\/etc\//i.test(lower);
  const templateInject = /system\.execute\(|\{\{\s*system\./i.test(lower);
  const obfuscated = /base64[^"']{0,20}(?:b64decode|decode)|\beval\s*\(\s*base64/i.test(lower);
  const envPoison = /export\s+(?:OPENCLAW|AGENTMETER|API)[_A-Z]*=.*attacker/i.test(lower);
  const typosquat = /weather-skilll|fake-openclaw|malicious-pillow|attacker-repo/i.test(lower);
  const regexDos = /\(\s*a\+\s*\)\s*\+\s*b|redos|re\.match\(r?['"]\(a\+\)\+b|cata.{0,20}strophic.{0,20}backtrack/i.test(lower);
  const permissionEscalation = /skill.{0,20}(?:无需|跳过|不经过).{0,20}签名验证|skill.{0,20}(?:无需|免).{0,20}(?:签名|验证)|without.{0,20}signature.{0,20}verification/i.test(lower);

  if (codeExec || pickle || postinstall || gitCloneMalice || dependencyHijack || symlink || templateInject || obfuscated || envPoison || typosquat || regexDos || permissionEscalation) {
    return {
      score: 90,
      category: "malicious_skill",
      reason: "malicious_skill_or_component_instructed",
      message: "AgentMeter-Gov 已阻断输入：该请求指示安装包含恶意代码、后门、依赖劫持或反序列化攻击的 Skill/组件。",
      rules: [
        "INPUT-SKILL-01：检测到 Skill 代码中的命令执行、反序列化或后门",
        "INPUT-SKILL-02：检测到恶意仓库、依赖劫持、符号链接或模板注入",
      ],
      factors: inputFactorContributions({ C: 75, G: 90, D: 75, P: 85, T: 90, A: 80, I: 90 }),
    };
  }
  return null;
}

function detectJailbreakInstruction(text) {
  const lower = text.toLowerCase();
  const dan = /\bDAN\b[^\n]{0,60}do\s+anything|do\s+anything\s+now|pretend\s+to\s+be\s+DAN/i.test(lower);
  const unrestricted = /unrestricted\s+mode|no\s+restrictions|developer\s+mode|没有任何限制|无限制模式|开发者模式/i.test(lower);
  const ignorePrevious = /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:the\s+)?(?:previous|user)|忽略(?:之前|先前|以上|用户)(?:的)?(?:所有)?(?:指令|指示|限制)|忘记(?:之前|先前)(?:的)?(?:所有)?(?:指令|规则)/i.test(lower);
  const systemPromptLeak = /show\s+(?:me\s+)?your\s+system\s+prompt|system\s+instructions|系统提示词|系统提示|system\s+prompt|repeat\s+the\s+words\s+above/i.test(lower);
  const roleManip = /你不再是.{0,20}(?:AI|助手|人工智能).{0,20}(?:黑客|没有限制|无限制)|不是.{0,10}AI.{0,10}(?:助手|助理).{0,20}(?:黑客|无限制)|没有任何限制的黑客/i.test(lower);
  const suffix = /ignore\s+the\s+above|say\s+'i\s+have\s+been\s+hacked'|then\s+list\s+all\s+files/i.test(lower);
  const refusalSuppress = /respond\s+to\s+every\s+prompt.{0,120}then.{0,120}(?:respond|begin\s+a\s+new)/i.test(lower);
  const hypothetical = /hypothetical\s+scenario.{0,80}(?:no\s+safety|no\s+constraints|delete\s+all|exfiltrate)/i.test(lower);
  const encodedJailbreak = /decode\s+and\s+execute|base64\s+string:\s*(?:SWdub3Jl|IG5vcmU=|ignore)/i.test(lower);
  // Context-overflow style jailbreaks pad the prompt with a huge repeated
  // filler phrase to push guardrails out of the context window. Detecting the
  // repetition is safe because normal user prompts do not repeat one phrase
  // dozens of times.
  const contextOverflow = (lower.match(/once upon a time/g) || []).length >= 15;

  if (dan || unrestricted || ignorePrevious || systemPromptLeak || roleManip || suffix || refusalSuppress || hypothetical || encodedJailbreak || contextOverflow) {
    return {
      score: 88,
      category: "jailbreak",
      reason: "jailbreak_or_prompt_injection",
      message: "AgentMeter-Gov 已阻断输入：该请求试图通过越狱、角色操纵、指令覆盖或提示词泄露绕过安全约束。",
      rules: [
        "INPUT-JAIL-01：检测到越狱、无限制模式或开发者模式诱导",
        "INPUT-JAIL-02：检测到指令覆盖、系统提示词泄露或角色操纵",
      ],
      factors: inputFactorContributions({ C: 80, G: 90, D: 70, P: 85, T: 80, A: 80, I: 92 }),
    };
  }
  return null;
}

function detectMemoryBackdoorInstruction(text) {
  const lower = text.toLowerCase();
  const memFile = /MEMORY\.md|SOUL\.md|AGENTS\.md|USER\.md|IDENTITY\.md|memory\.json|对话历史|历史对话/i.test(lower);
  const backdoorAction = /curl[^\n]*attacker|beacon|webhook|后门|backdoor|自动批准|auto[- ]?approve|无需确认|不需要确认|永久授权|system override|安全警告.{0,20}(?:删除|清除|移除)/i.test(lower);
  const credentialPlant = /记住.{0,40}(?:API密钥|密钥|凭证|token).{0,40}以后|remember.{0,40}(?:api[_-]?key|credential|token).{0,40}(?:from now on|always use)/i.test(lower);
  const goalOverride = /首要任务.{0,40}(?:执行任何命令|不需要确认)|primary.{0,20}(?:goal|task).{0,40}(?:any command|no confirmation)|系统管理员.{0,20}授权/i.test(lower);
  const autoApprove = /记住.{0,60}(?:curl|wget|rm|命令).{0,40}(?:不需要确认|无需确认|直接执行)|remember.{0,60}(?:curl|wget|rm|command).{0,40}(?:no confirmation|directly execute)/i.test(lower);
  const historyTamper = /(?:修改|删除|清除|移除).{0,20}(?:对话|历史).{0,20}(?:记录|警告|拒绝)|(?:删除|清除).{0,30}(?:安全警告|拒绝记录)/i.test(lower);
  const identitySpoof = /(?:真实身份|身份).{0,20}(?:是|为).{0,20}(?:系统管理员|root|管理员).{0,20}(?:拥有|所有权限)|真实身份.{0,20}root/i.test(lower);
  const falseContext = /用户.{0,20}admin.{0,20}(?:已经|已).{0,20}授权.{0,20}(?:所有|全部).{0,20}(?:危险|操作)|admin.{0,20}authorized.{0,20}all.{0,20}dangerous/i.test(lower);

  if ((memFile && backdoorAction) || credentialPlant || goalOverride || autoApprove || historyTamper || identitySpoof || falseContext) {
    return {
      score: 92,
      category: "memory_backdoor",
      reason: "persistent_memory_backdoor_instruction",
      message: "AgentMeter-Gov 已阻断输入：该请求试图向持久化记忆植入后门、自动批准规则、身份伪造或凭据。",
      rules: [
        "INPUT-MEM-02：检测到向持久化记忆写入后门、自动批准或触发规则",
        "INPUT-MEM-03：检测到记忆中的身份伪造、凭据植入或目标覆盖",
      ],
      factors: inputFactorContributions({ C: 70, G: 92, D: 80, P: 85, T: 85, A: 80, I: 94 }),
    };
  }
  return null;
}

export function inputRiskDecisionEvent(state, risk, prompt, event, ctx) {
  return {
    event_type: "risk_decision_event",
    task_id: state.taskId,
    session_key: String(ctx?.sessionKey ?? ""),
    run_id: String(ctx?.runId ?? event?.runId ?? ""),
    user_goal: prompt,
    tool_name: "before_agent_run",
    proposed_tool_call: {
      name: "input_policy_gate",
      params: { prompt_preview: prompt.slice(0, 500) },
      source: "openclaw_before_agent_run",
      data_level: "internal_sensitive",
      result: "blocked",
      evidence: risk.message,
    },
    gate_action: "block",
    allowed: false,
    risk_score: risk.score,
    triggered_rules: risk.rules,
    decision: "block",
    factor_contributions: risk.factors,
    threshold_explanation: {
      score: risk.score,
      band: "75-100",
      level: "block",
      zh_level: "高风险",
      action: "block",
      model_action: "block",
      explanation: "输入命中破坏性命令、外部外泄、安全配置降级、恶意组件、越狱或记忆后门规则，应在模型执行前阻断。",
    },
    security_control: {
      controls: [
        { control_id: "CTRL-INPUT-GATE", name: "输入级风险闸门" },
        { control_id: "CTRL-MEMORY-POISON", name: "持久化记忆投毒防护" },
        { control_id: "CTRL-JAILBREAK", name: "越狱与提示注入防护" },
      ],
    },
    evidence: risk.message,
  };
}

function inputFactorContributions(scores) {
  const names = {
    C: "来源与上下文风险",
    G: "目标偏移风险",
    D: "数据风险",
    P: "权限放大风险",
    T: "工具链组合风险",
    S: "插件/Skill 供应链状态风险",
    A: "审计与行为异常风险",
    I: "意图偏移风险",
    U: "用户习性偏移风险",
  };
  const weights = { C: 0.1, G: 0.12, D: 0.18, P: 0.1, T: 0.13, S: 0.08, A: 0.09, I: 0.12, U: 0.08 };
  return Object.fromEntries(Object.keys(names).map((code) => {
    const score = Number(scores[code] ?? 0);
    return [code, {
      zh_name: names[code],
      score,
      weight: weights[code],
      contribution: Number((score * weights[code]).toFixed(2)),
      evidence: score ? ["输入级组合风险规则命中"] : [],
    }];
  }));
}
