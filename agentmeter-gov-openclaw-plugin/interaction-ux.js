import { guardText } from "./content-guard.js";

function shellCommandFromParams(params) {
  return String(params?.command ?? params?.cmd ?? "").trim();
}

function isPublicHttpHostname(hostname) {
  const host = String(hostname ?? "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    return false;
  }
  if (host.includes(":")) {
    return !/^(?:::|::1|fc|fd|fe8|fe9|fea|feb)/i.test(host);
  }
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return true;
  const octets = host.split(".").map(Number);
  if (octets.some((item) => item < 0 || item > 255)) return false;
  return !(octets[0] === 0
    || octets[0] === 10
    || octets[0] === 127
    || (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127)
    || (octets[0] === 169 && octets[1] === 254)
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168)
    || octets[0] >= 224);
}

export function readOnlyPublicHttpRequest(params) {
  const command = shellCommandFromParams(params);
  if (!command || /[\r\n;&|><`]|\$\(|\$\{|%[^%\s]+%/.test(command)) return null;
  const match = command.match(/^curl(?:\.exe)?\s+([\s\S]+)$/i);
  if (!match) return null;
  const tokens = [];
  const tokenPattern = /"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s"']+)/g;
  let tokenMatch;
  let cursor = 0;
  while ((tokenMatch = tokenPattern.exec(match[1])) !== null) {
    if (match[1].slice(cursor, tokenMatch.index).trim()) return null;
    tokens.push(tokenMatch[1] ?? tokenMatch[2] ?? tokenMatch[3]);
    cursor = tokenPattern.lastIndex;
  }
  if (match[1].slice(cursor).trim()) return null;
  if (!tokens.length) return null;

  const urls = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (/^https:\/\//i.test(token)) {
      urls.push(token);
      continue;
    }
    if (["--fail", "--silent", "--show-error", "--compressed", "--head", "-f", "-s", "-S", "-I"].includes(token)) {
      continue;
    }
    if (["--max-time", "--connect-timeout"].includes(token) && /^\d{1,3}$/.test(tokens[index + 1] ?? "")) {
      index += 1;
      continue;
    }
    if (["--request", "-X"].includes(token) && /^(?:GET|HEAD)$/i.test(tokens[index + 1] ?? "")) {
      index += 1;
      continue;
    }
    if (token === "--url" && /^https:\/\//i.test(tokens[index + 1] ?? "")) {
      urls.push(tokens[index + 1]);
      index += 1;
      continue;
    }
    return null;
  }
  if (urls.length !== 1) return null;
  try {
    const url = new URL(urls[0]);
    if (url.protocol !== "https:" || url.username || url.password || !isPublicHttpHostname(url.hostname)) return null;
    if ([...url.searchParams.keys()].some((key) => /token|api[_-]?key|secret|password|credential|signature|x-amz/i.test(key))) {
      return null;
    }
    return { url: url.toString(), method: tokens.includes("--head") || tokens.includes("-I") ? "HEAD" : "GET" };
  } catch {
    return null;
  }
}

export function isReadOnlyOpenClawCommand(params) {
  let command = shellCommandFromParams(params);
  if (!command || /[\r\n;`]/.test(command) || /&&|\|\|/.test(command)) return false;
  command = command
    .replace(/\s+2\s*>\s*&\s*1\b/gi, "")
    .replace(/\s+\|\s+(?:out-string|format-(?:list|table)|select-object(?:\s+-\w+(?:\s+[^|]+)?)?)\s*$/i, "")
    .trim();
  const executable = String.raw`(?:openclaw(?:\.cmd|\.exe)?|(?:&\s*)?"[^"]*openclaw(?:\.cmd|\.exe)?")`;
  const flags = String.raw`(?:\s+--?(?:json|deep|all|verbose|no-color|plain|timeout)(?:[=\s]+\d+)?)`;
  return new RegExp(`^${executable}\\s+(?:status|gateway\\s+(?:status|health|probe)|plugins\\s+list|version)${flags}*$`, "i").test(command)
    || new RegExp(`^${executable}\\s+(?:--version|-v|--help|-h)$`, "i").test(command);
}

export function isReadOnlyProcessAction(params) {
  const action = String(params?.action ?? params?.operation ?? "").toLowerCase().trim();
  return ["poll", "log", "list", "status"].includes(action);
}

export function isBoundedOpenClawMaintenanceCommand(params) {
  const command = shellCommandFromParams(params);
  if (!command || /[\r\n`]|&&|\|\||>|<|\bcurl\b|\biwr\b|\bwget\b|invoke-webrequest|remove-item|clear-content|\brm\b|\bdel\b/i.test(command)) return false;
  const segments = command.split(";").map((item) => item.trim()).filter(Boolean);
  if (!segments.length) return false;
  return segments.every((segment) => {
    if (/^(?:write-host|echo)\s+[\w\s.,:：()（）'"\-]{1,120}$/i.test(segment)) return true;
    return /^openclaw(?:\.cmd|\.exe)?\s+(?:config\s+(?:get|set|unset)\b|gateway\s+(?:start|stop|restart|status|health|probe)\b|plugins\s+(?:list|info)\b|status\b|doctor\b)/i.test(segment);
  });
}

export function boundedTaskScopeKey(proposed) {
  return String(proposed?.name ?? "") === "run_shell" && isBoundedOpenClawMaintenanceCommand(proposed?.params)
    ? "openclaw_maintenance"
    : "";
}

export function parseApprovalCommand(prompt) {
  const rawText = String(prompt ?? "").trim();
  const metadataEnvelope = rawText.match(/^Conversation info \(untrusted metadata\):\s*```(?:json)?\s*[\s\S]*?```\s*/i);
  let text = metadataEnvelope ? rawText.slice(metadataEnvelope[0].length).trim() : rawText;
  const markdownWrapper = text.match(/^(\*\*|__)([\s\S]+)\1$/);
  if (markdownWrapper) text = markdownWrapper[2].trim();
  if (text.length > 120 || /[\r\n]/.test(text)) return null;
  // Match the complete control message. Quotes, questions, examples and mixed
  // instructions stay ordinary input, even when a pending approval exists.
  text = text.replace(/[。.!！]$/, "").trim();
  const id = String.raw`AGR-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*`;
  const slash = text.match(new RegExp(`^/approve(?:\\s+(${id}))?(?:\\s+(approve|allow|pass|reject|deny|refuse))?$`, "i"));
  if (slash) {
    return { reviewId: slash[1] ?? "", decision: /^(reject|deny|refuse)$/i.test(slash[2] ?? "") ? "reject" : "approve", scope: "exact_action" };
  }
  const commands = [
    ["reject", "exact_action", String.raw`(?:审批拒绝|拒绝放行|不同意|不批准|驳回|reject|denied|deny|refuse)`],
    ["approve", "bounded_task", String.raw`(?:(?:我)?(?:已知晓|知晓|接受)(?:后续)?风险[，,\s]*(?:一键放行|继续执行|(?:批准|允许)(?:继续|执行)?(?:本次|当前|本)任务)|(?:批准|允许|放行)(?:本次|当前)任务|approve\s+(?:this|current)\s+task)`],
    ["approve", "exact_action", String.raw`(?:审批通过|同意放行|批准(?:执行|继续|本次(?:操作)?|当前(?:操作)?)|允许(?:执行|继续|本次(?:操作)?|当前(?:操作)?)|一键放行|approve|approved|allow|pass)`],
  ];
  for (const [decision, scope, command] of commands) {
    const match = text.match(new RegExp(`^${command}(?:\\s+(${id}))?$`, "i"));
    if (match) return { reviewId: match[1] ?? "", decision, scope };
  }
  return null;
}

const NON_SECURITY_EXECUTION_PARAMS = new Set([
  "timeout",
  "timeoutMs",
  "timeout_ms",
  "yieldMs",
  "yield_ms",
  "pollIntervalMs",
  "poll_interval_ms",
]);

export function approvalSemanticParams(params) {
  if (!params || typeof params !== "object" || Array.isArray(params)) return params;
  return Object.fromEntries(Object.entries(params).filter(([key]) => (
    !NON_SECURITY_EXECUTION_PARAMS.has(key) && !key.startsWith("agentmeter_")
  )));
}

const APPROVAL_CONTENT_FIELDS = new Set([
  "after",
  "before",
  "body",
  "content",
  "data",
  "newText",
  "new_text",
  "oldText",
  "old_text",
  "text",
]);

export function approvalComparableParams(params) {
  return canonicalizeApprovalValue(approvalSemanticParams(params), "");
}

function canonicalizeApprovalValue(value, key) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeApprovalValue(item, key));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [
      childKey,
      canonicalizeApprovalValue(childValue, childKey),
    ]));
  }
  if (typeof value === "string" && APPROVAL_CONTENT_FIELDS.has(key)) {
    return guardText(value, { surface: "approval_signature" }).text
      .replace(/\r\n/g, "\n")
      .replace(/[ \t]+$/gm, "")
      .trimEnd();
  }
  return value;
}

function targetKey(proposed) {
  const params = proposed?.params ?? {};
  return String(params.path ?? params.file ?? params.target ?? params.to ?? "").trim();
}

function humanizeReviewReason(rules, fallback) {
  const joined = Array.isArray(rules) ? rules.join(" | ") : String(rules ?? "");
  const reasons = [];
  if (/INTENT|意图|drift/i.test(joined)) reasons.push("当前工具动作与用户原始目标存在偏差");
  if (/PROFILE|画像|cold|权限.*未知/i.test(joined)) reasons.push("当前用户或岗位的授权边界尚未建立");
  if (/BATCH|批量|burst/i.test(joined)) reasons.push("动作可能批量影响多个对象或记录");
  if (/SYSTEM|系统命令|SEM-I-01|P-01/i.test(joined)) reasons.push("动作将调用系统级工具，可能改变本机运行状态");
  if (/WRITE|写入|I-01/i.test(joined)) reasons.push("动作可能修改本地或内部数据");
  if (/SENSITIVE|SECRET|凭证|敏感/i.test(joined)) reasons.push("动作涉及敏感数据或凭证边界");
  if (reasons.length) return [...new Set(reasons)].slice(0, 2).join("；");
  const fallbackText = String(fallback ?? "").replace(/\s+/g, " ").trim();
  return fallbackText ? fallbackText.slice(0, 180) : "当前动作达到人工复核阈值，需要负责人确认后执行";
}

function describeReviewAction(proposed) {
  const params = proposed?.params ?? {};
  const command = shellCommandFromParams(params);
  if (command) return `${proposed.name}：${command.slice(0, 240)}`;
  const target = targetKey(proposed);
  return target ? `${proposed?.name ?? "unknown"}，目标 ${target}` : String(proposed?.name ?? "unknown");
}

function describeReviewImpact(proposed) {
  const name = String(proposed?.name ?? "");
  if (["read_document", "read_file", "web_search", "web_fetch"].includes(name)) return "只读，不修改文件或系统状态";
  if (["write_file", "apply_patch"].includes(name)) return `将修改 ${targetKey(proposed) || "本地文件"}`;
  if (name === "run_shell") return "将在本机执行命令；授权仅限当前会话内匹配的 OpenClaw 运维动作";
  if (["send_email", "upload_file"].includes(name)) return "会将数据发送到当前设备之外";
  return "可能产生可观察的系统或业务副作用";
}

export function formatHumanReviewMessage(proposed, result, pending) {
  const score = Number(result?.risk_measurement?.total_score ?? pending?.riskScore ?? 0);
  const rules = result?.risk_measurement?.matched_rules ?? pending?.matchedRules ?? [];
  const taskScopeAvailable = Boolean(boundedTaskScopeKey(proposed));
  const scopeHelp = taskScopeAvailable
    ? "\n如果这是连续的 OpenClaw 配置/运维任务，可回复“我已知晓后续风险，一键放行”，在当前会话内临时放行同类动作（10 分钟、最多 8 次）。"
    : "";
  return [
    "AgentMeter-Gov 需要人工复核",
    `原因：${humanizeReviewReason(rules, result?.message)}`,
    `拟执行操作：${describeReviewAction(proposed)}`,
    `影响范围：${describeReviewImpact(proposed)}`,
    `风险分：${score}/100`,
    `审批 ID：${pending.reviewId}`,
    `回复“审批通过 ${pending.reviewId}”仅放行上述动作一次。${scopeHelp}`,
    "临时放行不覆盖外发、敏感凭证、付款、授权、正式审批、公文篡改、删除审计或关闭防护；这些动作仍会单独复核或阻断。",
  ].join("\n");
}
