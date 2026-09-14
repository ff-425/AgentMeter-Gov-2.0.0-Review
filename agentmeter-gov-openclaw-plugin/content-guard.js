const SECRET_PATTERNS = [
  {
    id: "private_key",
    severity: "critical",
    regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----/gi,
  },
  {
    id: "credential_assignment",
    severity: "high",
    regex: /\b(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|API_KEY|ACCESS_TOKEN|AUTH_TOKEN|SECRET(?:_KEY)?|PASSWORD|AWS_SECRET_ACCESS_KEY)\b\s*[:=]\s*["']?([^\s"',;]{4,})["']?/gi,
  },
  { id: "bearer_token", severity: "high", regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi },
  { id: "jwt", severity: "high", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: "api_token", severity: "high", regex: /\b(?:sk|ghp|github_pat|xox[baprs])[-_A-Za-z0-9]{16,}\b/g },
  {
    id: "sensitive_url_parameter",
    severity: "high",
    regex: /(?:[?&](?:access_token|api_key|auth_token|password|secret|signature|x-amz-credential|x-amz-signature)=)[^&#\s]{8,}/gi,
  },
  { id: "cn_identity", severity: "medium", regex: /(?<!\d)\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?!\d)/g },
  { id: "cn_phone", severity: "medium", regex: /(?<!\d)1[3-9]\d{9}(?!\d)/g },
];

const REDACTION_LABELS = {
  private_key: "PRIVATE_KEY",
  credential_assignment: "CREDENTIAL",
  bearer_token: "BEARER_TOKEN",
  jwt: "JWT",
  api_token: "API_TOKEN",
  cn_identity: "IDENTITY_NUMBER",
  cn_phone: "PHONE_NUMBER",
  encoded_secret: "ENCODED_SECRET",
  sensitive_url_parameter: "SENSITIVE_URL_PARAMETER",
};

const TEXT_VALUE_KEYS = new Set([
  "body",
  "caption",
  "content",
  "description",
  "fallbackText",
  "label",
  "message",
  "question",
  "spokenText",
  "summary",
  "text",
  "title",
]);

export function inspectSensitiveContent(value) {
  const text = String(value ?? "");
  const findings = [];
  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    for (const match of text.matchAll(pattern.regex)) {
      if (isSanitizedPlaceholder(match[0])) continue;
      findings.push({ id: pattern.id, severity: pattern.severity, index: match.index ?? 0, length: match[0].length });
    }
  }
  for (const candidate of base64Candidates(text)) {
    if (containsDecodedSecret(candidate.decoded)) {
      findings.push({ id: "encoded_secret", severity: "high", index: candidate.index, length: candidate.raw.length });
    }
  }
  return findings.sort((a, b) => a.index - b.index || b.length - a.length);
}

export function guardText(value, { surface = "output" } = {}) {
  const text = String(value ?? "");
  const findings = inspectSensitiveContent(text);
  if (!findings.length) return { action: "allow", text, findings: [], surface };
  const critical = findings.some((item) => item.severity === "critical");
  const highCount = findings.filter((item) => item.severity === "high" || item.severity === "critical").length;
  const action = critical || highCount >= 3 ? "block" : "redact";
  return {
    action,
    text: action === "block"
      ? `AgentMeter-Gov blocked sensitive content on ${surfaceLabel(surface)}. Findings: ${uniqueFindingIds(findings).join(", ")}.`
      : redactRanges(text, findings),
    findings,
    surface,
  };
}

export function guardAgentMessage(message, options = {}) {
  if (typeof message === "string") {
    const result = guardText(message, options);
    return { action: result.action, message: result.text, findings: result.findings, text: result.text };
  }
  const cloned = structuredCloneSafe(message);
  const results = [];
  transformMessageText(cloned, (text) => {
    const result = guardText(text, options);
    results.push(result);
    return result.text;
  });
  const findings = results.flatMap((result) => result.findings);
  const action = results.some((result) => result.action === "block")
    ? "block"
    : results.some((result) => result.action === "redact") ? "redact" : "allow";
  return { action, message: cloned, findings, text: messageText(cloned) };
}

export function messageText(message) {
  if (!message || typeof message !== "object") return typeof message === "string" ? message : "";
  const values = [];
  collectMessageText(message, values);
  return values.join("\n");
}

function redactRanges(text, findings) {
  const ranges = findings
    .map((item) => ({ start: item.index, end: item.index + item.length, id: item.id }))
    .sort((a, b) => b.start - a.start || b.end - a.end);
  let output = text;
  let coveredStart = text.length + 1;
  for (const range of ranges) {
    if (range.end > coveredStart) continue;
    const label = REDACTION_LABELS[range.id] || "SENSITIVE_DATA";
    output = `${output.slice(0, range.start)}[REDACTED:${label}]${output.slice(range.end)}`;
    coveredStart = range.start;
  }
  return output;
}

function base64Candidates(text) {
  const candidates = [];
  const regex = /(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{24,}={0,2})(?=$|[^A-Za-z0-9+/=])/g;
  for (const match of text.matchAll(regex)) {
    const raw = match[1];
    if (raw.length % 4 !== 0 || raw.length > 4096) continue;
    try {
      const decoded = Buffer.from(raw, "base64").toString("utf8");
      if (decoded && printableRatio(decoded) > 0.82) {
        candidates.push({ raw, decoded, index: (match.index ?? 0) + match[0].indexOf(raw) });
      }
    } catch {
      // Ignore invalid candidates.
    }
  }
  return candidates;
}

function containsDecodedSecret(text) {
  return /(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|API_KEY|ACCESS_TOKEN|SECRET(?:_KEY)?|PASSWORD)\s*[:=]|-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----/i.test(text);
}

function printableRatio(text) {
  if (!text.length) return 0;
  const chars = [...text];
  return chars.filter((char) => /[\x09\x0A\x0D\x20-\x7E\u4E00-\u9FFF]/.test(char)).length / chars.length;
}

function transformMessageText(value, transform, seen = new WeakSet()) {
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item) => transformMessageText(item, transform, seen));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (typeof child === "string" && TEXT_VALUE_KEYS.has(key)) {
      value[key] = transform(child);
      continue;
    }
    if (child && typeof child === "object") transformMessageText(child, transform, seen);
  }
}

function isSanitizedPlaceholder(value) {
  return /(?:=|:)\s*\[REDACTED(?::[A-Z0-9_]+)?\]/i.test(String(value ?? ""));
}

function collectMessageText(value, output, seen = new WeakSet()) {
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item) => collectMessageText(item, output, seen));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (typeof child === "string" && TEXT_VALUE_KEYS.has(key)) {
      output.push(child);
      continue;
    }
    if (child && typeof child === "object") collectMessageText(child, output, seen);
  }
}

function structuredCloneSafe(value) {
  if (value == null || typeof value !== "object") return value;
  if (typeof structuredClone === "function") {
    try {
      return structuredClone(value);
    } catch {
      // SDK message objects can contain non-cloneable metadata.
    }
  }
  return JSON.parse(JSON.stringify(value));
}

function uniqueFindingIds(findings) {
  return [...new Set(findings.map((item) => item.id))];
}

function surfaceLabel(surface) {
  if (surface === "tool_result") return "tool result";
  if (surface === "message") return "outgoing message";
  if (surface === "file_content") return "file content return";
  return "model output";
}
