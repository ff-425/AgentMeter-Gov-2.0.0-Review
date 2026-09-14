import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, normalize, resolve } from "node:path";

import { assessInputRisk } from "./input-risk.js";

const PERSISTENT_RULE = /\u89c4\u5219|\u4ee5\u540e|\u6bcf\u5f53|\u81ea\u52a8|\u89e6\u53d1|\u6c38\u4e45|always|whenever|from now on/i;
const SIDE_EFFECT = /\u53d1\u9001|\u5916\u53d1|\u4e0a\u4f20|\u90ae\u4ef6|\u6267\u884c|\u5220\u9664|\u4fee\u6539\u5ba1\u6279|post\b|https?:\/\/|powershell|cmd|shell|send|upload|execute/i;
const PLAIN_PREFERENCE = /\u504f\u597d|\u4e3b\u9898|\u8bed\u8a00|\u65f6\u533a|preference|theme|language|timezone/i;

export function assessMemoryOperation(proposed, userGoal = "") {
  const name = String(proposed?.name ?? "");
  const params = proposed?.params && typeof proposed.params === "object" ? proposed.params : {};
  const path = memoryTargetPath(params);
  if (!path || !isMemoryPath(path)) return null;
  const operation = memoryOperation(name, params);
  const content = memoryContent(params);
  const combined = `${userGoal}\n${content}`.trim();
  const inputRisk = assessInputRisk(combined);
  if (operation === "read") {
    return {
      operation,
      path,
      action: "check_lineage",
      score: 10,
      classification: "memory_read",
      rules: ["MEM-READ-01: check cross-session taint before loading persistent memory"],
    };
  }
  if (inputRisk) {
    return {
      operation,
      path,
      action: "block",
      score: Math.max(92, Number(inputRisk.score || 0)),
      classification: "malicious_persistent_instruction",
      rules: ["MEM-WRITE-01: malicious persistent instruction", ...inputRisk.rules],
      evidence: inputRisk.message,
      contentHash: sha256(content),
    };
  }
  if (PERSISTENT_RULE.test(combined) && SIDE_EFFECT.test(combined)) {
    return {
      operation,
      path,
      action: "human_review",
      score: 58,
      classification: "persistent_side_effect_rule",
      rules: ["MEM-WRITE-02: persistent side effect requires human approval"],
      evidence: "Memory write contains a persistent rule with future side effects.",
      contentHash: sha256(content),
    };
  }
  return {
    operation,
    path,
    action: "allow",
    auditRequired: true,
    score: 12,
    classification: "benign_memory_write",
    localAllow: PLAIN_PREFERENCE.test(combined),
    rules: ["MEM-WRITE-ALLOW: benign preference or work memory"],
    evidence: "Memory write contains no persistent high-impact side effect.",
    contentHash: sha256(content),
  };
}

export async function readMemoryGovernanceState(path) {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    return {
      version: "memory-governance-v1",
      entries: Array.isArray(parsed.entries) ? parsed.entries : [],
    };
  } catch {
    return { version: "memory-governance-v1", entries: [] };
  }
}

export async function recordMemoryLineage(path, entry) {
  const state = await readMemoryGovernanceState(path);
  const normalizedPath = normalizeMemoryPath(entry.path);
  const next = {
    lineage_id: entry.lineage_id || `MEM-${Date.now().toString(36).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    active: entry.active !== false,
    tainted: Boolean(entry.tainted),
    ...entry,
    path: normalizedPath,
  };
  state.entries = [next, ...state.entries.filter((item) => {
    if (!item || item.lineage_id === next.lineage_id) return false;
    return !(normalizeMemoryPath(item.path) === normalizedPath && item.content_hash === next.content_hash);
  })].slice(0, 500);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(state, null, 2), "utf8");
  return next;
}

export async function findActiveTaint(statePath, targetPath) {
  const state = await readMemoryGovernanceState(statePath);
  const normalized = normalizeMemoryPath(targetPath);
  return state.entries.find((entry) => entry.active !== false && entry.tainted && normalizeMemoryPath(entry.path) === normalized) || null;
}

export function sanitizePoisonedMemoryText(value) {
  const blocks = String(value ?? "").split(/(?:\r?\n){2,}/);
  const removed = [];
  const kept = [];
  for (const block of blocks) {
    const risk = assessInputRisk(block);
    if (risk || (PERSISTENT_RULE.test(block) && SIDE_EFFECT.test(block))) removed.push(block);
    else if (block.trim()) kept.push(block.trimEnd());
  }
  return {
    changed: removed.length > 0,
    text: kept.length ? `${kept.join("\n\n")}\n` : "",
    removed,
  };
}

export function sanitizeMemoryMessage(message) {
  const cloned = cloneValue(message);
  const removed = [];
  transformText(cloned, (text) => {
    const result = sanitizePoisonedMemoryText(text);
    removed.push(...result.removed);
    return result.changed ? result.text : text;
  });
  return { changed: removed.length > 0, message: cloned, removed };
}

export async function cleanPoisonedMemoryFile(targetPath, quarantineDir) {
  if (!isMemoryPath(targetPath) || !isAbsolute(targetPath)) {
    return { changed: false, reason: "not_an_absolute_memory_path" };
  }
  const original = await readFile(targetPath, "utf8");
  const sanitized = sanitizePoisonedMemoryText(original);
  if (!sanitized.changed) return { ...sanitized, reason: "clean" };
  await mkdir(quarantineDir, { recursive: true });
  const digest = sha256(original).slice(0, 12);
  const backupPath = join(quarantineDir, `${basename(targetPath)}.${Date.now()}.${digest}.quarantine`);
  await writeFile(backupPath, original, "utf8");
  await writeFile(targetPath, sanitized.text, "utf8");
  return { ...sanitized, backupPath, reason: "poison_removed" };
}

export function isMemoryPath(value) {
  const normalized = normalizeMemoryPath(value);
  return /(?:^|\/)memory\.md$/i.test(normalized) || /(?:^|\/)memory\/[^/]+\.md$/i.test(normalized);
}

export function memoryTargetPath(params) {
  for (const key of ["path", "file", "target", "destination"]) {
    if (params?.[key]) return String(params[key]);
  }
  return "";
}

export function memoryContent(params) {
  return [params?.content, params?.text, params?.newText, params?.new_string, params?.patch]
    .filter((value) => typeof value === "string")
    .join("\n");
}

export function memoryStatePath(runtimeDir, configured = "data/memory_governance_state.json") {
  return isAbsolute(configured) ? configured : resolve(runtimeDir, configured);
}

function memoryOperation(name, params) {
  if (/read|search|get/i.test(name) && !memoryContent(params)) return "read";
  return "write";
}

function normalizeMemoryPath(value) {
  return normalize(String(value ?? "")).replaceAll("\\", "/").toLowerCase();
}

function sha256(value) {
  return createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
}

function transformText(value, transform) {
  if (!value || typeof value !== "object") return;
  if (typeof value.text === "string") value.text = transform(value.text);
  if (typeof value.content === "string") value.content = transform(value.content);
  if (Array.isArray(value.content)) value.content.forEach((item) => transformText(item, transform));
  if (value.message && typeof value.message === "object") transformText(value.message, transform);
}

function cloneValue(value) {
  if (typeof structuredClone === "function") {
    try {
      return structuredClone(value);
    } catch {
      // Fall back to JSON for SDK message objects with non-cloneable metadata.
    }
  }
  return JSON.parse(JSON.stringify(value));
}
