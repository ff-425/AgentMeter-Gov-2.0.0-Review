import { readFile, stat } from "node:fs/promises";
import { extname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { guardAgentMessage, guardText, inspectSensitiveContent, messageText } from "./content-guard.js";

const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const TEXT_FILE_EXTENSIONS = new Set([
  "",
  ".conf",
  ".csv",
  ".env",
  ".html",
  ".js",
  ".jsx",
  ".ini",
  ".json",
  ".key",
  ".log",
  ".md",
  ".pem",
  ".properties",
  ".ps1",
  ".py",
  ".rb",
  ".sh",
  ".sql",
  ".ts",
  ".tsx",
  ".text",
  ".toml",
  ".tsv",
  ".txt",
  ".xml",
  ".yaml",
  ".yml",
]);

export function guardPersistedToolResult(message) {
  return guardAgentMessage(message, { surface: "tool_result" });
}

export function guardAssistantMessage(message) {
  return guardAgentMessage(message, { surface: "message" });
}

export function finalAssistantText(event) {
  const messages = Array.isArray(event?.messages) ? event.messages : [];
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    const role = String(message?.role ?? "").toLowerCase();
    if (role === "assistant" || role === "model") return messageText(message);
  }
  return String(event?.lastAssistantMessage ?? "");
}

export async function guardReplyPayload(
  payload,
  { cwd = "", failClosed = true, maxFileBytes = DEFAULT_MAX_FILE_BYTES } = {},
) {
  const guardedMessage = guardAgentMessage(payload, { surface: "message" });
  const guardedPayload = guardedMessage.message;
  const mediaEntries = mediaUrls(guardedPayload);
  const blockedMedia = [];
  const fileFindings = [];

  for (const entry of mediaEntries) {
    const referenceFindings = inspectSensitiveContent(entry.url);
    if (referenceFindings.length) {
      blockedMedia.push({ ...entry, path: "", reason: "sensitive_media_reference" });
      fileFindings.push(...referenceFindings);
      continue;
    }
    const localPath = localMediaPath(entry.url, cwd);
    if (!localPath) continue;
    const inspection = await inspectLocalTextFile(localPath, { failClosed, maxFileBytes });
    if (inspection.action === "allow") continue;
    blockedMedia.push({ ...entry, path: localPath, reason: inspection.reason });
    fileFindings.push(...inspection.findings);
  }

  if (blockedMedia.length) {
    removeBlockedMedia(guardedPayload, blockedMedia);
    appendBlockedMediaNotice(guardedPayload, blockedMedia.length);
  }

  const findings = [...guardedMessage.findings, ...fileFindings];
  const action = blockedMedia.length || guardedMessage.action === "block"
    ? "block"
    : guardedMessage.action;
  return {
    action,
    message: guardedPayload,
    payload: guardedPayload,
    findings,
    blockedMedia,
    text: guardedMessage.text,
    surface: blockedMedia.length ? "file_content" : "message",
  };
}

async function inspectLocalTextFile(path, { failClosed, maxFileBytes }) {
  const extension = extname(path).toLowerCase();
  if (!TEXT_FILE_EXTENSIONS.has(extension)) {
    return failClosed
      ? unscannableFinding("unsupported_binary_media")
      : { action: "allow", findings: [], reason: "unsupported_binary_media" };
  }
  try {
    const info = await stat(path);
    if (!info.isFile()) {
      return failClosed
        ? unscannableFinding("local_media_not_file")
        : { action: "allow", findings: [], reason: "local_media_not_file" };
    }
    if (info.size > maxFileBytes) {
      return failClosed
        ? unscannableFinding("local_media_too_large")
        : { action: "allow", findings: [], reason: "local_media_too_large" };
    }
    const content = await readFile(path, "utf8");
    if (looksBinary(content)) {
      return failClosed
        ? unscannableFinding("binary_content_in_text_file")
        : { action: "allow", findings: [], reason: "binary_content_in_text_file" };
    }
    const guarded = guardText(content, { surface: "file_content" });
    if (guarded.action === "allow") {
      return { action: "allow", findings: [], reason: "clean_text_file" };
    }
    return {
      action: "block",
      findings: guarded.findings,
      reason: "sensitive_file_content",
    };
  } catch (error) {
    return failClosed
      ? unscannableFinding(`local_media_scan_failed:${String(error?.code ?? "unknown")}`)
      : { action: "allow", findings: [], reason: "local_media_scan_failed" };
  }
}

function looksBinary(content) {
  if (!content) return false;
  const sample = content.slice(0, 8192);
  if (sample.includes("\0")) return true;
  const replacements = [...sample].filter((char) => char === "\uFFFD").length;
  return replacements > Math.max(2, sample.length * 0.01);
}

function unscannableFinding(reason) {
  return {
    action: "block",
    reason,
    findings: [{ id: "unscannable_file", severity: "high", index: 0, length: 0 }],
  };
}

function mediaUrls(payload) {
  if (!payload || typeof payload !== "object") return [];
  const entries = [];
  if (typeof payload.mediaUrl === "string" && payload.mediaUrl) {
    entries.push({ field: "mediaUrl", index: 0, url: payload.mediaUrl });
  }
  if (Array.isArray(payload.mediaUrls)) {
    payload.mediaUrls.forEach((url, index) => {
      if (typeof url === "string" && url) entries.push({ field: "mediaUrls", index, url });
    });
  }
  return entries;
}

function localMediaPath(value, cwd) {
  const raw = String(value ?? "").trim();
  if (!raw) return "";
  if (/^file:\/\//i.test(raw)) {
    try {
      return fileURLToPath(raw);
    } catch {
      return "";
    }
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^[a-z]:[\\/]/i.test(raw)) return "";
  if (isAbsolute(raw)) return resolve(raw);
  return cwd ? resolve(cwd, raw) : "";
}

function removeBlockedMedia(payload, blockedMedia) {
  if (!payload || typeof payload !== "object") return;
  if (blockedMedia.some((item) => item.field === "mediaUrl")) delete payload.mediaUrl;
  const blockedIndexes = new Set(
    blockedMedia.filter((item) => item.field === "mediaUrls").map((item) => item.index),
  );
  if (Array.isArray(payload.mediaUrls) && blockedIndexes.size) {
    payload.mediaUrls = payload.mediaUrls.filter((_, index) => !blockedIndexes.has(index));
    if (!payload.mediaUrls.length) delete payload.mediaUrls;
  }
  payload.sensitiveMedia = true;
}

function appendBlockedMediaNotice(payload, count) {
  if (!payload || typeof payload !== "object") return;
  const notice = `AgentMeter-Gov blocked ${count} file attachment${count === 1 ? "" : "s"} because sensitive content could leave the protected runtime.`;
  payload.text = payload.text ? `${payload.text}\n\n${notice}` : notice;
}
