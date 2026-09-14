import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { guardAgentMessage } from "./content-guard.js";
import {
  finalAssistantText,
  guardAssistantMessage,
  guardPersistedToolResult,
  guardReplyPayload,
} from "./output-governance.js";

const safeFinal = finalAssistantText({
  messages: [
    { role: "user", content: "API_KEY=abcdefghijklmnop1234" },
    { role: "assistant", content: "The test value was not disclosed." },
  ],
});
assert.equal(safeFinal, "The test value was not disclosed.");

const sensitiveFinal = finalAssistantText({
  messages: [
    { role: "assistant", content: [{ type: "text", text: "DB_PASS=FinalSecret123" }] },
  ],
});
assert.equal(guardPersistedToolResult(sensitiveFinal).action, "redact");

const stringResult = guardPersistedToolResult("API_KEY=abcdefghijklmnop1234");
assert.equal(stringResult.action, "redact");
assert.equal(typeof stringResult?.then, "undefined");
assert.match(stringResult.message, /REDACTED:CREDENTIAL/);

const assistantResult = guardAssistantMessage({ role: "assistant", content: "DB_PASS=FinalSecret123" });
assert.equal(assistantResult.action, "redact");
assert.equal(typeof assistantResult?.then, "undefined");

assert.equal(guardPersistedToolResult("DB_PASS=[REDACTED]").action, "allow");
assert.equal(guardPersistedToolResult("API_KEY=[REDACTED:CREDENTIAL]").action, "allow");

const richPayload = guardAgentMessage({
  text: "Visible response is safe.",
  spokenText: "Call 13800138000 for the private result.",
  btw: { question: "Confirm identity 11010519491231002X" },
}, { surface: "message" });
assert.equal(richPayload.action, "redact");
assert.match(richPayload.message.spokenText, /REDACTED:PHONE_NUMBER/);
assert.match(richPayload.message.btw.question, /REDACTED:IDENTITY_NUMBER/);

const temp = await mkdtemp(join(tmpdir(), "agentmeter-output-"));
try {
  const cleanPath = join(temp, "public.txt");
  const sensitivePath = join(temp, "credentials.env");
  const largePath = join(temp, "large.log");
  const binaryPath = join(temp, "confidential.pdf");
  await writeFile(cleanPath, "Public project status only.\n", "utf8");
  await writeFile(sensitivePath, "DB_PASS=AttachmentSecret123\n", "utf8");
  await writeFile(largePath, "x".repeat(128), "utf8");
  await writeFile(binaryPath, Buffer.from("%PDF-1.7\0private-binary"));

  const attachmentResult = await guardReplyPayload({
    text: "Attached reports.",
    mediaUrls: [pathToFileURL(cleanPath).href, pathToFileURL(sensitivePath).href],
  });
  assert.equal(attachmentResult.action, "block");
  assert.equal(attachmentResult.blockedMedia.length, 1);
  assert.deepEqual(attachmentResult.payload.mediaUrls, [pathToFileURL(cleanPath).href]);
  assert.match(attachmentResult.payload.text, /blocked 1 file attachment/);

  const oversizedResult = await guardReplyPayload(
    { mediaUrl: largePath },
    { maxFileBytes: 32, failClosed: true },
  );
  assert.equal(oversizedResult.action, "block");
  assert.equal(oversizedResult.payload.mediaUrl, undefined);
  assert.ok(oversizedResult.findings.some((item) => item.id === "unscannable_file"));

  const binaryResult = await guardReplyPayload(
    { mediaUrl: binaryPath },
    { failClosed: true },
  );
  assert.equal(binaryResult.action, "block");
  assert.equal(binaryResult.payload.mediaUrl, undefined);
  assert.ok(binaryResult.findings.some((item) => item.id === "unscannable_file"));

  const permissiveBinaryResult = await guardReplyPayload(
    { mediaUrl: binaryPath },
    { failClosed: false },
  );
  assert.equal(permissiveBinaryResult.action, "allow");
  assert.equal(permissiveBinaryResult.payload.mediaUrl, binaryPath);

  const signedUrlResult = await guardReplyPayload({
    mediaUrl: "https://example.com/report?access_token=abcdefghijklmnop",
  });
  assert.equal(signedUrlResult.action, "block");
  assert.equal(signedUrlResult.payload.mediaUrl, undefined);

  const presentationResult = await guardReplyPayload({
    text: "Public status.",
    presentation: {
      blocks: [{ type: "text", text: "API_KEY=abcdefghijklmnop1234" }],
    },
    ttsSupplement: { spokenText: "Call 13800138000" },
  });
  assert.equal(presentationResult.action, "redact");
  assert.match(presentationResult.payload.presentation.blocks[0].text, /REDACTED:CREDENTIAL/);
  assert.match(presentationResult.payload.ttsSupplement.spokenText, /REDACTED:PHONE_NUMBER/);

  const remoteResult = await guardReplyPayload({ mediaUrl: "https://example.com/public.pdf" });
  assert.equal(remoteResult.action, "allow");
  assert.equal(remoteResult.payload.mediaUrl, "https://example.com/public.pdf");
} finally {
  await rm(temp, { recursive: true, force: true });
}

console.log(JSON.stringify({ total: 29, passed: 29 }));
