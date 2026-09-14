import { guardText } from "./content-guard.js";
import {
  guardAssistantMessage,
  guardReplyPayload,
} from "./output-governance.js";

export function registerOutputGovernanceHooks(
  api,
  { recordOutputGuard, scheduleBackground },
) {
  api.on(
    "before_message_write",
    (event, ctx) => {
      if (!isAssistantMessage(event?.message)) return undefined;
      const guarded = guardAssistantMessage(event.message);
      if (guarded.action === "allow") return undefined;
      scheduleBackground(api, "assistant transcript output audit", () => (
        recordOutputGuard(guarded, "before_message_write", event, ctx)
      ));
      return { message: guarded.message };
    },
    { priority: 1000, timeoutMs: 5000 },
  );

  api.on(
    "before_agent_finalize",
    async (event, ctx) => {
      const guarded = guardText(event?.lastAssistantMessage ?? "", { surface: "output" });
      if (guarded.action === "allow") return undefined;
      await recordOutputGuard(guarded, "before_agent_finalize", event, ctx);
      return {
        action: "revise",
        reason: "AgentMeter-Gov detected sensitive content in the final draft.",
        retry: {
          instruction: "Rewrite the final answer without repeating any credential, token, private key, identity number, or phone number. Replace sensitive values with [REDACTED].",
          idempotencyKey: `agentmeter-output-${String(ctx?.runId ?? event?.runId ?? event?.turnId ?? "final")}`,
          maxAttempts: 1,
        },
      };
    },
    { priority: 1000, timeoutMs: 5000 },
  );

  api.on(
    "reply_payload_sending",
    async (event, ctx) => {
      const guarded = await guardReplyPayload(event?.payload, {
        cwd: String(ctx?.cwd ?? ""),
        failClosed: api.pluginConfig?.failClosed !== false,
        maxFileBytes: Number(api.pluginConfig?.outputMaxFileBytes ?? 1024 * 1024),
      });
      if (guarded.action === "allow") return undefined;
      await recordOutputGuard(guarded, guarded.surface ?? "reply_payload_sending", event, ctx);
      return { payload: guarded.payload };
    },
    { priority: 1000, timeoutMs: 5000 },
  );

  api.on(
    "message_sending",
    async (event, ctx) => {
      const guarded = guardText(event?.content ?? "", { surface: "message" });
      if (guarded.action === "allow") return undefined;
      await recordOutputGuard(guarded, "message_sending", event, ctx);
      return {
        content: guarded.text,
        metadata: {
          ...(event?.metadata ?? {}),
          agentmeter_output_action: guarded.action,
        },
      };
    },
    { priority: 1000, timeoutMs: 5000 },
  );
}

function isAssistantMessage(message) {
  const role = String(message?.role ?? "").toLowerCase();
  return !role || role === "assistant" || role === "model";
}
