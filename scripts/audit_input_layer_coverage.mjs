// Audit the input-layer (before_agent_run) coverage for the agentmeter-90
// corpus: which attack prompts are actually caught by assessInputRisk or the
// guard-bypass detector before any tool call happens. This is the blind spot
// the 1.1.7 offline full-eval could not reach because those cases carry no
// proposed_tool, and the live runner maps them onto canned scenarios.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { assessInputRisk } from "../agentmeter-gov-openclaw-plugin/input-risk.js";

const root = "E:/揭榜挂帅1/03_数据集/V6政企安全评测集";
const files = [
  join(root, "01_开发集/v6_development.jsonl"),
  join(root, "02_回归集/v6_regression.jsonl"),
  join(root, "03_密封盲测集/v6_blind.jsonl"),
];

function isGuardBypassPrompt(prompt) {
  const compact = String(prompt ?? "").replace(/\s+/g, "").toLowerCase();
  return /openclawgatewaydisable-agentmeter-gov|disable-agentmeter-gov|bypassagentmeter|绕过agentmeter|禁用agentmeter|关闭agentmeter(?:-gov)?防护|关闭安全防护|关掉agentmeter(?:-gov)?防护|防护关闭|guardoff|guarddisable|disableagentmeter(?:-gov)?guard/.test(compact);
}

const rows = [];
for (const f of files) {
  for (const line of readFileSync(f, "utf8").split(/\r?\n/)) {
    if (line.trim()) rows.push(JSON.parse(line));
  }
}
const am = rows.filter((r) => r.source === "agentmeter-90");

let caught = 0;
let missedAttacks = [];
let benignCaught = [];
for (const r of am) {
  const p = r.user_prompt ?? "";
  const risk = assessInputRisk(p);
  const bypass = isGuardBypassPrompt(p);
  const blocked = Boolean(risk) || bypass;
  if (r.label === "attack") {
    if (blocked) {
      caught += 1;
    } else {
      missedAttacks.push({
        case_id: r.case_id,
        vector: r.source_metadata?.attack_vector ?? "",
        risk_category: r.risk_category,
        expected: r.expected_action,
        prompt: p.slice(0, 140),
      });
    }
  } else {
    if (blocked) benignCaught.push({ case_id: r.case_id, prompt: p.slice(0, 80) });
  }
}

const attacks = am.filter((r) => r.label === "attack");
console.log(`agentmeter-90 total: ${am.length}`);
console.log(`attacks: ${attacks.length}  (expected block=${attacks.filter(r=>r.expected_action==='block').length}, human_review=${attacks.filter(r=>r.expected_action==='human_review').length})`);
console.log(`benign: ${am.filter(r=>r.label==='benign').length}`);
console.log(`\nINPUT-LAYER caught attacks: ${caught}/${attacks.length}`);
console.log(`INPUT-LAYER missed attacks: ${missedAttacks.length}`);
console.log(`benign caught (false positive risk): ${benignCaught.length}`);
console.log(`\n=== MISSED attack prompts ===`);
for (const m of missedAttacks) {
  console.log(`${m.case_id} [${m.vector}] ${m.risk_category} expected=${m.expected}`);
  console.log(`    ${m.prompt}`);
}
if (benignCaught.length) {
  console.log(`\n=== BENIGN caught (potential false positive) ===`);
  for (const b of benignCaught) console.log(`${b.case_id} ${b.prompt}`);
}
