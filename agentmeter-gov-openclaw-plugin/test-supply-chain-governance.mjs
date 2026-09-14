import assert from "node:assert/strict";

import {
  classifySupplyChainResult,
  componentLifecycleRequest,
  resolveSupplyChainPaths,
} from "./supply-chain-governance.js";

const request = componentLifecycleRequest("skills_install", {
  skillPath: "C:/skills/reporting",
  baselinePath: "C:/skills/trusted/reporting",
});
assert.equal(request.candidate, "C:/skills/reporting");
assert.equal(request.baseline, "C:/skills/trusted/reporting");
assert.equal(componentLifecycleRequest("read_file", { path: "C:/skills/reporting/SKILL.md" }), null);
assert.equal(classifySupplyChainResult({ error: "offline" }, request).action, "block");
assert.equal(classifySupplyChainResult({
  scan: {
    signature_verification: { status: "valid" },
    version_lock_verification: { status: "valid" },
  },
  risk_measurement: { action: "allow" },
}, request).allowed, true);
assert.equal(classifySupplyChainResult({
  scan: {
    signature_verification: { status: "missing" },
    version_lock_verification: { status: "valid" },
  },
  risk_measurement: { action: "allow" },
}, request).action, "human_review");
const resolved = resolveSupplyChainPaths(
  { baseline: "agentmeter_v5/baseline", candidate: "agentmeter_v5/candidate" },
  "C:/OpenClaw/workspace",
);
assert.match(resolved.baseline.replaceAll("\\", "/"), /C:\/OpenClaw\/workspace\/agentmeter_v5\/baseline$/i);
assert.match(resolved.candidate.replaceAll("\\", "/"), /C:\/OpenClaw\/workspace\/agentmeter_v5\/candidate$/i);

console.log(JSON.stringify({ total: 8, passed: 8 }));
