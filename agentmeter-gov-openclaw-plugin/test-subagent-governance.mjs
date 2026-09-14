import assert from "node:assert/strict";

import { evaluateSubagentInheritance } from "./subagent-governance.js";

const benign = evaluateSubagentInheritance({
  auditId: "AUD-1",
  maxRiskScore: 18,
  authorization: ["read_public"],
  dataLevel: "public",
});
assert.equal(benign.allowed, true);
assert.equal(benign.inherited.parentAuditId, "AUD-1");
assert.deepEqual(benign.inherited.authorization, ["read_public"]);

assert.equal(evaluateSubagentInheritance({ maxRiskScore: 75 }).allowed, false);
assert.equal(evaluateSubagentInheritance({ tainted: true }).allowed, false);
assert.equal(evaluateSubagentInheritance({ blocked: true }).allowed, false);

console.log(JSON.stringify({ total: 6, passed: 6 }));
