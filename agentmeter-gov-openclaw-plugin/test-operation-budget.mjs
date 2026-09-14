import assert from "node:assert/strict";
import { consumeOperationBudget } from "./operation-budget.js";

const state = {};
const config = { maxToolCallsPerTurn: 8, maxSearchCallsPerTurn: 2, maxIdenticalToolCallsPerTurn: 2 };
assert.equal(consumeOperationBudget(state, { toolName: "web_search", params: { q: "a" } }, config), null);
assert.equal(consumeOperationBudget(state, { toolName: "web_search", params: { q: "b" } }, config), null);
assert.equal(consumeOperationBudget(state, { toolName: "web_search", params: { q: "c" } }, config)?.reason, "search_budget");

const retryState = {};
const call = { toolName: "read", params: { path: "same.txt" } };
assert.equal(consumeOperationBudget(retryState, call, config), null);
assert.equal(consumeOperationBudget(retryState, call, config), null);
assert.equal(consumeOperationBudget(retryState, call, config)?.reason, "identical_retry_budget");

const totalState = {};
for (let index = 0; index < 8; index += 1) {
  assert.equal(consumeOperationBudget(totalState, { toolName: "read", params: { path: `${index}.txt` } }, config), null);
}
assert.equal(consumeOperationBudget(totalState, { toolName: "read", params: { path: "overflow.txt" } }, config)?.reason, "total_tool_budget");

const processState = {};
for (let index = 0; index < 20; index += 1) {
  assert.equal(consumeOperationBudget(processState, { toolName: "process", params: { action: "poll" } }, config), null);
}
assert.equal(processState.operationBudget, undefined);
console.log({ total: 35, passed: 35 });
