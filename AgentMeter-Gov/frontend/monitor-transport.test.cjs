const assert = require('node:assert/strict');
const M = require('./monitor-model.js');
const first = { event_type: 'input_event', event_id: 'input', user_goal: 'fixture', gate_action: '', parameters: {} };
const last = { event_type: 'risk_decision_event', event_id: 'risk', user_goal: '', gate_action: 'block', parameters: { path: 'fixture.txt' } };
const original = { tasks: [{ task_id: 'fixture', events: [first, last], latest_decision: last, peak_decision: last }], task_count: 1 };
const compact = { tasks: [{ task_id: 'fixture', events: [
  { event_type: 'input_event', event_id: 'input', user_goal: 'fixture' },
  { event_type: 'risk_decision_event', event_id: 'risk', gate_action: 'block', parameters: { path: 'fixture.txt' } }
] }], task_count: 1, transport: 'task-events-v1', event_defaults: { user_goal: '', gate_action: '', parameters: {} }, decision_refs: [[1, 1]] };
assert.deepEqual(M.expandTaskPayload(compact), original);
assert.equal(M.expandTaskPayload(original), original);
for (const refs of [[[2, 1]], [[-1, 1]], [['1', 1]], [], [[1]]]) {
  assert.throws(() => M.expandTaskPayload({ ...compact, decision_refs: refs }));
}
assert.throws(() => M.expandTaskPayload({ ...compact, transport: 'unknown' }));
console.log('Lossless compact transport and invalid-reference tests passed');
