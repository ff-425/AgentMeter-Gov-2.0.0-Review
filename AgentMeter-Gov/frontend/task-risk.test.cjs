const assert = require('node:assert/strict');
const { test } = require('node:test');
const M = require('./monitor-model.js');
const event = (score, action) => ({event_type:'risk_decision_event', risk_score:score, decision:action});

test('mail capability lookup retains 14 after two allowed 6-point polls', () => {
  const task = M.normalizeTasks([{max_risk_score:6, events:[event(14,'allow'),event(6,'allow'),event(6,'allow')]}])[0];
  assert.equal(task.max_risk_score,14);
  assert.equal(M.taskRisk(task).score,14);
  assert.equal(M.taskRisk(task).decision.decision,'allow');
  assert.deepEqual(M.riskEvents(task).map(e=>e.risk_score),[14,6,6]);
});

test('later allow cannot hide an earlier block or review, regardless of score', () => {
  for (const action of ['block','deny','human_review']) {
    const summary=M.taskRisk({events:[event(40,action),event(60,'allow')]});
    assert.equal(summary.score,60);
    assert.equal(summary.decision.decision,action);
  }
  assert.equal(M.taskRisk({events:[event(40,'block'),event(60,'human_review')]}).decision.decision,'block');
});

test('missing, zero and historical summary scores retain their meaning', () => {
  assert.deepEqual(M.taskRisk({events:[]}),{score:null,decision:null});
  assert.equal(M.taskRisk({events:[event(0,'allow')]}).score,0);
  assert.equal(M.taskRisk({max_risk_score:80,events:[event(6,'allow')]}).score,80);
  const summary=M.taskRisk({risk_summary:{risk_score:55,action:'human_review'}});
  assert.equal(summary.score,55);
  assert.equal(summary.decision.summary_only,true);
});
