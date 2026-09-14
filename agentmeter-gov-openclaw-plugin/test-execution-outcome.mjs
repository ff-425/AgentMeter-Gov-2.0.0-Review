import {test} from 'node:test';
import assert from 'node:assert/strict';
import {agentExecutionOutcome,toolExecutionOutcome} from './execution-outcome.js';
import M from '../AgentMeter-Gov/frontend/monitor-model.js';

test('terminal assistant error overrides successful outer lifecycle',()=>{
  const outcome=agentExecutionOutcome({success:true,messages:[
    {role:'assistant',stopReason:'toolUse'},
    {role:'toolResult',details:{status:'completed'}},
    {role:'assistant',stopReason:'error',errorMessage:'terminated'},
  ]});
  assert.equal(outcome.execution_result,'failed');
  assert.equal(outcome.execution_error,'terminated');
  const task={events:[{event_type:'result_event',...outcome}]};
  assert.equal(M.execution(task).status,'failed');
  assert.match(M.execution(task).detail,/terminated/);
  assert.equal(M.taskState(task).code,'failed');
});
test('an earlier recovered model error does not fail a successful final turn',()=>{
  assert.equal(agentExecutionOutcome({success:true,messages:[
    {role:'assistant',stopReason:'error',errorMessage:'temporary error'},
    {role:'assistant',stopReason:'stop',content:'done'},
  ]}).execution_result,'completed');
});
test('explicit errors, cancellation, wrapped messages and absent outcome',()=>{
  assert.equal(agentExecutionOutcome({success:false,error:'timeout'}).execution_error,'timeout');
  assert.equal(agentExecutionOutcome({success:true,error:{message:'connection closed'}}).execution_result,'failed');
  assert.equal(agentExecutionOutcome({aborted:true}).execution_result,'failed');
  assert.equal(agentExecutionOutcome({messages:[{message:{role:'assistant',stopReason:'aborted'}}]}).execution_result,'failed');
  assert.equal(agentExecutionOutcome({}).execution_result,'incomplete');
});
test('background tool start and polling are pending, not successful side effects',()=>{
  assert.equal(toolExecutionOutcome({result:{details:{status:'running'}}}),'pending');
  assert.equal(toolExecutionOutcome({result:{details:{status:'running',exitCode:null}}}),'pending');
  assert.equal(toolExecutionOutcome({result:{details:{status:'completed',exitCode:0}}}),'success');
  assert.equal(toolExecutionOutcome({result:{details:{status:'completed',exitCode:17}}}),'failed');
  assert.equal(toolExecutionOutcome({result:{isError:true}}),'failed');
  assert.equal(toolExecutionOutcome({},true),'failed');
});
test('older backend passes a failure explanation through evidence',()=>{
  const task={events:[{event_type:'result_event',execution_result:'failed',evidence:'OpenClaw 执行失败：terminated'}]};
  assert.match(M.execution(task).detail,/terminated/);
  const ended={events:[{event_type:'result_event',execution_result:'completed'}]};
  assert.equal(M.taskState(ended).label,'任务已结束');
  assert.equal(M.execution(ended).confirmed,false);
});
