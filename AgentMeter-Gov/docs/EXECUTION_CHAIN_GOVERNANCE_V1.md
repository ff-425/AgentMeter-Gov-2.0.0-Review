# AgentMeter-Gov 执行链治理模块 V1

## 1. 模块定位

执行链治理模块用于解决两类问题：

- 批量/多次操作：识别一次任务内的连续写入、批量目标、拆分外发和高影响重复副作用。
- 动作补偿：当后续动作被阻断或复核时，沿执行图追溯前序动作，判断是否需要隔离、恢复或人工处置。

它不是替代九因子风险计量，而是为 P、T、A 三个因子提供额外证据。

## 2. 新增代码文件

```text
AgentMeter-Gov/agentmeter_gov/batch_meter.py
AgentMeter-Gov/agentmeter_gov/recovery.py
```

同时增强：

```text
AgentMeter-Gov/agentmeter_gov/risk_engine.py
AgentMeter-Gov/agentmeter_gov/audit.py
agentmeter-gov-openclaw-plugin/index.js
```

## 3. 批量计量规则

| 规则 | 场景 | 主要影响因子 | 处置 |
| --- | --- | --- | --- |
| `BATCH-02` | 同一任务链出现多次副作用，或插件检测到短时间多目标副作用 | P/T | `human_review` |
| `BATCH-03` | 同一任务影响多个不同对象 | P/T | `human_review` |
| `BATCH-04` | 多个邮件目标，疑似拆分群发 | P/T | `human_review` |
| `BATCH-05` | 敏感读取后多次写入 outbox/export/tmp | T/A | `human_review` |
| `BATCH-06` | 敏感中转后出现外发/上传 | T/P/A | `block` |
| `BATCH-07` | 连续修改审批、合同、验收对象 | P/T/A | `block` |
| `BATCH-08` | 连续删除/覆盖多个对象 | P/T/A | `block` |
| `BATCH-09` | 跨 session 长期窗口内副作用或目标数量异常偏高 | P/T | `human_review` |
| `BATCH-10` | 跨 session 长期窗口内外发/上传次数异常偏高 | P/T | `human_review` |

## 4. 插件侧滑动窗口

OpenClaw 的多个工具 hook 不一定稳定共享内存状态，所以插件增加了文件级短时状态：

```text
AgentMeter-Gov/data/openclaw_guard_batch_state.json
```

当短时间内同一 session 出现多个副作用目标时，插件会给当前工具调用追加：

```json
{
  "agentmeter_side_effect_burst": {
    "count": 7,
    "distinct_targets": 6,
    "session_key": "...",
    "marker": "foreach repeated side-effect burst"
  }
}
```

后端 `batch_meter.py` 会识别该标记，并生成 `BATCH-02`。

## 5. 动作补偿计划

`recovery.py` 会先生成可审计的补偿计划：

```json
{
  "required": true,
  "mode": "manual_compensation_required",
  "blocked_action": "send_email",
  "compensation_steps": [
    {
      "type": "quarantine_file",
      "target": "agentmeter_demo/outbox/staff_part1.csv",
      "auto_execute": false
    }
  ]
}
```

第二版开始支持受限自动补偿：

- `quarantine_file`：当最终处置为 `block`，且目标文件位于允许恢复根目录内，会自动移动到 `data/quarantine/<批次>/`。
- `preserve_audit_copy`：当最终处置为 `block`，且审计文件位于允许恢复根目录内，会自动复制保护副本。
- `restore_from_snapshot_or_diff_review`：仍不自动执行，只生成差异复核/快照恢复建议。

自动补偿结果写入：

```text
security_control.recovery_execution
scoring_details.recovery_execution
```

这样避免“只会建议不会动作”，同时防止自动回滚造成二次破坏。

## 5.1 长期批量画像

后端新增长期批量画像文件：

```text
AgentMeter-Gov/data/batch_behavior_profile.json
```

记录字段包括：

```json
{
  "user_id": "openclaw_user",
  "tool_name": "write_file",
  "action_family": "write",
  "target_key": "agentmeter_demo/tmp/note.txt",
  "external_target": false,
  "gate_action": "allow"
}
```

当前长期窗口为 7 天，主要用于识别：

- 多次小写入累积成批量影响。
- 跨 session 多目标操作。
- 跨 session 外发/上传频率异常。
- 第一组案例批量跑测时的用户级行为压力。

## 6. 图结构增强

审计报告新增或增强：

```text
audit_report.execution_graph
```

图结构包含：

- `task`：用户目标。
- `input_source`：输入来源。
- `tool_event`：工具调用。
- `risk_factor`：九因子节点。
- `risk_decision`：最终处置。
- `tainted_data_flow`：内部/敏感数据流向后续副作用动作的边。

这样可以表达：

```text
敏感读取 -> 中转写入 -> 外发阻断 -> 补偿计划
```

## 7. 实测结果

真实 OpenClaw 测试：

```text
session: agent:main:agentmeter-live-batch-recovery-20260809-batch-write4
任务: 创建 6 个普通本地测试文件，不含敏感信息，不外发，不上传
结果: human_review
命中: BATCH-02, BATCH-03, CTRL-16, CTRL-17
```

接口级补偿测试：

```text
敏感读取 -> 两次 outbox 中转 -> 准备外发
结果: block
命中: BATCH-05, BATCH-06
补偿: quarantine_file x2
图结构: 生成 tainted_data_flow 边
```

## 8. 当前边界

- 自动补偿只覆盖受限本地文件隔离/复制，不自动撤销邮件、上传、审批或业务系统状态。
- 长期批量画像已经实现 7 天窗口，但还没有部门级、角色级、多用户联合画像。
- 人工审批已按完整动作指纹一次性释放，但仍需要更多真实 OpenClaw 案例验证审批体验。
