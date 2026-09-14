# AgentMeter-Gov 安全防控层 V1

## 目标

AgentMeter-Gov 不只做风险识别和打分，还要在 OpenClaw 工具执行前形成可执行的安全处置计划。每次 `before_tool_call` 都输出 `security_control`，用于决定是否放行、降级、人工复核或阻断，并把处置证据写入审计链。

## 运行链路

```text
OpenClaw user goal
  -> before_agent_run 记录原始目标
  -> before_tool_call 捕获拟执行工具
  -> AgentMeter-Gov /api/gate
  -> C/G/D/P/T/S/A 风险计量
  -> security_control 安全处置计划
  -> allow / human_review / block
  -> 审计记录与结果追溯
```

## 处置模式

| policy_mode | 含义 | 执行效果 |
| --- | --- | --- |
| allow | 风险可接受时放行 | 继续执行并持续记录后续链路 |
| pause_for_approval | 人工复核 | 工具执行前暂停，审批通过后只释放本次动作 |
| deny | 强制阻断 | 工具执行前阻断，不产生危险副作用 |

## 控制点

| 控制点 | 名称 | 作用 |
| --- | --- | --- |
| CTRL-01 | before_tool_call 前置闸门 | 工具执行前完成风险计量和处置判定 |
| CTRL-02 | 结构化审计留痕 | 记录目标、来源、工具参数、分数、规则和处置 |
| CTRL-03 | 敏感标识脱敏 | 手机号、身份证号、编码敏感标识不得原样外发 |
| CTRL-04 | 外发目标管控 | 外部邮箱、外部 URL、跨域上传需授权或审批 |
| CTRL-05 | 批量动作限流与复核 | 群发、批量写入、批量删除进入人工复核 |
| CTRL-06 | 凭据资产隔离 | token、API key、密码、.env 禁止进入模型上下文和外发链路 |
| CTRL-07 | 正式文档写入保护 | 公文、合同、审批结论写入需快照和负责人确认 |
| CTRL-08 | 审计证据不可破坏 | 日志只允许追加说明或归档副本，不允许删除覆盖 |
| CTRL-09 | 审批流程权限边界 | 智能体只能生成草稿，不得代替负责人提交或通过审批 |
| CTRL-10 | 跨步骤数据流隔离 | 已访问内部/敏感数据后，后续外发、上传、群发动作需复核或阻断 |
| CTRL-11 | 插件与 Skill 漂移复核 | 插件或 Skill 版本漂移时要求确认来源、版本和权限边界 |
| CTRL-12 | 敏感数据中转区管控 | 内部或敏感数据写入 outbox、export、tmp、upload 等中转目录需复核 |
| CTRL-13 | 低可信来源副作用隔离 | 低可信文档或隐藏指令触发写入、命令、外发等副作用时进入复核 |

## 返回结构

`/api/gate` 返回顶层字段 `security_control`：

```json
{
  "policy_mode": "deny",
  "enforce_before_execution": true,
  "current_tool": "send_email",
  "risk_score": 99,
  "controls": [{"control_id": "CTRL-03"}],
  "transformations": [{"type": "redact_sensitive_identifier"}],
  "release_conditions": ["外发对象、数据范围和业务目的由用户或负责人明确确认"],
  "safe_alternatives": ["保留只读摘要、提取或分析类结果"],
  "redacted_proposed_params": {"content": "张三 [PHONE_REDACTED] [CHINA_ID_REDACTED]"}
}
```

## 当前增强重点

这版已经从“可演示拦截”提升为“可扩展运行时防控”：

1. 风险分数决定动作，动作生成控制计划。
2. 控制计划进入 OpenClaw 插件审计记录。
3. 高风险副作用在工具执行前终止。
4. 中高风险动作给出审批释放条件。
5. 敏感内容提供脱敏预览，便于复核和材料展示。
6. 跨步骤数据流进入控制计划，避免“先读内部数据、后伪装成普通外发”的绕过。

## 下一步增强

1. 将每个控制点做成可配置策略，支持按政企单位、部门和数据等级调整。
2. 对已放行但读取过内部数据的链路继续施加状态约束，例如禁止后续未授权外发。
3. 增加审批包字段：审批人、审批原因、脱敏预览、影响范围和一次性释放令牌。
4. 增加跨会话风险记忆：同一任务反复尝试绕过时提高分数。
5. 增加规则效果评估表：误报、漏报、阻断前副作用、审计完整率。
