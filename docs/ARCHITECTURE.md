# AgentMeter-Gov 1.0 系统架构

## 设计结论

1.0 保留“一个仓库、两个可部署部件”的结构，不在发布前进行大规模目录重命名：

```text
OpenClaw
  └─ agentmeter-gov-openclaw-plugin/
       ├─ Gateway 启动服务：探活并自动拉起 Python 后端
       ├─ 输入与持久化指令治理
       ├─ before_tool_call 前置闸门
       ├─ 输出与附件治理
       ├─ 记忆、子智能体、供应链治理
       └─ 结构化事件适配
                    │ HTTP /api/gate
                    ▼
AgentMeter-Gov/
  ├─ server.py                  服务与监控入口
  ├─ agentmeter_gov/
  │    ├─ risk_engine.py        风险计量与规则决策
  │    ├─ gate.py               工具调用闸门编排
  │    ├─ audit.py              审计报告
  │    ├─ event_store.py        事件存储与查询
  │    ├─ intent_analyzer.py    意图与目标偏移
  │    ├─ user_profile.py       行为画像
  │    ├─ batch_meter.py        批量/连续行为计量
  │    ├─ supply_chain.py       Skill/插件供应链检查
  │    ├─ recovery.py           阻断后恢复建议
  │    └─ evaluation.py         统一评测指标
  ├─ data/                      规则、固定案例、正式结果
  ├─ frontend/                  演示与审计查看界面
  ├─ scripts/                   场景、评测和测试脚本
  └─ docs/                      专题技术文档
```

这种划分已经满足 1.0：插件负责嵌入 OpenClaw 生命周期，服务负责统一计量、策略、审计和展示。后续若发展成多个适配器，再在 1.1+ 抽取 `adapters/`，当前不为“看起来更模块化”制造发布风险。

## 启动闭环

插件通过 OpenClaw 官方 `registerService` 注册后台服务。Gateway 正式启动时先检查 `gateUrl` 同源的 `/health`：健康则复用；本机 HTTP 地址不可用时，根据 `runtimeDir`、`backendRoot` 或 `AGENTMETER_GOV_HOME` 定位 `server.py` 并启动。能力发现、插件清单和配置检查等非正式运行模式不会产生进程副作用。

默认情况下，Gateway 退出时只终止由本次生命周期创建的 Python 子进程；预先存在或远程托管的后端不受影响。自动启动失败会写入本地结构化生命周期事件，工具闸门继续执行 fail-closed 策略。

## 两条控制轴

### 工具调用处置

| 动作 | 语义 | 是否执行工具 |
| --- | --- | --- |
| `allow` | 风险可接受，正常放行并审计 | 是 |
| `human_review` | 暂停当前请求，等待一次性审批 | 否，审批后才执行 |
| `block` | 风险不可接受，执行前阻断 | 否 |

原先文档中的 `degrade_and_audit` / `allow_with_audit` 没有独立执行语义：系统本来就审计所有决策，因此合并进 `allow`，风险分和命中规则继续表达“普通放行”和“需重点观察”的差异。

### 输出治理

| 动作 | 语义 |
| --- | --- |
| `allow` | 输出可发送 |
| `redact` | 把具体敏感值替换为类型占位符后发送 |
| `block` | 整体输出或附件禁止发送 |

脱敏不是“把内容删光”，而是在保留业务可读性的前提下去掉可识别、可复用的秘密。例如 `Authorization: Bearer abc...` 变为 `Authorization: [REDACTED:BEARER_TOKEN]`。严重私钥、密集敏感项、不可安全读取的附件则直接阻断。

## 闭环边界

完整链路必须同时具备：输入风险识别、工具执行前处置、人工复核、输出防泄漏、结构化审计、可查询报告、固定案例和指标验证。仅有风险分、仅有插件或仅有展示页都不算交付闭环。
