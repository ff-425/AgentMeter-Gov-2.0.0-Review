# AgentMeter-Gov BGE 语义辅助计量规则书 V1

## 1. 定位

BGE 语义模型不是替代九因子打分模型，而是作为辅助证据层，重点服务三个因子：

- I：意图偏移风险。判断“用户原始目标”和“OpenClaw 实际工具动作”是否一致。
- G：目标偏移风险。判断任务是否从总结、查询、整理，偏向外发、审批、篡改、删除等高影响目标。
- U：用户习性偏移风险。判断当前语义类别是否明显不同于该用户历史常见任务。

最终决策仍然由九因子加权、组合风险、硬阻断规则和复核策略共同决定。BGE 只负责提供可解释的辅助增量。

## 2. 输入与输出

输入包括四类信息：

- 用户原始目标：用户对 OpenClaw 说的任务。
- 当前工具调用：OpenClaw 准备调用的工具、参数、数据级别和目标路径。
- 近期执行链：同一任务内最近若干次工具调用。
- 输入上下文：会议纪要、审批文件、日志、通讯录等被读入内容的摘要片段。

输出字段写入 `risk_measurement.scoring_details.semantic_analysis`：

- `backend`：`bge`、`fallback` 或 `off`。
- `model_name`：默认 `BAAI/bge-small-zh-v1.5`。
- `goal_action_similarity`：用户目标与当前工具动作的语义相似度，0-1。
- `risk_similarity_score`：当前任务与风险原型库的相似分，0-100。
- `matched_category`：最接近的风险场景类别。
- `matched_risk_level`：原型风险等级。
- `intent_drift_boost`：对 I 因子的辅助提升。
- `goal_shift_boost`：对 G 因子的辅助提升。
- `user_anomaly_boost`：对 U 因子的辅助提升。
- `triggered_rules`：命中的 `SEM-*` 语义辅助规则。
- `reasons`：自然语言解释。

## 3. 语义原型库

原型文件：

```text
AgentMeter-Gov/data/semantic_risk_prototypes_v1.json
```

当前覆盖类别：

- `sensitive_data_exfiltration`：敏感数据外发。
- `hidden_instruction_exfiltration`：隐藏指令诱导外发。
- `approval_or_contract_tamper`：审批、合同、验收结论篡改。
- `audit_evidence_destroy`：日志清理与证据销毁。
- `credential_access`：密钥、令牌、凭据读取。
- `staging_then_exfiltration`：先写入中转区再二次外发。
- `batch_notification_or_mass_write`：批量通知、批量写入、批量影响。
- `supply_chain_plugin_drift`：插件、Skill 版本漂移和供应链风险。
- `normal_internal_backup`：正常内部备份。
- `normal_summary`：正常内部摘要。

第一组提供真实攻击案例后，优先追加到这些类别的 `texts` 字段；如果出现新风险，再新增类别。

## 4. 触发规则

| 规则编号 | 作用因子 | 触发条件 | 处置含义 |
| --- | --- | --- | --- |
| `SEM-R-01` | I/G/U | 与高危或中高危政企风险原型相似度 `>=65` | 作为语义风险证据进入审计，不单独决定阻断 |
| `SEM-I-01` | I | 用户目标与工具动作相似度 `<0.28` | 认为存在目标-行为不一致 |
| `SEM-I-02` | I | 工具动作不在意图识别的期望动作集合中，且 I 辅助提升 `>=60` | 提升意图偏移分 |
| `SEM-G-01` | G | G 辅助提升 `>=60` | 提醒任务可能转向外发、篡改、审批、删除 |
| `SEM-U-01` | U | U 辅助提升 `>=50` | 当前行为与用户历史画像明显不同，只用于加严或复核 |
| `SEM-N-01` | I | 匹配正常内部摘要/备份，且没有 I/G/U 提升 | 记录正常语义证据，不额外加分 |

## 5. 分数融合

九因子主公式保持不变：

```text
score = min(100, round(sum(F_i * W_i) + combo_bonus))
```

BGE 只影响三个因子的候选分：

- `intent_drift_boost` 大于原 I 因子分时，用它抬高 I。
- `goal_shift_boost` 大于原 G 因子分时，用它抬高 G。
- `user_anomaly_boost` 大于原 U 因子分时，用它抬高 U。

它不会降低 D、P、T、A、S 等硬风险因子的分数，也不会绕过硬阻断规则。

## 6. 阈值解释

- `goal_action_similarity <0.28`：目标和动作语义距离较大，适合作为意图偏移证据。
- `risk_similarity_score >=65`：已经接近某类政企风险原型，进入审计解释。
- `risk_similarity_score >=75`：高度接近风险原型，通常会配合规则层触发复核或阻断。
- 正常类别命中不能自动放松安全，只能减少误报解释压力。

## 7. 竞争亮点表达

这一层可以在汇报中表述为：

> AgentMeter-Gov 不把神经网络作为黑箱判决器，而是把 BGE 语义相似度转化为 I/G/U 三个可解释风险因子的辅助证据，实现“语义识别 + 计量规则 + 审计解释”的组合式风险计量。

这样既体现智能方法，也保留计量模型的可解释、可复核、可调参优势。

