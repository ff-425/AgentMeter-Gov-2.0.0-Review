# 运行配置与测评汇总

本目录提供运行配置和 645 案例综合真机测评的机器可读汇总，不包含原始案例、盲测集或会话内容。

- evaluation_metrics.json：综合真机测评的规模、案例级指标、事件级指标和统计说明。
- risk_scoring_rules_v1.json：风险评分规则。
- security_policy_v1.json：运行安全策略。
- semantic_risk_prototypes_v1.json：风险引擎使用的语义原型。
- user_profiles.example.json：用户画像配置示例。

文件名中的 v1 是配置格式版本。测评指标以 `evaluation_metrics.json` 为准；测评覆盖插件版本 0.3.0 至 1.1.11，是随 2.0.0 仓库发布的综合基线，并非只针对 2.0.0 的独立复测。
