# 第三方评测数据说明

AgentMeter-Gov 的 `external-pilot-v1` 使用以下公共研究基准的固定版本构建。归一化案例仅用于安全评测与研究，原项目版权仍归各自作者所有。

| 项目 | 固定提交 | 许可证 | 上游地址 |
| --- | --- | --- | --- |
| AgentDojo | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT | <https://github.com/ethz-spylab/agentdojo> |
| InjecAgent | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT | <https://github.com/uiuc-kang-lab/InjecAgent> |
| ToolEmu | `ac4a7ab7ed8c7985d96231e214bd6b54304b7ddb` | Apache-2.0 | <https://github.com/ryoungj/ToolEmu> |

仓库不执行第三方基准中的工具调用，也不连接其外部服务。`scripts/import_external_benchmarks.py` 负责从单独保存的、固定提交快照生成统一案例；`scripts/run_external_benchmark.py` 只在 AgentMeter-Gov 的一次性隔离靶场中验证副作用。
