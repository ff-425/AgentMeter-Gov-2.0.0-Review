# AgentMeter-Gov 2.0.0 · 源码评审

面向 OpenClaw 的政企智能体安全防护与行为审计系统。本仓库提供最终 2.0.0 的独立源码快照，仅保留一次初始提交。

**源码公开供查看与评审，不采用开源许可证。** 评审人员可按 [评审使用条款](LICENSE) 在隔离环境中安装运行；其他使用、修改、再分发或商业用途须取得书面授权。GitHub 服务条款允许的查看及 Fork 不受影响。第三方内容遵循 [各自许可证](THIRD_PARTY_NOTICES.md)。

## 下载安装

[GitHub Release v2.0.0](https://github.com/ff-425/AgentMeter-Gov-2.0.0-Review/releases/tag/v2.0.0) 提供 Windows x64 安装程序、便携包及 SHA-256 校验文件。安装程序适合直接安装；便携包目标机器无需另装 Python，但需要 OpenClaw 2026.6.5 或更新版本。

## 评审入口

- [系统架构](docs/ARCHITECTURE.md)
- [2.0.0 版本说明](AgentMeter-Gov/docs/RELEASE_2.0.0.md)
- [645 案例综合真机测评](AgentMeter-Gov/docs/EVALUATION_RESULTS.md)
- [后端与网页源码](AgentMeter-Gov/)
- [OpenClaw 插件](agentmeter-gov-openclaw-plugin/)
- [公开范围与核验说明](REVIEW_SCOPE.md)

## 源码运行

支持 Windows x64；源码环境需要 Python 3.11+、Node.js 20+ 和 OpenClaw 2026.6.5 或更新版本。

```powershell
git clone https://github.com/ff-425/AgentMeter-Gov-2.0.0-Review.git
cd AgentMeter-Gov-2.0.0-Review
python -m pip install -r AgentMeter-Gov/requirements.txt
Copy-Item AgentMeter-Gov/.env.example AgentMeter-Gov/.env
openclaw plugins install (Resolve-Path ./agentmeter-gov-openclaw-plugin) --force
openclaw plugins enable agentmeter-gov-guard
openclaw config set plugins.entries.agentmeter-gov-guard.config.runtimeDir (Resolve-Path ./AgentMeter-Gov).Path
openclaw config set plugins.entries.agentmeter-gov-guard.config.autoStartBackend true
openclaw config validate
openclaw gateway restart
```

配置模板中的令牌和签名密钥需要按评审环境设置。插件会自动检查并启动本地后端，监控地址为 `http://127.0.0.1:8765`。

## 测试与数据

公开仓库收录 645 个唯一案例的综合真机测评汇总：518 个攻击案例的综合防护成功率为 **99.03%**，AgentMeter 干预率为 **69.88%**，有害绕过率为 **0.97%**；127 个正常业务案例的放行率为 **92.13%**，硬误报率为 **3.94%**。完整指标见 [综合真机测评结果](AgentMeter-Gov/docs/EVALUATION_RESULTS.md)，机器可读数据见 [`evaluation_metrics.json`](AgentMeter-Gov/data/evaluation_metrics.json)。

测评覆盖 2026-08-10 至 2026-09-06，涉及插件版本 0.3.0 至 1.1.11，是随 2.0.0 仓库发布的综合测评基线，并非只针对 2.0.0 的独立复测。公开仓库不附带旧案例集、盲测集、测试计划、原始会话或历史运行结果。

测试和评测程序源码保留。依赖外部案例文件的测试、演示及 `scripts/verify_release.ps1` 全量验收，需要在受控环境中补齐相应数据后运行。

可独立执行的监控前端回归：

```powershell
node --test AgentMeter-Gov/frontend/monitor-model.test.cjs AgentMeter-Gov/frontend/monitor-transport.test.cjs
```
