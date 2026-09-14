# AgentMeter-Gov 运行时安全策略配置 V1

## 文件位置

运行时安全策略文件：

```text
data/security_policy_v1.json
```

该文件负责 OpenClaw 工具调用前的识别词库和安全策略字典。它和 `data/risk_scoring_rules_v1.json` 分工不同：

| 文件 | 作用 |
| --- | --- |
| `risk_scoring_rules_v1.json` | 管权重、阈值、分数解释 |
| `security_policy_v1.json` | 管外发目标、凭据资产、危险命令、编码识别、staging 目录等安全识别策略 |

## 已配置内容

当前策略包含：

- 外发目标标记：HTTP、HTTPS、FTP、SFTP、S3、hxxp、hxxps、裸域名、普通邮箱等。
- 凭据资产标记：`.env`、`.npmrc`、SSH key、kubeconfig、AWS credentials、service account 等。
- 危险命令标记：`remove-item`、`iwr`、`wget`、`powershell -e`、`-enc`、日志重命名/清空等。
- staging 目录：`outbox`、`export`、`tmp`、`upload`、`queue` 等。
- 正式文档和审批词库：公文、合同、审批、workflow、accepted、approved 等。
- 文本规范化开关：NFKC、零宽字符清理、URL decode、字段拼接、数字紧凑化。
- 编码检测开关：Base64、分段 Base64、Hex。

## 运行时返回

`/api/gate` 会在风险结果中返回策略版本：

```json
{
  "security_policy_version": "1.0",
  "security_policy_source": "E:\\揭榜挂帅1\\AgentMeter-Gov\\data\\security_policy_v1.json"
}
```

这意味着审计报告能追溯到当时采用的是哪版安全策略。

## 团队维护建议

### 安全组

负责维护：

- `external_markers`
- `secret_markers`
- `dangerous_command_markers`
- `shortener_domains`
- `staging_path_markers`

### 计量规则组

负责维护：

- 新增策略命中后如何加分
- 是否进入 `human_review`
- 是否进入 `block`

### 工程组

负责维护：

- JSON 加载逻辑
- 策略回退机制
- 红队回归脚本
- OpenClaw 插件侧审计字段

## 修改后必须跑的回归

```powershell
python scripts\run_security_defense_tests.py
python scripts\run_redteam_attack_suite.py
python scripts\run_demo.py
```

当前基线：

```text
安全防护实测：8/8
红队攻击套件：30/30
1.0 固定闭环案例：以 `run_demo.py` 当次输出为准
```

## 下一步

1. 把具体分数触发条件继续迁移到 JSON。
2. 给策略文件增加 schema 校验。
3. 增加策略版本变更日志。
4. 按行业场景拆分策略包，例如政务、金融、园区、国企办公。
