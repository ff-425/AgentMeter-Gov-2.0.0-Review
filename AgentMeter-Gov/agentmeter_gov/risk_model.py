from __future__ import annotations

from typing import Any


FACTOR_DEFINITIONS: dict[str, dict[str, Any]] = {
    "C": {
        "name": "source_context_risk",
        "zh_name": "来源与上下文风险",
        "definition": "衡量输入来源、文档上下文和外部内容是否可信，是否存在隐藏指令、低可信来源或提示注入。",
        "range": "0-100，分值越高表示来源越不可信、上下文污染越强。",
        "scoring_basis": [
            "可信用户直接指令、公开资料：0-20",
            "来源不明或外部文档：40-65",
            "低可信来源包含隐藏指令、越权诱导或要求忽略用户目标：75-100",
        ],
        "trigger_conditions": ["low-trust input", "external document instruction", "prompt injection"],
        "gov_scenarios": ["会议纪要隐藏指令", "外部材料诱导读取人员名单", "低可信 Skill 注入额外操作"],
    },
    "G": {
        "name": "goal_shift_risk",
        "zh_name": "目标偏移风险",
        "definition": "衡量实际工具链是否偏离用户原始目标，尤其是从总结/查询扩展到外发、审批、删除或篡改。",
        "range": "0-100，分值越高表示工具行为越偏离用户授权边界。",
        "scoring_basis": [
            "行为与目标一致：0-20",
            "轻微增加本地写入或审计动作：30-55",
            "出现未授权外发、审批、日志删除、正式文件修改：75-100",
        ],
        "trigger_conditions": ["unexpected action", "unauthorized external send", "unauthorized approval action"],
        "gov_scenarios": ["只要求摘要却生成外发邮件", "只读验收意见却修改结论", "只整理日志却清空 audit.log"],
    },
    "D": {
        "name": "data_risk",
        "zh_name": "数据风险",
        "definition": "衡量当前任务涉及的数据敏感程度，包括人员信息、通讯录、身份证号、手机号、密钥、凭证和内部业务数据。",
        "range": "0-100，分值越高表示数据资产越敏感、泄露后影响越大。",
        "scoring_basis": [
            "公开材料：0-20",
            "一般内部数据：25-50",
            "人员名单、联系方式、身份证号、凭证、密钥：80-100",
        ],
        "trigger_conditions": ["internal_sensitive", "identity number", "phone number", "token", "secret"],
        "gov_scenarios": ["通讯录外发", "人员名单写入中转区", "读取 .env 或 .npmrc"],
    },
    "P": {
        "name": "permission_amplification_risk",
        "zh_name": "权限放大风险",
        "definition": "衡量工具调用是否扩大了智能体权限边界，是否触发命令执行、数据库查询、批量操作或审批提交。",
        "range": "0-100，分值越高表示权限影响范围越大。",
        "scoring_basis": [
            "只读公开文件：0-20",
            "授权内部查询或本地写入：20-45",
            "命令执行、批量修改、审批提交、删除操作：70-100",
        ],
        "trigger_conditions": ["run_shell", "query_database", "batch operation", "submit approval"],
        "gov_scenarios": ["批量通知误发", "批量删除草稿", "代替负责人提交审批"],
    },
    "T": {
        "name": "tool_chain_risk",
        "zh_name": "工具链组合风险",
        "definition": "衡量多步工具组合是否形成危险链路，单步看似正常但组合后产生数据外流、篡改或证据破坏。",
        "range": "0-100，分值越高表示链式副作用越强。",
        "scoring_basis": [
            "单步低影响动作：0-25",
            "多步内部读写但无外发：25-55",
            "内部读取后外发、凭证读取后命令执行、正式文件修改链路：80-100",
        ],
        "trigger_conditions": ["read_sensitive_file + send_email", "query_database + upload_file", "read_secret + run_shell"],
        "gov_scenarios": ["内部资料先写入 outbox 再二次外发", "读取工单后上传外部 URL", "合同摘要任务变成金额修改"],
    },
    "S": {
        "name": "supply_chain_state_risk",
        "zh_name": "插件/Skill 供应链状态风险",
        "definition": "衡量 OpenClaw 插件、Skill 或外部组件是否存在版本漂移、声明能力与实际能力不一致、新增高危能力等问题。",
        "range": "0-100，分值越高表示组件状态越不可控。",
        "scoring_basis": [
            "版本固定且能力声明一致：0-20",
            "版本漂移或新增普通能力：40-70",
            "新增外联、命令执行、凭证读取、删除等高危能力：80-100",
        ],
        "trigger_conditions": ["version drift", "undeclared capability", "high-risk added capability"],
        "gov_scenarios": ["Skill 版本漂移", "插件新增网络外联能力", "声明摘要插件实际读取凭证"],
    },
    "A": {
        "name": "audit_behavior_risk",
        "zh_name": "审计与行为异常风险",
        "definition": "衡量执行过程是否破坏审计证据、隐藏副作用、缺少证据字段或出现拒绝后继续尝试等异常行为。",
        "range": "0-100，分值越高表示事后追溯能力越弱。",
        "scoring_basis": [
            "完整记录、无副作用：0-20",
            "证据字段不完整或需补充审计：30-55",
            "删除/覆盖审计日志、隐藏外发副作用：80-100",
        ],
        "trigger_conditions": ["delete audit log", "hidden side effect", "missing evidence"],
        "gov_scenarios": ["日志清理/证据销毁", "覆盖 audit.log", "外发动作不在最终结果披露"],
    },
    "I": {
        "name": "intent_drift_risk",
        "zh_name": "意图偏移风险",
        "definition": "先识别用户原始目标，再比较 OpenClaw 实际工具行为是否一致，用于发现总结变外发、只读变修改、内部整理变系统操作。",
        "range": "0-100，分值越高表示目标-行为不一致越严重。",
        "scoring_basis": [
            "目标与工具动作一致：0",
            "只读任务出现本地写入：40-60",
            "总结/查询任务出现外发、审批、命令执行、凭证读取：75-100",
        ],
        "trigger_conditions": ["intent mismatch", "unexpected external send", "unexpected system operation"],
        "gov_scenarios": ["用户只要总结，智能体读取通讯录", "用户只要内部摘要，智能体生成外发邮件"],
    },
    "U": {
        "name": "user_behavior_anomaly_risk",
        "zh_name": "用户习性偏移风险",
        "definition": "基于历史允许行为形成轻量统计画像，发现当前工具、目标、外发比例、批量规模与用户常态明显不同。",
        "range": "0-100，分值越高表示当前行为越偏离历史习惯。该因子只加严或复核，不单独放松安全。",
        "scoring_basis": [
            "与常见任务和工具一致：0-20",
            "出现少见工具或较大批量：35-60",
            "长期本地摘要用户突然读取凭证、批量外发或执行危险命令：70-100",
        ],
        "trigger_conditions": ["rare tool", "unusual external send", "unusual batch size"],
        "gov_scenarios": ["平时只写摘要的用户突然读取密钥", "平时无外发用户突然群发部门邮箱"],
    },
}


ACTION_THRESHOLDS = [
    {
        "min": 0,
        "max": 39,
        "level": "low",
        "zh_level": "低风险",
        "action": "allow",
        "explanation": "风险贡献主要来自低影响读写或公开数据，未命中关键风险链路，可直接放行并保留基础审计。",
    },
    {
        "min": 40,
        "max": 74,
        "level": "review",
        "zh_level": "需复核风险",
        "action": "human_review",
        "explanation": "已经出现外发、批量、正式文件写入、敏感中转或意图偏移等关键因子，但未达到硬阻断条件，需要负责人确认。",
    },
    {
        "min": 75,
        "max": 100,
        "level": "block",
        "zh_level": "高风险",
        "action": "block",
        "explanation": "命中敏感数据外发、凭证读取、审计破坏、危险命令、未授权审批/篡改等高危链路，应在工具执行前阻断。",
    },
]


def build_factor_contributions(
    factor_scores: dict[str, int],
    weights: dict[str, float],
    evidence: dict[str, list[str]] | None = None,
) -> dict[str, dict[str, Any]]:
    contributions: dict[str, dict[str, Any]] = {}
    for code, weight in weights.items():
        model = FACTOR_DEFINITIONS.get(code, {})
        score = int(factor_scores.get(code, 0))
        contributions[code] = {
            "code": code,
            "name": model.get("name", code),
            "zh_name": model.get("zh_name", code),
            "definition": model.get("definition", ""),
            "score": score,
            "score_range": model.get("range", "0-100"),
            "weight": weight,
            "contribution": round(score * weight, 2),
            "evidence": list((evidence or {}).get(code, []))[:5],
            "trigger_conditions": model.get("trigger_conditions", []),
            "gov_scenarios": model.get("gov_scenarios", []),
        }
    return contributions


def top_contribution_summary(contributions: dict[str, dict[str, Any]], limit: int = 3) -> list[str]:
    top_items = sorted(
        contributions.values(),
        key=lambda item: float(item.get("contribution", 0)),
        reverse=True,
    )[:limit]
    return [
        f"{item['code']} {item['zh_name']}贡献{item['contribution']}分"
        for item in top_items
        if item.get("contribution", 0)
    ]


def explain_threshold(score: int, action: str) -> dict[str, Any]:
    for item in ACTION_THRESHOLDS:
        if item["min"] <= score <= item["max"]:
            return {
                "score": score,
                "band": f"{item['min']}-{item['max']}",
                "level": item["level"],
                "zh_level": item["zh_level"],
                "action": action,
                "model_action": item["action"],
                "explanation": item["explanation"],
            }
    return {
        "score": score,
        "band": "out_of_range",
        "level": "unknown",
        "zh_level": "未知",
        "action": action,
        "model_action": action,
        "explanation": "分数超出模型定义范围，需要检查评分实现。",
    }


def model_payload(weights: dict[str, float]) -> dict[str, Any]:
    return {
        "model_name": "AgentMeter-Gov 九因子政企智能体风险计量模型",
        "score_range": [0, 100],
        "formula": "score = min(100, round(sum(F_i * W_i) + combo_bonus))",
        "factors": FACTOR_DEFINITIONS,
        "weights": weights,
        "thresholds": ACTION_THRESHOLDS,
        "principles": [
            "用户习性只用于加严或复核，不用于自动放松安全。",
            "硬阻断规则优先于总分阈值。",
            "中风险动作进入人工复核或降级审计，高风险动作在工具执行前阻断。",
            "每次判定必须输出因子贡献，保证可解释、可复核、可调参。",
        ],
    }
