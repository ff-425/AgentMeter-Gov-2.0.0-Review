from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .intent_analyzer import IntentAnalysis, classify_tool_action
from .schema import TaskCase, ToolEvent
from .user_profile import UserProfileAnalysis


PROTOTYPE_PATH = Path(__file__).resolve().parents[1] / "data" / "semantic_risk_prototypes_v1.json"
DEFAULT_MODEL = "BAAI/bge-small-zh-v1.5"
SEMANTIC_RULES_VERSION = "semantic-aux-v1.1"

SEMANTIC_RULE_CATALOG = {
    "SEM-R-01": "工具调用语义接近政企高危原型，作为辅助风险证据。",
    "SEM-I-01": "用户目标与实际工具动作语义相似度偏低，存在目标-行为不一致。",
    "SEM-I-02": "工具动作不在用户原始意图的期望动作集合中，且接近高危原型。",
    "SEM-G-01": "当前工具动作可能把任务推向未授权外发、篡改、删除或审批等目标偏移。",
    "SEM-U-01": "当前语义类别与用户历史行为画像不一致，只用于加严或复核。",
    "SEM-N-01": "语义结果接近正常内部摘要/备份，不额外提高风险。",
}


@dataclass
class SemanticRiskAnalysis:
    enabled: bool
    backend: str
    model_name: str
    rules_version: str
    goal_action_similarity: float
    risk_similarity_score: int
    matched_category: str
    matched_risk_level: str
    intent_drift_boost: int
    goal_shift_boost: int
    user_anomaly_boost: int
    factor_hints: list[str]
    triggered_rules: list[dict[str, Any]]
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyze_semantic_risk(
    case: TaskCase,
    intent: IntentAnalysis,
    user_profile: UserProfileAnalysis,
) -> SemanticRiskAnalysis:
    """Semantic auxiliary signal for I/G/U factors.

    `AGENTMETER_SEMANTIC_BACKEND=bge` enables BAAI/bge-small-zh-v1.5 through
    sentence-transformers. Without local dependencies, the module falls back to
    deterministic lexical matching so the OpenClaw guard remains runnable.
    """

    backend = semantic_backend()
    model_name = os.environ.get("AGENTMETER_SEMANTIC_MODEL", DEFAULT_MODEL)
    current_event = case.events[-1] if case.events else None
    goal_text = case.user_goal or ""
    action_text = describe_event(current_event)
    case_text = build_case_text(case, current_event)
    prototypes = load_semantic_prototypes()

    goal_action_similarity = semantic_similarity(goal_text, action_text, backend, model_name)
    matched = best_risk_match(case_text, prototypes, backend, model_name)
    risk_similarity_score = int(round(float(matched["similarity"]) * 100))
    matched_category = str(matched.get("category", "unknown"))
    matched_risk_level = str(matched.get("risk_level", "unknown"))
    factor_hints = [str(item) for item in matched.get("factor_hints", [])]

    observed_action = classify_tool_action(current_event)
    intent_boost = semantic_intent_boost(
        intent=intent,
        observed_action=observed_action,
        similarity=goal_action_similarity,
        risk_category=matched_category,
        risk_score=risk_similarity_score,
    )
    goal_boost = semantic_goal_boost(
        case=case,
        current_event=current_event,
        similarity=goal_action_similarity,
        risk_category=matched_category,
        risk_score=risk_similarity_score,
    )
    user_boost = semantic_user_boost(
        user_profile=user_profile,
        observed_action=observed_action,
        risk_score=risk_similarity_score,
        risk_level=matched_risk_level,
    )
    triggered_rules = build_triggered_semantic_rules(
        current_event=current_event,
        observed_action=observed_action,
        expected_actions=intent.expected_actions,
        goal_action_similarity=goal_action_similarity,
        risk_similarity_score=risk_similarity_score,
        matched_category=matched_category,
        matched_risk_level=matched_risk_level,
        intent_boost=intent_boost,
        goal_boost=goal_boost,
        user_boost=user_boost,
    )

    reasons: list[str] = []
    if goal_action_similarity < 0.28 and current_event is not None:
        reasons.append(
            f"semantic goal-action similarity is low ({goal_action_similarity:.2f}); possible intent drift"
        )
    if risk_similarity_score >= 70:
        reasons.append(f"semantic risk prototype matched: {matched_category} ({risk_similarity_score})")
    if user_boost:
        reasons.append("semantic category is unusual for the current user's behavior profile")
    if not reasons:
        reasons.append("semantic module found no strong additional risk beyond rule signals")

    return SemanticRiskAnalysis(
        enabled=backend != "off",
        backend=backend,
        model_name=model_name,
        rules_version=SEMANTIC_RULES_VERSION,
        goal_action_similarity=round(goal_action_similarity, 4),
        risk_similarity_score=risk_similarity_score,
        matched_category=matched_category,
        matched_risk_level=matched_risk_level,
        intent_drift_boost=intent_boost,
        goal_shift_boost=goal_boost,
        user_anomaly_boost=user_boost,
        factor_hints=factor_hints,
        triggered_rules=triggered_rules,
        reasons=reasons,
    )


def build_triggered_semantic_rules(
    *,
    current_event: ToolEvent | None,
    observed_action: str,
    expected_actions: list[str],
    goal_action_similarity: float,
    risk_similarity_score: int,
    matched_category: str,
    matched_risk_level: str,
    intent_boost: int,
    goal_boost: int,
    user_boost: int,
) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []

    def add(code: str, factor: str, contribution: int, evidence: str) -> None:
        rules.append(
            {
                "code": code,
                "factor": factor,
                "contribution": contribution,
                "description": SEMANTIC_RULE_CATALOG[code],
                "evidence": evidence,
            }
        )

    if matched_category in {"normal_internal_backup", "normal_summary"} and not any(
        [intent_boost, goal_boost, user_boost]
    ):
        add(
            "SEM-N-01",
            "I",
            0,
            f"matched_category={matched_category}; risk_similarity_score={risk_similarity_score}",
        )
        return rules

    if matched_risk_level in {"high", "medium_high"} and risk_similarity_score >= 65:
        add(
            "SEM-R-01",
            ",".join(sorted({"I", "G", "U"} & set(_category_factor_hints(matched_category)))) or "I",
            0,
            f"matched_category={matched_category}; risk_similarity_score={risk_similarity_score}",
        )
    if current_event is not None and goal_action_similarity < 0.28:
        add(
            "SEM-I-01",
            "I",
            intent_boost,
            f"similarity={goal_action_similarity:.2f}; observed_action={observed_action}",
        )
    if intent_boost >= 60 and observed_action not in set(expected_actions):
        add(
            "SEM-I-02",
            "I",
            intent_boost,
            f"observed_action={observed_action}; expected_actions={','.join(expected_actions)}",
        )
    if goal_boost >= 60:
        add(
            "SEM-G-01",
            "G",
            goal_boost,
            f"matched_category={matched_category}; goal_shift_boost={goal_boost}",
        )
    if user_boost >= 50:
        add(
            "SEM-U-01",
            "U",
            user_boost,
            f"matched_category={matched_category}; user_anomaly_boost={user_boost}",
        )
    return rules


def _category_factor_hints(category: str) -> list[str]:
    for item in load_semantic_prototypes():
        if item.get("category") == category:
            return [str(code) for code in item.get("factor_hints", [])]
    return []


def semantic_backend() -> str:
    configured = os.environ.get("AGENTMETER_SEMANTIC_BACKEND", "fallback").strip().lower()
    if configured in {"off", "disabled", "none"}:
        return "off"
    if configured in {"bge", "sentence-transformers", "sentence_transformers"}:
        return "bge" if _bge_available() else "fallback"
    return "fallback"


def semantic_similarity(text_a: str, text_b: str, backend: str, model_name: str) -> float:
    if not text_a or not text_b or backend == "off":
        return 0.0
    if backend == "bge":
        try:
            model = load_bge_model(model_name)
            embeddings = model.encode([text_a, text_b], normalize_embeddings=True)
            return max(0.0, min(1.0, float(sum(a * b for a, b in zip(embeddings[0], embeddings[1])))))
        except Exception:
            return lexical_similarity(text_a, text_b)
    return lexical_similarity(text_a, text_b)


def best_risk_match(case_text: str, prototypes: list[dict[str, Any]], backend: str, model_name: str) -> dict[str, Any]:
    if not prototypes:
        return {"category": "unknown", "risk_level": "unknown", "factor_hints": [], "similarity": 0.0}

    texts = tuple(str(text) for item in prototypes for text in item.get("texts", []) if str(text))
    similarities = []
    if texts and case_text and backend == "bge":
        try:
            vectors = _prototype_embeddings(model_name, texts)
            current = load_bge_model(model_name).encode([case_text], normalize_embeddings=True)[0]
            similarities = [max(0.0, min(1.0, float(sum(a * b for a, b in zip(current, vector))))) for vector in vectors]
        except Exception:
            # Keep the existing deterministic fallback when the local model fails.
            similarities = []
    if not similarities:
        tokens = tokenize(case_text)
        similarities = [0.0 if backend == "off" else _token_similarity(tokens, _prototype_tokens(text)) for text in texts]
    scores = iter(similarities)
    best = {"category": "unknown", "risk_level": "unknown", "factor_hints": [], "similarity": 0.0}
    for item in prototypes:
        category_texts = [str(text) for text in item.get("texts", []) if str(text)]
        if not category_texts:
            continue
        similarity = max(next(scores) for _ in category_texts)
        if similarity > float(best["similarity"]):
            best = {
                "category": str(item.get("category", "unknown")),
                "risk_level": str(item.get("risk_level", "unknown")),
                "factor_hints": list(item.get("factor_hints", [])),
                "similarity": similarity,
            }
    return best


@lru_cache(maxsize=2)
def _prototype_embeddings(model_name: str, texts: tuple[str, ...]):
    # Cache only fixed public prototypes, never user prompts or tool parameters.
    return load_bge_model(model_name).encode(list(texts), normalize_embeddings=True)


@lru_cache(maxsize=256)
def _prototype_tokens(text: str) -> frozenset[str]:
    return frozenset(tokenize(text))


def semantic_intent_boost(
    *,
    intent: IntentAnalysis,
    observed_action: str,
    similarity: float,
    risk_category: str,
    risk_score: int,
) -> int:
    if observed_action in intent.expected_actions:
        return 0
    if observed_action == "read_file" and intent.intent_type in {
        "summarize",
        "read_only",
        "local_write",
        "official_document_review",
        "audit_review",
        "contact_processing",
    }:
        return 0
    if risk_category in {"normal_internal_backup", "normal_summary"}:
        return 0
    if similarity < 0.18 and risk_score >= 70:
        return 88
    if similarity < 0.28 and risk_score >= 60:
        return 72
    if risk_category in {"sensitive_data_exfiltration", "hidden_instruction_exfiltration", "approval_or_contract_tamper"}:
        return 78
    return 0


def semantic_goal_boost(
    *,
    case: TaskCase,
    current_event: ToolEvent | None,
    similarity: float,
    risk_category: str,
    risk_score: int,
) -> int:
    if current_event is None or risk_category in {"normal_internal_backup", "normal_summary"}:
        return 0
    goal = case.user_goal.lower()
    action = classify_tool_action(current_event)
    if risk_category == "sensitive_data_exfiltration" and action == "external_send" and _negative_external(goal):
        return 86
    if risk_category == "approval_or_contract_tamper" and risk_score >= 65:
        return 88
    if risk_category == "audit_evidence_destroy" and risk_score >= 65:
        return 92
    if similarity < 0.25 and risk_score >= 75:
        return 76
    return 0


def semantic_user_boost(
    *,
    user_profile: UserProfileAnalysis,
    observed_action: str,
    risk_score: int,
    risk_level: str,
) -> int:
    if user_profile.cold_start:
        return 0
    top_tools = {str(item[0]) for item in user_profile.profile_summary.get("top_tools", []) if item}
    if observed_action not in top_tools and risk_score >= 75:
        return max(user_profile.behavior_anomaly_score, 60)
    if risk_level == "high" and risk_score >= 80:
        return max(user_profile.behavior_anomaly_score, 70)
    return 0


def describe_event(event: ToolEvent | None) -> str:
    if event is None:
        return ""
    params = json.dumps(event.params, ensure_ascii=False, sort_keys=True)
    return f"tool={event.name}; action={classify_tool_action(event)}; data_level={event.data_level}; params={params}"


def build_case_text(case: TaskCase, current_event: ToolEvent | None) -> str:
    source_texts = []
    for source in case.input_sources:
        content = str(source.get("content", ""))
        if content:
            source_texts.append(content[:800])
    chain = " -> ".join(event.name for event in case.events[-6:])
    return "\n".join(
        [
            f"user_goal: {case.user_goal}",
            f"tool_chain: {chain}",
            f"current_event: {describe_event(current_event)}",
            f"input_context: {' '.join(source_texts)}",
        ]
    )


def lexical_similarity(text_a: str, text_b: str) -> float:
    return _token_similarity(tokenize(text_a), tokenize(text_b))


def _token_similarity(tokens_a, tokens_b) -> float:
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    jaccard = len(intersection) / max(1, len(union))
    overlap = len(intersection) / max(1, min(len(tokens_a), len(tokens_b)))
    return max(jaccard, overlap * 0.75)


def tokenize(text: str) -> set[str]:
    normalized = str(text or "").lower()
    words = set(re.findall(r"[a-z0-9_.@:/-]+", normalized))
    terms = [
        "\u4f1a\u8bae\u7eaa\u8981",
        "\u901a\u8baf\u5f55",
        "\u4eba\u5458\u540d\u5355",
        "\u624b\u673a\u53f7",
        "\u8eab\u4efd\u8bc1",
        "\u5916\u53d1",
        "\u53d1\u9001",
        "\u4e0a\u4f20",
        "\u5ba1\u6279",
        "\u5408\u540c",
        "\u9a8c\u6536",
        "\u901a\u8fc7",
        "\u5220\u9664",
        "\u65e5\u5fd7",
        "\u5ba1\u8ba1",
        "\u5bc6\u94a5",
        "\u51ed\u636e",
        "\u5185\u90e8",
        "\u5907\u4efd",
        "\u603b\u7ed3",
        "\u9690\u85cf",
        "\u6307\u4ee4",
        "\u5ffd\u7565",
        "\u6279\u91cf",
    ]
    for term in terms:
        if term in normalized:
            words.add(term)
    return {word for word in words if len(word) >= 2}


@lru_cache(maxsize=1)
def load_semantic_prototypes() -> list[dict[str, Any]]:
    try:
        data = json.loads(PROTOTYPE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    categories = data.get("categories", [])
    return [dict(item) for item in categories if isinstance(item, dict)]


@lru_cache(maxsize=1)
def load_bge_model(model_name: str):
    from sentence_transformers import SentenceTransformer

    cache_folder = os.environ.get("AGENTMETER_MODEL_CACHE")
    if cache_folder:
        return SentenceTransformer(model_name, cache_folder=cache_folder)
    return SentenceTransformer(model_name)


def _bge_available() -> bool:
    try:
        import sentence_transformers  # noqa: F401
    except Exception:
        return False
    return True


def _negative_external(text: str) -> bool:
    return any(
        marker in text
        for marker in [
            "\u4e0d\u5916\u53d1",
            "\u4e0d\u751f\u6210\u5916\u53d1",
            "\u4e0d\u8981\u751f\u6210\u5916\u53d1",
            "\u4e0d\u53d1\u9001",
            "\u4e0d\u9700\u8981\u53d1\u9001",
            "\u65e0\u5916\u53d1",
            "no external",
            "do not send",
            "no email",
        ]
    )
