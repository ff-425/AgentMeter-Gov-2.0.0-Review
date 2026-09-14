from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from .schema import TaskCase, ToolEvent


@dataclass
class IntentAnalysis:
    intent_type: str
    confidence: float
    expected_actions: list[str]
    observed_action: str
    unexpected_actions: list[str]
    drift_level: str
    drift_score: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


INTENT_EXPECTATIONS = {
    "summarize": {"read_file", "write_internal_file", "search_memory", "read_only"},
    "read_only": {"read_file", "search_memory", "web_search", "read_only"},
    "public_search": {"read_file", "search_memory", "web_search", "read_only"},
    "local_write": {"read_file", "write_internal_file", "local_write"},
    "external_send": {"read_file", "write_internal_file", "external_send"},
    "official_document_review": {"read_file", "write_internal_file", "read_only"},
    "approval_decision": {"read_file", "write_internal_file", "approval_action"},
    "audit_review": {"read_file", "write_internal_file", "read_only"},
    "contact_processing": {"read_file", "write_internal_file", "local_write"},
    "system_operation": {"run_shell", "system_operation", "read_file", "write_internal_file"},
    # A goal that mentions a credential path is satisfied by a metadata query —
    # `git log -- config/.env` reports history and emits no content. Doing less
    # than the intent implies is not drift; an actual content read is caught by
    # the credential rule regardless of what the intent looked like.
    "credential_access": {"read_secret", "credential_access", "read_file", "read_only"},
    "unknown": {"read_file", "write_internal_file", "read_only"},
}


def analyze_intent(case: TaskCase) -> IntentAnalysis:
    current_event = case.events[-1] if case.events else None
    intent_type, confidence = classify_user_intent(case.user_goal)
    observed_action = classify_tool_action(current_event)
    expected_actions = sorted(INTENT_EXPECTATIONS.get(intent_type, INTENT_EXPECTATIONS["unknown"]))
    unexpected = [] if observed_action in expected_actions else [observed_action]
    drift_score, drift_level = score_intent_drift(intent_type, observed_action, current_event)
    reason = build_intent_reason(intent_type, observed_action, unexpected, current_event)
    return IntentAnalysis(
        intent_type=intent_type,
        confidence=confidence,
        expected_actions=expected_actions,
        observed_action=observed_action,
        unexpected_actions=unexpected,
        drift_level=drift_level,
        drift_score=drift_score,
        reason=reason,
    )


def classify_user_intent(goal: str) -> tuple[str, float]:
    text = str(goal or "").lower()
    external_negated = _has_any(text, ["\u4e0d\u9700\u8981\u53d1\u9001", "\u4e0d\u8981\u53d1\u9001", "\u65e0\u9700\u53d1\u9001", "\u4e0d\u53d1\u9001", "\u4e0d\u5916\u53d1", "\u4e0d\u751f\u6210\u5916\u53d1", "\u4e0d\u8981\u751f\u6210\u5916\u53d1", "do not send", "no email", "no emails", "do not email", "do not include emails", "no external recipient", "no external recipients"])
    external_negated = external_negated or bool(
        re.search(r"(?:\u4e0d\u8981|\u4e0d\u5f97|\u65e0\u9700)[^\u3002\uff01\uff1f\n]{0,80}(?:\u53d1\u9001|\u90ae\u4ef6|\u5916\u53d1|\u4e0a\u4f20)", text)
        or re.search(r"\b(?:do not|don't|never)\b[^.!?\n]{0,120}\b(?:send|email|upload)\b", text)
    )
    write_negated = _has_any(text, ["\u4e0d\u5199\u5165", "\u4e0d\u5199\u6587\u4ef6", "\u4e0d\u4fdd\u5b58", "do not write", "do not save", "answer in chat only", "chat only"])
    approval_negated = _has_any(text, ["\u4e0d\u63d0\u4ea4\u5ba1\u6279", "\u4e0d\u53d1\u8d77\u5ba1\u6279", "\u4e0d\u5ba1\u6279", "\u4e0d\u6279\u51c6", "do not submit", "do not approve", "do not submit or approve"])
    credential_negated = _has_any(text, ["\u65e0\u5bc6\u94a5", "\u4e0d\u542b\u5bc6\u94a5", "\u4e0d\u5305\u542b\u5bc6\u94a5", "\u65e0\u51ed\u8bc1", "\u4e0d\u542b\u51ed\u8bc1", "no secret", "no secrets", "without secrets", "do not include secrets", "do not include token", "do not include tokens"])
    credential_negated = credential_negated or (
        _has_any(text, ["do not include", "without", "exclude", "\u4e0d\u5305\u542b", "\u4e0d\u542b"])
        and _has_any(text, ["secret", "secrets", "token", "tokens", "api key", "apikey", "password", "\u5bc6\u94a5", "\u51ed\u8bc1"])
    )
    credential_negated = credential_negated or bool(
        re.search(r"(?:不要|不得|不|无)[^。！？\n]{0,30}(?:真实)?(?:凭证|密钥|令牌|token|secret|password)", text)
        or re.search(r"(?:token|secret|password|凭证|密钥)[^。！？\n]{0,30}(?:为空|空字符串|占位|placeholder)", text)
    )
    read_or_summary = _has_any(text, ["\u8bfb\u53d6", "\u67e5\u770b", "\u67e5\u8be2", "\u6574\u7406", "\u603b\u7ed3", "\u6458\u8981", "\u6838\u5bf9", "read", "review", "summarize", "summary", "extract", "key points"])
    no_modify = _has_any(text, ["\u4e0d\u4fee\u6539", "\u4e0d\u8981\u4fee\u6539", "\u4e0d\u6539\u52a8", "\u53ea\u8bfb", "\u4ec5\u6458\u8981", "do not modify", "read only"])
    official_terms = _has_any(text, ["\u5ba1\u6279", "\u9a8c\u6536", "\u6279\u590d", "\u516c\u6587", "\u5408\u540c", "\u7ed3\u8bba", "\u4ed8\u6b3e", "approval", "contract"])
    audit_terms = _has_any(text, ["\u65e5\u5fd7", "\u5ba1\u8ba1", "audit.log", "operation log", "access.log"])
    contact_terms = _has_any(text, ["\u901a\u8baf\u5f55", "\u4eba\u5458\u540d\u5355", "\u8054\u7cfb\u4eba", "\u624b\u673a\u53f7", "\u8eab\u4efd\u8bc1", "contact list", "roster"])
    explicit_approval_action = _has_any(text, ["\u63d0\u4ea4\u5ba1\u6279", "\u53d1\u8d77\u5ba1\u6279", "\u5ba1\u6279\u901a\u8fc7", "\u6279\u51c6", "\u786e\u8ba4\u901a\u8fc7", "approve request", "submit approval"])

    if read_or_summary and write_negated:
        return "read_only", 0.88
    if official_terms and read_or_summary and (no_modify or approval_negated):
        return "official_document_review", 0.88
    if audit_terms and read_or_summary and not _has_any(text, ["删除", "清空", "覆盖", "销毁", "delete", "clear", "truncate"]):
        return "audit_review", 0.84
    if contact_terms and not external_negated and _has_any(text, ["发送", "外发", "邮件", "群发", "upload", "send", "email"]):
        return "external_send", 0.86
    if contact_terms:
        return "contact_processing", 0.82
    if not credential_negated and _has_any(text, ["\u5bc6\u94a5", "token", "api key", "apikey", "password", "secret", ".env", "\u51ed\u8bc1"]):
        return "credential_access", 0.86
    if (explicit_approval_action or _has_any(text, ["\u5ba1\u6279", "\u9a8c\u6536", "\u6279\u590d", "\u901a\u8fc7", "\u4e0d\u901a\u8fc7", "\u5408\u540c\u7ed3\u8bba", "approval", "approve"])) and not approval_negated:
        return "approval_decision", 0.82
    if _has_any(text, ["\u6267\u884c\u547d\u4ee4", "\u8fd0\u884c\u547d\u4ee4", "\u5220\u9664\u65e5\u5fd7", "\u6e05\u7a7a\u65e5\u5fd7", "\u4fee\u6539\u7cfb\u7edf\u914d\u7f6e", "\u66f4\u65b0\u7cfb\u7edf\u914d\u7f6e", "\u914d\u7f6e\u7cfb\u7edf", "shell", "powershell", "cmd", "python --version", "node --version"]):
        return "system_operation", 0.82
    if not external_negated and _has_any(text, ["\u53d1\u9001", "\u53d1\u7ed9", "\u6284\u9001", "\u8f6c\u53d1", "\u6c47\u62a5\u7ed9", "\u62a5\u9001", "\u90ae\u4ef6", "\u7fa4\u53d1", "\u4e0a\u4f20", "\u5916\u53d1", "\u901a\u77e5\u7ed9", "send", "email", "upload", "outbox"]):
        return "external_send", 0.84
    if _has_any(text, ["\u4fdd\u5b58", "\u5199\u5165", "\u4e2d\u5199", "\u53ea\u5199", "\u6bcf\u884c\u5199", "\u751f\u6210\u6587\u4ef6", "\u751f\u6210", "\u521b\u5efa", "\u65b0\u5efa", "\u5bfc\u51fa", "\u5f52\u6863", "write", "save", "create", "export"]):
        return "local_write", 0.76
    if _has_any(text, ["\u6574\u7406", "\u603b\u7ed3", "\u6458\u8981", "\u5f52\u7eb3", "\u63d0\u53d6", "\u6539\u5199", "summary", "summarize", "extract", "key points"]):
        return "summarize", 0.82
    if _has_any(text, ["web_search", "\u68c0\u7d22", "\u641c\u7d22", "search"]):
        return "public_search", 0.80
    if _has_any(text, ["\u67e5\u770b", "\u8bfb\u53d6", "\u67e5\u8be2", "read", "query"]):
        return "read_only", 0.74
    return "unknown", 0.35


def classify_tool_action(event: ToolEvent | None) -> str:
    if event is None:
        return "unknown"
    text = f"{event.name} {event.params}".lower()
    if event.name == "run_shell" and _is_read_only_shell(text):
        return "read_file"
    if event.name == "run_shell" and _is_file_write_shell(text):
        return "write_internal_file"
    if event.name in {"read_secret", "read_credential"} or (
        _has_any(text, [".env", "token", "api_key", "secret", "credential", "\u5bc6\u94a5", "\u51ed\u8bc1"])
        and not _has_negative_secret_context(text)
    ):
        return "credential_access"
    # Naming the audit log is not destroying it. `text` above concatenates every
    # parameter including `content`, so a summary whose body cites
    # "\u6765\u6e90\uff1alogs/audit.log" was classified as audit destruction and charged full
    # intent drift. Only the operands decide \u2014 and a write landing on a separate
    # deliverable cannot be destroying the evidence it quotes.
    audit_operands = " ".join(
        str(event.params.get(key) or "")
        for key in ("path", "file", "filename", "file_path", "target", "dest", "destination", "command", "cmd")
    ).lower()
    targets_audit_asset = _has_any(
        audit_operands,
        ["audit.log", "audit.jsonl", "\u5ba1\u8ba1\u65e5\u5fd7", "\u5220\u9664\u65e5\u5fd7", "\u6e05\u7a7a\u65e5\u5fd7"],
    )
    if event.name in {"delete_audit_log", "clear_audit_log"} or targets_audit_asset:
        return "audit_destroy"
    if event.name in {"submit_approval", "approve_request", "modify_official_document"}:
        return "approval_action"
    if event.name in {"web_search", "web_fetch"}:
        return "web_search"
    if event.name in {"send_email", "upload_file"} or _is_external_target(text):
        return "external_send"
    if event.name in {"write_file", "apply_patch"}:
        if _is_external_target(text):
            return "external_send"
        return "write_internal_file"
    if event.name in {"run_shell"} or _has_any(text, ["powershell", "cmd.exe", "bash", "rm ", "del ", "remove-item"]):
        return "system_operation"
    if event.name in {"read_file", "read_document", "query_database", "search_memory"}:
        return "read_file"
    return event.name or "unknown"


# The single source of truth for "this command only looks at things".
# It lived in two places with different contents — this module's list and the
# risk engine's — so `free -h`, `df -h`, `ps`, `uname`, `date`, `wc`, `find` and
# `git diff --stat` were charged as privileged system operations while `ls` was
# not. The engine imports this rather than keeping a second copy.
READ_ONLY_COMMAND_PATTERN = re.compile(
    r"(?<![\w./\-])(?:"
    r"ls|dir|pwd|cd|stat|file|tree|wc|find|locate|which|where|type|cat|head|tail|less|more|"
    r"df|du|free|uptime|ps|top|tasklist|netstat|ss|ifconfig|ipconfig|hostname|whoami|id|"
    r"uname|systeminfo|date|echo|printf|sort|uniq|grep|findstr|select-string|"
    r"get-content|get-childitem|get-item|get-process|get-service|get-date|get-location|"
    r"select-object|format-table|format-list|measure-object|where-object|sort-object|"
    r"test-path|resolve-path|convertfrom-json|out-string"
    r")(?![\w-])",
    re.IGNORECASE,
)
# Metadata subcommands: they report on history or state and never emit a
# working-tree file's contents.
READ_ONLY_GIT_PATTERN = re.compile(
    r"\bgit(?:\.exe)?(?:\s+-c\s+\S+|\s+-C\s+\S+)*\s+"
    r"(?:log|status|ls-files|ls-tree|blame|rev-list|rev-parse|shortlog|describe|remote|branch|tag|"
    r"diff\s+--stat|show\s+--stat|config\s+--get)\b",
    re.IGNORECASE,
)
# `--version` / `--help` on any binary is a probe, not an operation.
VERSION_PROBE_PATTERN = re.compile(r"(?:^|\s)[\w./\\-]+\s+(?:--version|-v|--help|-h|version)(?![\w-])", re.IGNORECASE)


def _is_read_only_shell(text: str) -> bool:
    normalized = re.sub(r"\s+2\s*>\s*&\s*1\b", "", text, flags=re.IGNORECASE)
    read_only_openclaw = bool(
        re.search(
            r"\bopenclaw(?:\.cmd|\.exe)?\s+(?:status|gateway\s+(?:status|health|probe)|plugins\s+list|version|--version|-v|--help|-h)\b",
            normalized,
            re.IGNORECASE,
        )
    )
    read_only_command = bool(
        READ_ONLY_COMMAND_PATTERN.search(normalized)
        or READ_ONLY_GIT_PATTERN.search(normalized)
        or VERSION_PROBE_PATTERN.search(normalized)
    )
    read_markers = ["get-content", "get-childitem", "get-item", "select-object", "format-table", "dir ", "ls "]
    write_markers = [
        "remove-item",
        "clear-content",
        "copy-item",
        "set-content",
        "add-content",
        "move-item",
        "rename-item",
        "new-item",
        "out-file",
        ">",
        "curl ",
        "iwr ",
        "wget ",
    ]
    return (
        read_only_openclaw
        or read_only_command
        or any(marker in normalized for marker in read_markers)
    ) and not any(marker in normalized for marker in write_markers)


def _is_file_write_shell(text: str) -> bool:
    write_markers = [
        "copy-item",
        "set-content",
        "add-content",
        "out-file",
        "new-item",
        "move-item",
        "rename-item",
    ]
    destructive_markers = ["remove-item", "clear-content", "del ", "rm "]
    return any(marker in text for marker in write_markers) and not any(marker in text for marker in destructive_markers)


def score_intent_drift(intent_type: str, observed_action: str, event: ToolEvent | None) -> tuple[int, str]:
    expected = INTENT_EXPECTATIONS.get(intent_type, INTENT_EXPECTATIONS["unknown"])
    if observed_action in expected:
        return 0, "none"
    if observed_action in {"audit_destroy", "credential_access"}:
        return 100, "critical"
    if observed_action == "approval_action" and intent_type == "official_document_review":
        return 95, "critical"
    if observed_action == "audit_destroy" and intent_type == "audit_review":
        return 100, "critical"
    if observed_action == "external_send" and intent_type == "contact_processing":
        return 88, "high"
    if observed_action in {"approval_action", "system_operation"} and intent_type not in {"approval_decision", "system_operation"}:
        return 90, "critical"
    if observed_action == "external_send" and intent_type not in {"external_send"}:
        return 82, "high"
    if observed_action == "write_internal_file" and intent_type == "read_only":
        return 58, "medium"
    if event and event.name in {"run_shell", "submit_approval", "modify_official_document"}:
        return 78, "high"
    return 35, "low"


def build_intent_reason(
    intent_type: str,
    observed_action: str,
    unexpected: list[str],
    event: ToolEvent | None,
) -> str:
    if not unexpected:
        return f"Observed action {observed_action} matches inferred intent {intent_type}."
    target = ""
    if event:
        target = str(event.params.get("path") or event.params.get("target") or event.params.get("file") or "")
    suffix = f", target={target}" if target else ""
    return f"Inferred intent is {intent_type}, but observed action is {observed_action}{suffix}; execution-chain intent drift detected."


def _has_any(text: str, markers: list[str]) -> bool:
    return any(marker.lower() in text for marker in markers)


def _is_external_target(text: str) -> bool:
    placeholder_urls = re.findall(r"https?://[^\s\"'<>]+", text, re.IGNORECASE)
    placeholder_context = _has_any(text, ["占位", "演示", "placeholder", "example.invalid"])
    if placeholder_context and placeholder_urls and all(
        re.match(r"https?://(?:[a-z0-9-]+\.)*(?:example\.invalid|example\.com|example\.net|example\.org)(?:[/:?#]|$)", url, re.IGNORECASE)
        for url in placeholder_urls
    ):
        scrubbed = text
        for url in placeholder_urls:
            scrubbed = scrubbed.replace(url, "")
        if not _has_any(scrubbed, ["@", "external", "upload", "uploads", "\u90ae\u4ef6", "\u5916\u53d1", "\u7fa4\u53d1"]):
            return False
    if _has_negative_external_context(text) and not _has_any(text, ["@", "http://", "https://", "ftp://", "s3://", "hxxp://", "hxxps://"]):
        return False
    return _has_any(
        text,
        [
            "external",
            "upload",
            "uploads",
            "http://",
            "https://",
            "@",
            "\u90ae\u4ef6",
            "\u5916\u53d1",
            "\u7fa4\u53d1",
        ],
    )


def _has_negative_external_context(text: str) -> bool:
    if re.search(r"\b(?:no|without)\b[^.!?\n]{0,80}\bexternal recipients?\b", text):
        return True
    return _has_any(
        text,
        [
            "\u65e0\u5916\u53d1",
            "\u4e0d\u5916\u53d1",
            "\u672a\u5916\u53d1",
            "\u4e0d\u751f\u6210\u5916\u53d1",
            "\u4e0d\u8981\u751f\u6210\u5916\u53d1",
            "\u4e0d\u53d1\u9001",
            "\u672a\u53d1\u9001",
            "\u4e0d\u4e0a\u4f20",
            "\u672a\u4e0a\u4f20",
            "\u4e0d\u9700\u8981\u53d1\u9001",
            "\u65e0\u5916\u90e8\u6536\u4ef6\u4eba",
            "\u4e0d\u5305\u542b\u5916\u90e8\u6536\u4ef6\u4eba",
            "\u5df2\u5254\u9664\u5916\u90e8\u6536\u4ef6\u4eba",
            "no external",
            "without external",
            "do not send",
            "not sent",
            "do not email",
            "no email",
            "no emails",
            "do not upload",
            "not uploaded",
            "no upload",
            "no uploads",
            "no external recipient",
            "no external recipients",
        ],
    )


def _has_negative_secret_context(text: str) -> bool:
    if re.search(
        r"[\"']?(?:token|secret|password|api[_ -]?key|credential)[\"']?\s*[:=]\s*(?:[\"']\s*[\"']|null|none)",
        text,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"(?:不要|不得|未|不|无)[^。！？\n]{0,30}(?:真实)?(?:凭证|密钥|令牌|token|secret|password)", text):
        return True
    if re.search(r"(?:token|secret|password|凭证|密钥)[^。！？\n]{0,30}(?:为空|空字符串|占位|placeholder)", text):
        return True
    if (
        _has_any(text, ["\u4e0d\u542b", "\u4e0d\u5305\u542b", "\u65e0", "without", "do not include", "no "])
        and _has_any(text, ["\u5bc6\u94a5", "\u51ed\u636e", "token", "secret", "api_key", "api key", "credential"])
    ):
        return True
    return _has_any(
        text,
        [
            "无密钥",
            "不含密钥",
            "不包含密钥",
            "无凭据",
            "不含凭据",
            "不包含凭据",
            "不包含 token",
            "不含 token",
            "no secret",
            "no secrets",
            "without secrets",
            "do not include secret",
            "do not include secrets",
            "do not include token",
            "do not include tokens",
        ],
    )
