# -*- coding: utf-8 -*-
"""No method in the risk engine may be defined twice.

Six were. Python keeps only the last definition, so the earlier copies were
dead code that still looked authoritative — and one of them carried a hardening
rule ("an unbounded selector is a batch operation") that had therefore never
run. Editing a shadowed copy is silent: the tests pass, the behaviour does not
change, and nobody finds out. This test makes that failure loud.

It also pins the batch-detection behaviour that hardening was meant to provide.
"""
from __future__ import annotations

import ast
import collections
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agentmeter_gov import risk_engine as engine_module  # noqa: E402

MODULES = (
    "agentmeter_gov/risk_engine.py",
    "agentmeter_gov/intent_analyzer.py",
    "agentmeter_gov/gate.py",
    "agentmeter_gov/event_store.py",
)

failures: list[str] = []


def check_no_shadowed_definitions() -> None:
    print("重复定义检查")
    for relative in MODULES:
        path = ROOT / relative
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        seen: dict[tuple[str, str], list[int]] = collections.defaultdict(list)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                scope = node.name
                body = node.body
            elif isinstance(node, ast.Module):
                scope = "<module>"
                body = node.body
            else:
                continue
            for item in body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    seen[(scope, item.name)].append(item.lineno)
        duplicates = {key: lines for key, lines in seen.items() if len(lines) > 1}
        if duplicates:
            for (scope, name), lines in sorted(duplicates.items()):
                message = f"{relative}: {scope}.{name} 重复定义于 {lines}，只有最后一个生效"
                print(f"  [FAIL] {message}")
                failures.append(message)
        else:
            print(f"  [ok  ] {relative}")


def check_unbounded_selector_is_batch() -> None:
    print("无界选择器必须判为批量操作")
    engine = engine_module.RiskEngine()

    def event(name, params):
        return engine_module.ToolEvent(
            name=name, params=params, source="openclaw_before_tool_call",
            data_level="internal", result="proposed", evidence="regression",
        )

    positives = [
        ("ids=all", "delete_records", {"ids": "all"}),
        ("ids=*", "delete_records", {"ids": "*"}),
        ("scope=全部", "grant_access", {"scope": "全部", "role": "admin"}),
        ("target=所有", "send_email", {"target": "所有", "subject": "通知"}),
        ("filter=everything", "delete_records", {"filter": "everything"}),
        ("正文覆盖所有人员", "send_email", {"to": "a@x.com", "body": "发给所有人员"}),
        ("显式批量词", "send_email", {"to": "a@x.com", "body": "群发通知"}),
        ("超长列表", "delete_records", {"ids": list(range(20))}),
    ]
    negatives = [
        ("单条 id", "delete_records", {"ids": "42"}),
        ("普通清理措辞", "run_shell", {"command": "Remove-Item build/tmp/a.log"}),
    ]
    for label, name, params in positives:
        result = engine._is_batch_operation(event(name, params))
        print(f"  [{'ok  ' if result else 'FAIL'}] 批量: {label}")
        if not result:
            failures.append(f"批量漏判: {label}")
    for label, name, params in negatives:
        result = engine._is_batch_operation(event(name, params))
        print(f"  [{'ok  ' if not result else 'FAIL'}] 非批量: {label}")
        if result:
            failures.append(f"批量误判: {label}")


def main() -> int:
    check_no_shadowed_definitions()
    check_unbounded_selector_is_batch()
    print()
    if failures:
        print(f"FAILED: {len(failures)}")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("no shadowed definitions; batch detection intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
