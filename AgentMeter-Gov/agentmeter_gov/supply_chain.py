from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

from .schema import TaskCase, ToolEvent


TEXT_EXTENSIONS = {
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".py",
    ".ps1",
    ".sh",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
}

IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "dist", "build"}
MAX_FILE_BYTES = 300_000

CAPABILITY_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "filesystem_read": [
        (r"\breadFile(?:Sync)?\s*\(", "Node.js file read"),
        (r"\bopen\s*\([^)]*,\s*['\"]r", "Python file read"),
        (r"\bGet-Content\b", "PowerShell file read"),
    ],
    "filesystem_write": [
        (r"\bwriteFile(?:Sync)?\s*\(", "Node.js file write"),
        (r"\bappendFile(?:Sync)?\s*\(", "Node.js file append"),
        (r"\bSet-Content\b|\bOut-File\b|\bAdd-Content\b", "PowerShell file write"),
        (r"\bopen\s*\([^)]*,\s*['\"][wa]", "Python file write"),
    ],
    "destructive_file_operation": [
        (r"\bunlink(?:Sync)?\s*\(", "Node.js delete file"),
        (r"\brmSync\s*\(", "Node.js recursive delete"),
        (r"\bRemove-Item\b|\bdel\b|\berase\b", "PowerShell delete"),
        (r"\bos\.remove\b|\bshutil\.rmtree\b", "Python delete"),
    ],
    "external_network": [
        (r"\bfetch\s*\(\s*['\"]https?://", "HTTP fetch"),
        (r"\baxios\.\w+\s*\(\s*['\"]https?://", "Axios HTTP call"),
        (r"\brequests\.(?:post|get|put)\s*\(\s*['\"]https?://", "Python requests call"),
        (r"\bInvoke-WebRequest\b|\bcurl\b|\bwget\b", "Shell HTTP client"),
    ],
    "command_execution": [
        (r"\bchild_process\b|\bexec\s*\(|\bspawn\s*\(", "Node.js command execution"),
        (r"\bsubprocess\.\w+\s*\(", "Python subprocess"),
        (r"\bStart-Process\b|\bInvoke-Expression\b", "PowerShell command execution"),
    ],
    "credential_access": [
        (r"\bprocess\.env\b|\bos\.environ\b", "environment variable access"),
        (r"\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|id_rsa\b|credentials\b", "credential file marker"),
        (r"api[_-]?key|token|password|secret|private[_-]?key", "secret keyword"),
    ],
    "dynamic_code": [
        (r"\beval\s*\(|\bnew Function\s*\(", "dynamic JavaScript execution"),
        (r"(?<!\.)\bexec\s*\(|\bcompile\s*\(", "dynamic Python execution"),
        (r"EncodedCommand|fromCharCode|atob\s*\(", "obfuscation marker"),
    ],
}

DECLARED_CAPABILITY_KEYWORDS: dict[str, list[str]] = {
    "filesystem_read": ["read", "read_file", "read_document", "读取", "文档读取"],
    "filesystem_write": ["write", "write_file", "save", "output", "写入", "保存"],
    "external_network": ["network", "http", "api", "upload", "send", "email", "外联", "上传", "发送"],
    "command_execution": ["shell", "exec", "command", "subprocess", "命令", "脚本"],
    "credential_access": ["credential", "secret", "token", "api_key", "凭据", "密钥"],
    "destructive_file_operation": ["delete", "remove", "unlink", "删除", "清理"],
    "dynamic_code": ["eval", "dynamic", "动态执行"],
}

HIGH_RISK_CAPABILITIES = {
    "external_network",
    "command_execution",
    "credential_access",
    "destructive_file_operation",
    "dynamic_code",
}


def scan_component(candidate_dir: str | Path, baseline_dir: str | Path | None = None) -> dict[str, Any]:
    candidate = Path(candidate_dir).resolve()
    baseline = Path(baseline_dir).resolve() if baseline_dir else None
    if not candidate.exists() or not candidate.is_dir():
        raise FileNotFoundError(f"candidate component directory not found: {candidate}")
    if baseline and (not baseline.exists() or not baseline.is_dir()):
        raise FileNotFoundError(f"baseline component directory not found: {baseline}")

    candidate_inventory = _inventory(candidate)
    baseline_inventory = _inventory(baseline) if baseline else {}
    component = _component_identity(candidate, candidate_inventory)
    baseline_component = _component_identity(baseline, baseline_inventory) if baseline else {}
    declared = _declared_capabilities(candidate_inventory, component)
    observed = _observed_capabilities(candidate_inventory)
    baseline_observed = _observed_capabilities(baseline_inventory) if baseline else set()
    component_digest = _component_digest(candidate_inventory)
    signature = _verify_signature(candidate_inventory, component_digest)
    version_lock = _verify_version_lock(candidate_inventory, component, component_digest)

    added_files = sorted(set(candidate_inventory) - set(baseline_inventory))
    removed_files = sorted(set(baseline_inventory) - set(candidate_inventory))
    changed_files = sorted(
        path
        for path in set(candidate_inventory) & set(baseline_inventory)
        if candidate_inventory[path]["sha256"] != baseline_inventory[path]["sha256"]
    )
    added_capabilities = sorted(observed - baseline_observed)
    undeclared_capabilities = sorted(cap for cap in observed if cap not in declared)
    high_risk_added = sorted(set(added_capabilities) & HIGH_RISK_CAPABILITIES)
    high_risk_undeclared = sorted(set(undeclared_capabilities) & HIGH_RISK_CAPABILITIES)
    evidence = _evidence_for(candidate_inventory, set(added_capabilities) | set(high_risk_undeclared))

    drift_flags = []
    if baseline and component.get("name") == baseline_component.get("name") and component.get("version") != baseline_component.get("version"):
        drift_flags.append("version_changed")
    if added_files or changed_files or removed_files:
        drift_flags.append("file_tree_changed")
    if added_capabilities:
        drift_flags.append("behavior_capability_added")
    if high_risk_undeclared:
        drift_flags.append("declared_observed_mismatch")
    if {"credential_access", "external_network"} <= observed:
        drift_flags.append("possible_secret_exfiltration")
    if {"filesystem_read", "external_network"} <= observed and high_risk_undeclared:
        drift_flags.append("possible_data_exfiltration")
    if signature["status"] == "missing":
        drift_flags.append("signature_missing")
    elif signature["status"] != "valid":
        drift_flags.append("signature_invalid")
    if version_lock["status"] == "missing":
        drift_flags.append("version_lock_missing")
    elif version_lock["status"] != "valid":
        drift_flags.append("version_lock_mismatch")

    score = _risk_score(
        high_risk_added=high_risk_added,
        high_risk_undeclared=high_risk_undeclared,
        drift_flags=drift_flags,
        observed=observed,
    )
    if "signature_invalid" in drift_flags or "version_lock_mismatch" in drift_flags:
        score = max(score, 85)
    elif "signature_missing" in drift_flags or "version_lock_missing" in drift_flags:
        score = max(score, 55)
    recommendation = "allow"
    if score >= 85:
        recommendation = "block"
    elif score >= 55:
        recommendation = "human_review"
    elif score >= 25:
        recommendation = "allow"

    return {
        "scanner": "agentmeter-gov-supply-chain-v2",
        "component": component,
        "baseline_component": baseline_component,
        "candidate_dir": str(candidate),
        "baseline_dir": str(baseline) if baseline else "",
        "declared_capabilities": sorted(declared),
        "observed_capabilities": sorted(observed),
        "baseline_observed_capabilities": sorted(baseline_observed),
        "capability_comparison": {
            "matched": sorted(observed & declared),
            "declared_not_observed": sorted(declared - observed),
            "observed_not_declared": sorted(observed - declared),
            "continuous_check_digest": hashlib.sha256(
                json.dumps({"declared": sorted(declared), "observed": sorted(observed)}, sort_keys=True).encode("utf-8")
            ).hexdigest(),
        },
        "added_observed_capabilities": added_capabilities,
        "undeclared_capabilities": undeclared_capabilities,
        "high_risk_added_capabilities": high_risk_added,
        "high_risk_undeclared_capabilities": high_risk_undeclared,
        "file_diff": {
            "added": added_files,
            "changed": changed_files,
            "removed": removed_files,
        },
        "component_digest": component_digest,
        "signature_verification": signature,
        "version_lock_verification": version_lock,
        "sbom": {
            "format": "agentmeter-sbom-v1",
            "component": component.get("name", candidate.name),
            "version": component.get("version", "unknown"),
            "files": [
                {"path": rel, "size": item["size"], "sha256": item["sha256"]}
                for rel, item in sorted(candidate_inventory.items())
            ],
        },
        "drift_flags": drift_flags,
        "risk_score": score,
        "risk_level": _risk_level(score),
        "recommendation": recommendation,
        "evidence": evidence,
    }


def scan_to_task_case(scan: dict[str, Any], task_id: str = "supply-chain-skill-drift-001") -> TaskCase:
    component = scan.get("component", {})
    component_name = component.get("name") or "unknown-skill"
    events = [
        ToolEvent(
            name="skill_scan",
            params={
                "candidate_dir": scan.get("candidate_dir", ""),
                "baseline_dir": scan.get("baseline_dir", ""),
                "component": component,
            },
            source="agentmeter_supply_chain_scanner",
            data_level="public",
            result="success",
            evidence="Skill/package inventory, manifest and code capability scan completed before execution.",
        )
    ]

    observed = set(scan.get("observed_capabilities", []))
    if "credential_access" in observed:
        events.append(
            ToolEvent(
                name="read_secret",
                params={"target": ".env/API token/credential marker", "component": component_name},
                source="skill_static_scan",
                data_level="secret",
                result="proposed",
                evidence="Static scan found credential access patterns in the candidate Skill.",
            )
        )
    if "command_execution" in observed:
        events.append(
            ToolEvent(
                name="run_shell",
                params={"component": component_name, "reason": "candidate Skill contains command execution capability"},
                source="skill_static_scan",
                data_level="internal",
                result="proposed",
                evidence="Static scan found shell/subprocess execution patterns not required by declared summary behavior.",
            )
        )
    if "destructive_file_operation" in observed:
        events.append(
            ToolEvent(
                name="delete_file",
                params={"component": component_name, "target": "local/audit/workspace file"},
                source="skill_static_scan",
                data_level="internal",
                result="proposed",
                evidence="Static scan found file deletion or cleanup behavior.",
            )
        )
    if "filesystem_read" in observed and ("external_network" in observed or "credential_access" in observed):
        events.append(
            ToolEvent(
                name="read_sensitive_file",
                params={"component": component_name, "target": "shared/internal document or credential file"},
                source="skill_static_scan",
                data_level="internal_sensitive",
                result="proposed",
                evidence="Candidate Skill can read local files in a chain that also includes exfiltration-capable behavior.",
            )
        )
    if "external_network" in observed:
        events.append(
            ToolEvent(
                name="upload_file",
                params={"component": component_name, "url": "https://external-demo.com/upload"},
                source="skill_static_scan",
                data_level="internal_sensitive" if "filesystem_read" in observed else "internal",
                result="proposed",
                evidence="Static scan found external network/upload behavior in the candidate Skill.",
            )
        )

    return TaskCase(
        task_id=task_id,
        title=f"Skill/插件供应链漂移扫描：{component_name}",
        user_goal="在 OpenClaw 中安装或启用会议摘要 Skill 前，验证新版本是否仍只执行文档摘要职责。",
        input_sources=[
            {
                "name": component_name,
                "type": "skill",
                "trust": "medium",
                "version_drift": bool(scan.get("drift_flags")),
                "tags": ["skill", "supply_chain", "version_drift"],
                "content": "Candidate Skill is compared with the trusted baseline before execution.",
                "supply_chain_scan": scan,
                "declared_capabilities": scan.get("declared_capabilities", []),
                "observed_capabilities": scan.get("observed_capabilities", []),
                "risk_score": scan.get("risk_score", 0),
            }
        ],
        events=events,
        expected_label=scan.get("recommendation", "unknown"),
    )


def _inventory(root: Path | None) -> dict[str, dict[str, Any]]:
    if root is None:
        return {}
    inventory: dict[str, dict[str, Any]] = {}
    for path in root.rglob("*"):
        if path.is_dir() or any(part in IGNORE_DIRS for part in path.relative_to(root).parts):
            continue
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        text = ""
        if path.suffix.lower() in TEXT_EXTENSIONS and size <= MAX_FILE_BYTES:
            text = path.read_text(encoding="utf-8", errors="ignore")
        inventory[rel] = {
            "path": str(path),
            "size": size,
            "sha256": sha256,
            "text": text,
        }
    return inventory


def _component_identity(root: Path | None, inventory: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if root is None:
        return {}
    identity = {"name": root.name, "version": "unknown", "manifest": ""}
    for manifest_name in ("skill.json", "plugin.json", "package.json"):
        item = inventory.get(manifest_name)
        if not item or not item.get("text"):
            continue
        try:
            data = json.loads(item["text"])
        except json.JSONDecodeError:
            continue
        identity["manifest"] = manifest_name
        identity["name"] = str(data.get("name") or data.get("displayName") or identity["name"])
        identity["version"] = str(data.get("version") or identity["version"])
        identity["description"] = str(data.get("description") or "")
        for key in ("capabilities", "permissions", "tools"):
            if key in data:
                identity[key] = data[key]
        return identity
    return identity


def _component_digest(inventory: dict[str, dict[str, Any]]) -> str:
    excluded = {"agentmeter.sig.json", "agentmeter.sbom.json", "agentmeter.lock.json"}
    canonical = "\n".join(
        f"{rel}:{item['size']}:{item['sha256']}"
        for rel, item in sorted(inventory.items())
        if rel not in excluded
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _verify_signature(inventory: dict[str, dict[str, Any]], digest: str) -> dict[str, Any]:
    item = inventory.get("agentmeter.sig.json")
    if not item or not item.get("text"):
        return {"status": "missing", "algorithm": "", "signer": ""}
    try:
        payload = json.loads(item["text"])
    except json.JSONDecodeError:
        return {"status": "invalid", "reason": "malformed_signature_file"}
    algorithm = str(payload.get("algorithm") or "").lower()
    signer = str(payload.get("signer") or "")
    if str(payload.get("digest") or "") != digest:
        return {"status": "invalid", "algorithm": algorithm, "signer": signer, "reason": "digest_mismatch"}
    if algorithm != "hmac-sha256":
        return {"status": "invalid", "algorithm": algorithm, "signer": signer, "reason": "unsupported_algorithm"}
    key = os.getenv("AGENTMETER_SKILL_SIGNING_KEY", "")
    if not key:
        return {"status": "unverifiable", "algorithm": algorithm, "signer": signer, "reason": "signing_key_unavailable"}
    expected = hmac.new(key.encode("utf-8"), digest.encode("ascii"), hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(str(payload.get("signature") or ""), expected)
    return {"status": "valid" if valid else "invalid", "algorithm": algorithm, "signer": signer, "reason": "" if valid else "signature_mismatch"}


def _verify_version_lock(inventory: dict[str, dict[str, Any]], component: dict[str, Any], digest: str) -> dict[str, Any]:
    item = inventory.get("agentmeter.lock.json")
    if not item or not item.get("text"):
        return {"status": "missing", "locked_version": "", "locked_digest": ""}
    try:
        payload = json.loads(item["text"])
    except json.JSONDecodeError:
        return {"status": "invalid", "reason": "malformed_lock_file"}
    locked_version = str(payload.get("version") or "")
    locked_digest = str(payload.get("digest") or "")
    mismatches = []
    if locked_version != str(component.get("version") or "unknown"):
        mismatches.append("version")
    if locked_digest != digest:
        mismatches.append("digest")
    expected_files = payload.get("files") or {}
    if isinstance(expected_files, dict):
        for rel, expected_hash in expected_files.items():
            if inventory.get(rel, {}).get("sha256") != expected_hash:
                mismatches.append(f"file:{rel}")
    return {
        "status": "invalid" if mismatches else "valid",
        "locked_version": locked_version,
        "locked_digest": locked_digest,
        "mismatches": mismatches,
    }


def _declared_capabilities(inventory: dict[str, dict[str, Any]], component: dict[str, Any]) -> set[str]:
    declared_text = json.dumps(component, ensure_ascii=False).lower()
    for name in ("README.md", "readme.md", "SKILL.md"):
        if name in inventory:
            declared_text += "\n" + str(inventory[name].get("text", "")).lower()
    declared = set()
    for capability, keywords in DECLARED_CAPABILITY_KEYWORDS.items():
        if any(keyword.lower() in declared_text for keyword in keywords):
            declared.add(capability)
    return declared


def _observed_capabilities(inventory: dict[str, dict[str, Any]]) -> set[str]:
    observed = set()
    for item in inventory.values():
        text = str(item.get("text", ""))
        if not text:
            continue
        for capability, patterns in CAPABILITY_PATTERNS.items():
            if any(re.search(pattern, text, re.IGNORECASE) for pattern, _label in patterns):
                observed.add(capability)
    return observed


def _evidence_for(inventory: dict[str, dict[str, Any]], capabilities: set[str]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for rel, item in inventory.items():
        text = str(item.get("text", ""))
        if not text:
            continue
        lines = text.splitlines()
        for capability in sorted(capabilities):
            for pattern, label in CAPABILITY_PATTERNS.get(capability, []):
                for index, line in enumerate(lines, 1):
                    if not re.search(pattern, line, re.IGNORECASE):
                        continue
                    evidence.append(
                        {
                            "capability": capability,
                            "file": rel,
                            "line": index,
                            "pattern": label,
                            "snippet": line.strip()[:180],
                        }
                    )
                    break
                if any(ev["capability"] == capability and ev["file"] == rel for ev in evidence):
                    break
        if len(evidence) >= 20:
            break
    return evidence


def _risk_score(
    *,
    high_risk_added: list[str],
    high_risk_undeclared: list[str],
    drift_flags: list[str],
    observed: set[str],
) -> int:
    score = 5
    score += 12 if "version_changed" in drift_flags else 0
    score += 10 if "file_tree_changed" in drift_flags else 0
    score += 18 if "behavior_capability_added" in drift_flags else 0
    score += 22 if "declared_observed_mismatch" in drift_flags else 0
    score += 25 if "possible_data_exfiltration" in drift_flags else 0
    score += 28 if "possible_secret_exfiltration" in drift_flags else 0
    score += 8 * len(high_risk_added)
    score += 6 * len(high_risk_undeclared)
    if {"command_execution", "external_network"} <= observed:
        score += 12
    if {"destructive_file_operation", "external_network"} <= observed:
        score += 8
    return min(100, score)


def _risk_level(score: int) -> str:
    if score >= 85:
        return "high"
    if score >= 55:
        return "elevated"
    if score >= 25:
        return "medium"
    return "low"
