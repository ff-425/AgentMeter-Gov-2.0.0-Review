import { isAbsolute, resolve } from "node:path";

const LIFECYCLE = /install|enable|activate|load|register|update|upgrade/;
const COMPONENT = /skill|plugin|extension|component/;

export function componentLifecycleRequest(toolName, params = {}) {
  const name = String(toolName ?? "").toLowerCase();
  const action = String(params?.action ?? params?.operation ?? "").toLowerCase();
  const kind = String(params?.type ?? params?.kind ?? params?.componentType ?? "").toLowerCase();
  const lifecycleDetected = LIFECYCLE.test(name) || LIFECYCLE.test(action);
  const componentDetected = COMPONENT.test(name) || COMPONENT.test(kind) || Boolean(
    params?.skillPath || params?.pluginPath || params?.componentPath,
  );
  if (!lifecycleDetected || !componentDetected) return null;
  return {
    toolName: String(toolName ?? ""),
    candidate: firstString(
      params?.candidate,
      params?.skillPath,
      params?.pluginPath,
      params?.componentPath,
      params?.directory,
      params?.path,
      params?.source,
    ),
    baseline: firstString(params?.baseline, params?.baselinePath, params?.trustedPath),
  };
}

export function classifySupplyChainResult(result, request) {
  if (!request?.candidate) {
    return { allowed: false, action: "block", reason: "component_path_required" };
  }
  if (!result || result.error) {
    return { allowed: false, action: "block", reason: "scanner_unavailable" };
  }
  const signature = String(result.scan?.signature_verification?.status ?? "missing");
  const versionLock = String(result.scan?.version_lock_verification?.status ?? "missing");
  if (signature === "invalid" || versionLock === "invalid") {
    return { allowed: false, action: "block", reason: "invalid_signature_or_version_lock" };
  }
  const measuredAction = String(result.risk_measurement?.action ?? result.scan?.recommendation ?? "human_review");
  if (measuredAction === "block") {
    return { allowed: false, action: "block", reason: "supply_chain_policy_block" };
  }
  if (signature !== "valid" || versionLock !== "valid" || measuredAction === "human_review") {
    return { allowed: false, action: "human_review", reason: "unsigned_or_unlocked_component" };
  }
  return { allowed: true, action: measuredAction, reason: "verified_component" };
}

export function resolveSupplyChainPaths(request, workspaceDir = "") {
  const root = String(workspaceDir ?? "").trim();
  const resolveOne = (value) => {
    const raw = String(value ?? "").trim();
    if (!raw || isAbsolute(raw) || !root) return raw;
    return resolve(root, raw);
  };
  return {
    ...request,
    baseline: resolveOne(request?.baseline),
    candidate: resolveOne(request?.candidate),
  };
}

function firstString(...values) {
  const value = values.find((item) => typeof item === "string" && item.trim());
  return value ? value.trim() : "";
}
