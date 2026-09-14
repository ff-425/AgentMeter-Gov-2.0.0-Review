export function evaluateSubagentInheritance(parent = {}) {
  const inherited = {
    parentAuditId: parent.auditId ?? parent.taskId ?? "",
    maxRiskScore: Number(parent.maxRiskScore ?? 0),
    blocked: Boolean(parent.blocked),
    tainted: Boolean(parent.tainted || parent.hiddenInstructionDetected),
    authorization: Array.isArray(parent.authorization) ? [...parent.authorization] : [],
    dataLevel: parent.dataLevel ?? "public",
  };
  const denied = inherited.blocked || inherited.tainted || inherited.maxRiskScore >= 75;
  return {
    allowed: !denied,
    inherited,
    reason: denied ? "inherited_parent_risk" : "inherit_and_allow",
  };
}
