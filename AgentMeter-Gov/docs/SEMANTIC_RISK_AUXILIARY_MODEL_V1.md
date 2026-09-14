# AgentMeter-Gov Semantic Auxiliary Model V1

## Position

This module is not a replacement for the nine-factor risk metering model.
It is an auxiliary signal layer for:

- I: intent drift risk
- G: goal shift risk
- U: user behavior anomaly risk

The main decision is still explainable and factor-based. Semantic matching only
raises evidence when the user's original goal and the proposed OpenClaw tool
call look inconsistent, or when the case is close to a known government-enterprise
risk prototype.

## Selected Model

First neural backend:

```text
BAAI/bge-small-zh-v1.5
```

Reason:

- Strong Chinese semantic retrieval capability.
- Small enough for local prototype use.
- Suitable for comparing user goal, tool action, and risk-case prototypes.
- Easier to explain in the competition than a black-box end-to-end classifier.

## Runtime Modes

Default mode:

```text
AGENTMETER_SEMANTIC_BACKEND=fallback
```

This uses deterministic lexical/prototype matching and requires no model
download. It is used to keep the OpenClaw guard stable during live tests.

Neural mode:

```powershell
$env:AGENTMETER_SEMANTIC_BACKEND="bge"
$env:AGENTMETER_SEMANTIC_MODEL="BAAI/bge-small-zh-v1.5"
```

Neural mode requires `sentence-transformers` and its local model files.

Disable mode:

```powershell
$env:AGENTMETER_SEMANTIC_BACKEND="off"
```

## Output Fields

Each risk decision includes:

- `semantic_analysis.backend`
- `semantic_analysis.model_name`
- `semantic_analysis.goal_action_similarity`
- `semantic_analysis.risk_similarity_score`
- `semantic_analysis.matched_category`
- `semantic_analysis.intent_drift_boost`
- `semantic_analysis.goal_shift_boost`
- `semantic_analysis.user_anomaly_boost`
- `semantic_analysis.reasons`

## Prototype Library

Prototype file:

```text
AgentMeter-Gov/data/semantic_risk_prototypes_v1.json
```

Each category contains:

- `category`
- `risk_level`
- `factor_hints`
- `texts`

The first group can add real OpenClaw attack cases into `texts`. The second
group can then test whether the semantic layer improves I/G/U scoring.

## Design Principle

The semantic layer can increase risk evidence, but it should not silently reduce
security requirements. A user's historical habit can explain why a behavior is
familiar, but it cannot prove that an unusual high-risk action is safe.
