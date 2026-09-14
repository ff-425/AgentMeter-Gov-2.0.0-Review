"""Reconcile individual review requests with OpenClaw approval/release events."""
from __future__ import annotations

import json
from datetime import datetime, timezone


def review_id(event: dict) -> str:
    # Old dashboard envelopes put AGR IDs in approval_id. APP IDs are grants,
    # never request IDs and must not be used in /agentmeter approve commands.
    explicit = event.get("review_id") or ""
    legacy = event.get("approval_id") or ""
    return explicit or (legacy if legacy.startswith("AGR-") else "")


def _calls(event: dict) -> set[str]:
    return {event[key] for key in ("call_id", "tool_call_id", "operation_id") if event.get(key)}


def _operation_tool(event: dict) -> str:
    proposed = event.get("proposed_tool_call") or {}
    name = str(event.get("tool_name") or proposed.get("name") or "")
    aliases = {
        "read": "read_file", "read_document": "read_file",
        "write": "write_file", "write_document": "write_file",
        "edit": "edit_file", "edit_document": "edit_file", "apply_patch": "edit_file",
        "exec": "run_shell",
    }
    return aliases.get(name, name)


def _same_operation(left: dict, right: dict) -> bool:
    a, b = _calls(left), _calls(right)
    if a and b:
        return bool(a & b)
    lp, rp = left.get("proposed_tool_call") or {}, right.get("proposed_tool_call") or {}
    tool_a, tool_b = _operation_tool(left), _operation_tool(right)
    params_a, params_b = left.get("parameters") or lp.get("params"), right.get("parameters") or rp.get("params")
    # Pair the decision and its subsequent pending envelope one-to-one only
    # when the complete operation agrees. A tool name alone proves nothing.
    return bool(tool_a and tool_a == tool_b and params_a and params_b
                and json.dumps(params_a, sort_keys=True) == json.dumps(params_b, sort_keys=True))


def _time(event: dict) -> datetime:
    try:
        value = datetime.fromisoformat(str(event.get("timestamp") or "").replace("Z", "+00:00"))
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def reconcile_reviews(grouped: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Return review state per original task, without moving raw audit events.

    Approval replies may have a different task ID. Resolve them by a unique
    review ID and compatible session; ambiguous/no-ID replies stay unresolved.
    """
    result = {key: [] for key in grouped}
    for key, events in grouped.items():
        reviews = result[key]
        for event_index, event in enumerate(sorted(events, key=_time)):
            pending = event.get("event_type") == "pending_review_event"
            decision = event.get("event_type") == "risk_decision_event" and event.get("gate_action") == "human_review"
            if not (pending or decision):
                continue
            identifier = review_id(event)
            matches = [r for r in reviews if identifier and r["review_id"] == identifier]
            unpaired = [r for r in reviews if not r.get("paired")
                        and r["request_event"].get("event_type") != event.get("event_type")
                        and (not r["review_id"] or not identifier or r["review_id"] == identifier)
                        and _same_operation(r["request_event"], event)]
            if not matches:
                matches = unpaired[-1:]
            elif pending and unpaired:
                # Retried decisions may reuse the same pending request ID.
                for duplicate in unpaired:
                    if duplicate is not matches[0] and not duplicate["review_id"]:
                        reviews.remove(duplicate)
            if matches:
                match = matches[0]
                if match["request_event"].get("event_type") != event.get("event_type"):
                    match["paired"] = True
                if pending and match["request_event"].get("event_type") != "pending_review_event":
                    matches[0]["request_event"] = event
                match["review_id"] = identifier or match["review_id"]
                continue
            reviews.append({"review_key": f"{key}:review:{event_index}", "review_id": identifier,
                            "approval_id": "", "state": "pending", "request_event": event,
                            "resolution_event": None})

    all_reviews = [(key, review) for key, reviews in result.items() for review in reviews]
    by_id: dict[str, list[tuple[str, dict]]] = {}
    by_grant: dict[str, list[tuple[str, dict]]] = {}
    for owner, review in all_reviews:
        if review["review_id"]:
            by_id.setdefault(review["review_id"], []).append((owner, review))
    resolutions = sorted(((key, event) for key, events in grouped.items() for event in events
                          if event.get("event_type") == "approval_event"
                          or (event.get("event_type") == "risk_decision_event"
                              and event.get("gate_action") == "human_review_approved")), key=lambda pair: _time(pair[1]))
    for task_key, event in resolutions:
        if event.get("approval_scope") == "no_pending_review":
            continue
        released = event.get("gate_action") == "human_review_approved"
        decision = str(event.get("review_decision") or "").lower()
        if not released and decision not in {"approve", "reject"}:
            continue
        identifier = review_id(event)
        grant = event.get("approval_id") or ""
        candidates = []
        pool = by_id.get(identifier, []) if identifier else by_grant.get(grant, []) if released and grant else [(task_key, review) for review in result[task_key]]
        for owner, review in pool:
            request = review["request_event"]
            session, source_session = event.get("session_key"), request.get("session_key")
            if session and source_session and session != source_session:
                continue
            if _time(event) < _time(request):
                continue
            if identifier:
                matches = review["review_id"] == identifier
            elif released and grant:
                matches = bool(review["approval_id"] and review["approval_id"] == grant)
            elif released:
                matches = owner == task_key and _same_operation(request, event)
            else:
                matches = owner == task_key and bool(_calls(request) & _calls(event))
            if matches:
                candidates.append((owner, review))
        if len(candidates) != 1:
            continue
        owner, review = candidates[0]
        # Approval grants alone never prove execution. A release is terminal
        # for this request; duplicate late approval envelopes cannot undo it.
        if review["state"] in {"released", "rejected"}:
            continue
        review["state"] = "released" if released else "approved" if decision == "approve" else "rejected"
        if grant and review["approval_id"] != grant:
            by_grant.setdefault(grant, []).append((owner, review))
        review["approval_id"] = grant or review["approval_id"]
        review["resolution_event"] = event
    return result


def task_status(events: list[dict], reviews: list[dict]) -> str:
    states = {review["state"] for review in reviews}
    if "pending" in states:
        return "awaiting_review"
    actions = {event.get("gate_action") for event in events if event.get("event_type") == "risk_decision_event"}
    if actions & {"block", "deny"}:
        return "blocked"
    if "rejected" in states:
        return "review_rejected"
    if "approved" in states:
        return "approved_awaiting_retry"
    results = [event for event in events if event.get("event_type") == "result_event"]
    if results:
        outcome = str(results[-1].get("execution_result") or results[-1].get("status") or "completed").lower()
        if outcome not in {"pending", "awaiting_review", "running"}:
            return "failed" if outcome in {"failed", "error"} else "completed"
    return "running"
