"""
triage.py - the decision step.

Deliberately a short, explicit rule set an analyst could read and audit in
thirty seconds, not a black box. Being able to say *why* a disposition was
reached is a security-engineering principle, not a shortcut: an automated
decision needs the same accountability as a human analyst's, so every decision
is written to a reasoning log with the facts it was based on.

Dispositions:
  - CONFIRMED  (high priority)          -> level >= 12 AND (public IP over the
                                           abuse threshold OR the alert came from
                                           a correlation rule, i.e. it is already
                                           corroborated across multiple lab rules)
  - TRIAGED    (needs analyst review)   -> level >= 10 otherwise
  - LOGGED     (no ticket)              -> anything lower

Standard library only.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

# Thresholds, kept as named constants so the policy is visible and tunable.
CONFIRM_LEVEL = 12          # Wazuh level at/above which we consider auto-confirming
TRIAGE_LEVEL = 10           # Wazuh level at/above which we open a review ticket
ABUSE_SCORE_THRESHOLD = 50  # AbuseIPDB confidence score (0-100) that counts as "bad"

# Correlation / composite rules in the honeypot-siem ruleset. An alert from one
# of these is, by construction, corroborated by more than one event, so it counts
# as "already correlated across multiple lab rules".
CORRELATION_RULE_IDS = {"100104", "100105", "100110", "100151"}

DEFAULT_LOG = os.environ.get(
    "SOAR_TRIAGE_LOG",
    os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs", "decisions.log")),
)


def _rule(alert: dict) -> dict:
    return alert.get("rule") or {}


def is_correlated(alert: dict) -> bool:
    return str(_rule(alert).get("id")) in CORRELATION_RULE_IDS


def decide(alert: dict, enrichment: dict) -> dict:
    """Return a disposition dict. Pure function: no I/O, easy to unit test."""
    rule = _rule(alert)
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    rule_id = str(rule.get("id", "?"))

    rep = (enrichment or {}).get("reputation") or {}
    abuse_score = rep.get("abuse_score")
    public_bad = bool(rep.get("available") and isinstance(abuse_score, int)
                      and abuse_score >= ABUSE_SCORE_THRESHOLD)
    correlated = is_correlated(alert)

    reasoning = [f"rule {rule_id} fired at level {level}"]

    if level >= CONFIRM_LEVEL and (public_bad or correlated):
        disposition, priority, create_ticket = "auto-confirmed", "high", True
        if public_bad:
            reasoning.append(
                f"source IP has an AbuseIPDB score of {abuse_score} "
                f"(>= {ABUSE_SCORE_THRESHOLD}), treated as known-bad")
        if correlated:
            reasoning.append(
                f"rule {rule_id} is a correlation rule, so the alert is "
                "corroborated across multiple detections, not a single event")
        reasoning.append(f"level {level} >= {CONFIRM_LEVEL} with corroboration -> auto-confirm at high priority")
    elif level >= TRIAGE_LEVEL:
        disposition, priority, create_ticket = "auto-triaged", "medium", True
        reasoning.append(
            f"level {level} >= {TRIAGE_LEVEL} but no strong corroboration "
            "(no high abuse score and not a correlation rule) -> open a ticket for analyst review")
    else:
        disposition, priority, create_ticket = "logged", "low", False
        reasoning.append(f"level {level} < {TRIAGE_LEVEL} -> log only, no ticket raised")

    ip_cat = (enrichment or {}).get("category")
    if ip_cat and ip_cat != "public":
        reasoning.append(f"source IP classified as {ip_cat}, external reputation not applicable")

    return {
        "disposition": disposition,
        "priority": priority,
        "create_ticket": create_ticket,
        "rule_id": rule_id,
        "level": level,
        "correlated": correlated,
        "abuse_score": abuse_score,
        "reasoning": reasoning,
    }


def log_decision(decision: dict, alert: dict, enrichment: dict, path: str = DEFAULT_LOG) -> str:
    """Append one structured, timestamped record of the decision and the facts it
    rested on. Returns the path written. Best-effort: never raises into the pipeline."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "alert_id": alert.get("id") or (alert.get("rule") or {}).get("id"),
        "src_ip": (enrichment or {}).get("ip"),
        "ip_category": (enrichment or {}).get("category"),
        "disposition": decision.get("disposition"),
        "priority": decision.get("priority"),
        "create_ticket": decision.get("create_ticket"),
        "reasoning": decision.get("reasoning"),
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as e:
        # Logging must not take the pipeline down; surface it on stderr only.
        import sys
        print(f"[soar-triage] WARN: could not write decision log to {path}: {e}", file=sys.stderr)
    return path
