#!/usr/bin/env python3
"""
main.py - the soar-triage pipeline entry point.

Wazuh invokes the integration launcher, which calls this with the path to the
alert JSON as the first argument. The flow is:

    load alert  ->  enrich (classify IP + reputation)  ->  triage (decide + log)
                ->  ticket (file a GitHub Issue if the disposition warrants one)

Every step prints a one-line trace to stdout so the live run shows
enrichment -> triage -> ticket in sequence (visible in the Wazuh
integration log / ossec.log and in a manual run).

Credentials come only from the environment, optionally seeded from a .env file
next to the repo root. Nothing secret is read from code or arguments.

Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import enrich as enrich_mod   # noqa: E402
import triage as triage_mod   # noqa: E402
import ticket as ticket_mod   # noqa: E402


def load_env(path: str = None) -> None:
    """Minimal .env loader: KEY=VALUE lines, '#' comments, no dependency on
    python-dotenv. Does not override variables already set in the environment."""
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key, val = key.strip(), val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except OSError:
        pass


def _log(msg: str) -> None:
    """Trace one pipeline step. Prints to stdout (for manual runs) and, when
    SOAR_TRIAGE_TRACE is set, appends to that file too. Wazuh's integratord sends
    the script's stdout to /dev/null, so the file is how a live run is captured."""
    line = f"[soar-triage] {msg}"
    print(line, flush=True)
    trace = os.environ.get("SOAR_TRIAGE_TRACE")
    if trace:
        try:
            with open(trace, "a", encoding="utf-8") as fh:
                fh.write(f"{datetime.now(timezone.utc).isoformat()} {line}\n")
        except OSError:
            pass


def run(alert_path: str) -> dict:
    with open(alert_path, encoding="utf-8") as fh:
        alert = json.load(fh)

    rule = alert.get("rule") or {}
    _log(f"alert received: rule {rule.get('id')} level {rule.get('level')} - {rule.get('description', '')[:70]}")

    # 1. enrich
    enrichment = enrich_mod.enrich(alert, api_key=os.environ.get("ABUSEIPDB_API_KEY"))
    rep = enrichment.get("reputation", {})
    _log(f"enrich: {enrichment.get('ip')} -> {enrichment.get('category')}; "
         f"reputation: {'score ' + str(rep.get('abuse_score')) if rep.get('available') else rep.get('note')}")

    # 2. triage
    decision = triage_mod.decide(alert, enrichment)
    log_path = triage_mod.log_decision(decision, alert, enrichment)
    _log(f"triage: {decision['disposition']} (priority {decision['priority']}); reasoning logged to {log_path}")

    # 3. ticket
    ticket_result = {"created": False, "reason": "no ticket for this disposition"}
    if decision["create_ticket"]:
        title, body, labels = ticket_mod.format_issue(alert, enrichment, decision)
        ticket_result = ticket_mod.create_issue(
            title, body,
            repo=os.environ.get("GITHUB_REPO"),
            token=os.environ.get("GITHUB_TOKEN"),
            labels=labels,
        )
        if ticket_result.get("created"):
            _log(f"ticket: filed GitHub Issue #{ticket_result['number']} -> {ticket_result['url']}")
        else:
            _log(f"ticket: not filed ({ticket_result.get('reason')})")
    else:
        _log("ticket: skipped, disposition does not warrant a ticket")

    return {"enrichment": enrichment, "decision": decision, "ticket": ticket_result}


def main(argv) -> int:
    if len(argv) < 2:
        print("usage: main.py <alert-json-file>", file=sys.stderr)
        return 2
    load_env()
    try:
        run(argv[1])
    except FileNotFoundError:
        print(f"[soar-triage] ERROR: alert file not found: {argv[1]}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"[soar-triage] ERROR: alert file is not valid JSON: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
