"""
ticket.py - file the triage result as a GitHub Issue.

This is a real API integration, not a mock: with a token set, running the
pipeline creates an actual Issue in this repo that anyone can open and read. The
body is formatted like incident-investigation-report's incident-ticket.md
(severity, summary, IOCs, enrichment, disposition) so the three projects share a
common vocabulary.

Token hygiene: the token comes only from the environment (loaded from .env),
never from code or the repo. Use a fine-grained PAT scoped to Issues:write on the
one repo, nothing broader. Like the enrichment step, every failure mode returns a
result dict rather than raising, so a bad token never crashes the pipeline.

Standard library only.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Optional

GITHUB_API = "https://api.github.com"

_PRIORITY_LABEL = {"high": "priority:high", "medium": "priority:medium", "low": "priority:low"}


def format_issue(alert: dict, enrichment: dict, decision: dict) -> tuple:
    """Build (title, body, labels) from the pipeline outputs. Pure function."""
    rule = alert.get("rule") or {}
    rule_id = rule.get("id", "?")
    level = rule.get("level", "?")
    desc = rule.get("description", "(no description)")
    mitre = ", ".join((rule.get("mitre") or {}).get("id", []) or []) or "n/a"
    ip = enrichment.get("ip") or "unknown"
    cat = enrichment.get("category", "unknown")
    rep = enrichment.get("reputation") or {}

    disposition = decision.get("disposition", "unknown")
    priority = decision.get("priority", "low")

    if rep.get("available"):
        rep_line = (f"AbuseIPDB score {rep.get('abuse_score')} / 100, "
                    f"{rep.get('total_reports')} reports, {rep.get('country')}, {rep.get('isp')}")
    else:
        rep_line = f"not applicable ({rep.get('note', 'enrichment unavailable')})"

    title = f"[{disposition}] rule {rule_id} (level {level}) from {ip}"

    body = f"""**Auto-filed by soar-triage** (automated first-response). This ticket was
created by the triage automation the instant the alert fired, before a human
opened the investigation.

| Field | Value |
|-------|-------|
| Disposition | `{disposition}` |
| Priority | `{priority}` |
| Detected by | rule {rule_id}, level {level} |
| ATT&CK | {mitre} |
| Source IP | {ip} ({cat}) |
| Reputation | {rep_line} |

## Summary

{desc}

## Enrichment

- IP classification: **{cat}** ({enrichment.get('reason', '')})
- Reputation: {rep_line}

## Why the automation decided this

{chr(10).join('- ' + r for r in decision.get('reasoning', []))}

## Next step for the analyst

{"Confirmed high-priority: open the full investigation and begin containment." if priority == "high"
  else "Review this alert and confirm or dismiss; enrichment context is above."}

---
_Lab exercise. `web-prod-01` is a Cowrie honeypot; see
[honeypot-siem](https://github.com/themodernhacker/honeypot-siem) and
[incident-investigation-report](https://github.com/themodernhacker/incident-investigation-report)._
"""

    labels = ["soar-triage", "automated", _PRIORITY_LABEL.get(priority, "priority:low")]
    return title, body, labels


def create_issue(title: str, body: str, repo: Optional[str], token: Optional[str],
                 labels: Optional[list] = None, timeout: float = 8.0) -> dict:
    """POST a new Issue. Never raises: returns {'created': bool, ...}."""
    if not token:
        return {"created": False, "reason": "no GITHUB_TOKEN set, ticket not filed"}
    if not repo:
        return {"created": False, "reason": "no GITHUB_REPO set, ticket not filed"}

    url = f"{GITHUB_API}/repos/{repo}/issues"
    data = json.dumps({"title": title, "body": body, "labels": labels or []}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "soar-triage",
        "Content-Type": "application/json",
    })
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return {"created": True, "number": payload.get("number"), "url": payload.get("html_url")}
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read().decode("utf-8")).get("message", "")
        except Exception:
            pass
        return {"created": False, "reason": f"GitHub HTTP {e.code}: {detail or e.reason}"}
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as e:
        return {"created": False, "reason": f"GitHub network error ({e.__class__.__name__})"}
