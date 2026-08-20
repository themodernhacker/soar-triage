# Case study: manual vs automated triage

This is where the "impact" line on a CV comes from, and where it stays honest.
The claim is not "SOAR is faster" in the abstract; it is a measured comparison of
doing the same first-response by hand versus letting this pipeline do it, with the
caveats stated plainly.

## What is being compared

For a single Wazuh alert (level >= 10), the first-response work is the same three
steps whether a human or the automation does it:

1. **Enrich** the source IP: is it internal, or public, and if public does it have
   a reputation.
2. **Triage**: pick a disposition (confirm / needs-review / log-only) and be able
   to say why.
3. **Ticket**: write it up in a consistent format so the next person can act on it.

The automation is [`src/main.py`](../src/main.py) wired into Wazuh's
`wazuh-integratord`; the manual version is me doing the same three steps by hand.

## Method

**Manual baseline.** Do the three steps by hand, once, on one real alert from a
live run: open the alert in the Wazuh dashboard, look up the source IP's
reputation, decide a disposition, and write a ticket in the same format the
automation produces. Time it wall-clock, start to finished ticket.

**Automated run.** With the integration live, trigger the same alert and time from
the moment the alert fires to the moment the GitHub Issue is filed.

Both are timed on the same lab, the same alert type (the level 12 post-compromise
escalation, rule 100151), so it is a like-for-like comparison.

## Results

| Path | Time | How measured |
|------|------|--------------|
| Manual, by hand | **[ fill in: your single self-timed run ]** | wall clock, dashboard to written ticket |
| Automated, end to end | **[ fill in: alert fires to Issue filed, from your live run ]** | integration log timestamp to GitHub Issue timestamp |
| Automated, compute only | **~0.2 ms median** (50 runs) | enrich + triage + log, measured locally; excludes the network round-trips |

The compute figure is real and measured (the enrichment classification, the
decision, and the reasoning log take a fraction of a millisecond). The end-to-end
automated time is dominated entirely by two network round-trips, the AbuseIPDB
lookup (skipped in this lab, see below) and the GitHub Issue API call, not by the
logic. Fill the two bracketed cells from your own runs; do not estimate them.

## Honest caveats

These matter more than an inflated number:

- **The manual baseline is a single self-timed run, not a rigorous study.** One
  person, one alert, no averaging. It is indicative, not a benchmark, and the CV
  line should carry that qualifier ("reduced a single-run triage from about X to
  about Y") rather than dropping it.
- **In this lab, AbuseIPDB is always skipped.** The honeypot's attacker traffic
  comes from an RFC 1918 Docker gateway, so the enrichment classifies it locally
  and never makes the external call. That is the honest, expected path (the same
  point the IOC notes in `incident-investigation-report` make about lab
  addresses). The AbuseIPDB code path is exercised by the mocked unit tests and
  would light up on real internet-facing traffic.
- **The automation does not replace the analyst.** An `auto-confirmed` ticket is a
  head start, not a verdict: it hands a human an enriched, reasoned ticket to
  action, and it files the low-value ones so they are recorded without costing
  anyone attention. The judgment call on a confirmed incident is still a person's.

## Evidence

From the live run (see [`../evidence/screenshots/`](../evidence/screenshots/)):

1. The Wazuh alert firing in the dashboard.
2. The integration's console/log trace showing enrich -> triage -> ticket in
   sequence, plus the decision log with its reasoning.
3. The resulting GitHub Issue in this repo's Issues tab.

## What this proves

Not that automation is magic, but that the repetitive, mechanical part of
first-response, the part that is identical every time and that burns an analyst's
attention on alerts that turn out to be routine, can be done in the time it takes
a network call to return, with a full reasoning trail, and with the genuinely
interesting alerts handed to a human already enriched and prioritised.
