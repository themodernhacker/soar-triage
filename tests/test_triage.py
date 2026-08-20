"""
Unit tests for the soar-triage pipeline.

Runs with zero API keys and zero live network access: AbuseIPDB and GitHub are
both mocked. Covers every triage disposition branch plus the enrichment
classification and the reasoning log.

    python -m unittest discover -s tests        # or:  python tests/test_triage.py
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import enrich   # noqa: E402
import triage   # noqa: E402
import ticket   # noqa: E402


def make_alert(level, rule_id="100002", src_ip="203.0.113.10", desc="test alert", mitre=None):
    return {
        "rule": {"id": str(rule_id), "level": level, "description": desc,
                 "mitre": {"id": mitre or []}},
        "data": {"src_ip": src_ip},
    }


def enrichment(category="public", available=False, abuse_score=None, ip="203.0.113.10"):
    return {
        "ip": ip, "category": category, "is_public": category == "public",
        "reason": f"{category} test",
        "reputation": {"available": available, "abuse_score": abuse_score,
                       "note": "ok" if available else "skipped"},
    }


class TestDispositionBranches(unittest.TestCase):
    """The four branches the brief calls out."""

    def test_below_threshold_logs_only(self):
        d = triage.decide(make_alert(5), enrichment(category="private"))
        self.assertEqual(d["disposition"], "logged")
        self.assertFalse(d["create_ticket"])

    def test_private_ip_mid_level_is_triaged(self):
        d = triage.decide(make_alert(10, rule_id="100108"), enrichment(category="private", ip="172.19.0.1"))
        self.assertEqual(d["disposition"], "auto-triaged")
        self.assertTrue(d["create_ticket"])
        self.assertEqual(d["priority"], "medium")

    def test_public_low_score_high_level_falls_through_to_triage(self):
        # level 12 but a non-correlation rule and a low abuse score -> no confirm
        d = triage.decide(make_alert(12, rule_id="100002"),
                          enrichment(category="public", available=True, abuse_score=10))
        self.assertEqual(d["disposition"], "auto-triaged")
        self.assertTrue(d["create_ticket"])

    def test_public_high_score_high_level_is_confirmed(self):
        d = triage.decide(make_alert(12, rule_id="100002"),
                          enrichment(category="public", available=True, abuse_score=90))
        self.assertEqual(d["disposition"], "auto-confirmed")
        self.assertEqual(d["priority"], "high")
        self.assertTrue(any("AbuseIPDB score of 90" in r for r in d["reasoning"]))

    def test_correlation_rule_confirms_even_on_private_ip(self):
        # rule 100105 is a correlation rule, so a level-12 alert is corroborated
        d = triage.decide(make_alert(12, rule_id="100105"), enrichment(category="private", ip="172.19.0.1"))
        self.assertEqual(d["disposition"], "auto-confirmed")
        self.assertTrue(d["correlated"])
        self.assertTrue(any("correlation rule" in r for r in d["reasoning"]))


class TestReasoningLog(unittest.TestCase):
    def test_decision_is_logged_with_reasoning(self):
        alert = make_alert(12, rule_id="100105", src_ip="172.19.0.1")
        enr = enrichment(category="private", ip="172.19.0.1")
        d = triage.decide(alert, enr)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "decisions.log")
            triage.log_decision(d, alert, enr, path=path)
            with open(path, encoding="utf-8") as fh:
                line = fh.read().strip()
        record = json.loads(line)
        self.assertEqual(record["disposition"], "auto-confirmed")
        self.assertEqual(record["src_ip"], "172.19.0.1")
        self.assertTrue(record["reasoning"])
        self.assertIn("ts", record)


class TestEnrichmentClassification(unittest.TestCase):
    def test_private_reserved_public_invalid(self):
        self.assertEqual(enrich.classify_ip("172.19.0.1").category, "private")
        self.assertEqual(enrich.classify_ip("203.0.113.10").category, "reserved")   # TEST-NET-3
        self.assertEqual(enrich.classify_ip("127.0.0.1").category, "loopback")
        pub = enrich.classify_ip("8.8.8.8")
        self.assertEqual(pub.category, "public")
        self.assertTrue(pub.is_public)
        self.assertEqual(enrich.classify_ip(None).category, "missing")
        self.assertEqual(enrich.classify_ip("not-an-ip").category, "invalid")

    def test_private_ip_skips_external_lookup(self):
        alert = make_alert(12, src_ip="172.19.0.1")
        with patch.object(enrich, "lookup_abuseipdb") as m:
            out = enrich.enrich(alert, api_key="unused")
            m.assert_not_called()
        self.assertFalse(out["reputation"]["available"])
        self.assertEqual(out["category"], "private")

    def test_public_ip_uses_mocked_reputation(self):
        alert = make_alert(12, src_ip="8.8.8.8")
        fake = enrich.Reputation(available=True, abuse_score=77, country="US", isp="Example")
        with patch.object(enrich, "lookup_abuseipdb", return_value=fake) as m:
            out = enrich.enrich(alert, api_key="key")
            m.assert_called_once()
        self.assertTrue(out["reputation"]["available"])
        self.assertEqual(out["reputation"]["abuse_score"], 77)

    def test_abuseipdb_missing_key_is_graceful(self):
        rep = enrich.lookup_abuseipdb("8.8.8.8", api_key=None)
        self.assertFalse(rep.available)
        self.assertIn("no ABUSEIPDB_API_KEY", rep.note)


class TestTicket(unittest.TestCase):
    def test_format_issue_contains_key_fields(self):
        alert = make_alert(12, rule_id="100105", desc="successful login after brute force",
                           mitre=["T1078", "T1110"])
        d = triage.decide(alert, enrichment(category="private", ip="172.19.0.1"))
        title, body, labels = ticket.format_issue(alert, enrichment(category="private", ip="172.19.0.1"), d)
        self.assertIn("100105", title)
        self.assertIn("auto-confirmed", title)
        self.assertIn("T1078", body)
        self.assertIn("Why the automation decided this", body)
        self.assertIn("priority:high", labels)

    def test_create_issue_without_token_is_noop(self):
        r = ticket.create_issue("t", "b", repo="owner/repo", token=None)
        self.assertFalse(r["created"])
        self.assertIn("no GITHUB_TOKEN", r["reason"])

    def test_create_issue_success_is_mocked(self):
        class FakeResp:
            def __init__(self, data): self._d = data.encode()
            def read(self): return self._d
            def __enter__(self): return self
            def __exit__(self, *a): return False

        payload = json.dumps({"number": 7, "html_url": "https://github.com/x/soar-triage/issues/7"})
        with patch("ticket.urllib.request.urlopen", return_value=FakeResp(payload)) as m:
            r = ticket.create_issue("t", "b", repo="x/soar-triage", token="fake-token", labels=["soar-triage"])
            m.assert_called_once()
        self.assertTrue(r["created"])
        self.assertEqual(r["number"], 7)
        self.assertTrue(r["url"].endswith("/7"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
