"""
enrich.py - alert enrichment for the soar-triage pipeline.

Two jobs, in order:

1. Classify the source IP locally first. Private (RFC 1918), loopback, link-local
   and TEST-NET / documentation (RFC 5737) addresses cannot have a meaningful
   public reputation, so we label them and skip the external lookup entirely. The
   honeypot lab's own traffic comes from an RFC 1918 Docker gateway, so in this
   lab most real runs land in this branch, and that is stated plainly rather than
   hidden.
2. For a genuinely public IP, query AbuseIPDB's free tier for a reputation score.
   A missing key, a rate limit, or a network error must never crash the pipeline:
   we log the failure and return "enrichment unavailable" so the alert still gets
   triaged and ticketed.

Standard library only, so it runs unchanged inside the Wazuh manager container.
"""

from __future__ import annotations

import ipaddress
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Optional

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# RFC 5737 documentation ranges (TEST-NET-1/2/3). ipaddress treats these as
# global, so we check them explicitly rather than relying on is_private.
_TESTNET = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


@dataclass
class Reputation:
    available: bool
    source: str = "abuseipdb"
    abuse_score: Optional[int] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    total_reports: Optional[int] = None
    note: str = ""


@dataclass
class Enrichment:
    ip: Optional[str]
    category: str                      # loopback|private|link-local|reserved|multicast|public|invalid|missing
    is_public: bool
    reason: str
    reputation: Reputation = field(default_factory=lambda: Reputation(available=False))

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def classify_ip(ip: Optional[str]) -> Enrichment:
    """Local, offline classification of a source IP. No network calls."""
    if not ip:
        return Enrichment(ip=ip, category="missing", is_public=False,
                          reason="no source IP present on the alert")
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return Enrichment(ip=ip, category="invalid", is_public=False,
                          reason="source value is not a valid IP address")

    if obj.is_loopback:
        cat, reason = "loopback", "loopback address, not routable"
    elif any(obj in net for net in _TESTNET):
        cat, reason = "reserved", "RFC 5737 TEST-NET (documentation), not routable"
    elif obj.is_private:
        cat, reason = "private", "RFC 1918 private address, not internet-routable"
    elif obj.is_link_local:
        cat, reason = "link-local", "link-local address, not routable"
    elif obj.is_multicast:
        cat, reason = "multicast", "multicast address, not a real host"
    elif obj.is_reserved or obj.is_unspecified:
        cat, reason = "reserved", "reserved address space, not routable"
    else:
        return Enrichment(ip=ip, category="public", is_public=True,
                          reason="public, internet-routable address")

    return Enrichment(ip=ip, category=cat, is_public=False, reason=reason)


def lookup_abuseipdb(ip: str, api_key: Optional[str], timeout: float = 6.0) -> Reputation:
    """Query AbuseIPDB for a public IP. Never raises: every failure mode returns
    an unavailable Reputation with a note explaining why."""
    if not api_key:
        return Reputation(available=False, note="no ABUSEIPDB_API_KEY set, lookup skipped")

    url = f"{ABUSEIPDB_URL}?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            payload = json.loads(resp.read().decode("utf-8")).get("data", {})
        return Reputation(
            available=True,
            abuse_score=payload.get("abuseConfidenceScore"),
            country=payload.get("countryCode"),
            isp=payload.get("isp"),
            total_reports=payload.get("totalReports"),
            note="ok",
        )
    except urllib.error.HTTPError as e:
        if e.code == 429:
            return Reputation(available=False, note="AbuseIPDB rate limit (HTTP 429), continued without reputation")
        if e.code in (401, 403):
            return Reputation(available=False, note=f"AbuseIPDB auth error (HTTP {e.code}), check the API key")
        return Reputation(available=False, note=f"AbuseIPDB HTTP {e.code}, continued without reputation")
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as e:
        return Reputation(available=False, note=f"AbuseIPDB network error ({e.__class__.__name__}), continued without reputation")
    except (ValueError, KeyError) as e:
        return Reputation(available=False, note=f"AbuseIPDB response parse error ({e.__class__.__name__})")


def enrich(alert: dict, api_key: Optional[str] = None) -> dict:
    """Top-level enrichment: classify the alert's source IP, then look up
    reputation only if it is public. Returns a plain dict for triage/ticket."""
    src_ip = (alert.get("data") or {}).get("src_ip") or (alert.get("data") or {}).get("srcip")
    result = classify_ip(src_ip)
    if result.is_public:
        result.reputation = lookup_abuseipdb(result.ip, api_key)
    else:
        result.reputation = Reputation(available=False, note=f"{result.category} IP, external lookup skipped")
    return result.to_dict()
