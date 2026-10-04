"""Sample feed rows, in the shape FeedCache._aggregate produces, for tests that need
published output without a database."""
from __future__ import annotations

from uninvited.identity import Identity

NOW = 1_790_000_000      # a fixed 'now', so output never depends on the clock

# The reference deployment. The published-bytes fixtures were captured from it, so tests that
# compare against them run as it, which also proves the published identifiers never moved.
LIVE = Identity(site="dmz.ahmadmesto.com", owner="Ahmad Mesto", owner_title="Security Engineer",
                owner_url="https://ahmadmesto.com")


def row(ip: str, **over):
    base = {
        "ip": ip, "kind": "attack", "classification": "malicious", "label": None,
        "verified": 12, "engaged": 9, "first_ts": NOW - 5 * 86400, "last_ts": NOW - 3600,
        "span": 5 * 86400 - 3600, "protocols": ["SSH"], "exploits": [], "n_proto": 1,
        "n_exploit": 0, "techniques": ["T1110"], "cves": [], "tags": ["ssh-bruteforce"],
        "host_type": "hosting", "collateral": "low", "iso": "NL", "country": "Netherlands",
        "asn": 64500, "network": "Example Hosting BV", "hassh": "ae8bd7dd09970555aa4ea8ab1b0b1e1c",
        "score": 55, "expires_ts": NOW - 3600 + 7 * 86400,
    }
    base.update(over)
    return base


def rows():
    """Six hosts that between them exercise every branch of the STIX builder."""
    return [
        row("198.51.100.20"),
        row("198.51.100.21", protocols=["HTTP", "CAM"], techniques=["T1190"], exploits=["Hikvision RCE (CVE-2021-36260)"],
            cves=["CVE-2021-36260"], tags=["web-exploit", "camera-exploit"], engaged=40, score=82,
            first_ts=NOW - 86400, last_ts=NOW - 600, host_type="isp", collateral="medium",
            expires_ts=NOW - 600 + 5 * 86400),
        row("203.0.113.30", protocols=["MODBUS", "S7"], techniques=["T1692.001", "T0888", "T0801"],
            tags=["ics-write", "ics-recon"], engaged=5, score=40, hassh=None, iso=None, country=None,
            asn=None, network=None, host_type="unknown", collateral="unknown"),
        row("2001:db8::7", protocols=["TNET", "SSH"], techniques=["T1110"], tags=["telnet-bruteforce", "persistent"],
            engaged=900, score=97, first_ts=NOW - 29 * 86400, last_ts=NOW - 60,
            expires_ts=NOW - 60 + 10 * 86400, network="=SUM(1+1) Telecom"),
        row("192.0.2.99", protocols=["HTTP"], techniques=["T1595.002"], exploits=[], tags=[],
            engaged=3, score=12, first_ts=NOW - 7200, last_ts=NOW - 7200, expires_ts=NOW - 7200 + 3 * 86400),
        row("198.51.100.22", protocols=["RDP"], techniques=["T1021.001"], tags=["rdp-scan"], engaged=7, score=30,
            first_ts=NOW - 2 * 86400, last_ts=NOW - 86400, expires_ts=NOW - 86400 + 5 * 86400),
    ]
