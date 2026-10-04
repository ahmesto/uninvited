"""The malware-URL lists: download addresses that attackers asked this honeypot to fetch.

Where the attacker lists name hosts that attacked, these name the infrastructure behind
the attacks. A botnet that exploits a camera sends a command in the same request,
`wget http://203.0.113.9:43777/Mozi.a`, and that address is what the request is for
(droppers.py finds them, the store counts them).

Nothing here fetches anything. A URL is listed because attackers asked for it, not
because anyone looked at what it serves, so the lists say what they know and no more:

  * A URL is listed when it was delivered by at least two different hosts, or when the
    host that delivered it is the host it points at. The first rule is the defence
    against someone sending a request that names a legitimate address to get it blocked,
    which takes two sources instead of one. The second is the common botnet case, an
    infected device offering its own copy, which cannot be aimed at a third party.
  * Never listed: a private or reserved address, anything under feed.exclude, and the
    big platforms in intel.NEVER_DOMAINS.
  * confidence is 50 for one host, 65 for two, 80 for three and 95 for four or more,
    counted over every delivery, and file name hints at the malware family (a hint, not
    an identification).
  * Each entry carries an advisory expiry two weeks after it was last asked for.
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from collections.abc import Callable
from typing import Any

from .core import iso_utc
from .textsafe import csv_cell

# stem -> window in hours
WINDOWS: dict[str, int] = {"malware-urls-24h": 24, "malware-urls-7d": 168, "malware-urls-30d": 720}
LABELS = {24: "24h", 168: "7d", 720: "30d"}
MIN_SOURCES = 2
TTL_DAYS = 14


def confidence(sources: int) -> int:
    return min(95, 35 + 15 * max(1, sources))


def read(con: sqlite3.Connection, now: int, host_ok: Callable[[str], bool]) -> list[dict[str, Any]]:
    """Every URL seen in the last 30 days that passes the rules above, strongest first."""
    rows: list[dict[str, Any]] = []
    for r in con.execute("SELECT * FROM droppers WHERE last_ts >= ?", (now - 30 * 86400,)):
        try:
            sources = json.loads(r["sources"])
            exploits = json.loads(r["exploits"] or "[]")
        except ValueError:
            continue
        n = len(sources)
        if not (r["self_hosted"] or n >= MIN_SOURCES) or not host_ok(r["host"]):
            continue
        rows.append({
            "url": r["url"], "host": r["host"], "port": r["port"], "scheme": r["scheme"],
            "file": r["file"] or None, "family": r["family"], "first_ts": r["first_ts"],
            "last_ts": r["last_ts"], "hits": r["hits"], "sources": n,
            "self_hosted": bool(r["self_hosted"]), "exploits": exploits,
            "confidence": confidence(n), "expires_ts": r["last_ts"] + TTL_DAYS * 86400,
        })
    rows.sort(key=lambda r: (-r["confidence"], -r["last_ts"], r["url"]))
    return rows


def window(rows: list[dict[str, Any]], hours: int, now: int) -> list[dict[str, Any]]:
    return [r for r in rows if r["last_ts"] >= now - hours * 3600]


def record(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": r["url"], "host": r["host"], "port": r["port"], "scheme": r["scheme"],
        "file": r["file"], "family_hint": r["family"],
        "first_seen": iso_utc(r["first_ts"]), "last_seen": iso_utc(r["last_ts"]),
        "sightings": r["hits"], "sources": r["sources"], "self_hosted": r["self_hosted"],
        "delivered_by": r["exploits"], "confidence": r["confidence"],
        "expires": iso_utc(r["expires_ts"]),
    }


RULE = ("a download address that followed a download command in a request to the honeypot, "
        "delivered by at least 2 different hosts or hosted by the host that sent it. "
        "Listed from what was asked for. Nothing is fetched.")


def txt(brand: str, site: str, hours: int, rows: list[dict[str, Any]]) -> str:
    head = [
        f"# {brand} feed: malware download URLs ({site})",
        f"# window {LABELS[hours]}. rule: {RULE}",
        "# WARNING: live malware URLs in raw form, for proxy and DNS filters. Do not browse to them.",
        "# These are addresses attackers wanted victims to download from. The site shows them defanged.",
        f"# newest: {iso_utc(max((r['last_ts'] for r in rows), default=0)) or 'none'}",
        f"# {len(rows)} URLs, one per line, strongest first.",
    ]
    return "\n".join(head + [r["url"] for r in rows]) + "\n"


def json_doc(brand: str, site: str, schema: str, hours: int, rows: list[dict[str, Any]]) -> str:
    doc = {
        "schema_version": schema,
        "feed": f"{brand} malware download URLs",
        "source": site,
        "window": LABELS[hours],
        "rule": RULE,
        "fields": {
            "sources": "how many different hosts delivered this URL (counted up to 50)",
            "self_hosted": "the host that delivered it is the host it points at",
            "family_hint": "from the file name only. A hint, not an identification.",
            "delivered_by": "what the delivering requests were classified as",
            "confidence": "50 for one source, 65 for two, 80 for three, 95 for four or more",
            "expires": "advisory: drop it from your own copy after this time",
        },
        "count": len(rows),
        "indicators": [record(r) for r in rows],
    }
    return json.dumps(doc, indent=1) + "\n"


def csv_text(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["url", "host", "port", "scheme", "file", "family_hint", "first_seen", "last_seen",
                "sightings", "sources", "self_hosted", "delivered_by", "confidence", "expires"])
    for r in rows:
        w.writerow([csv_cell(c) for c in [
            r["url"], r["host"], r["port"], r["scheme"], r["file"] or "", r["family"] or "",
            iso_utc(r["first_ts"]), iso_utc(r["last_ts"]), r["hits"], r["sources"],
            "true" if r["self_hosted"] else "false", ";".join(r["exploits"]), r["confidence"],
            iso_utc(r["expires_ts"])]])
    return buf.getvalue()
