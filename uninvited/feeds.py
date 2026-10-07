"""Published threat feed: filtered address lists, built off the request path.

An address goes on the attacker list only if the honeypot can stand behind it.
Three rules, all static and readable:

  1. The source is real. Every listener is TCP except SIP over UDP, and a UDP
     source address can be forged by anyone. A completed TCP handshake cannot.
     UDP-only sources are never published.
  2. It did something. A bare connection or port scan is recorded on the
     dashboard but does not count toward the list. Credential attempts, exploit
     requests and relay probes do.
  3. It is what the classifier says it is. Research scanners and Tor exits are
     published as their own lists, never mixed into the attacker list.

Each list is written as plain text, JSON, CSV, and (attackers only) STIX 2.1,
plus one MISP feed. All of them are rebuilt from a read-only connection every
few minutes and held in memory, so subscribers never touch SQLite and never
contend with the honeypot's writes. Content that has not changed keeps its
ETag and Last-Modified, so polling clients get 304s.
"""
from __future__ import annotations

import csv
import email.utils
import hashlib
import io
import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from . import classify, defender, digest, history, intel, notables, stix, taxii, urlfeed
from .core import iso_utc
from .identity import Identity
from .textsafe import csv_cell

log = logging.getLogger("uninvited.feeds")

REFRESH_SECONDS = 300
CRAWLER_KEEP = 86400      # seconds a confirmed crawler name is trusted
CRAWLER_RETRY = 600       # seconds before an unconfirmed one is looked up again

# Bumped when a field is renamed or removed. Adding fields does not bump it.
# 1.0 (2026-09-30): first published schema, tags, host type and expiry included.
SCHEMA_VERSION = "1.0"

# What changed in the published data, newest last. Breaking changes bump
# SCHEMA_VERSION; additions are listed here so a consumer can see them coming.
CHANGELOG = [
    {"date": "2026-09-30", "schema_version": "1.0", "change": "first published schema"},
    {"date": "2026-10-01", "schema_version": "1.0",
     "change": "added Modbus tags ics-recon and ics-write and ATT&CK for ICS technique ids "
               "T1692.001, T0888, T0801 (STIX source mitre-ics-attack)"},
    {"date": "2026-10-01", "schema_version": "1.0",
     "change": "added /feed/status.json and /feed/changes/{list}?since= for net additions "
               "and removals"},
    {"date": "2026-10-02", "schema_version": "1.0",
     "change": "added a read-only TAXII 2.1 server at /taxii2/ (five collections, the same STIX "
               "indicators as the bundle files) and a taxii block in /feed/index.json"},
    {"date": "2026-10-02", "schema_version": "1.0",
     "change": "a reverse DNS name that names a scanner or a big crawler now has to resolve forward "
               "to the same address before the host is kept off the attacker list; a scanner "
               "believed on its name alone is listed as an attacker as soon as it tries a password "
               "or an exploit"},
    {"date": "2026-10-02", "schema_version": "1.0",
     "change": "added the malware-urls-24h, -7d and -30d lists (txt, json, csv, STIX url indicators, and a "
               "TAXII collection): download addresses attackers asked the honeypot to fetch, listed when "
               "two hosts delivered them or the host delivered its own. Nothing is fetched. New tag "
               "malware-delivery, new ATT&CK id T1105 on hosts that sent a download command, and the web "
               "classifier now names malware droppers, shell command injection, and TLS or SOCKS sent "
               "to a web port"},
    {"date": "2026-10-02", "schema_version": "1.0",
     "change": "added the ja3 field (TLS client fingerprint) to every attacker, research and Tor record, and a "
               "ja3 column at the end of the CSV files"},
    {"date": "2026-10-02", "schema_version": "1.0",
     "change": "CSV cells that start with = + - or @ now carry a leading apostrophe so spreadsheets "
               "read them as text"},
    {"date": "2026-10-03", "schema_version": "1.0",
     "change": "MISP feed, after an import into a stock MISP 2.5.48: every address carries first_seen, "
               "last_seen, an uninvited:score tag and its ATT&CK techniques as mitre-attack-pattern "
               "galaxy tags (also on the event); CVEs tried are vulnerability attributes; an address "
               "that left the list in the last two weeks is sent with deleted set so MISP removes it; "
               "the event timestamp is the build time and analysis is ongoing"},
    {"date": "2026-10-03", "schema_version": "1.0",
     "change": "MISP feed: an attribute's timestamp is when it last changed, not the host's last activity, "
               "and the event's is the newest of them; MISP only replaces what has a newer timestamp, so "
               "the fields added above had reached 24 of 1,098 addresses in a MISP that already held the event"},
    {"date": "2026-10-03", "schema_version": "1.0",
     "change": "after loading every format into its real consumer: each nftables file fills its own set "
               "(attackers_7d, persistent_7d; was one shared set named bad) and empties it first, so a reload "
               "replaces; the malware URL text files say they hold raw URLs; index.json lists the defender "
               "files; MISP tags carry colours; responses are cached only until the next rebuild; SSH client "
               "fingerprints (hassh) are now captured for every SSH login, not one host in eight"},
    {"date": "2026-10-06", "schema_version": "1.0",
     "change": "an attacker leaves every list at its expires time (3 to 11 days after its last attack) instead of "
               "staying for the whole window, and a malware URL 14 days after it was last asked for; lists are "
               "ordered by score halved for every 3 days without an attack, so the most active come first; "
               "T1110 is now T1110.001 (guessing) or T1110.003 (spraying), file hunts are T1595.003 and product "
               "probes T1595.002 instead of T1190; host_type also comes from the network number; STIX bundles "
               "and TAXII collections carry attack-pattern objects, malware families and the relationships "
               "between them; notable.atom names the address in each entry and carries machine-readable "
               "indicators"},
]

PRECISION_REFRESH = 3600   # the accuracy measure is expensive and slow-moving

# hours -> label used in file names
WINDOWS: dict[int, str] = {24: "24h", 168: "7d", 720: "30d"}

# stem -> (kind, window hours, minimum events). Attackers count events that went
# beyond a bare connection; research and Tor count any verified event.
SPECS: dict[str, tuple[str, int, int]] = {
    "attackers-24h": ("attack", 24, 3),
    "attackers-7d": ("attack", 168, 3),
    "attackers-30d": ("attack", 720, 3),
    "research-7d": ("research", 168, 1),
    "tor-7d": ("tor", 168, 1),
}

MISP_STEM = "attackers-7d"


CONTENT_TYPES = {
    "txt": "text/plain; charset=utf-8",
    "json": "application/json",
    "csv": "text/csv; charset=utf-8",
    "stix": "application/stix+json;version=2.1",
}


def _served_names() -> dict[str, str]:
    """Every published path -> its content type. Static, so unknown names 404
    even while the first build is still running."""
    names: dict[str, str] = {}
    for stem, (kind, _h, _m) in SPECS.items():
        names[f"{stem}.txt"] = CONTENT_TYPES["txt"]
        names[f"{stem}.json"] = CONTENT_TYPES["json"]
        names[f"{stem}.csv"] = CONTENT_TYPES["csv"]
        if kind == "attack":
            names[f"{stem}.stix.json"] = CONTENT_TYPES["stix"]
    for stem in urlfeed.WINDOWS:
        names[f"{stem}.txt"] = CONTENT_TYPES["txt"]
        names[f"{stem}.json"] = CONTENT_TYPES["json"]
        names[f"{stem}.csv"] = CONTENT_TYPES["csv"]
        names[f"{stem}.stix.json"] = CONTENT_TYPES["stix"]
    for tag in intel.TAG_LISTS:
        names[f"tag-{tag}-7d.txt"] = CONTENT_TYPES["txt"]
    names["attackers-high-7d.txt"] = CONTENT_TYPES["txt"]
    names["index.json"] = CONTENT_TYPES["json"]
    names["status.json"] = CONTENT_TYPES["json"]
    names["notable.atom"] = "application/atom+xml; charset=utf-8"
    for stem in defender.IPREP_CATEGORIES:
        names[f"{stem}.nft"] = CONTENT_TYPES["txt"]
        names[f"{stem}.zeek.intel"] = CONTENT_TYPES["txt"]
        names[f"{stem}.iprep.list"] = CONTENT_TYPES["txt"]
    names["iprep-categories.txt"] = CONTENT_TYPES["txt"]
    names["misp/manifest.json"] = CONTENT_TYPES["json"]
    names["misp/hashes.csv"] = CONTENT_TYPES["csv"]
    return names        # plus the MISP event file, whose name comes from the site (FeedCache.names)


NAMES: dict[str, str] = _served_names()


def _change_lists() -> tuple[str, ...]:
    """The lists whose additions and removals are tracked: every attacker,
    research and Tor list, the behaviour lists and the high-confidence cut."""
    return (tuple(SPECS) + tuple(f"tag-{t}-7d" for t in intel.TAG_LISTS)
            + ("attackers-high-7d",))


CHANGE_LISTS: tuple[str, ...] = _change_lists()

# A knock counts as verified when its source address cannot have been forged.
#
# json_extract yields NULL for a missing key and NOT NULL is NULL, so each
# expression is wrapped to always come out 0 or 1. Rows whose detail is not
# valid JSON are treated as ordinary TCP events rather than raising.
def _field(name: str, default: str) -> str:
    return (f"COALESCE(CASE WHEN json_valid(k.detail) "
            f"THEN json_extract(k.detail, '$.{name}') END, {default})")


_UDP = f"({_field('source', chr(39) + chr(39))} = 'udp')"
_SCAN = f"({_field('scan', '0')} = 1)"
_EXPLOIT = _field("exploit", chr(39) + chr(39))
# What an industrial-protocol client did: write, identity or read.
_ICS = _field("ics", chr(39) + chr(39))

# Real attack events per address inside a time span. Used to ask, of the hosts
# that qualified for the list a day or a week ago, how many came back.
_ENGAGED_IPS_SQL = f"""
SELECT k.ip AS ip, COUNT(*) AS n FROM knocks k
WHERE k.ts > ? AND k.ts <= ? AND NOT {_UDP} AND NOT {_SCAN}
GROUP BY k.ip
"""

# How many different usernames and passwords each address tried: spraying or guessing.
_SPREAD_SQL = """
SELECT ip, COUNT(DISTINCT username) AS users, COUNT(DISTINCT password) AS passwords
FROM knocks WHERE ts >= ? AND password IS NOT NULL GROUP BY ip
"""

_AGG_SQL = f"""
SELECT k.ip AS ip, k.proto AS proto, {_EXPLOIT} AS exploit, {_ICS} AS ics,
       SUM(CASE WHEN NOT {_UDP} THEN 1 ELSE 0 END)                    AS verified,
       SUM(CASE WHEN NOT {_UDP} AND NOT {_SCAN} THEN 1 ELSE 0 END)    AS engaged,
       SUM(CASE WHEN NOT {_UDP} AND NOT {_SCAN}
                 AND (k.username IS NOT NULL OR k.password IS NOT NULL) THEN 1 ELSE 0 END) AS creds,
       MIN(k.ts) AS first_ts,
       MAX(k.ts) AS last_ts
FROM knocks k
WHERE k.ts >= ?
GROUP BY k.ip, k.proto, exploit, ics
"""


@dataclass
class Snapshot:
    body: bytes
    etag: str
    modified: float
    content_type: str = CONTENT_TYPES["txt"]

    @property
    def last_modified(self) -> str:
        return email.utils.formatdate(self.modified, usegmt=True)


def _networks(entries: Iterable[str]) -> list:
    out = []
    for raw in entries or []:
        try:
            out.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            log.warning("feed.exclude entry ignored, not an address: %r", raw)
    return out


class FeedCache:
    def __init__(self, db_path: str, exclude: Iterable[str] = (),
                 state_path: str | None = None, ident: Identity | None = None):
        self.db_path = db_path
        # Who publishes: the address and name every file carries, and the namespace every
        # identifier is derived from, so they stay stable from one rebuild to the next.
        self.ident = ident or Identity()
        self.site, self.brand, self.ns = self.ident.site, self.ident.brand, self.ident.ns
        self.org_uuid = str(uuid.uuid5(self.ns, "organisation"))
        self.misp_event_uuid = str(uuid.uuid5(self.ns, "misp-event-" + MISP_STEM))
        self.names = {**NAMES, f"misp/{self.misp_event_uuid}.json": CONTENT_TYPES["json"]}
        # MISP attribute uuid -> (its content, when that content last changed). See _misp.
        self._misp_marks: dict[str, tuple[str, int]] = {}
        self.exclude = _networks(exclude)
        # Additions and removals per list, kept across restarts when a state
        # file is given.
        self.history = history.ListHistory(state_path)
        self._hlock = threading.Lock()
        self.confirm = classify.forward_confirms      # replaced in tests
        self._crawlers: dict[str, tuple[bool, float]] = {}
        self.stix = stix.Maker(self.site, self.brand, self.ns)
        taxii_state = (os.path.join(os.path.dirname(os.path.abspath(state_path)), "taxii_state.json")
                       if state_path else None)
        self.taxii = taxii.TaxiiState(self.stix, self.ns, taxii_state)
        self._url_counts: dict[str, int] = {}
        # Download URLs seen in the last week that the list rule has not confirmed (urlfeed.unconfirmed).
        self.unconfirmed: list[dict[str, Any]] = []
        self._list_rows: dict[str, tuple[str, list[dict[str, Any]]]] = {}
        self._as_of: int = 0
        # The weekly digest: the current one in memory, one JSON file per ISO week on disk.
        self.digest: dict[str, Any] | None = None
        self.digest_dir = (os.path.join(os.path.dirname(os.path.abspath(state_path)), "digests")
                           if state_path else None)
        self.files: dict[str, Snapshot] = {}
        # hours -> per-address rows for that window; feeds /api/blocklist too.
        self.windows: dict[int, list[dict[str, Any]]] = {}
        self.by_ip: dict[int, dict[str, dict[str, Any]]] = {}
        self.built_at: float = 0.0
        self.precision: dict[str, Any] = {}
        self._precision_at: float = 0.0
        self._spread: dict[str, tuple[int, int]] = {}
        self._spread_at: float = 0.0

    # ------------------------------------------------------------ building

    def _crawler_confirmed(self, ip: str, rdns: str) -> bool:
        """Does a reverse name under a big crawler's domain resolve forward to this
        address? Anyone can put "crawl-1.googlebot.com" in the reverse zone of their
        own address, and the protection below would then let them attack unlisted.
        A yes is kept for a day, a no for ten minutes (a DNS hiccup should not
        stick)."""
        now = time.time()
        hit = self._crawlers.get(ip)
        if hit and now - hit[1] < (CRAWLER_KEEP if hit[0] else CRAWLER_RETRY):
            return hit[0]
        if len(self._crawlers) > 5000:
            self._crawlers.clear()
        ok = bool(self.confirm(rdns.rstrip("."), ip))
        self._crawlers[ip] = (ok, now)
        return ok

    def _url_host_ok(self, host: str) -> bool:
        """May a download URL on this host be listed? An address goes through the same
        checks as an attacker. A name is refused when it belongs to a big platform, where
        a request naming one of its files is as likely an attempt to get the file blocked."""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            host = host.lower().rstrip(".")
            return not any(host == d or host.endswith("." + d) for d in intel.NEVER_DOMAINS)
        return self._publishable(host)

    def _excluded(self, ip: str) -> bool:
        """Under feed.exclude: the operator's own addresses."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in net for net in self.exclude)

    def _publishable(self, ip: str, rdns: str | None = None) -> bool:
        """Never listed, whatever the host did: private and shared space, the
        addresses in intel.NEVER_ADDRESSES, the big search crawlers (a name under
        their domain that resolves back to the address), and anything under
        feed.exclude in the config."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if not addr.is_global or ip in intel.NEVER_ADDRESSES:
            return False
        if (rdns and rdns.lower().rstrip(".").endswith(intel.NEVER_RDNS_SUFFIXES)
                and self._crawler_confirmed(ip, rdns)):
            return False
        return not any(addr in net for net in self.exclude)

    def _aggregate(self, con: sqlite3.Connection, actors: dict[str, dict[str, Any]],
                   since: int, spread: dict[str, tuple[int, int]] | None = None) -> list[dict[str, Any]]:
        per: dict[str, dict[str, Any]] = {}
        for r in con.execute(_AGG_SQL, (since,)):
            if not r["verified"]:
                continue
            a = per.setdefault(r["ip"], {
                "verified": 0, "engaged": 0, "first_ts": r["first_ts"],
                "last_ts": r["last_ts"], "by_proto": {}, "seen_protos": set(),
                "exploits": {}, "ics": {}, "creds": {},
            })
            a["verified"] += int(r["verified"])
            a["engaged"] += int(r["engaged"] or 0)
            a["first_ts"] = min(a["first_ts"], r["first_ts"])
            a["last_ts"] = max(a["last_ts"], r["last_ts"])
            a["seen_protos"].add(r["proto"])
            if r["engaged"]:
                a["by_proto"][r["proto"]] = a["by_proto"].get(r["proto"], 0) + int(r["engaged"])
                if r["proto"] in intel.HTTP_PROTOS and r["exploit"]:
                    a["exploits"][r["exploit"]] = (
                        a["exploits"].get(r["exploit"], 0) + int(r["engaged"]))
                if r["proto"] in intel.ICS_PROTOS and r["ics"]:
                    a["ics"][r["ics"]] = a["ics"].get(r["ics"], 0) + int(r["engaged"])
                if r["creds"]:
                    a["creds"][r["proto"]] = a["creds"].get(r["proto"], 0) + int(r["creds"])

        rows = []
        for ip, a in per.items():
            meta = actors.get(ip, {})
            if not self._publishable(ip, meta.get("rdns")):
                continue
            techniques, cves = intel.tags(a["by_proto"], a["exploits"], a["ics"], a["creds"],
                                          (spread or {}).get(ip, (0, 0)))
            named = intel.named_exploits(a["exploits"])
            protos = sorted(a["by_proto"]) or sorted(a["seen_protos"])
            # The actors table remembers when an address was first and last
            # seen across the whole database, which is what persistence means.
            # Inside a 24 hour window nothing could look older than a day.
            life_first = min(a["first_ts"], meta.get("first_ts") or a["first_ts"])
            life_last = max(a["last_ts"], meta.get("last_ts") or a["last_ts"])
            htype = intel.host_type(meta.get("isp"), meta.get("rdns"), meta.get("asn"))
            kind = meta.get("kind") or "attack"
            rows.append({
                "ip": ip, "kind": kind,
                "classification": intel.CLASSIFICATION.get(kind, kind),
                "label": meta.get("label"),
                "verified": a["verified"], "engaged": a["engaged"],
                "first_ts": life_first, "last_ts": a["last_ts"],
                "span": life_last - life_first,
                "protocols": protos, "exploits": named,
                "n_proto": len(a["by_proto"]), "n_exploit": len(named),
                "techniques": techniques, "cves": cves,
                "tags": intel.behaviour_tags(a["by_proto"], a["exploits"], cves,
                                             life_last - life_first, a["ics"], a["creds"]),
                "host_type": htype, "collateral": intel.COLLATERAL[htype],
                "iso": meta.get("iso"), "country": meta.get("country"),
                "asn": meta.get("asn"), "network": meta.get("isp"),
                "hassh": meta.get("hassh"), "ja3": meta.get("ja3"),
                "score": None, "expires_ts": None,
            })
        return rows

    @staticmethod
    def _score(windows: dict[int, list[dict[str, Any]]]) -> None:
        """One score per address, from the longest window, so the same host
        carries the same number in every file."""
        longest = {r["ip"]: r for r in windows[max(WINDOWS)]}
        for rows in windows.values():
            for r in rows:
                if r["kind"] != "attack":
                    continue
                b = longest.get(r["ip"], r)
                r["score"] = intel.score(b["engaged"], b["n_proto"],
                                         b["span"], b["n_exploit"])
                # When it leaves the lists, unless it attacks again.
                r["expires_ts"] = r["last_ts"] + 86400 * intel.ttl_days(
                    r["host_type"], r["score"])

    def _listable(self, ip: str, actors: dict[str, dict[str, Any]]) -> bool:
        meta = actors.get(ip, {})
        return ((meta.get("kind") or "attack") == "attack"
                and self._publishable(ip, meta.get("rdns")))

    def _measure_precision(self, con: sqlite3.Connection,
                           actors: dict[str, dict[str, Any]], now: int) -> dict[str, Any]:
        """Of the hosts that qualified a day ago, and a week ago, how many
        attacked again since. Computed from the raw table, so the claim can be
        checked. Hosts that went quiet count against the feed."""
        def tally(ips: list[str], after: set[str]) -> dict[str, Any]:
            back = sum(1 for ip in ips if ip in after)
            return {"listed": len(ips), "returned": back,
                    "rate": round(back / len(ips), 3) if ips else None}

        # Tiers by how many real attack events the host had in the window
        # before the cut. If they matter, heavier hosts come back more often.
        tiers = (("3-9", 3, 9), ("10-49", 10, 49), ("50+", 50, 10 ** 9))
        out: dict[str, Any] = {}
        for label, span in (("next_24h", 86400), ("next_7d", 7 * 86400)):
            cut = now - span
            before = {r["ip"]: r["n"] for r in con.execute(_ENGAGED_IPS_SQL, (cut - span, cut))}
            after = {r["ip"] for r in con.execute(_ENGAGED_IPS_SQL, (cut, now))}
            listed = [ip for ip, n in before.items() if n >= 3 and self._listable(ip, actors)]
            res = tally(listed, after)
            res["by_events"] = {
                name: tally([ip for ip in listed if lo <= before[ip] <= hi], after)
                for name, lo, hi in tiers}
            # Hosts already on record a week before the cut.
            res["long_standing"] = tally(
                [ip for ip in listed
                 if (actors.get(ip, {}).get("first_ts") or cut) <= cut - 7 * 86400], after)
            out[label] = res
        out["measured_at"] = iso_utc(now)
        out["meaning"] = ("Of the hosts that qualified for the list at that time, the share that "
                          "attacked this server again since. One server sees a small slice of the "
                          "internet, so this understates how many kept attacking elsewhere.")
        return out

    def refresh(self) -> None:
        """Blocking. Run it in an executor."""
        now = int(time.time())
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=15)
        con.row_factory = sqlite3.Row
        try:
            actors = {
                r["ip"]: dict(r) for r in con.execute(
                    "SELECT ip, kind, label, iso, country, isp, asn, hassh, ja3, rdns, "
                    "first_ts, last_ts FROM actors")
            }
            # Guessing or spraying changes slowly and the query costs as much as the aggregate, so hourly.
            if not self._spread_at or now - self._spread_at > PRECISION_REFRESH:
                self._spread = {r["ip"]: (r["users"], r["passwords"])
                                for r in con.execute(_SPREAD_SQL, (now - max(WINDOWS) * 3600,))}
                self._spread_at = now
            spread = self._spread
            windows = {hours: self._aggregate(con, actors, now - hours * 3600, spread)
                       for hours in WINDOWS}
            url_rows = urlfeed.read(con, now, self._url_host_ok)
            unconfirmed = urlfeed.unconfirmed(con, now, self._url_host_ok, lambda ip: not self._excluded(ip))
            # The Atom feed is not behind the dashboard's scrubber, so an excluded address
            # (the operator testing from home) is kept out of it here.
            notable_items = [i for i in notables.from_connection(con, 24, now)
                             if not i.get("ip") or not self._excluded(i["ip"])]
            if not self.precision or now - self._precision_at > PRECISION_REFRESH:
                self.precision = self._measure_precision(con, actors, now)
                self._precision_at = now
        finally:
            con.close()
        self._score(windows)

        files: dict[str, Snapshot] = {}
        counts = []
        selected: dict[str, list[dict[str, Any]]] = {}
        curated: list[dict[str, Any]] = []
        list_rows: dict[str, tuple[str, list[dict[str, Any]]]] = {}
        for stem, (kind, hours, min_hits) in SPECS.items():
            rows = self._select(windows[hours], kind, min_hits, now)
            selected[stem] = rows
            list_rows[stem] = (kind, rows)
            counts.append(f"{stem}={len(rows)}")
            files[f"{stem}.txt"] = self._txt(kind, hours, min_hits, rows)
            files[f"{stem}.json"] = self._json(kind, hours, min_hits, rows)
            files[f"{stem}.csv"] = self._csv(rows)
            if kind == "attack":
                files[f"{stem}.stix.json"] = self._stix(hours, rows)
            if stem == MISP_STEM:
                files.update(self._misp(hours, rows, now))

        # Subsets of the 7 day list: one per behaviour, and the high-confidence cut.
        week = selected["attackers-7d"]
        for tag in intel.TAG_LISTS:
            rows = [r for r in week if tag in r["tags"]]
            list_rows[f"tag-{tag}-7d"] = ("attack", rows)
            files[f"tag-{tag}-7d.txt"] = self._txt(
                "attack", 168, 3, rows, subtitle=f"tagged {tag}, {intel.TAG_DESCRIPTIONS[tag]}")
            curated.append({"name": f"tag-{tag}-7d", "count": len(rows),
                            "file": f"/feed/tag-{tag}-7d.txt",
                            "meaning": intel.TAG_DESCRIPTIONS[tag]})
        high = [r for r in week if (r["score"] or 0) >= intel.HIGH_SCORE]
        list_rows["attackers-high-7d"] = ("attack", high)
        files["attackers-high-7d.txt"] = self._txt(
            "attack", 168, 3, high, subtitle=f"score {intel.HIGH_SCORE} or higher")
        curated.append({"name": "attackers-high-7d", "count": len(high),
                        "file": "/feed/attackers-high-7d.txt",
                        "meaning": f"score {intel.HIGH_SCORE} or higher"})
        url_lists: dict[str, list[dict[str, Any]]] = {}
        for stem, hours in urlfeed.WINDOWS.items():
            rows = urlfeed.window(url_rows, hours, now)
            url_lists[stem] = rows
            counts.append(f"{stem}={len(rows)}")
            files[f"{stem}.txt"] = self._snap(urlfeed.txt(self.brand, self.site, hours, rows), CONTENT_TYPES["txt"])
            files[f"{stem}.json"] = self._snap(
                urlfeed.json_doc(self.brand, self.site, SCHEMA_VERSION, hours, rows), CONTENT_TYPES["json"])
            files[f"{stem}.csv"] = self._snap(urlfeed.csv_text(rows), CONTENT_TYPES["csv"])
            files[f"{stem}.stix.json"] = self._snap(
                json.dumps(self.stix.url_bundle(hours, rows), indent=1) + "\n", CONTENT_TYPES["stix"])
        self._url_counts = {s: len(r) for s, r in url_lists.items()}
        self.taxii.update({**{s: list_rows[s][1] for s in taxii.STEMS if s in list_rows},
                           **{s: url_lists[s] for s in taxii.STEMS if s in url_lists}}, now)
        # Defender formats and the notable-events feed, rendered from lists already built above.
        for stem in defender.IPREP_CATEGORIES:
            rows = list_rows[stem][1]
            files[f"{stem}.nft"] = self._snap(defender.nft_set(self.brand, self.site, stem, rows, now), CONTENT_TYPES["txt"])
            files[f"{stem}.zeek.intel"] = self._snap(defender.zeek_intel(self.brand, self.site, stem, rows, now), CONTENT_TYPES["txt"])
            files[f"{stem}.iprep.list"] = self._snap(defender.iprep_list(stem, rows), CONTENT_TYPES["txt"])
        files["iprep-categories.txt"] = self._snap(defender.iprep_categories(), CONTENT_TYPES["txt"])
        files["notable.atom"] = self._snap(
            notables.atom(notable_items, self.brand, self.site, now, {r["url"] for r in url_rows}),
            NAMES["notable.atom"])
        files["index.json"] = self._index(selected, curated)
        try:
            con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=15)
            con.row_factory = sqlite3.Row
            try:
                week = digest.build(digest._Via(con), json.loads(files["index.json"].body), now)
            finally:
                con.close()
            self.digest = week
            if self.digest_dir:
                os.makedirs(self.digest_dir, exist_ok=True)
                tmp = os.path.join(self.digest_dir, week["id"] + ".json.tmp")
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(week, fh)
                os.replace(tmp, os.path.join(self.digest_dir, week["id"] + ".json"))
        except Exception:
            log.exception("digest not built")

        # Record who joined and left each list, then publish the status page
        # (which reports how far back that history reaches).
        with self._hlock:
            self.history.update({n: {r["ip"] for r in rows}
                                 for n, (_k, rows) in list_rows.items()}, now)
        files["status.json"] = self._status(list_rows, now)

        # Content that did not change keeps its old Last-Modified.
        for name, snap in files.items():
            old = self.files.get(name)
            snap.modified = old.modified if old and old.etag == snap.etag else float(now)

        # Swap in one step so a request never sees half of a rebuild.
        self.by_ip = {h: {r["ip"]: r for r in rows} for h, rows in windows.items()}
        self.windows, self.files, self.built_at = windows, files, time.time()
        self._list_rows, self._as_of = list_rows, now
        self.unconfirmed = unconfirmed
        log.info("feed rebuilt: %s", ", ".join(counts))

    @staticmethod
    def _select(rows: list[dict[str, Any]], kind: str, min_hits: int, now: float) -> list[dict[str, Any]]:
        """The hosts on one list. An attacker is on it until its expiry, and the list is ordered by
        score halved for every few quiet days (intel.rank), so the most active come first."""
        if kind != "attack":
            picked = [r for r in rows if r["kind"] == kind and r["verified"] >= min_hits]
            picked.sort(key=lambda r: (-r["verified"], r["ip"]))
            return picked
        picked = [r for r in rows if r["kind"] == kind and r["engaged"] >= min_hits
                  and (r["expires_ts"] or 0) >= now]
        picked.sort(key=lambda r: (-intel.rank(r["score"], now - r["last_ts"]), -r["engaged"], r["ip"]))
        return picked

    # ------------------------------------------------------------ renderers

    @staticmethod
    def _snap(body: str | bytes, content_type: str) -> Snapshot:
        data = body.encode() if isinstance(body, str) else body
        return Snapshot(body=data, etag='"' + hashlib.sha1(data).hexdigest()[:16] + '"',
                        modified=0.0, content_type=content_type)

    @staticmethod
    def _rule(kind: str, min_hits: int) -> str:
        if kind == "attack":
            return ("TCP-verified sources with at least "
                    f"{min_hits} credential or exploit events")
        return "TCP-verified sources seen at all"

    @staticmethod
    def _what(kind: str) -> str:
        return {"attack": "attacking hosts", "research": "research scanners",
                "tor": "Tor exit nodes"}[kind]

    def _txt(self, kind: str, hours: int, min_hits: int, rows: list[dict[str, Any]],
             subtitle: str | None = None) -> Snapshot:
        newest = iso_utc(max((r["last_ts"] for r in rows), default=0)) or "none"
        head = [
            f"# {self.brand} feed: {self._what(kind)} ({self.site})",
            f"# window {WINDOWS[hours]}. rule: {self._rule(kind, min_hits)}.",
        ]
        if subtitle:
            head.append(f"# subset: {subtitle}.")
        head += [
            "# UDP-only sources are never listed, they can be spoofed.",
            f"# newest listed activity: {newest}",
            f"# {len(rows)} addresses, one per line"
            + (", most active first. Each leaves 3 to 11 days after its last attack." if kind == "attack" else "."),
        ]
        return self._snap("\n".join(head + [r["ip"] for r in rows]) + "\n", CONTENT_TYPES["txt"])

    @staticmethod
    def _record(r: dict[str, Any], kind: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ip": r["ip"],
            "first_seen": iso_utc(r["first_ts"]),
            "last_seen": iso_utc(r["last_ts"]),
            "events": r["engaged"] if kind == "attack" else r["verified"],
            "protocols": r["protocols"],
            "country": r["iso"],
            "asn": r["asn"],
            "network": r["network"],
            "attack_techniques": r["techniques"],
            "cves": r["cves"],
            "exploits": r["exploits"],
            "hassh": r["hassh"],
            "ja3": r.get("ja3"),
            "label": r["label"],
            "classification": r["classification"],
            "tags": r["tags"],
            "host_type": r["host_type"],
            "collateral_risk": r["collateral"],
        }
        if kind == "attack":
            out["score"] = r["score"]
            out["expires"] = iso_utc(r["expires_ts"])
        return out

    def _json(self, kind: str, hours: int, min_hits: int, rows: list[dict[str, Any]]) -> Snapshot:
        doc = {
            "schema_version": SCHEMA_VERSION,
            "feed": f"{self.brand} {self._what(kind)}",
            "source": self.site,
            "window": WINDOWS[hours],
            "rule": self._rule(kind, min_hits) + ". UDP-only sources are never listed.",
            "score": ("0 to 100. volume, breadth, persistence and named exploits, see intel.py. "
                      "The list is ordered by score halved for every 3 days without an attack"
                      if kind == "attack" else None),
            "fields": {
                "tags": "what the host did, in plain words",
                "host_type": "hosting, isp or unknown, a guess from the network number and name",
                "collateral_risk": "low for hosting, medium for isp (may be shared or reassigned)",
                "expires": "when it leaves this list unless it attacks again: 3 to 11 days after its last "
                           "attack, shorter for consumer lines, longer for strong evidence",
                "hassh": "SSH client fingerprint. Hosts with the same value run the same SSH client software",
                "ja3": "TLS client fingerprint (JA3), from a TLS hello sent to a plain web port. Hosts with the same "
                       "value run the same TLS stack",
            },
            "count": len(rows),
            "indicators": [self._record(r, kind) for r in rows],
        }
        return self._snap(json.dumps(doc, indent=1) + "\n", CONTENT_TYPES["json"])

    def _csv(self, rows: list[dict[str, Any]]) -> Snapshot:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["ip", "first_seen", "last_seen", "events", "score", "protocols",
                    "country", "asn", "network", "hassh", "attack_techniques",
                    "cves", "exploits", "label", "classification", "tags",
                    "host_type", "collateral_risk", "expires", "ja3"])
        for r in rows:
            w.writerow([csv_cell(c) for c in [
                r["ip"], iso_utc(r["first_ts"]), iso_utc(r["last_ts"]),
                r["engaged"] if r["kind"] == "attack" else r["verified"],
                "" if r["score"] is None else r["score"],
                ";".join(r["protocols"]), r["iso"] or "", r["asn"] or "",
                r["network"] or "", r["hassh"] or "", ";".join(r["techniques"]),
                ";".join(r["cves"]), ";".join(r["exploits"]), r["label"] or "",
                r["classification"], ";".join(r["tags"]), r["host_type"], r["collateral"],
                iso_utc(r["expires_ts"]) or "", r.get("ja3") or "",
            ]])
        return self._snap(buf.getvalue(), CONTENT_TYPES["csv"])

    def _index(self, selected: dict[str, list[dict[str, Any]]],
               curated: list[dict[str, Any]]) -> Snapshot:
        """Catalog of every list, plus the numbers the dashboard's Feed tab
        needs, so that page loads one small file instead of the big ones."""
        lists = []
        for stem, (kind, hours, min_hits) in SPECS.items():
            files = {ext: f"/feed/{stem}.{ext}" for ext in ("txt", "json", "csv")}
            if kind == "attack":
                files["stix"] = f"/feed/{stem}.stix.json"
            lists.append({
                "name": stem, "kind": kind, "window": WINDOWS[hours],
                "count": len(selected[stem]), "rule": self._rule(kind, min_hits),
                "files": files,
            })
        day, week, month = (selected["attackers-24h"], selected["attackers-7d"],
                            selected["attackers-30d"])
        now = time.time()

        techniques = Counter(t for r in day for t in r["techniques"])
        tag_counts = Counter(t for r in day for t in r["tags"])
        host_types = Counter(r["host_type"] for r in week)
        protocols = Counter(p for r in day for p in r["protocols"])
        countries = Counter((r["iso"], r["country"]) for r in week if r["iso"])
        networks = Counter((r["asn"], r["network"]) for r in week if r["asn"] or r["network"])

        def ranked(counter: Counter, keys: tuple[str, ...], limit: int = 8) -> list[dict[str, Any]]:
            top = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:limit]
            return [dict(zip(keys, k), count=n) for k, n in top]

        edges = ((0, 19), (20, 39), (40, 59), (60, 79), (80, 100))
        spread = [{"range": f"{lo}-{hi}",
                   "count": sum(1 for r in month if lo <= (r["score"] or 0) <= hi)}
                  for lo, hi in edges]

        def top(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return [self._record(r, "attack") for r in rows[:15]]

        newest = max((r["last_ts"] for rows in selected.values() for r in rows), default=0)
        doc = {
            "schema_version": SCHEMA_VERSION,
            "site": self.site,
            "brand": self.brand,
            "generated": iso_utc(now),
            "rebuilt_every_seconds": REFRESH_SECONDS,
            "newest_activity": iso_utc(newest),
            "lists": lists,
            "url_lists": [{"name": stem, "window": urlfeed.LABELS[hours],
                           "count": self._url_counts.get(stem, 0), "rule": urlfeed.RULE,
                           "files": {ext: f"/feed/{stem}.{ext}" for ext in ("txt", "json", "csv", "stix.json")}}
                          for stem, hours in urlfeed.WINDOWS.items()],
            "curated": curated,
            "defender": [{"name": stem, "nft_set": defender.nft_name(stem),
                          "files": {"nft": f"/feed/{stem}.nft", "zeek": f"/feed/{stem}.zeek.intel",
                                    "iprep": f"/feed/{stem}.iprep.list"},
                          "iprep_category": cid}
                         for stem, (cid, _desc) in defender.IPREP_CATEGORIES.items()],
            "iprep_categories": "/feed/iprep-categories.txt",
            "notable": "/feed/notable.atom",
            "precision": self.precision,
            "tag_meanings": intel.TAG_DESCRIPTIONS,
            "tags_24h": dict(sorted(tag_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "host_types_7d": dict(sorted(host_types.items(), key=lambda kv: (-kv[1], kv[0]))),
            "misp": {"feed_url": f"https://{self.site}/feed/misp",
                     "manifest": "/feed/misp/manifest.json"},
            "taxii": {"version": "2.1", "discovery": f"https://{self.site}/taxii2/",
                      "api_root": f"https://{self.site}/taxii2/root/",
                      "collections": [{"id": self.taxii.ids[s], "name": s,
                                       "title": taxii.COLLECTIONS[s][0], "count": self.taxii.count(s)}
                                      for s in taxii.STEMS]},
            "status": "/feed/status.json",
            "changes": "/feed/changes/{list}?since={time}",
            "changes_lists": list(CHANGE_LISTS),
            "new_24h": sum(1 for r in day if r["first_ts"] >= now - 86400),
            "techniques_24h": dict(sorted(techniques.items(), key=lambda kv: (-kv[1], kv[0]))),
            "protocols_24h": dict(sorted(protocols.items(), key=lambda kv: (-kv[1], kv[0]))),
            "countries_7d": ranked(countries, ("iso", "country")),
            "networks_7d": ranked(networks, ("asn", "network")),
            "score_spread_30d": spread,
            "top": {"24h": top(day), "7d": top(week), "30d": top(month)},
            "top_24h": [self._record(r, "attack") for r in day[:12]],
            "cves_30d": [{"ip": r["ip"], "cves": r["cves"], "last_seen": iso_utc(r["last_ts"])}
                         for r in month if r["cves"]],
        }
        return self._snap(json.dumps(doc, indent=1) + "\n", CONTENT_TYPES["json"])

    def _stix(self, hours: int, rows: list[dict[str, Any]]) -> Snapshot:
        """STIX 2.1 bundle (the objects are built in stix.py, shared with TAXII)."""
        return self._snap(json.dumps(self.stix.bundle(hours, rows), indent=1) + "\n",
                          CONTENT_TYPES["stix"])

    def _misp(self, hours: int, rows: list[dict[str, Any]], now: int) -> dict[str, Snapshot]:
        """MISP feed: manifest.json, hashes.csv, and one event per file.

        One event, updated in place: its uuid never changes. Each address carries its first and
        last activity, its score as a tag, and its ATT&CK techniques as MISP galaxy tags; the CVEs
        tried this week are vulnerability attributes. An address that left the list within the
        history kept (two weeks) is sent with deleted set, which is how MISP removes it.

        MISP replaces an event, and each attribute inside it, only when the timestamp is newer than
        its own copy. So an attribute's timestamp is when its content last changed (remembered from
        one rebuild to the next), not when the host was last active, and the event's is the newest
        of those. After a restart everything is new once, which makes every MISP take it all again."""
        date = time.strftime("%Y-%m-%d", time.gmtime(now))
        info = f"{self.brand} honeypot: hosts that attacked {self.site} in the last {WINDOWS[hours]}"
        orgc = {"name": self.site, "uuid": self.org_uuid}

        def misp_time(ts: int) -> str:
            return time.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00", time.gmtime(ts))

        def galaxy(technique: str) -> dict[str, str]:
            return {"name": f'misp-galaxy:mitre-attack-pattern="{intel.MISP_ATTACK[technique]}"', "colour": "#0088cc"}

        attributes, hashes, techniques, cves = [], [], set(), {}
        for r in rows:
            comment = f"score {r['score']}; {r['engaged']} events; " + ", ".join(r["techniques"])
            if r["cves"]:
                comment += "; " + ", ".join(r["cves"])
            known = [t for t in r["techniques"] if t in intel.MISP_ATTACK]
            techniques.update(known)
            for cve in r["cves"]:
                cves.setdefault(cve, []).append(r["ip"])
            attributes.append({
                "uuid": str(uuid.uuid5(self.ns, "attribute-" + r["ip"])),
                "type": "ip-src", "category": "Network activity",
                "value": r["ip"], "to_ids": True, "comment": comment,
                "first_seen": misp_time(r["first_ts"]), "last_seen": misp_time(r["last_ts"]),
                "Tag": ([{"name": f'uninvited:tag="{t}"', "colour": "#c0392b"} for t in r["tags"]]
                        + [{"name": f'uninvited:score="{r["score"]}"', "colour": "#7f8c8d"}]
                        + [galaxy(t) for t in known]),
            })
            hashes.append(f"{hashlib.md5(r['ip'].encode()).hexdigest()},{self.misp_event_uuid}")
        for cve, ips in sorted(cves.items()):
            attributes.append({
                "uuid": str(uuid.uuid5(self.ns, "vulnerability-" + cve)),
                "type": "vulnerability", "category": "External analysis", "value": cve, "to_ids": False,
                "comment": f"tried by {len(ips)} host{'s' if len(ips) != 1 else ''} on this list: " + ", ".join(sorted(ips)[:20]),
            })
            hashes.append(f"{hashlib.md5(cve.encode()).hexdigest()},{self.misp_event_uuid}")
        listed = {r["ip"] for r in rows}
        stem = f"attackers-{WINDOWS[hours]}"
        with self._hlock:
            gone = (self.history.removed(stem) | (self.history.members.get(stem, set()) - listed)) - listed
        for ip in sorted(gone):
            attributes.append({
                "uuid": str(uuid.uuid5(self.ns, "attribute-" + ip)), "type": "ip-src",
                "category": "Network activity", "value": ip, "to_ids": False, "deleted": True,
                "comment": "left the list",
            })
        # Every tag carries a colour: MISP logs a warning for each one that does not.
        tags = ([{"name": "tlp:clear", "colour": "#ffffff"}, {"name": "type:OSINT", "colour": "#004646"},
                 {"name": 'osint:source-type="block-or-filter-list"', "colour": "#004646"}]
                + [galaxy(t) for t in sorted(techniques)])
        marks: dict[str, tuple[str, int]] = {}

        def stamp(key: str, content: Any) -> int:
            mark = json.dumps(content, sort_keys=True)
            old = self._misp_marks.get(key)
            marks[key] = (mark, old[1] if old and old[0] == mark else now)
            return marks[key][1]

        for a in attributes:
            a["timestamp"] = str(stamp(a["uuid"], a))
        changed = max([stamp("event", [info, tags])] + [int(a["timestamp"]) for a in attributes])
        self._misp_marks = marks                       # forget attributes that are no longer sent
        event = {"Event": {
            "uuid": self.misp_event_uuid, "info": info, "date": date,
            "threat_level_id": "3", "analysis": "1", "published": True,
            "timestamp": str(changed), "publish_timestamp": str(changed),
            "Orgc": orgc, "Org": orgc, "Tag": tags, "Attribute": attributes,
        }}
        manifest = {self.misp_event_uuid: {
            "Orgc": orgc, "Tag": tags, "info": info, "date": date,
            "analysis": "1", "threat_level_id": "3", "timestamp": str(changed),
        }}
        return {
            "misp/manifest.json": self._snap(json.dumps(manifest, indent=1) + "\n", CONTENT_TYPES["json"]),
            "misp/hashes.csv": self._snap("\n".join(hashes) + ("\n" if hashes else ""), CONTENT_TYPES["csv"]),
            f"misp/{self.misp_event_uuid}.json": self._snap(json.dumps(event, indent=1) + "\n", CONTENT_TYPES["json"]),
        }

    # ------------------------------------------------------------- serving

    @property
    def ready(self) -> bool:
        return bool(self.files)

    def get(self, name: str) -> Snapshot | None:
        return self.files.get(name)

    def _status(self, list_rows: dict[str, tuple[str, list[dict[str, Any]]]], now: int) -> Snapshot:
        doc = {
            "schema_version": SCHEMA_VERSION,
            "site": self.site,
            "generated": iso_utc(now),
            "rebuilt_every_seconds": REFRESH_SECONDS,
            "lists": {n: len(rows) for n, (_k, rows) in list_rows.items()},
            "url_lists": dict(self._url_counts),
            "changes": {
                "endpoint": f"https://{self.site}/feed/changes/{{list}}?since={{time}}",
                "since_accepts": "an ISO 8601 time or epoch seconds; default the last 24 hours",
                "history_days": history.KEEP_SECONDS // 86400,
                "history_from": {n: iso_utc(self.history.history_from(n)) for n in list_rows},
                "recorded": self.history.size(),
            },
            "changelog": CHANGELOG,
        }
        return self._snap(json.dumps(doc, indent=1) + "\n", CONTENT_TYPES["json"])

    def changes(self, name: str, since: int) -> dict[str, Any] | None:
        """Net additions and removals on one list since `since`. None for a
        list that does not exist. See history.py for what 'net' means."""
        if name not in CHANGE_LISTS or not self.ready:
            return None
        with self._hlock:
            net = self.history.net_changes(name, since)
            start = self.history.history_from(name)
        if net is None:
            return None
        kind, rows = self._list_rows.get(name, ("attack", []))
        by_ip = {r["ip"]: r for r in rows}
        return {
            "schema_version": SCHEMA_VERSION,
            "list": name,
            "since": iso_utc(since),
            "as_of": iso_utc(self._as_of),
            "as_of_epoch": self._as_of,
            "history_from": iso_utc(start),
            "reset": net["reset"],
            "reset_meaning": ("Your copy is older than the history kept here. Fetch the whole "
                              "list again, then use as_of as your next since."
                              if net["reset"] else None),
            "added": [self._record(by_ip[ip], kind) if ip in by_ip else {"ip": ip}
                      for ip in net["added"]],
            "removed": net["removed"],
            "count_now": len(rows),
            "use": ("Add the 'added' addresses to your copy, drop the 'removed' ones, "
                    "and send as_of_epoch as since next time."),
        }

    def lookup(self, ip: str, threshold: int = 3) -> dict[str, Any]:
        """Is this address on the feed, and if not, why not. Answers from the
        in-memory build, so it costs no database work."""
        listed: dict[str, bool] = {}
        row: dict[str, Any] | None = None
        now = time.time()
        for hours, label in WINDOWS.items():
            r = self.by_ip.get(hours, {}).get(ip)
            listed[label] = bool(r and r["kind"] == "attack" and r["engaged"] >= threshold
                                 and (r["expires_ts"] or 0) >= now)
            if r is not None:
                row = r          # the longest window that saw it wins
        out: dict[str, Any] = {"listed": listed, "score": None, "techniques": [],
                               "cves": [], "exploits": [], "engaged_30d": 0,
                               "tags": [], "host_type": None, "collateral_risk": None,
                               "expires": None}
        if row is not None:
            out.update(score=row["score"], techniques=row["techniques"], cves=row["cves"],
                       exploits=row["exploits"], engaged_30d=row["engaged"],
                       kind=row["kind"], tags=row["tags"], host_type=row["host_type"],
                       collateral_risk=row["collateral"], expires=iso_utc(row["expires_ts"]))
        return out

    def blocklist(self, hours: int, min_hits: int) -> list[str]:
        """Backs /api/blocklist. Same rules as the published attacker lists.

        `hours` is honoured by last-seen time. `min_hits` is counted over the
        smallest published window that contains it, which can be a little wider.
        """
        window = next((w for w in sorted(WINDOWS) if w >= hours), max(WINDOWS))
        now = time.time()
        cutoff = now - hours * 3600
        rows = [r for r in self.windows.get(window, [])
                if r["kind"] == "attack" and r["engaged"] >= min_hits
                and (r["last_ts"] or 0) >= cutoff and (r["expires_ts"] or 0) >= now]
        rows.sort(key=lambda r: (-intel.rank(r["score"], now - r["last_ts"]), -r["engaged"], r["ip"]))
        return [r["ip"] for r in rows]
