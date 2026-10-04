"""SQLite persistence.

Two tables carry the whole dashboard:

  knocks    every attempt, pruned on a retention window
  counters  running totals per (kind, proto, key) so leaderboards never
            have to aggregate the raw table at request time

A home server sees a few hundred thousand knocks a month. SQLite in WAL mode
handles that without breaking a sweat, and it means no second daemon to babysit.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import pathlib
import sqlite3
import threading
import time
from typing import Any

from . import payload
from .classify import is_mirai_pair
from .core import Knock
from .intel import GENERIC_EXPLOITS

log = logging.getLogger("uninvited.store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS knocks (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    proto    TEXT    NOT NULL,
    ip       TEXT    NOT NULL,
    port     INTEGER NOT NULL,
    username TEXT,
    password TEXT,
    iso      TEXT,
    country  TEXT,
    region   TEXT,
    city     TEXT,
    lat      REAL,
    lng      REAL,
    asn      INTEGER,
    isp      TEXT,
    lines    TEXT,
    detail   TEXT,
    kind     TEXT,
    label    TEXT,
    hassh    TEXT
);
CREATE INDEX IF NOT EXISTS idx_knocks_ts    ON knocks(ts DESC);
CREATE INDEX IF NOT EXISTS idx_knocks_proto ON knocks(proto, ts DESC);
CREATE INDEX IF NOT EXISTS idx_knocks_ip    ON knocks(ip);

CREATE TABLE IF NOT EXISTS counters (
    kind    TEXT    NOT NULL,
    proto   TEXT    NOT NULL,
    key     TEXT    NOT NULL,
    label   TEXT,
    count   INTEGER NOT NULL DEFAULT 0,
    first_ts INTEGER,
    last_ts INTEGER,
    PRIMARY KEY (kind, proto, key)
);
CREATE INDEX IF NOT EXISTS idx_counters_top ON counters(kind, proto, count DESC);

-- One row per source address. Survives knock pruning, so "seen for 9 days
-- across 3 protocols" stays true after the raw rows age out.
CREATE TABLE IF NOT EXISTS actors (
    ip       TEXT PRIMARY KEY,
    hassh    TEXT,
    first_ts INTEGER,
    last_ts  INTEGER,
    hits     INTEGER NOT NULL DEFAULT 0,
    iso      TEXT,
    country  TEXT,
    isp      TEXT,
    asn      INTEGER,
    protos   TEXT,
    kind     TEXT,
    label    TEXT,
    rdns     TEXT,
    demoted  INTEGER,
    ja3      TEXT
);
CREATE INDEX IF NOT EXISTS idx_actors_hits ON actors(hits DESC);
CREATE INDEX IF NOT EXISTS idx_actors_seen ON actors(last_ts DESC);
CREATE INDEX IF NOT EXISTS idx_actors_kind ON actors(kind, hits DESC);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- One row per distinct request. raw is the first instance seen, as bytes, and
-- is untrusted: only ever shown through payload.escape(). Owner-only.
CREATE TABLE IF NOT EXISTS payloads (
    sha      TEXT PRIMARY KEY,
    proto    TEXT    NOT NULL,
    first_ts INTEGER NOT NULL,
    last_ts  INTEGER NOT NULL,
    count    INTEGER NOT NULL DEFAULT 1,
    raw      BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payloads_first ON payloads(first_ts DESC);

-- Download URLs found in captured requests (droppers.py). One row per URL. sources is a
-- JSON list of the distinct addresses that delivered it, capped; nothing here is fetched.
CREATE TABLE IF NOT EXISTS droppers (
    url         TEXT PRIMARY KEY,
    host        TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    scheme      TEXT    NOT NULL,
    file        TEXT,
    family      TEXT,
    first_ts    INTEGER NOT NULL,
    last_ts     INTEGER NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 1,
    sources     TEXT    NOT NULL,
    self_hosted INTEGER NOT NULL DEFAULT 0,
    exploits    TEXT
);
CREATE INDEX IF NOT EXISTS idx_droppers_last ON droppers(last_ts DESC);

-- "This entry is wrong" notes from visitors. Read by the owner, never served.
CREATE TABLE IF NOT EXISTS reports (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    ip     TEXT    NOT NULL,
    note   TEXT,
    client TEXT
);
"""

MAX_REPORTS = 5000   # a cap, so the form cannot be used to fill the disk
MAX_DROPPERS = 20000  # distinct download URLs kept; past this, new ones are not stored
MAX_SOURCES = 50      # distinct delivering addresses remembered per URL

KINDS = ("loc", "user", "pass", "cred", "isp", "ip")


class Store:
    """One writer connection behind a lock, and a read-only connection per reading
    thread. WAL lets readers run while the writer commits, so a slow dashboard
    query never holds up ingestion and ingestion never holds up a query. (A
    database that is not a file, which only a test would use, falls back to
    sharing the writer.)"""

    def __init__(self, path: str):
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.path = path
        self._memory = path == ":memory:" or path.startswith("file:")
        self._tls = threading.local()
        self._readers: list[sqlite3.Connection] = []
        self._readers_lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.lock = threading.Lock()
        self._migrate()
        self._seed_start_time()

    # ----------------------------------------------------------------- reading

    def _reader(self) -> sqlite3.Connection | None:
        if self._memory:
            return None
        con = getattr(self._tls, "con", None)
        if con is None:
            uri = pathlib.Path(os.path.abspath(self.path)).as_uri() + "?mode=ro"
            con = sqlite3.connect(uri, uri=True, timeout=10, check_same_thread=False)
            con.row_factory = sqlite3.Row
            self._tls.con = con
            with self._readers_lock:
                self._readers.append(con)
        return con

    def _all(self, sql: str, params: Any = ()) -> list[sqlite3.Row]:
        con = self._reader()
        if con is None:
            with self.lock:
                return self.db.execute(sql, params).fetchall()
        return con.execute(sql, params).fetchall()

    def _one(self, sql: str, params: Any = ()) -> sqlite3.Row | None:
        con = self._reader()
        if con is None:
            with self.lock:
                return self.db.execute(sql, params).fetchone()
        return con.execute(sql, params).fetchone()

    # Columns added after the first release. CREATE TABLE IF NOT EXISTS is a
    # no-op on a database that already exists, so new columns have to be
    # ALTERed in or every query touching them fails on an upgraded install.
    MIGRATIONS: dict[str, list[tuple[str, str]]] = {
        "knocks": [("kind", "TEXT"), ("label", "TEXT"), ("hassh", "TEXT")],
        "actors": [("hassh", "TEXT"), ("demoted", "INTEGER"), ("ja3", "TEXT")],
    }

    def _migrate(self) -> None:
        with self.lock:
            for table, columns in self.MIGRATIONS.items():
                exists = self.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()
                if not exists:
                    continue
                have = {r["name"] for r in
                        self.db.execute(f"PRAGMA table_info({table})").fetchall()}
                for name, coltype in columns:
                    if name in have:
                        continue
                    self.db.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {coltype}"
                    )
                    log.info("migrated %s: added column %s", table, name)
            self.db.commit()
        self._backfill_actors()

    def _backfill_actors(self) -> None:
        """Populate actors from history on first upgrade.

        Without this, an existing install shows an empty offenders panel and a
        zeroed attack/research split until enough new traffic arrives, which
        looks broken rather than new.
        """
        with self.lock:
            have = self.db.execute("SELECT COUNT(*) AS n FROM actors").fetchone()["n"]
            knocks = self.db.execute("SELECT COUNT(*) AS n FROM knocks").fetchone()["n"]
            if have or not knocks:
                return
            self.db.execute(
                """INSERT OR IGNORE INTO actors
                   (ip, first_ts, last_ts, hits, iso, country, isp, asn, protos, kind, label)
                   SELECT ip, MIN(ts), MAX(ts), COUNT(*),
                          MAX(iso), MAX(country), MAX(isp), MAX(asn),
                          (SELECT GROUP_CONCAT(DISTINCT proto) FROM knocks k2
                            WHERE k2.ip = k.ip),
                          COALESCE(MAX(kind), 'attack'), MAX(label)
                   FROM knocks k GROUP BY ip"""
            )
            self.db.commit()
            n = self.db.execute("SELECT COUNT(*) AS n FROM actors").fetchone()["n"]
            log.info("backfilled %d actors from %d historical knocks", n, knocks)

    def close(self) -> None:
        with self._readers_lock:
            for con in self._readers:
                try:
                    con.close()
                except sqlite3.Error:
                    pass
            self._readers.clear()
        self._tls = threading.local()
        with self.lock:
            self.db.commit()
            self.db.close()

    # ------------------------------------------------------------------ meta

    def _seed_start_time(self) -> None:
        with self.lock:
            row = self.db.execute(
                "SELECT value FROM meta WHERE key='first_start'"
            ).fetchone()
            if row is None:
                self.db.execute(
                    "INSERT INTO meta(key, value) VALUES('first_start', ?)",
                    (str(int(time.time())),),
                )
                self.db.commit()

    def first_start(self) -> int:
        row = self._one("SELECT value FROM meta WHERE key='first_start'")
        return int(row["value"]) if row else int(time.time())

    # ----------------------------------------------------------------- write

    def _counter_keys(self, knock: Knock) -> list[tuple[str, str, str]]:
        """(kind, key, label) tuples to bump for this knock."""
        pairs = [
            ("loc", knock.iso, knock.country),
            ("isp", knock.isp, knock.isp),
            ("ip", knock.ip, knock.ip),
        ]
        if knock.username is not None:
            pairs.append(("user", knock.username, knock.username))
        if knock.password is not None:
            pairs.append(("pass", knock.password, knock.password))
        cred = knock.cred()
        if cred is not None:
            pairs.append(("cred", cred, cred))
        return pairs

    @staticmethod
    def _keep_payload(cur: sqlite3.Cursor, knock: Knock) -> str | None:
        """Store the request once per signature and count repeats. Returns the
        payload id, or None when the table is full and this one is new."""
        sha = payload.key(knock.raw_sig)
        hit = cur.execute("UPDATE payloads SET count = count + 1, last_ts = ? WHERE sha = ?",
                          (knock.ts, sha)).rowcount
        if hit:
            return sha
        total = cur.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
        if total >= payload.MAX_PAYLOADS:
            return None
        cur.execute(
            "INSERT INTO payloads(sha, proto, first_ts, last_ts, count, raw) "
            "VALUES (?,?,?,?,1,?)",
            (sha, knock.proto, knock.ts, knock.ts, knock.raw[:payload.MAX_RAW]),
        )
        return sha

    @staticmethod
    def _keep_dropper(cur: sqlite3.Cursor, d, knock: Knock) -> None:
        """Count one delivery of a download URL, remembering who delivered it."""
        try:
            own = ipaddress.ip_address(d.host) == ipaddress.ip_address(knock.ip)
        except ValueError:
            own = False
        exploit = (knock.detail or {}).get("exploit")
        row = cur.execute("SELECT sources, exploits FROM droppers WHERE url = ?", (d.url,)).fetchone()
        if row is None:
            if cur.execute("SELECT COUNT(*) FROM droppers").fetchone()[0] >= MAX_DROPPERS:
                return
            cur.execute(
                "INSERT INTO droppers(url, host, port, scheme, file, family, first_ts, last_ts, hits, "
                "sources, self_hosted, exploits) VALUES (?,?,?,?,?,?,?,?,1,?,?,?)",
                (d.url, d.host, d.port, d.scheme, d.file, d.family, knock.ts, knock.ts,
                 json.dumps([knock.ip]), 1 if own else 0, json.dumps([exploit] if exploit else [])))
            return
        sources = json.loads(row["sources"])
        if knock.ip not in sources and len(sources) < MAX_SOURCES:
            sources.append(knock.ip)
        exploits = json.loads(row["exploits"] or "[]")
        if exploit and exploit not in exploits and len(exploits) < 5:
            exploits.append(exploit)
        cur.execute(
            "UPDATE droppers SET hits = hits + 1, last_ts = ?, sources = ?, exploits = ?, "
            "self_hosted = MAX(self_hosted, ?) WHERE url = ?",
            (knock.ts, json.dumps(sources), json.dumps(exploits), 1 if own else 0, d.url))

    def record(self, knock: Knock) -> dict[str, Any]:
        """Persist a knock and return the stats the LAST KNOCK panel needs."""
        pairs = self._counter_keys(knock)
        stats: dict[str, dict[str, Any]] = {}

        with self.lock:
            cur = self.db.cursor()
            if knock.raw and knock.raw_sig:
                sha = self._keep_payload(cur, knock)
                if sha:
                    knock.detail["payload"] = sha
            for d in knock.droppers[:5]:
                self._keep_dropper(cur, d, knock)
            cur.execute(
                """INSERT INTO knocks
                   (ts, proto, ip, port, username, password, iso, country,
                    region, city, lat, lng, asn, isp, lines, detail, kind, label,
                    hassh)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    knock.ts, knock.proto, knock.ip, knock.port,
                    knock.username, knock.password, knock.iso, knock.country,
                    knock.region, knock.city, knock.lat, knock.lng,
                    knock.asn, knock.isp,
                    json.dumps([list(p) for p in knock.lines]),
                    json.dumps(knock.detail),
                    knock.kind, knock.label, knock.hassh,
                ),
            )

            prev_actor = cur.execute(
                "SELECT first_ts, protos FROM actors WHERE ip = ?", (knock.ip,)
            ).fetchone()
            protos = set((prev_actor["protos"] or "").split(",")) if prev_actor else set()
            protos.discard("")
            protos.add(knock.proto)
            # demoted is one-way: a scanner we believed on an unconfirmed name that
            # then tried a password or an exploit stays an attacker, even if a later
            # lookup (after a restart, say) would believe the name again.
            cur.execute(
                """INSERT INTO actors(ip, first_ts, last_ts, hits, iso, country,
                                      isp, asn, protos, kind, label, rdns, hassh, demoted, ja3)
                   VALUES (?,?,?,1,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                     hits = hits + 1, last_ts = excluded.last_ts,
                     iso = excluded.iso, country = excluded.country,
                     isp = excluded.isp, asn = excluded.asn,
                     protos = excluded.protos,
                     kind = CASE WHEN COALESCE(actors.demoted, 0) = 1 OR excluded.demoted = 1
                                 THEN 'attack' ELSE excluded.kind END,
                     label = CASE WHEN COALESCE(actors.demoted, 0) = 1 OR excluded.demoted = 1
                                  THEN NULL ELSE excluded.label END,
                     demoted = MAX(COALESCE(actors.demoted, 0), excluded.demoted),
                     rdns = COALESCE(excluded.rdns, actors.rdns),
                     hassh = COALESCE(excluded.hassh, actors.hassh),
                     ja3 = COALESCE(excluded.ja3, actors.ja3)""",
                (knock.ip, knock.ts, knock.ts, knock.iso, knock.country,
                 knock.isp, knock.asn, ",".join(sorted(protos)),
                 knock.kind, knock.label, knock.rdns, knock.hassh,
                 1 if knock.demoted else 0, knock.ja3),
            )

            for kind, key, label in pairs:
                prev = cur.execute(
                    "SELECT count, last_ts FROM counters "
                    "WHERE kind=? AND proto='ALL' AND key=?",
                    (kind, key),
                ).fetchone()
                stats[kind] = {
                    "count": (prev["count"] if prev else 0) + 1,
                    "prev_ts": prev["last_ts"] if prev else None,
                }
                for scope in ("ALL", knock.proto):
                    cur.execute(
                        """INSERT INTO counters(kind, proto, key, label, count,
                                                first_ts, last_ts)
                           VALUES (?,?,?,?,1,?,?)
                           ON CONFLICT(kind, proto, key) DO UPDATE SET
                             count = count + 1,
                             label = excluded.label,
                             last_ts = excluded.last_ts""",
                        (kind, scope, key, label, knock.ts, knock.ts),
                    )

            for scope in ("ALL", knock.proto):
                cur.execute(
                    """INSERT INTO counters(kind, proto, key, label, count,
                                            first_ts, last_ts)
                       VALUES ('total', ?, 'total', 'total', 1, ?, ?)
                       ON CONFLICT(kind, proto, key) DO UPDATE SET
                         count = count + 1, last_ts = excluded.last_ts""",
                    (scope, knock.ts, knock.ts),
                )
            self.db.commit()

        # Rank lookups are cheap thanks to the (kind, proto, count) index.
        for kind, key, _label in pairs:
            stats[kind]["rank"] = self.rank(kind, "ALL", key)
        return stats

    # ------------------------------------------------------------------ read

    def rank(self, kind: str, proto: str, key: str) -> int | None:
        row = self._one(
            "SELECT count FROM counters WHERE kind=? AND proto=? AND key=?",
            (kind, proto, key),
        )
        if row is None:
            return None
        ahead = self._one(
            "SELECT COUNT(*) AS n FROM counters "
            "WHERE kind=? AND proto=? AND count > ?",
            (kind, proto, row["count"]),
        )
        return int(ahead["n"]) + 1

    def top(self, kind: str, proto: str = "ALL", limit: int = 30) -> list[dict]:
        rows = self._all(
            "SELECT key, label, count, last_ts FROM counters "
            "WHERE kind=? AND proto=? ORDER BY count DESC, last_ts DESC "
            "LIMIT ?",
            (kind, proto, limit),
        )
        out = []
        for r in rows:
            item = {"key": r["key"], "label": r["label"], "count": r["count"], "last_ts": r["last_ts"]}
            if kind == "cred":   # the page tags pairs from Mirai's leaked table
                user, _, password = str(r["key"]).partition(":")
                item["mirai"] = is_mirai_pair(user, password)
            out.append(item)
        return out

    def boards(self, proto: str = "ALL", limit: int = 30) -> dict[str, list[dict]]:
        return {kind: self.top(kind, proto, limit) for kind in KINDS}

    FEED_COLS = ("SELECT ts, proto, ip, port, username, password, iso, country, "
                 "region, city, lat, lng, asn, isp, lines FROM knocks ")

    # The kinds the live page filters by. Everything but "exploit" is a set of services.
    KIND_PROTOS = {
        "device": ("CAM", "ROUTER"), "industrial": ("MODBUS", "S7", "ENIP", "DNP3"), "ai": ("MCP",),
        "web": ("HTTP",), "login": ("SSH", "TNET", "FTP", "SMTP", "RDP", "SIP", "SMB"),
    }

    @staticmethod
    def _feed_rows(rows) -> list[dict]:
        out = []
        for r in rows:
            item = dict(r)
            item["user"] = item.pop("username")
            item["pass"] = item.pop("password")
            try:
                item["lines"] = json.loads(item["lines"] or "[]")
            except (TypeError, ValueError):
                item["lines"] = []
            out.append(item)
        return out

    def feed(self, proto: str = "ALL", limit: int = 100) -> list[dict]:
        sql = self.FEED_COLS
        params: tuple = ()
        if proto != "ALL":
            sql += "WHERE proto=? "
            params = (proto,)
        sql += "ORDER BY id DESC LIMIT ?"
        return self._feed_rows(self._all(sql, (*params, limit)))

    def feed_kind(self, kind: str, limit: int = 100) -> list[dict]:
        """The most recent events of one kind, however far back they reach. The live page's
        recent window is minutes long and the quiet decoys see a few events an hour, so a
        filter on the window alone showed nothing."""
        if kind == "exploit":
            marks = ",".join("?" * len(GENERIC_EXPLOITS))
            sql = (self.FEED_COLS.replace("FROM knocks ", "FROM knocks, json_each(knocks.lines) AS j ") +
                   "WHERE json_extract(j.value, '$[0]') = 'exploit' "
                   f"AND json_extract(j.value, '$[1]') NOT IN ({marks}) ORDER BY knocks.id DESC LIMIT ?")
            return self._feed_rows(self._all(sql, (*tuple(GENERIC_EXPLOITS), limit)))
        protos = self.KIND_PROTOS.get(kind)
        if not protos:
            return self.feed("ALL", limit)
        marks = ",".join("?" * len(protos))
        sql = self.FEED_COLS + f"WHERE proto IN ({marks}) ORDER BY id DESC LIMIT ?"
        return self._feed_rows(self._all(sql, (*protos, limit)))

    def daily_hits(self, ip: str, days: int = 30) -> list[int]:
        """Connections per UTC day from one address, oldest day first, `days` entries."""
        now = int(time.time())
        today = now - now % 86400
        start = today - (days - 1) * 86400
        rows = self._all("SELECT (ts - ?) / 86400 AS d, COUNT(*) AS n FROM knocks WHERE ip = ? AND ts >= ? GROUP BY d",
                         (start, ip, start))
        out = [0] * days
        for r in rows:
            i = int(r["d"])
            if 0 <= i < days:
                out[i] = int(r["n"])
        return out

    def totals(self) -> dict[str, Any]:
        rows = self._all(
            "SELECT proto, count, first_ts, last_ts FROM counters "
            "WHERE kind='total'"
        )
        per_proto = {}
        total = 0
        last_ts = None
        for r in rows:
            if r["proto"] == "ALL":
                total = r["count"]
                last_ts = r["last_ts"]
            else:
                per_proto[r["proto"]] = {
                    "count": r["count"],
                    "first_ts": r["first_ts"],
                    "last_ts": r["last_ts"],
                }
        return {"total": total, "last_ts": last_ts, "per_proto": per_proto}

    def timeline(self, hours: int = 24, buckets: int = 144,
                 proto: str = "ALL") -> list[int]:
        """Knock counts per time bucket, oldest first. Feeds the heat ribbon."""
        now = int(time.time())
        span = hours * 3600
        start = now - span
        width = max(1, span // buckets)
        sql = (
            "SELECT (ts - ?) / ? AS bucket, COUNT(*) AS n FROM knocks "
            "WHERE ts >= ? "
        )
        params: list = [start, width, start]
        if proto != "ALL":
            sql += "AND proto = ? "
            params.append(proto)
        sql += "GROUP BY bucket"
        rows = self._all(sql, params)
        out = [0] * buckets
        for r in rows:
            idx = int(r["bucket"])
            if 0 <= idx < buckets:
                out[idx] = r["n"]
        return out

    def offenders(self, limit: int = 25, kind: str | None = None) -> list[dict]:
        """Most persistent source addresses, with how long they have been at it."""
        sql = ("SELECT ip, first_ts, last_ts, hits, iso, country, isp, asn, "
               "protos, kind, label, rdns FROM actors ")
        params: list = []
        if kind:
            sql += "WHERE kind = ? "
            params.append(kind)
        sql += "ORDER BY hits DESC LIMIT ?"
        params.append(limit)
        rows = self._all(sql, params)
        out = []
        for r in rows:
            item = dict(r)
            item["protos"] = [p for p in (r["protos"] or "").split(",") if p]
            span = max(0, (r["last_ts"] or 0) - (r["first_ts"] or 0))
            item["days"] = round(span / 86400, 1)
            out.append(item)
        return out

    def actors_many(self, ips: list[str]) -> dict[str, dict]:
        """The stored summary for a batch of addresses, in one query."""
        if not ips:
            return {}
        marks = ",".join("?" * len(ips))
        rows = self._all(
            "SELECT ip, kind, label, first_ts, last_ts, hits, protos "
            f"FROM actors WHERE ip IN ({marks})", ips)
        return {r["ip"]: dict(r) for r in rows}

    def add_report(self, ip: str, note: str, client: str) -> bool:
        """Store a wrong-entry note. False once the table is full."""
        with self.lock:
            n = self.db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            if n >= MAX_REPORTS:
                return False
            self.db.execute(
                "INSERT INTO reports(ts, ip, note, client) VALUES (?,?,?,?)",
                (int(time.time()), ip, note[:500], client[:64]))
            self.db.commit()
        return True

    def evidence(self, ip: str, limit: int = 30) -> dict:
        """Everything the honeypot recorded about one address, for the lookup
        box and the evidence drawer. Parameterised throughout; the ip index
        keeps it fast even for a host with tens of thousands of events."""
        actor = self._one(
            "SELECT ip, first_ts, last_ts, hits, iso, country, isp, asn, protos, "
            "kind, label, rdns, hassh, ja3 FROM actors WHERE ip = ?", (ip,)
        )
        if actor is None:
            return {"found": False}
        rows = self._all(
            "SELECT ts, proto, port, username, password, detail FROM knocks "
            "WHERE ip = ? ORDER BY ts DESC LIMIT ?", (ip, limit)
        )
        creds = self._all(
            "SELECT username, password, COUNT(*) AS n FROM knocks "
            "WHERE ip = ? AND (username IS NOT NULL OR password IS NOT NULL) "
            "GROUP BY username, password ORDER BY n DESC LIMIT 8", (ip,)
        )
        shared = 0
        if actor["hassh"]:
            shared = self._one(
                "SELECT COUNT(*) FROM actors WHERE hassh = ? AND ip != ?",
                (actor["hassh"], ip)
            )[0]

        shared_ja3 = 0
        if actor["ja3"]:
            shared_ja3 = self._one(
                "SELECT COUNT(*) FROM actors WHERE ja3 = ? AND ip != ?", (actor["ja3"], ip))[0]
        events = []
        for r in rows:
            try:
                d = json.loads(r["detail"]) if r["detail"] else {}
            except ValueError:
                d = {}
            what = ""
            if d.get("exploit") and d.get("exploit") != "Unclassified Probe":
                what = str(d["exploit"])
            elif d.get("method"):
                what = f"{d['method']} {d.get('path', '')}".strip()
            elif d.get("scan"):
                what = "connected, sent nothing"
            elif d.get("dial_country"):
                what = f"toll call to {d['dial_country']}"
            events.append({
                "ts": r["ts"], "proto": r["proto"], "user": r["username"],
                "pass": r["password"], "what": what[:120],
            })
        item = dict(actor)
        item["protos"] = [p for p in (actor["protos"] or "").split(",") if p]
        return {
            "found": True, "actor": item, "events": events,
            "credentials": [{"user": c["username"], "pass": c["password"], "count": c["n"]}
                            for c in creds],
            "hassh": {"value": actor["hassh"], "shared_with": shared},
            "ja3": {"value": actor["ja3"], "shared_with": shared_ja3},
        }

    def actor(self, ip: str) -> dict | None:
        """One address. Backs the 'has your IP been here' lookup."""
        row = self._one(
            "SELECT ip, first_ts, last_ts, hits, iso, country, isp, protos, "
            "kind, label FROM actors WHERE ip = ?", (ip,)
        )
        if row is None:
            return None
        item = dict(row)
        item["protos"] = [p for p in (row["protos"] or "").split(",") if p]
        return item

    def services(self, hours: int = 24) -> dict[str, int]:
        """Connections per service in the last `hours`, every class of host counted."""
        rows = self._all("SELECT proto, COUNT(*) AS n FROM knocks WHERE ts >= ? GROUP BY proto",
                         (int(time.time()) - hours * 3600,))
        return {r["proto"]: int(r["n"]) for r in rows}

    def heatmap(self, days: int = 7) -> dict[str, Any]:
        """Connections by weekday and hour, UTC, split by kind. 7 rows (Monday first) of 24."""
        now = int(time.time())
        rows = self._all(
            "SELECT (strftime('%w', ts, 'unixepoch') + 6) % 7 AS wd, strftime('%H', ts, 'unixepoch') AS hr, "
            "kind, COUNT(*) AS n FROM knocks WHERE ts >= ? GROUP BY wd, hr, kind",
            (now - days * 86400,))
        grid = {k: [[0] * 24 for _ in range(7)] for k in ("attack", "research")}
        for r in rows:
            k = "research" if r["kind"] == "research" else "attack"
            grid[k][int(r["wd"])][int(r["hr"])] += int(r["n"])
        return {"days": days, "weekday_first": "Monday", "timezone": "UTC", **grid}

    def cred_stats(self, limit: int = 20000) -> dict[str, Any]:
        """What the guessed passwords look like: lengths, make-up, and how concentrated they are."""
        rows = self.top("pass", "ALL", limit)
        total = sum(r["count"] for r in rows) or 1
        lengths = [0] * 17
        digits = upper = symbol = year = empty = 0
        for r in rows:
            p, n = r["key"] or "", r["count"]
            lengths[min(len(p), 16)] += n
            if p == "":
                empty += n
            elif p.isdigit():
                digits += n
            if any(c.isupper() for c in p):
                upper += n
            if any(not c.isalnum() for c in p):
                symbol += n
            if len(p) >= 4 and p[-4:].isdigit() and p[-4:-2] in ("19", "20"):
                year += n
        share = lambda n: round(100 * n / total, 1)  # noqa: E731
        return {
            "distinct": len(rows), "tries": total,
            "length_share": [share(n) for n in lengths],
            "digits_only": share(digits), "with_upper": share(upper), "with_symbol": share(symbol),
            "ends_with_year": share(year), "empty": share(empty),
            "top10_share": share(sum(r["count"] for r in rows[:10])),
            "top100_share": share(sum(r["count"] for r in rows[:100])),
        }

    def emerging(self, days: int = 7, baseline_days: int = 30, min_hosts: int = 2) -> dict[str, Any]:
        """What showed up this week that the weeks before did not: exploit names, web paths and
        credential pairs first seen in the window, each tried by at least `min_hosts` hosts."""
        now = int(time.time())
        since, floor = now - days * 86400, now - (days + baseline_days) * 86400

        def seen(sql: str, lo: int, hi: int) -> dict[str, dict]:
            out = {}
            for r in self._all(sql, (lo, hi)):
                if r["k"] not in (None, ""):
                    out[r["k"]] = {"first_ts": r["first"], "hits": r["n"], "hosts": r["h"]}
            return out

        line = ("SELECT json_extract(j.value, '$[1]') AS k, MIN(ts) AS first, COUNT(*) AS n, COUNT(DISTINCT ip) AS h "
                "FROM knocks, json_each(knocks.lines) AS j WHERE ts >= ? AND ts < ? AND kind != 'research' "
                "AND json_extract(j.value, '$[0]') = '{key}' GROUP BY k")
        cred = ("SELECT username || ':' || password AS k, MIN(ts) AS first, COUNT(*) AS n, COUNT(DISTINCT ip) AS h "
                "FROM knocks WHERE ts >= ? AND ts < ? AND password IS NOT NULL AND kind != 'research' GROUP BY k")
        out: dict[str, Any] = {"days": days, "baseline_days": baseline_days}
        for name, sql in (("exploits", line.format(key="exploit")), ("paths", line.format(key="path")),
                          ("credentials", cred)):
            this = seen(sql, since, now + 1)
            before = seen(sql, floor, since)
            # A generic probe name (Root Fingerprint, Open Proxy Probe...) is not an exploit, and a
            # name the classifier only started using this week is not an emerging threat.
            # A credential pair in the all-time top 100 that was tried before the baseline window
            # (its all-time count is more than this week's) is an old favourite coming round
            # again, not something new.
            common = ({r["key"]: r["count"] for r in self.top("cred", "ALL", 100)}
                      if name == "credentials" else {})
            fresh = [{"value": k, **v} for k, v in this.items()
                     if k not in before and v["hosts"] >= min_hosts
                     and not (name == "exploits" and k in GENERIC_EXPLOITS)
                     and not (k in common and common[k] > v["hits"])]
            fresh.sort(key=lambda x: (-x["hosts"], -x["hits"], x["value"]))
            out[name] = fresh[:25]
        return out

    def traffic_split(self) -> dict[str, int]:
        """Attack vs research-scanner vs Tor, so the headline number is honest."""
        rows = self._all(
            "SELECT kind, COUNT(*) AS hosts, SUM(hits) AS hits "
            "FROM actors GROUP BY kind"
        )
        labels = self._all(
            "SELECT label, SUM(hits) AS hits FROM actors "
            "WHERE label IS NOT NULL GROUP BY label ORDER BY hits DESC LIMIT 8"
        )
        split ={r["kind"] or "attack": int(r["hits"] or 0) for r in rows}
        hosts = {r["kind"] or "attack": int(r["hosts"] or 0) for r in rows}
        return {"hits": split, "hosts": hosts,
                "operators": [{"label": r["label"], "hits": int(r["hits"] or 0)}
                              for r in labels]}

    def timeline_split(self, hours: int = 24, buckets: int = 144) -> dict[str, list[int]]:
        """Same buckets, split by verdict, so the chart can stack them."""
        now = int(time.time())
        span = hours * 3600
        start = now - span
        width = max(1, span // buckets)
        rows = self._all(
            "SELECT (ts - ?) / ? AS bucket, COALESCE(kind,'attack') AS k, "
            "COUNT(*) AS n FROM knocks WHERE ts >= ? GROUP BY bucket, k",
            (start, width, start),
        )
        out = {k: [0] * buckets for k in ("attack", "research", "tor")}
        for r in rows:
            idx = int(r["bucket"])
            kind = r["k"] if r["k"] in out else "attack"
            if 0 <= idx < buckets:
                out[kind][idx] = r["n"]
        return out

    def window(self, hours: int = 1, offset_hours: int = 0) -> dict:
        """Aggregate facts for one time window. Feeds the written summary."""
        now = int(time.time())
        end = now - offset_hours * 3600
        start = end - hours * 3600
        row = self._one(
            "SELECT COUNT(*) AS hits, COUNT(DISTINCT ip) AS hosts "
            "FROM knocks WHERE ts >= ? AND ts < ?", (start, end)
        )
        protos = self._all(
            "SELECT proto, COUNT(*) AS n FROM knocks WHERE ts >= ? AND ts < ? "
            "GROUP BY proto ORDER BY n DESC", (start, end)
        )
        actors = self._all(
            "SELECT ip, COUNT(*) AS n, MAX(country) AS country, MAX(isp) AS isp, "
            "MAX(asn) AS asn, COALESCE(MAX(kind),'attack') AS kind "
            "FROM knocks WHERE ts >= ? AND ts < ? GROUP BY ip "
            "ORDER BY n DESC LIMIT 10", (start, end)
        )
        countries = self._all(
            "SELECT country, COUNT(*) AS n FROM knocks WHERE ts >= ? AND ts < ? "
            "AND country IS NOT NULL GROUP BY country ORDER BY n DESC LIMIT 5",
            (start, end)
        )
        creds = self._all(
            "SELECT username, password, COUNT(*) AS n FROM knocks "
            "WHERE ts >= ? AND ts < ? AND username IS NOT NULL "
            "GROUP BY username, password ORDER BY n DESC LIMIT 40", (start, end)
        )
        fresh = self._one(
            "SELECT COUNT(*) AS n FROM actors WHERE first_ts >= ? AND first_ts < ?",
            (start, end)
        )
        return {
            "start": start, "end": end, "hours": hours,
            "hits": row["hits"], "hosts": row["hosts"],
            "protos": [(r["proto"], r["n"]) for r in protos],
            "actors": [dict(r) for r in actors],
            "countries": [(r["country"], r["n"]) for r in countries],
            "creds": [(r["username"], r["password"], r["n"]) for r in creds],
            "new_hosts": fresh["n"],
        }

    def actor_creds(self, hours: int = 24, min_hits: int = 2) -> dict[str, set]:
        """ip -> the credential pairs it tried. Behavioural fingerprint."""
        cutoff = int(time.time()) - hours * 3600
        rows = self._all(
            "SELECT ip, username, password FROM knocks "
            "WHERE ts >= ? AND username IS NOT NULL GROUP BY ip, username, password",
            (cutoff,)
        )
        counts = self._all(
            "SELECT ip, COUNT(*) AS n FROM knocks WHERE ts >= ? GROUP BY ip",
            (cutoff,)
        )
        busy ={r["ip"] for r in counts if r["n"] >= min_hits}
        out: dict[str, set] = {}
        for r in rows:
            if r["ip"] not in busy:
                continue
            out.setdefault(r["ip"], set()).add(
                f"{r['username'] or ''}:{r['password'] or ''}"
            )
        return out

    def actor_hasshes(self, hours: int = 24) -> dict[str, str]:
        """ip -> SSH client fingerprint. Far stronger evidence than a wordlist."""
        cutoff = int(time.time()) - hours * 3600
        rows = self._all(
            "SELECT ip, hassh, COUNT(*) AS n FROM knocks "
            "WHERE ts >= ? AND hassh IS NOT NULL "
            "GROUP BY ip, hassh ORDER BY n DESC", (cutoff,)
        )
        out: dict[str, str] = {}
        for r in rows:
            out.setdefault(r["ip"], r["hassh"])   # most frequent per host
        return out

    def actor_meta(self, ips: list[str]) -> dict[str, dict]:
        if not ips:
            return {}
        marks = ",".join("?" * len(ips))
        rows = self._all(
            f"SELECT ip, country, iso, isp, asn, hits, protos, kind, label, hassh "
            f"FROM actors WHERE ip IN ({marks})", ips
        )
        return {r["ip"]: dict(r) for r in rows}

    def prune(self, days: int) -> int:
        if days <= 0:
            return 0
        cutoff = int(time.time()) - days * 86400
        with self.lock:
            cur = self.db.execute("DELETE FROM knocks WHERE ts < ?", (cutoff,))
            self.db.execute("DELETE FROM payloads WHERE last_ts < ?", (cutoff,))
            self.db.execute("DELETE FROM droppers WHERE last_ts < ?", (cutoff,))
            self.db.commit()
        return cur.rowcount
