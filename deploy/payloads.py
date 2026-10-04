#!/usr/bin/env python3
"""Read the raw web requests the honeypot has kept, one row per distinct probe.

    python3 /opt/uninvited/payloads.py                    newest 20 first seen
    python3 /opt/uninvited/payloads.py --new 7            first seen in the last 7 days
    python3 /opt/uninvited/payloads.py --top 15           most repeated
    python3 /opt/uninvited/payloads.py --sha 3f9a...      one payload in full

Read-only. The bytes come from attackers, so everything is printed through
uninvited.payload.escape: control characters and non-ASCII are shown as \\xNN and
nothing is ever interpreted. Do not paste the output into a shell or a browser
without that in mind.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [here, os.path.dirname(here)]
from uninvited.payload import escape  # noqa: E402


def stamp(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))


def main() -> int:
    ap = argparse.ArgumentParser(description="Show captured web requests")
    ap.add_argument("--db", default="/var/lib/uninvited/uninvited.db")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--new", type=int, metavar="DAYS", help="only payloads first seen in the last DAYS")
    ap.add_argument("--top", type=int, metavar="N", help="the N most repeated instead of the newest")
    ap.add_argument("--sha", help="show one payload in full (prefix is enough)")
    ap.add_argument("--width", type=int, default=160, help="characters shown per row")
    args = ap.parse_args()

    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        if args.sha:
            rows = db.execute("SELECT * FROM payloads WHERE sha LIKE ? LIMIT 5",
                              (args.sha.replace("%", "") + "%",)).fetchall()
            for r in rows:
                print(f"{r['sha']}  {r['proto']}  first {stamp(r['first_ts'])}  "
                      f"last {stamp(r['last_ts'])}  seen {r['count']}x")
                print(escape(r["raw"]))
                print()
            return 0 if rows else 1

        where, params = "", []
        if args.new:
            where = "WHERE first_ts >= ?"
            params.append(int(time.time()) - args.new * 86400)
        order = "count DESC" if args.top else "first_ts DESC"
        limit = args.top or args.limit
        rows = db.execute(f"SELECT * FROM payloads {where} ORDER BY {order} LIMIT ?",
                          [*params, limit]).fetchall()
        total = db.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
    except sqlite3.OperationalError:
        print("no payloads table yet")
        return 0

    print(f"{total} distinct payloads stored")
    for r in rows:
        first_line = escape(r["raw"].split(b"\r\n", 1)[0], args.width)
        print(f"{r['sha'][:8]}  {stamp(r['first_ts'])}  x{r['count']:<6} {first_line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
