#!/usr/bin/env python3
"""Read the wrong-entry reports visitors have sent.

    python3 reports.py                       newest 20
    python3 reports.py --db /var/lib/uninvited/uninvited.db --limit 100

Read-only, standard library only. Notes are free text from the public internet,
so treat them as untrusted: this prints them, it never acts on them, and nothing
but printable characters reaches your terminal.
"""
from __future__ import annotations

import argparse
import sqlite3
import time


def plain(text) -> str:
    """A stranger wrote this and a terminal is about to show it: control characters,
    escape sequences and direction overrides become a question mark."""
    return "".join(c if c.isprintable() else "?" for c in str(text or ""))


def main() -> int:
    ap = argparse.ArgumentParser(description="Show wrong-entry reports")
    ap.add_argument("--db", default="/var/lib/uninvited/uninvited.db")
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute("SELECT id, ts, ip, note FROM reports ORDER BY id DESC LIMIT ?",
                          (args.limit,)).fetchall()
    except sqlite3.OperationalError:
        print("no reports table yet")
        return 0
    if not rows:
        print("no reports")
        return 0
    for r in rows:
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(r["ts"]))
        print(f"#{r['id']:<4} {when} UTC  {plain(r['ip']):<40} {plain(r['note'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
