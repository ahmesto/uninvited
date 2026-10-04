#!/usr/bin/env python3
"""Print the numbers for a write-up from an instance's public endpoints, with their sources.

    python tools/findings.py https://dmz.ahmadmesto.com

Every figure comes from the live instance's own public API, so anyone can run this and get the same
answer. Nothing is stored. Use it before you publish a number: copy it from here, never from memory.
"""
from __future__ import annotations

import json
import sys
import urllib.request


def get(base: str, path: str):
    req = urllib.request.Request(base.rstrip("/") + path, headers={"User-Agent": "uninvited-findings/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    base = sys.argv[1]
    stats = get(base, "/api/stats")
    index = get(base, "/feed/index.json")
    boards = get(base, "/api/boards?proto=ALL&limit=15")["boards"]
    split = get(base, "/api/split")
    camp = get(base, "/api/campaigns?hours=168")["campaigns"]

    total = stats["total"]
    days = stats["uptime_minutes"] / 1440
    print(f"# Numbers from {base}\n")
    print(f"as of {index['generated']} (feed rebuilt every {index['rebuilt_every_seconds']} seconds)\n")
    print(f"events recorded: {total:,} in {days:.1f} days, about {total / days:,.0f} a day   [/api/stats]")
    print("\nby service   [/api/stats]")
    for p in stats["proto_stats"]:
        print(f"  {p['proto']:7} {p['count']:>9,}  {pct(p['count'], total):>6}")
    hits, hosts = split["hits"], split["hosts"]
    print("\nattackers against research scanners   [/api/split]")
    for kind in ("attack", "research", "tor"):
        print(f"  {kind:9} {hosts.get(kind, 0):>7,} hosts  {hits.get(kind, 0):>9,} events  {pct(hits.get(kind, 0), total):>6}")
    print("  busiest scanner operators: " + ", ".join(f"{o['label']} {o['hits']:,}" for o in split["operators"][:5]))
    lists = {l["name"]: l["count"] for l in index["lists"]}
    print("\nlists now   [/feed/index.json]  " + ", ".join(f"{k} {v:,}" for k, v in lists.items()))
    for u in index.get("url_lists", []):
        print(f"  {u['name']}: {u['count']:,}")
    p = index["precision"]
    print("\nmeasured accuracy   [/feed/index.json precision]")
    for key, label in (("next_24h", "listed a day ago, attacked again within 24 hours"),
                       ("next_7d", "listed a week ago, attacked again within 7 days")):
        r = p[key]
        print(f"  {label}: {r['returned']} of {r['listed']} ({100 * (r['rate'] or 0):.0f}%); "
              f"already on record a week: {r['long_standing']['returned']} of {r['long_standing']['listed']} "
              f"({100 * (r['long_standing']['rate'] or 0):.0f}%)")
    print("\nmost tried credentials   [/api/boards]")
    for kind in ("user", "pass", "cred"):
        print(f"  {kind}: " + ", ".join(f"{(r['label'] or r['key'])!r} {r['count']:,}" for r in boards[kind][:8]))
    print("\nwhere from, events   [/api/boards loc and isp]")
    print("  countries: " + ", ".join(f"{r['label']} {r['count']:,}" for r in boards["loc"][:6]))
    print("  networks:  " + ", ".join(f"{r['label']} {r['count']:,}" for r in boards["isp"][:6]))
    print("\nwhere from, listed hosts (7 days)   [/feed/index.json]")
    print("  countries: " + ", ".join(f"{c['country']} {c['count']}" for c in index["countries_7d"][:6]))
    print("  host types: " + ", ".join(f"{k} {v}" for k, v in index["host_types_7d"].items()))
    print("\nwhat they did, hosts in 24 hours   [/feed/index.json]  " + ", ".join(f"{k} {v}" for k, v in index["tags_24h"].items()))
    print("named vulnerabilities, 30 days: " + (", ".join(f"{h['cves'][0]} ({h['ip']})" for h in index["cves_30d"]) or "none"))
    print("\ncampaigns this week   [/api/campaigns]")
    for c in camp[:4]:
        print(f"  {c['id']}: {c['hosts']} hosts, {c['hits']:,} hits, grouped by {c['basis']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
