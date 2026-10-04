"""What is worth a look: the few events in a window that an analyst would stop for.

Two kinds, both decided from stored data and nothing else:

* FIRST THIS WEEK. An attacker did something to a decoy that nobody did in the seven days
  before the window: sent a write, stop or program command to an industrial decoy, used a
  named exploit, or called a tool on the AI tool server. "The same thing" means the same
  protocol and function, the same exploit name, or the same tool name.
* NEW DROPPER. A download address showed up in a request for the first time inside the
  window. It is shown defanged and never fetched.
* ACTIVE NOW. The same kinds of event as the first, seen in the window but also in the week
  before. Not news, so it comes after the other two and never enters the Atom feed; it is
  there so the box agrees with the red rows in the feed instead of saying "nothing new".

Routine password guessing and generic probes are never notable. The module reads through
`Store._all`, so it uses the read-only connections and never blocks the writer.
"""
from __future__ import annotations

import json
import time
from typing import Any

from .core import PROTO_LABELS
from .intel import GENERIC_EXPLOITS

LOOKBACK_DAYS = 7
MAX_ROWS = 3000
MAX_ITEMS = 6
ICS_KINDS = ("write", "control", "program")

# What `lines` and `detail` must contain for a stored knock to be a candidate at all. A cheap
# prefilter, so a busy hour does not read every row.
CANDIDATE = """(detail LIKE '%"ics"%' OR lines LIKE '%"exploit"%' OR lines LIKE '%"tool"%')
               AND kind != 'research'"""


def _loads(text: str | None, default: Any) -> Any:
    try:
        value = json.loads(text) if text else default
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def signature(proto: str, lines: dict[str, str], detail: dict[str, Any]) -> tuple | None:
    """The identity of what an attacker did, or None when it is routine."""
    ics = detail.get("ics")
    if ics in ICS_KINDS:
        return ("ics", proto, ics, lines.get("function") or "")
    exploit = lines.get("exploit")
    if exploit and exploit not in GENERIC_EXPLOITS:
        return ("exploit", exploit)
    tool = lines.get("tool")
    if tool:
        return ("tool", tool)
    return None


def _short(proto: str) -> str:
    return PROTO_LABELS.get(proto, proto).replace(" (industrial)", "")


def _title(sig: tuple, proto: str) -> str:
    if sig[0] == "ics":
        function = sig[3] or {"write": "a write", "control": "a control command", "program": "a program download"}[sig[2]]
        return f"{function} sent to the {_short(proto)} decoy"
    if sig[0] == "exploit":
        return sig[1]
    return f"AI tool call: {sig[1]}"


def defang(url: str) -> str:
    """hxxp and [.] so a copied address is never clickable."""
    out = url.replace("http", "hxxp", 1) if url.startswith("http") else url
    return out.replace(".", "[.]")


def _notable_events(store, since: int, now: int) -> tuple[list[dict], list[dict]]:
    """Two lists: what was done in the window that nobody did in the week before (first this
    week), and what was done in the window that had been seen before (active now)."""
    rows = store._all(
        f"""SELECT ts, proto, ip, iso, country, lines, detail FROM knocks
            WHERE ts >= ? AND ts <= ? AND {CANDIDATE} ORDER BY ts DESC LIMIT {MAX_ROWS}""",
        (since, now))
    wanted: dict[tuple, dict] = {}
    for r in rows:
        lines = dict(_loads(r["lines"], []))
        sig = signature(r["proto"], lines, _loads(r["detail"], {}))
        if sig is None:
            continue
        item = wanted.get(sig)
        if item is None:
            wanted[sig] = {"sig": sig, "ts": r["ts"], "first_ts": r["ts"], "ip": r["ip"], "proto": r["proto"],
                           "iso": r["iso"], "country": r["country"], "count": 1, "hosts": {r["ip"]},
                           "days": {r["ts"] // 86400}}
        else:
            item["count"] += 1
            item["first_ts"] = min(item["first_ts"], r["ts"])
            item["hosts"].add(r["ip"])
            item["days"].add(r["ts"] // 86400)
    if not wanted:
        return [], []
    # Was the same thing done in the week before the window, and on how many days?
    before = store._all(
        f"""SELECT ts, proto, lines, detail FROM knocks
            WHERE ts >= ? AND ts < ? AND {CANDIDATE} LIMIT {MAX_ROWS * 4}""",
        (since - LOOKBACK_DAYS * 86400, since))
    seen_before: set[tuple] = set()
    for r in before:
        lines = dict(_loads(r["lines"], []))
        sig = signature(r["proto"], lines, _loads(r["detail"], {}))
        if sig is not None:
            seen_before.add(sig)
            if sig in wanted:
                wanted[sig]["days"].add(r["ts"] // 86400)
    fresh = [w for sig, w in wanted.items() if sig not in seen_before]
    active = [w for sig, w in wanted.items() if sig in seen_before]
    return fresh, active


def _new_droppers(store, since: int, now: int) -> list[dict]:
    rows = store._all("SELECT url, host, family, file, first_ts, hits, sources, self_hosted "
                      "FROM droppers WHERE first_ts >= ? AND first_ts <= ? ORDER BY first_ts DESC LIMIT 20",
                      (since, now))
    out = []
    for r in rows:
        n = len(_loads(r["sources"], []))
        what = r["family"] or "malware"
        out.append({"id": f"d{r['first_ts']}-{abs(hash(r['url'])) % 10**6}", "tag": "NEW DROPPER", "kind": "dropper",
                    "ts": r["first_ts"], "title": f"A {what} download was requested",
                    "meta": f"{defang(r['url'])} · asked for by {max(n, 1)} host{'s' if n > 1 else ''}",
                    "count": r["hits"]})
    return out


def _x(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def atom(items: list[dict], brand: str, site: str, now: int) -> str:
    """An Atom feed of the notable events, newest first. Addresses are in it (they are public on the
    site already); credentials never are."""
    iso = lambda ts: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))  # noqa: E731
    base = f"https://{site}"
    head = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        f"<title>{_x(brand)}: worth a look</title>",
        f'<link href="{base}/feed/notable.atom" rel="self"/>',
        f'<link href="{base}/"/>',
        f"<id>tag:{_x(site)},2026:notable</id>",
        f"<updated>{iso(now)}</updated>",
        f"<author><name>{_x(brand)}</name></author>",
        "<subtitle>Exploits, control commands and malware download addresses first seen on a server left open on purpose. Routine password guessing is never in this feed.</subtitle>",
    ]
    entries = []
    for i in items:
        if i["tag"] == "ACTIVE NOW":   # the feed is for news; a repeat is not news
            continue
        link =f"{base}/#ip={i['ip']}" if i.get("ip") else f"{base}/#intel-urls"
        entries += [
            "<entry>",
            f"<title>{_x(i['tag'].title())}: {_x(i['title'])}</title>",
            f'<link href="{link}"/>',
            f"<id>tag:{_x(site)},2026:{_x(i['id'])}</id>",
            f"<updated>{iso(i['ts'])}</updated>",
            f"<summary>{_x(i['meta'])}" + (f" ({i['count']} times)" if i.get("count", 1) > 1 else "") + "</summary>",
            "</entry>",
        ]
    return "\n".join(head + entries + ["</feed>"]) + "\n"


class _Reader:
    """Wraps a read-only sqlite connection in the one method this module uses on a Store,
    so the feed builder can call notables() with the connection it already holds."""

    def __init__(self, con):
        self.con = con

    def _all(self, sql, params=()):
        return self.con.execute(sql, params).fetchall()


def from_connection(con, hours: int, now: int) -> list[dict]:
    return notables(_Reader(con), hours, now)


def notables(store, hours: int, now: int) -> list[dict]:
    """First-this-week events and new droppers, newest first; then what is active now (a named
    exploit, control command or tool call seen in the window that is not new), busiest first.
    The first kind is news; the second explains the red rows in the feed when there is no news."""
    since = now - hours * 3600
    fresh, active = _notable_events(store, since, now)
    items: list[dict] = []
    for w in fresh:
        items.append({"id": f"n{w['ts']}-{abs(hash(w['sig'])) % 10**6}", "tag": "FIRST THIS WEEK", "kind": w["sig"][0],
                      "ts": w["ts"], "title": _title(w["sig"], w["proto"]),
                      "meta": f"{w['proto']} · {w['country'] or w['iso'] or 'unknown'}",
                      "ip": w["ip"], "count": w["count"]})
    items += _new_droppers(store, since, now)
    items.sort(key=lambda i: -i["ts"])
    active.sort(key=lambda w: (-len(w["hosts"]), -w["count"], -w["ts"]))
    span = "hour" if hours == 1 else f"{hours} hours"
    for w in active:
        n, d = len(w["hosts"]), len(w["days"])
        items.append({"id": f"a{w['ts']}-{abs(hash(w['sig'])) % 10**6}", "tag": "ACTIVE NOW", "kind": w["sig"][0],
                      "ts": w["ts"], "title": _title(w["sig"], w["proto"]),
                      "meta": f"{w['proto']} · {n} host{'s' if n != 1 else ''} this {span} · seen on {d} of the last {LOOKBACK_DAYS + 1} days",
                      "ip": w["ip"], "count": w["count"]})
    return items[:MAX_ITEMS]
