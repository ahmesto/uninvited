"""The weekly digest: one page, written by the feed, not by hand.

Every number comes from the same data the dashboard shows, computed when the feed is rebuilt,
and every sentence is a template filled from those numbers, so nothing on the page can say more
than the data does. The current week is at /week; each week is also kept at /week/<year>-<week>
so an old link keeps pointing at what it pointed at.
"""
from __future__ import annotations

import datetime as dt
import functools
import html
import json
import re
import time
from typing import Any

from . import analyze
from .intel import GENERIC_EXPLOITS, TECHNIQUES
from .store import Store

CAMP_CAP = 40          # analyze.clusters max_size: a wordlist run by more hosts comes back as several full groups
LOGIN_PROTOS = ("SSH", "TNET", "FTP", "RDP", "SMB", "SMTP", "SIP")


class _Via:
    """Lets a read-only sqlite connection stand in for a Store: its own `_all` and `_one`, and
    every other Store method bound to it. The feed builder already holds such a connection."""

    def __init__(self, con):
        self.con = con

    def _all(self, sql, params=()):
        return self.con.execute(sql, params).fetchall()

    def _one(self, sql, params=()):
        return self.con.execute(sql, params).fetchone()

    def __getattr__(self, name):
        return functools.partial(getattr(Store, name), self)


def week_id(ts: int) -> str:
    y, w, _ = dt.datetime.fromtimestamp(ts, dt.UTC).isocalendar()
    return f"{y}-{w:02d}"


def valid_id(s: str) -> bool:
    return bool(re.fullmatch(r"20\d\d-[0-5]\d", s or ""))


def _day(ts: int) -> str:
    d = dt.datetime.fromtimestamp(ts, dt.UTC)
    return f"{d:%B} {d.day}, {d.year}"


def _n(x: Any) -> str:
    return f"{int(x or 0):,}"


def _words(n: int) -> str:
    return ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"][n] if 0 <= n <= 10 else str(n)


def _rate(p: dict, key: str, sub: str | None = None) -> int | None:
    v = (p or {}).get(key) or {}
    if sub:
        v = v.get(sub) or {}
    return None if v.get("rate") is None else round(v["rate"] * 100)


def build(store, index: dict[str, Any], now: int) -> dict[str, Any]:
    """Everything the page shows, as plain data. `store` is a Store or a _Via."""
    week = store.window(168)
    since = now - 168 * 3600
    guesses = store._one("SELECT COUNT(*) AS n FROM knocks WHERE ts >= ? AND username IS NOT NULL", (since,))["n"]
    exploit_rows = store._all(
        "SELECT ip, lines FROM knocks WHERE ts >= ? AND lines LIKE '%\"exploit\"%' AND kind != 'research' LIMIT 5000", (since,))
    exploit_hosts: set[str] = set()
    for r in exploit_rows:
        try:
            lines = dict(json.loads(r["lines"] or "[]"))
        except (ValueError, TypeError):
            continue
        if lines.get("exploit") and lines["exploit"] not in GENERIC_EXPLOITS:
            exploit_hosts.add(r["ip"])
    hm = store.heatmap(7)
    grid = hm.get("attack") or []
    by_hour = [sum(row[h] for row in grid) for h in range(24)] if grid else []
    cs = store.cred_stats()
    clusters = _merge(analyze.clusters(store, 168))

    lists = {x["name"]: x["count"] for x in index.get("lists") or []}
    curated = {c["name"]: c["count"] for c in index.get("curated") or []}
    precision = index.get("precision") or {}
    protos24 = index.get("protocols_24h") or {}

    return {
        "id": week_id(now), "built": now, "from": since, "to": now,
        "hits": week["hits"], "hosts": week["hosts"], "new_hosts": week["new_hosts"],
        "guess_share": round(100 * guesses / week["hits"]) if week["hits"] else 0,
        "listed_7d": lists.get("attackers-7d", 0), "persistent": curated.get("tag-persistent-7d", 0),
        "high": curated.get("attackers-high-7d", 0), "research_7d": lists.get("research-7d", 0),
        "accuracy": {"long_day": _rate(precision, "next_24h", "long_standing"), "long_week": _rate(precision, "next_7d", "long_standing"),
                     "all_day": _rate(precision, "next_24h"), "all_week": _rate(precision, "next_7d")},
        "new_24h": index.get("new_24h", 0),
        "countries": [(c["country"], c["count"]) for c in (index.get("countries_7d") or [])[:5]],
        "networks": [(c.get("network") or "an unnamed network", c["count"]) for c in (index.get("networks_7d") or [])[:5]],
        "host_types": index.get("host_types_7d") or {},
        "techniques": [(t, TECHNIQUES.get(t, ""), n) for t, n in (index.get("techniques_24h") or {}).items()][:6],
        "clusters": clusters[:3],
        "exploit_hosts": len(exploit_hosts),
        "cves": [(c["ip"], c["cves"][0], (c.get("last_seen") or "")[:10]) for c in (index.get("cves_30d") or [])[:3]],
        "peak_hour": by_hour.index(max(by_hour)) if by_hour else None,
        "low_hour": by_hour.index(min(by_hour)) if by_hour else None,
        "even_hours": bool(by_hour) and min(by_hour) / (max(by_hour) or 1) > 0.45,
        "top10_share": cs.get("top10_share"), "digits_only": cs.get("digits_only"),
        "top_passwords": [p for _, p, _ in week["creds"] if p][:3],
        "spread": [(x["range"], x["count"]) for x in index.get("score_spread_30d") or []],
        "services": sorted(protos24.items(), key=lambda kv: -kv[1])[:6],
        "protos": week["protos"][:6],
    }


def _merge(clusters: list[dict]) -> list[dict]:
    """Full groups with the same basis are one wordlist split by the size cap; show them as one."""
    out: list[dict] = []
    full: dict[str, dict] = {}
    for c in clusters:
        head = full.get(c.get("basis") or "") if c["hosts"] >= CAMP_CAP else None
        if head:
            head["hosts"] += c["hosts"]
            head["hits"] += c["hits"]
            head["groups"] += 1
            continue
        item = dict(c, groups=1)
        if c["hosts"] >= CAMP_CAP:
            full[c.get("basis") or ""] = item
        out.append(item)
    return out


def story(d: dict[str, Any]) -> list[str]:
    """The sentences under "the story of the week", one per fact, each from the numbers above."""
    out = [f"Password guessing was {d['guess_share']}% of everything."]
    c = (d.get("clusters") or [None])[0]
    if c:
        out.append(f"{_n(c['hosts'])} hosts" + (f" in {_words(c['groups'])} groups" if c["groups"] > 1 else "") +
                   f" ran the same credential list, one {c['phrase']}, for {_n(c['hits'])} attempts between them.")
    n = d["exploit_hosts"]
    if n:
        s = f"{_words(n).capitalize()} host{'s' if n != 1 else ''} tried a named exploit."
        if d["cves"]:
            _ip, cve, day = d["cves"][0]
            s += f" The only request this month that matched a specific CVE was {cve}, on {day}."
        out.append(s)
    else:
        out.append("No host tried a named exploit this week." + (" " if not d["cves"] else ""))
    if d["peak_hour"] is not None:
        out.append(f"The busiest hour was {d['peak_hour']:02d}:00 UTC and the quietest {d['low_hour']:02d}:00. " +
                   ("The hours are close to even, which is what automated scanning looks like: nobody is at a keyboard."
                    if d["even_hours"] else "The hours are uneven, so part of this traffic follows somebody's working day rather than a scheduler."))
    if d["top10_share"] is not None:
        out.append(f"Of the passwords tried, {d['top10_share']}% were one of the ten most common. " +
                   (f"One in {round(100 / d['digits_only'])} was digits only. " if d.get("digits_only") else "") +
                   (", ".join(d["top_passwords"][:-1]) + " and " + d["top_passwords"][-1] + " led."
                    if len(d["top_passwords"]) >= 2 else ""))
    return [s.strip() for s in out]


def page(d: dict[str, Any], ident, current: bool) -> str:
    e = html.escape
    site, brand = ident.site, ident.brand
    acc = d["accuracy"]
    pct = lambda v: "–" if v is None else f"{v}%"  # noqa: E731
    rows = lambda items, cls="": "".join(  # noqa: E731
        f'<div class="row{cls}"><span>{e(str(k))}</span><b class="mono">{_n(v)}</b></div>' for k, v in items)
    bars = ""
    if d["countries"]:
        top = max(v for _, v in d["countries"])
        bars = "".join(f'<div class="row"><span>{e(k)}</span><b class="mono">{_n(v)}</b></div>'
                       f'<div class="bar"><i style="width:{100 * v / top:.0f}%"></i></div>' for k, v in d["countries"])
    ht = d["host_types"]
    tech = "".join(f'<div class="row"><span><span class="mono dim">{e(t)}</span> {e(name)}</span><b class="mono">{_n(n)}</b></div>'
                   for t, name, n in d["techniques"])
    spread = "".join(f'<div class="row{" hot" if r.startswith("80") else ""}"><span>{e(r.replace("-", " to "))}</span><b class="mono">{_n(n)}</b></div>'
                     for r, n in d["spread"])
    services = "".join(f'<div class="row"><span>{e(p)}</span><b class="mono">{_n(n)}</b></div>' for p, n in d["services"])
    paras = "".join(f"<p>{e(s)}</p>" for s in story(d))
    title = f"This week on a server left open on purpose · {brand}"
    desc = f"{_n(d['hits'])} unsolicited connections in 7 days, {_n(d['listed_7d'])} hosts listed, {_n(d['persistent'])} of them persistent."
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(d["built"]))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(desc)}">
<link rel="canonical" href="https://{e(site)}/week/{e(d['id'])}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:type" content="article">
<meta property="og:site_name" content="{e(brand)}">
<meta property="og:title" content="{e(title)}">
<meta property="og:description" content="{e(desc)}">
<meta property="og:url" content="https://{e(site)}/week/{e(d['id'])}">
<meta property="og:image" content="https://{e(site)}/og.png">
<meta name="twitter:card" content="summary_large_image">
<link href="/static/vendor/jetbrains-mono.css" rel="stylesheet">
<style>
:root{{--bg:#0b0b0c;--text:#f2f2f0;--text2:#c4c4c8;--label:#8b8b90;--dim:#86868c;--rule:#1d1d20;--edge:#2a2a2e;--red:#ef4444;--green:#22c55e;--mono:'JetBrains Mono',ui-monospace,monospace}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:13px/1.5 Arial,Helvetica,sans-serif}}
a{{color:var(--text2);text-decoration:none}}a:hover{{color:var(--text)}}.mono{{font-family:var(--mono)}}.dim{{color:var(--dim)}}
header{{display:flex;flex-wrap:wrap;align-items:center;gap:10px 18px;padding:8px 20px;min-height:52px;border-bottom:1px solid var(--rule)}}
.brand{{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-weight:700;letter-spacing:2.5px;font-size:13px;color:var(--text)}}
.brand i{{display:inline-block;width:8px;height:15px;background:#dc2626}}
nav{{display:flex;flex-wrap:wrap;border:1px solid var(--edge);font-size:11px;letter-spacing:1px}}nav a{{padding:9px 16px;white-space:nowrap;border-right:1px solid var(--edge)}}nav a:last-child{{border-right:none}}nav a.on{{background:var(--text);color:var(--bg)}}
.wrap{{max-width:1360px;margin:0 auto;padding:30px 20px 40px}}
.k{{font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--label)}}
h1{{font-size:32px;line-height:1.15;letter-spacing:-.3px;margin:10px 0 12px}}
.lead{{font-size:15px;line-height:1.6;color:var(--text2);max-width:900px;margin:0 0 24px}}
.stats{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;background:var(--rule);border:1px solid var(--rule)}}
.stats>div{{background:var(--bg);padding:20px}}.stats b{{display:block;font-family:var(--mono);font-size:34px;font-weight:700;line-height:1}}.stats b+span{{display:block;margin-top:8px;font-size:12.5px;line-height:1.5;color:var(--label)}}
.grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px;margin-top:20px;align-items:start}}.grid .wide{{grid-column:span 2}}
.blk{{border:1px solid var(--rule)}}.hd{{display:flex;justify-content:space-between;gap:12px;padding:10px 18px;border-bottom:1px solid var(--rule);font-size:11px;letter-spacing:1.2px;text-transform:uppercase;color:var(--text2)}}.hd span{{color:var(--dim);letter-spacing:0;text-transform:none}}
.bd{{padding:8px 18px 14px}}.row{{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid #161618;font-size:13px}}.row b{{font-weight:400;color:var(--text2)}}.row.hot span,.row.hot b{{color:var(--red)}}
.bar{{height:2px;background:#1a1a1d;margin:-4px 0 6px}}.bar i{{display:block;height:100%;background:var(--text2)}}
.story p{{font-size:14.5px;line-height:1.7;margin:0 0 12px}}.fine{{font-size:11.5px;line-height:1.6;color:var(--dim);margin:10px 0 0}}.fine a{{border-bottom:1px solid #3a3a3f}}
.green{{color:var(--green)}}
footer{{margin-top:40px;display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px 16px;padding:12px 20px;border-top:1px solid var(--rule);font-size:11px;color:var(--dim)}}
@media (max-width:900px){{.stats{{grid-template-columns:1fr 1fr}}.grid{{grid-template-columns:1fr}}.grid .wide{{grid-column:auto}}h1{{font-size:24px}}}}
</style>
</head>
<body>
<header>
<a class="brand" href="/">{e(brand.upper())}<i></i></a>
<nav><a href="/#live">LIVE</a><a href="/#intel">THREAT INTEL</a><a href="/#use">USE IT</a><a href="/#build">ABOUT</a><a href="/week" class="on">THIS WEEK</a></nav>
{ident.owner_link('style="margin-left:auto;font-size:12.5px;border-bottom:1px solid #55555a"')}
</header>
<div class="wrap">
<div class="k">Weekly digest · written by the feed, not by hand{"" if current else " · an earlier week"}</div>
<h1>This week on a server left open on purpose</h1>
<p class="lead">{e(_day(d["from"]))} to {e(_day(d["to"]))}. Every number below is computed from the published feed at the moment the page is built, and each panel says which file it came from. The current week is at <a href="/week">/week</a>; this one stays at <a href="/week/{e(d['id'])}">/week/{e(d['id'])}</a>.</p>
<div class="stats">
<div><b>{_n(d["hits"])}</b><span>unsolicited connections in 7 days, from {_n(d["hosts"])} addresses, {_n(d["new_hosts"])} of them never seen before</span></div>
<div><b>{_n(d["listed_7d"])}</b><span>hosts on the 7 day attacker list, {_n(d["persistent"])} of them persistent and {_n(d["high"])} high confidence</span></div>
<div><b>{_n(d["research_7d"])}</b><span>research scanners, kept on their own list</span></div>
<div><b class="green">{pct(acc["long_day"])}</b><span>of hosts on record for a week attacked again within a day</span></div>
</div>
<div class="grid">
<div class="blk"><div class="hd">Where they came from<span>hosts, 7 days</span></div><div class="bd">{bars or '<div class="row"><span>nothing listed yet</span></div>'}<p class="fine">from <a href="/feed/index.json">index.json</a> · countries_7d</p></div></div>
<div class="blk"><div class="hd">Where they ran<span>networks, 7 days</span></div><div class="bd">{rows(d["networks"])}<p class="fine">{_n(ht.get("isp"))} on consumer ISPs, {_n(ht.get("hosting"))} on hosting, {_n(ht.get("unknown"))} unknown. Consumer addresses get reassigned, so they carry the shortest expiry.</p></div></div>
<div class="blk"><div class="hd">What they did<span>ATT&amp;CK, 24 hours</span></div><div class="bd">{tech}<p class="fine">hosts per technique, from <a href="/feed/index.json">index.json</a> · techniques_24h</p></div></div>
<div class="blk wide story"><div class="hd">The story of the week<span>written from the numbers above, one sentence per fact</span></div><div class="bd" style="padding-top:14px">{paras}</div></div>
<div class="blk"><div class="hd">How the feed did<span>measured, not claimed</span></div><div class="bd">
<div class="row"><span>Week-old listings back within a day</span><b class="mono green">{pct(acc["long_day"])}</b></div>
<div class="row"><span>Week-old listings back within 7 days</span><b class="mono">{pct(acc["long_week"])}</b></div>
<div class="row"><span>All listings back within a day</span><b class="mono">{pct(acc["all_day"])}</b></div>
<div class="row"><span>All listings back within 7 days</span><b class="mono">{pct(acc["all_week"])}</b></div>
<div class="row"><span>Hosts first seen in the last 24 hours</span><b class="mono">{_n(d["new_24h"])}</b></div>
<p class="fine">One server sees a small slice of the internet, so these rates are a floor, not a verdict.</p></div></div>
<div class="blk"><div class="hd">Score spread<span>30 days</span></div><div class="bd">{spread}</div></div>
<div class="blk"><div class="hd">Services hit<span>hosts, 24 hours</span></div><div class="bd">{services}</div></div>
<div class="blk"><div class="hd">Take it with you<span>this digest, elsewhere</span></div><div class="bd">
<div class="row"><span><a href="/week/{e(d['id'])}.json">JSON</a> with every number on this page</span></div>
<div class="row"><span><a href="/feed/notable.atom">Atom feed</a> of the notable events</span></div>
<div class="row"><span><a href="/feed/attackers-7d.txt">The 7 day list</a> this digest describes</span></div>
<p class="fine">Built {e(stamp)}. A new digest replaces the one at /week every rebuild; dated addresses never change their week.</p></div></div>
</div>
</div>
<footer><span>Data licensed CC BY 4.0. Credit {e(brand)}.</span><span>{ident.credit()}</span><span>nothing here grants access · no attacker input is ever executed</span></footer>
</body>
</html>
"""
