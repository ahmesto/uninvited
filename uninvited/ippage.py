"""One page per address, with a social card: /ip/{address} and /ip/{address}/card.png.

The page is rendered on the server from the same lookup answer the dashboard's evidence drawer uses, so
a shared link unfurls with the address, the score and one honest sentence. Everything in it came from an
attacker, so every string is escaped, there is no inline script (the CSP is enforced), and the wording is
"attacked this server", never "is malicious".
"""
from __future__ import annotations

import html
import io
import time
from typing import Any

W, H = 1200, 630


def _iso(ts: int | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) + " UTC" if ts else ""


def _day(ts: int | None) -> str:
    return time.strftime("%b %d", time.gmtime(ts)) if ts else ""


def verdict(d: dict[str, Any]) -> str:
    """One plain sentence about what the address did, from the record and nothing else."""
    a = d.get("actor") or {}
    if not d.get("found"):
        return d.get("why_not") or "This server has never seen that address."
    protos = ", ".join(a.get("protos") or [])
    hits = int(a.get("hits") or 0)
    s = (f"{hits:,} connection{'s' if hits != 1 else ''} to this server"
         + (f" on {protos}" if protos else "")
         + (f", from {_day(a.get('first_ts'))} to {_day(a.get('last_ts'))}." if a.get("first_ts") else "."))
    ex = d.get("exploits") or []
    if ex:
        s += " Named exploits: " + ", ".join(ex[:3]) + ("." if len(ex) <= 3 else f" and {len(ex) - 3} more.")
    listed = d.get("listed") or {}
    on = [w for w in ("24h", "7d", "30d") if listed.get(w)]
    if on:
        s += " On the " + ", ".join(on) + " list" + ("s" if len(on) > 1 else "") + "."
        if d.get("expires"):
            s += f" Leaves them on {d['expires'][:10]} if it stays quiet."
    elif d.get("why_not"):
        s += " " + d["why_not"]
    return s


def _bars_svg(daily: list[int]) -> str:
    n = max(1, len(daily))
    peak = max(1, max(daily) if daily else 1)
    w, h, gap = 720, 56, 3
    bw = (w - gap * (n - 1)) / n
    parts = []
    for i, v in enumerate(daily):
        if not v:
            continue
        bh = max(1, round(v / peak * h))
        col = "#ef4444" if v == peak else "#4a4a50"
        parts.append(f'<rect x="{i * (bw + gap):.1f}" y="{h - bh}" width="{bw:.1f}" height="{bh}" fill="{col}"/>')
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" preserveAspectRatio="none" role="img" '
            f'aria-label="connections per day, {n} days">' + "".join(parts) + "</svg>")


def page(d: dict[str, Any], daily: list[int], ident) -> str:
    e = html.escape
    site, brand = ident.site, ident.brand
    ip = d.get("ip") or ""
    a = d.get("actor") or {}
    found = bool(d.get("found"))
    score = d.get("score")
    listed = d.get("listed") or {}
    hot = found and score is not None and score >= 60
    v = verdict(d)
    title = f"{ip} on {brand}" if ip else brand
    desc = v[:200]
    place = " · ".join(x for x in (a.get("country"), a.get("isp"), f"AS{a['asn']}" if a.get("asn") else "") if x)
    kind = d.get("host_type")
    risk = d.get("collateral_risk")
    tags = "".join(f'<span class="pill{" hot" if t in ("web-exploit", "ics-write", "ics-control", "malware-delivery") else ""}">{e(t)}</span>'
                   for t in (d.get("tags") or []))
    cves = "".join(f'<span class="pill hot">{e(c)}</span>' for c in (d.get("cves") or []))
    exploits = ", ".join(e(x) for x in (d.get("exploits") or [])) or "none"
    techs = " · ".join(f'<span class="mono">{e(t)}</span>' for t in (d.get("techniques") or [])) or "none"
    creds = "".join(f'<div class="ev"><span class="mono">{e((c.get("user") or "") + " : " + (c.get("pass") or ""))}</span>'
                    f'<span class="n">{int(c.get("count") or 0):,}</span></div>' for c in (d.get("credentials") or [])[:12])
    events = "".join(
        f'<div class="ev"><span class="mono t">{e(_iso(x.get("ts")))}</span><span class="mono p">{e(x.get("proto") or "")}</span>'
        f'<span>{e(x.get("what") or ((x.get("user") or "") + ":" + (x.get("pass") or "")) or "connection")}</span></div>'
        for x in (d.get("events") or [])[:30])
    on = ", ".join(w for w in ("24h", "7d", "30d") if listed.get(w)) or "not on the feed"
    nft = f"nft add rule inet filter input ip{'6' if ':' in ip else ''} saddr {ip} drop" if ip else ""
    status = "" if found else '<p class="why">This server has never seen that address, so there is nothing to show.</p>'
    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(desc)}">
<meta name="robots" content="noindex">
<link rel="canonical" href="https://{e(site)}/ip/{e(ip)}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:type" content="website">
<meta property="og:site_name" content="{e(brand)}">
<meta property="og:title" content="{e(title)}">
<meta property="og:description" content="{e(desc)}">
<meta property="og:url" content="https://{e(site)}/ip/{e(ip)}">
<meta property="og:image" content="https://{e(site)}/ip/{e(ip)}/card.png">
<meta property="og:image:width" content="{W}">
<meta property="og:image:height" content="{H}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{e(title)}">
<meta name="twitter:description" content="{e(desc)}">
<meta name="twitter:image" content="https://{e(site)}/ip/{e(ip)}/card.png">
<link href="/static/vendor/jetbrains-mono.css" rel="stylesheet">
<style>
:root{{--bg:#0b0b0c;--text:#f2f2f0;--text2:#c4c4c8;--label:#8b8b90;--dim:#86868c;--rule:#1d1d20;--edge:#2a2a2e;--red:#ef4444;--mono:'JetBrains Mono',ui-monospace,monospace}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:13px/1.5 Arial,Helvetica,sans-serif}}
a{{color:var(--text2);text-decoration:none}}a:hover{{color:var(--text)}}
.mono{{font-family:var(--mono)}}
header{{display:flex;flex-wrap:wrap;align-items:center;gap:10px 18px;padding:8px 20px;min-height:52px;border-bottom:1px solid var(--rule)}}
.brand{{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-weight:700;letter-spacing:2.5px;font-size:13px;color:var(--text)}}
.brand i{{display:inline-block;width:8px;height:15px;background:#dc2626}}
nav{{display:flex;flex-wrap:wrap;border:1px solid var(--edge);font-size:11px;letter-spacing:1px}}nav a{{padding:9px 16px;white-space:nowrap;border-right:1px solid var(--edge)}}nav a:last-child{{border-right:none}}
.wrap{{display:flex;flex-wrap:wrap;gap:40px;padding:32px 20px 0;align-items:flex-start;max-width:1400px;margin:0 auto}}
.main{{flex:3 1 600px;min-width:0}}aside{{flex:2 1 360px;min-width:0}}
.ttl{{font-size:11px;letter-spacing:1.5px;color:var(--text2);text-transform:uppercase}}
.ip{{font-family:var(--mono);font-size:34px;font-weight:700;letter-spacing:-.02em;word-break:break-all}}
.score{{font-family:var(--mono);font-size:52px;font-weight:700;line-height:1;text-align:right}}.score small{{display:block;margin-top:4px;font:11px Arial,Helvetica,sans-serif;color:var(--dim)}}
.verdict{{margin:18px 0 0;font-size:15px;line-height:1.6}}.why{{color:var(--label)}}
.pill{{display:inline-block;font-family:var(--mono);font-size:11px;color:var(--text2);border:1px solid #3a3a3f;padding:2px 7px;margin:0 6px 6px 0}}.pill.hot{{color:var(--red);border-color:#5b2022}}
.facts{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 24px;margin-top:20px}}.facts>div{{padding:10px 0;border-bottom:1px solid #161618}}.facts small{{display:block;font-size:11px;color:var(--dim)}}
.ev{{display:flex;gap:12px;padding:8px 0;border-bottom:1px solid #161618;font-size:12.5px}}.ev .t{{flex:0 0 130px;color:var(--dim)}}.ev .p{{flex:0 0 52px;color:var(--text2)}}.ev .n{{margin-left:auto;color:var(--label)}}
.acts{{display:flex;flex-wrap:wrap;gap:8px;margin-top:22px}}.acts a{{border:1px solid var(--edge);padding:9px 14px;color:var(--text)}}.acts a:hover{{border-color:var(--label)}}
code{{display:block;font-family:var(--mono);font-size:12px;color:var(--text2);background:#111113;padding:10px 12px;margin-top:10px;overflow-x:auto}}
.card{{border:1px solid var(--edge);background:#0f0f11}}.card img{{display:block;width:100%;height:auto}}
footer{{margin-top:40px;display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px 16px;padding:12px 20px;border-top:1px solid var(--rule);font-size:11px;color:var(--dim)}}
@media (max-width:700px){{.facts{{grid-template-columns:1fr 1fr}}.ip{{font-size:26px}}.score{{font-size:40px}}}}
</style>
</head>
<body>
<header>
<a class="brand" href="/">{e(brand.upper())}<i></i></a>
<nav><a href="/#live">LIVE</a><a href="/#intel">THREAT INTEL</a><a href="/#use">USE IT</a><a href="/#build">ABOUT</a><a href="/week">THIS WEEK</a></nav>
{ident.owner_link('style="margin-left:auto;font-size:12.5px;border-bottom:1px solid #55555a"')}
</header>
<div class="wrap">
<div class="main">
<div class="ttl">Address page</div>
<div style="display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin-top:14px">
<div style="min-width:0"><div class="ip">{e(ip)}</div><div style="margin-top:6px;font-size:12.5px;color:var(--label)">{e(place)}{(" · " + e(kind) + (", " + e(risk) + " collateral risk" if risk and risk != "unknown" else "")) if kind and kind != "unknown" else ""}</div></div>
{f'<div class="score" style="color:{"var(--red)" if hot else "var(--text)"}">{int(score)}<small>score of 100</small></div>' if found and score is not None else ""}
</div>
<p class="verdict">{e(v)}</p>{status}
<div style="margin-top:12px">{cves}{tags}</div>
{f'<div style="margin-top:24px;display:flex;justify-content:space-between;align-items:baseline"><span class="ttl">Activity, 30 days</span><span style="font-size:11px;color:var(--dim)">connections per day</span></div><div style="margin-top:10px">{_bars_svg(daily)}</div><div class="mono" style="display:flex;justify-content:space-between;margin-top:4px;font-size:10.5px;color:var(--dim)"><span>{e(_day(int(time.time()) - 29 * 86400))}</span><span>today</span></div>' if found else ""}
{f'''<div class="facts">
<div><small>First seen</small><span class="mono">{e(_iso(a.get("first_ts")))}</span></div>
<div><small>Last seen</small><span class="mono">{e(_iso(a.get("last_ts")))}</span></div>
<div><small>Listed on</small><span class="mono">{e(on)}{(" · until " + e(d["expires"][:10]) + " if quiet") if d.get("expires") else ""}</span></div>
<div><small>Named exploits</small>{exploits}</div>
<div><small>ATT&amp;CK</small>{techs}</div>
<div><small>Class</small>{e(a.get("kind") or "attack")}{(" · " + e(a["label"])) if a.get("label") else ""}</div>
</div>''' if found else ""}
{f'<div style="margin-top:22px;display:flex;justify-content:space-between;align-items:baseline"><span class="ttl">Most recent requests</span><span style="font-size:11px;color:var(--dim)">{min(30, len(d.get("events") or []))} of {int(a.get("hits") or 0):,} · nothing here was executed</span></div><div style="margin-top:8px">{events or "<div class=why>Nothing recorded.</div>"}</div>' if found else ""}
{f'<div style="margin-top:22px" class="ttl">Credentials tried</div><div style="margin-top:8px">{creds}</div>' if creds else ""}
<div class="acts">
<a href="/api/lookup?ip={e(ip)}">JSON</a>
<a href="/feed/attackers-7d.stix.json">STIX feed</a>
<a href="/#ip={e(ip)}">Open in the dashboard</a>
<a href="/#ip={e(ip)}">Report a wrong entry</a>
</div>
{f'<div style="margin-top:14px;font-size:11px;color:var(--dim)">Block it, once, with nftables:</div><code>{e(nft)}</code>' if found else ""}
</div>
<aside>
<div class="ttl">When this page is shared</div>
<div class="card" style="margin-top:12px"><img src="/ip/{e(ip)}/card.png" width="{W}" height="{H}" alt="Card for {e(ip)}"></div>
<p style="margin:14px 0 0;font-size:12.5px;line-height:1.65;color:var(--label)">This page shows what one address did to a server left open on purpose. It is evidence of what reached this server, not an accusation about who owns the address. Addresses get reassigned, which is why every listing carries an expiry. If this is your address and the record looks wrong, use the report link.</p>
</aside>
</div>
<footer><span>Data licensed CC BY 4.0. Credit {e(brand)}.</span><span>{ident.credit()}</span><span>nothing here grants access · no attacker input is ever executed</span></footer>
</body>
</html>
"""
    return body


def card_svg(d: dict[str, Any], site: str, brand: str) -> str:
    e = html.escape
    a = d.get("actor") or {}
    ip = d.get("ip") or ""
    score = d.get("score")
    hot = d.get("found") and score is not None and score >= 60
    line1 = " · ".join(x for x in (a.get("country"), a.get("isp")) if x)
    line2 = verdict(d)
    if len(line2) > 110:
        line2 = line2[:107] + "..."
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">
<rect width="{W}" height="{H}" fill="#0b0b0c"/>
<rect x="84" y="84" width="22" height="42" fill="#dc2626"/>
<text x="124" y="118" fill="#f2f2f0" font-family="JetBrains Mono, DejaVu Sans Mono, monospace" font-weight="700" font-size="30" letter-spacing="6">{e(brand.upper())}</text>
{f'<text x="{W - 84}" y="140" fill="{"#ef4444" if hot else "#f2f2f0"}" font-family="JetBrains Mono, DejaVu Sans Mono, monospace" font-weight="700" font-size="108" text-anchor="end">{int(score)}</text>' if d.get("found") and score is not None else ""}
<text x="84" y="330" fill="#f2f2f0" font-family="JetBrains Mono, DejaVu Sans Mono, monospace" font-weight="700" font-size="84">{e(ip)}</text>
<text x="84" y="384" fill="#c4c4c8" font-family="DejaVu Sans, Arial, sans-serif" font-size="30">{e(line1)}</text>
<text x="84" y="436" fill="#8b8b90" font-family="DejaVu Sans, Arial, sans-serif" font-size="25">{e(line2)}</text>
<line x1="0" y1="{H - 70}" x2="{W}" y2="{H - 70}" stroke="#26262a"/>
<text x="84" y="{H - 28}" fill="#8b8b90" font-family="DejaVu Sans, Arial, sans-serif" font-size="22">{e(site)}/ip/{e(ip)}</text>
<text x="{W - 84}" y="{H - 28}" fill="#6b7280" font-family="DejaVu Sans, Arial, sans-serif" font-size="22" text-anchor="end">evidence, not an accusation</text>
</svg>"""


def card_png(d: dict[str, Any], site: str, brand: str) -> bytes | None:
    """The same card drawn with Pillow, the way the home-page card is. None when Pillow is missing."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return None
    from .card import MONO_FACES, SANS_FACES, _font
    a = d.get("actor") or {}
    ip = d.get("ip") or ""
    score = d.get("score")
    hot = d.get("found") and score is not None and score >= 60
    BG, TEXT, TEXT2, MUTED, DIM, RED, RED_T = (11, 11, 12), (242, 242, 240), (196, 196, 200), (139, 139, 144), (107, 112, 128), (220, 38, 38), (239, 68, 68)
    img = Image.new("RGB", (W, H), BG)
    dr = ImageDraw.Draw(img)
    f_brand, f_score, f_sans, f_small = _font(MONO_FACES, 30), _font(MONO_FACES, 108), _font(SANS_FACES, 30), _font(SANS_FACES, 22)
    dr.rectangle([84, 84, 106, 126], fill=RED)
    dr.text((124, 88), " ".join(brand.upper()), font=f_brand, fill=TEXT)
    if d.get("found") and score is not None:
        s = str(int(score))
        dr.text((W - 84 - dr.textlength(s, font=f_score), 50), s, font=f_score, fill=RED_T if hot else TEXT)
    size = 84
    f_ip = _font(MONO_FACES, size)
    while size > 40 and dr.textlength(ip, font=f_ip) > W - 168:
        size -= 6
        f_ip = _font(MONO_FACES, size)
    dr.text((84, 250), ip, font=f_ip, fill=TEXT)
    dr.text((84, 356), " · ".join(x for x in (a.get("country"), a.get("isp")) if x)[:70], font=f_sans, fill=TEXT2)
    v = verdict(d)
    f_v = _font(SANS_FACES, 25)
    words, lines, cur = v.split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if dr.textlength(t, font=f_v) > W - 168 and cur:
            lines.append(cur)
            cur = w
        else:
            cur = t
    if cur:
        lines.append(cur)
    for i, ln in enumerate(lines[:3]):
        dr.text((84, 410 + i * 34), ln, font=f_v, fill=MUTED)
    dr.line([(0, H - 70), (W, H - 70)], fill=(38, 38, 42))
    dr.text((84, H - 50), f"{site}/ip/{ip}", font=f_small, fill=MUTED)
    tail = "evidence, not an accusation"
    dr.text((W - 84 - dr.textlength(tail, font=f_small), H - 50), tail, font=f_small, fill=DIM)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()
