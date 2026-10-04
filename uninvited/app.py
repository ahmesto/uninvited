"""Dashboard: WebSocket live feed, REST endpoints, blocklist export."""
from __future__ import annotations

import asyncio
import collections
import ipaddress
import json
import os
import re
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse, Response)
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import digest, hardening, intel, ippage, sitefiles, taxii
from .analyze import campaigns, narrate
from .card import build_png, build_png_native, build_svg
from .core import Config, Knock, PROTO_COLORS
from .feeds import CHANGE_LISTS, REFRESH_SECONDS, FeedCache
from .identity import Identity
from .history import parse_since
from .notables import notables as find_notables
from .redact import Scrubber
from .store import Store

log = logging.getLogger("uninvited.web")

STATIC = Path(__file__).resolve().parent.parent / "static"

SEND_TIMEOUT = 3  # seconds a dashboard client gets to accept one message


class Busy(Exception):
    """Too many distinct heavy reads are already waiting."""


class ReadCache:
    """The answers to the heavy read endpoints, shared by every visitor.

    The dashboard queries aggregate a day or a week of knocks. Run them for each
    request and a handful of clients polling in a loop, or one script, can keep
    the machine busy that is also running every decoy. So each answer is computed
    at most once per key per `ttl` seconds however many ask (the first request
    does the work, the rest wait for it), on a small dedicated thread pool and
    never on the event loop. If more than `limit` different keys are waiting,
    new ones are refused with Busy instead of queued.
    """

    def __init__(self, ttl: float = 8.0, workers: int = 2, limit: int = 12,
                 max_keys: int = 256):
        self.ttl, self.limit, self.max_keys = ttl, limit, max_keys
        self._pool = ThreadPoolExecutor(workers, thread_name_prefix="read")
        self._items: dict[tuple, tuple[float, Any]] = {}
        self._flights: dict[tuple, asyncio.Future] = {}

    def _fresh(self, key: tuple):
        hit = self._items.get(key)
        if hit and time.monotonic() - hit[0] < self.ttl:
            return hit
        return None

    async def get(self, key: tuple, fn):
        hit = self._fresh(key)
        if hit:
            return hit[1]
        flight = self._flights.get(key)
        if flight is None:
            if len(self._flights) >= self.limit:
                raise Busy()
            loop = asyncio.get_running_loop()
            flight = loop.run_in_executor(self._pool, fn)
            self._flights[key] = flight

            def done(fut: asyncio.Future, key=key) -> None:
                self._flights.pop(key, None)
                if not fut.cancelled() and fut.exception() is None:
                    self._items[key] = (time.monotonic(), fut.result())
                    if len(self._items) > self.max_keys:
                        for old in sorted(self._items, key=lambda k: self._items[k][0])[
                                :self.max_keys // 4]:
                            self._items.pop(old, None)

            flight.add_done_callback(done)
        # shield: one visitor hanging up must not cancel the work the others wait for
        return await asyncio.shield(flight)


class Hub:
    """Fan-out of live knocks to every connected browser."""

    MAX_CLIENTS = 200
    MAX_PER_ADDRESS = 8

    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self.reads = ReadCache()
        self.clients: set[WebSocket] = set()
        self._owner: dict[WebSocket, str] = {}
        self.recent = collections.deque(maxlen=4000)  # timestamps for rolling kpm
        self.started = int(time.time())
        # Addresses that must never be shown, see redact.py. Stored data is
        # untouched; only what leaves the process is rewritten.
        self.scrub = Scrubber((cfg["dashboard"] or {}).get("hide", []))

    @staticmethod
    def _dump(message: dict) -> str:
        # Same encoding Starlette's send_json uses, so payloads are unchanged.
        return json.dumps(message, separators=(",", ":"), ensure_ascii=False)

    async def join(self, ws: WebSocket) -> None:
        # A public dashboard means anyone can open sockets. Each one holds a
        # snapshot and receives every broadcast, so an uncapped set is a free
        # memory-exhaustion lever.
        if len(self.clients) >= self.MAX_CLIENTS:
            await ws.close(code=1013)  # try again later
            log.warning("refused websocket, %d clients already connected",
                        len(self.clients))
            return
        # One address cannot take every seat.
        who = client_ip(ws) or "?"
        if sum(1 for o in self._owner.values() if o == who) >= self.MAX_PER_ADDRESS:
            await ws.close(code=1013)
            return
        try:
            snapshot = await self.reads.get(("snapshot",), self.snapshot)
        except Busy:
            await ws.close(code=1013)
            return
        await ws.accept()
        self.clients.add(ws)
        self._owner[ws] = who
        await ws.send_text(self.scrub.text(
            self._dump({"type": "init", "data": snapshot})))

    def leave(self, ws: WebSocket) -> None:
        self.clients.discard(ws)
        self._owner.pop(ws, None)

    def kpm(self, window: int = 300) -> float:
        cutoff = time.time() - window
        hits = sum(1 for ts in self.recent if ts >= cutoff)
        # Floor the divisor at one minute. Without it the first few seconds
        # after a restart extrapolate a handful of knocks into a silly rate.
        elapsed = min(window, max(60.0, time.time() - self.started))
        return round(hits / (elapsed / 60), 1)

    def snapshot(self) -> dict:
        totals = self.store.totals()
        first = self.store.first_start()
        uptime = max(1, int((time.time() - first) / 60))
        proto_stats = []
        for proto in self.cfg.protocols:
            row = totals["per_proto"].get(proto, {})
            count = row.get("count", 0)
            span = max(1, int((time.time() - (row.get("first_ts") or first)) / 60))
            proto_stats.append(
                {
                    "proto": proto,
                    "count": count,
                    "pct": round(count * 100 / totals["total"], 1) if totals["total"] else 0.0,
                    "kpm": round(count / span, 1),
                    "last_ts": row.get("last_ts"),
                }
            )
        return {
            # Only what a visitor's page can use. The rest of the block (the security contact,
            # the CSP mode) is the owner's, and the snapshot is public.
            "site": {k: v for k, v in (self.cfg["site"] or {}).items()
                     if k in ("title", "tagline", "about", "url")},
            "protocols": self.cfg.protocol_meta(),
            "colors": PROTO_COLORS,
            "total": totals["total"],
            "last_ts": totals["last_ts"],
            "uptime_minutes": uptime,
            "kpm": self.kpm(),
            "proto_stats": proto_stats,
            "boards": self.store.boards("ALL", self.cfg["board_size"]),
            "feed": self.store.feed("ALL", self.cfg["feed_size"]),
            "split": self.store.traffic_split(),
            "offenders": self.store.offenders(12),
            "narrative": narrate(self.store, 1),
            "campaigns": campaigns(self.store, 24),
        }

    async def publish(self, knock: Knock, stats: dict) -> None:
        self.recent.append(knock.ts)
        totals = self.store.totals()
        payload = {
            "type": "knock",
            "data": {
                **knock.public(),
                "stats": stats,
                "total": totals["total"],
                "kpm": self.kpm(),
                "proto_count": totals["per_proto"].get(knock.proto, {}).get("count", 0),
            },
        }
        # Concurrent, each with a deadline. publish() sits in every listener's
        # emit path, so one client that connects and never reads must not be
        # able to stall the whole honeypot.
        text = self.scrub.text(self._dump(payload))
        results = await asyncio.gather(
            *(self._send(ws, text) for ws in list(self.clients))
        )
        for ws in results:
            if ws is not None:
                self.leave(ws)

    async def _send(self, ws: WebSocket, text: str) -> WebSocket | None:
        """Returns the socket if it failed or timed out, else None."""
        try:
            await asyncio.wait_for(ws.send_text(text), SEND_TIMEOUT)
            return None
        except Exception:
            # A timed-out send may have written half a frame, so the socket
            # is not reusable. Close it rather than keep it in the set.
            try:
                await asyncio.wait_for(ws.close(), 1)
            except Exception:
                pass
            return ws


# Ports worth reporting on. Short list on purpose: this is a courtesy check,
# not a scanner.
CHECK_PORTS: list[tuple[int, str]] = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (80, "HTTP"),
    (443, "HTTPS"), (445, "SMB"), (3389, "RDP"), (8080, "HTTP alt"),
    (8443, "HTTPS alt"),
]
CHECK_COOLDOWN = 120          # seconds between checks for one address
CHECK_CONCURRENCY = 4         # simultaneous checks server-wide
_check_seen: dict[str, float] = {}
_check_gate = asyncio.Semaphore(CHECK_CONCURRENCY)

LOOKUP_LIMIT = 40             # address lookups per visitor per minute (a shared office NAT counts as one visitor)
_lookup_hits: dict[str, collections.deque] = {}

REPORT_LIMIT = 5              # wrong-entry reports per visitor per hour
_report_hits: dict[str, collections.deque] = {}

BULK_LIMIT = 10               # bulk checks per visitor per hour
BULK_MAX_ADDRESSES = 200      # unique addresses answered per bulk check
BULK_MAX_BODY = 65536
_bulk_hits: dict[str, collections.deque] = {}

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# A trailing dot means an embedded IPv4 (::ffff:192.0.2.4), which the IPv4 pattern
# picks up whole, so it is not also read as a broken IPv6 fragment.
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:.])")


def extract_ips(text: str, limit: int) -> tuple[list[str], bool]:
    """Unique valid addresses in the order they appear, and whether there were
    more than `limit`. Times like 12:30:45 look a little like IPv6, so every
    candidate goes through the real parser."""
    seen: dict[str, None] = {}
    truncated = False
    for match in sorted([(m.start(), m.group()) for rx in (_IPV4, _IPV6)
                         for m in rx.finditer(text)]):
        try:
            ip = str(ipaddress.ip_address(match[1]))
        except ValueError:
            continue
        if ip in seen:
            continue
        if len(seen) >= limit:
            truncated = True
            break
        seen[ip] = None
    return list(seen), truncated


def parse_addr(text: str):
    """One plain address, or None.

    Python reads "2001:db8::1%anything" as an address with a zone, and str() hands the
    zone back, so whatever follows the % would travel as part of the address into the
    address page, the share card and the report table. A zone only means something on
    the machine that wrote it, so it is refused. An IPv4 address written as IPv6
    (::ffff:192.0.2.4) is that IPv4 address.
    """
    if "%" in text:
        return None
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return getattr(addr, "ipv4_mapped", None) or addr


class TooLarge(Exception):
    pass


async def read_limited(request: Request, limit: int) -> bytes:
    """The request body, refusing to hold more than `limit` bytes. request.body()
    reads whatever is sent, so a large POST to a small endpoint would sit in memory
    first and be rejected afterwards."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise TooLarge()
    chunks, size = [], 0
    stream = request.stream()
    try:
        async for chunk in stream:
            size += len(chunk)
            if size > limit:
                raise TooLarge()
            chunks.append(chunk)
    finally:
        close = getattr(stream, "aclose", None)
        if close:
            await close()
    return b"".join(chunks)


def client_ip(request) -> str:
    """The visitor's real address. Behind a tunnel the socket peer is the
    tunnel itself, so Cloudflare's header comes first."""
    peer = request.client.host if request.client else ""
    # Only the local tunnel or proxy may vouch for a visitor's address. A
    # direct connection can set these headers to anything, and portcheck
    # would then probe whatever address it names.
    if peer not in ("127.0.0.1", "::1"):
        return peer
    head = request.headers
    return (head.get("cf-connecting-ip")
            or head.get("x-forwarded-for", "").split(",")[0].strip()
            or peer)


async def probe_port(ip: str, port: int, timeout: float = 1.2) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        _reader, writer = await asyncio.wait_for(fut, timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        return True
    except Exception:
        return False


def build_app(cfg: Config, store: Store, hub: Hub, feeds: FeedCache) -> FastAPI:
    # No generated documentation pages and no schema endpoint: the public files are described in the docs.
    app = FastAPI(title="uninvited", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    if hub.scrub.active:
        @app.middleware("http")
        async def scrub_api(request: Request, call_next):
            """Rewrite hidden values out of every /api/ response."""
            response = await call_next(request)
            if not request.url.path.startswith("/api/"):
                return response
            body = b"".join([chunk async for chunk in response.body_iterator])
            headers = {k: v for k, v in response.headers.items()
                       if k.lower() != "content-length"}
            return Response(hub.scrub.data(body), status_code=response.status_code,
                            headers=headers)

    def clean_proto(proto: str) -> str:
        proto = (proto or "ALL").upper()
        return proto if proto in cfg.protocols else "ALL"

    # Added last, so they wrap everything above: HEAD is answered like GET minus
    # the body, and every response carries the security headers (hardening.py).
    # site.csp in the config picks "report" (the default) or "enforce" for the
    # Content-Security-Policy, so it can be switched without a code change.
    ident = Identity.from_cfg(cfg)
    site, brand = ident.site, ident.brand
    app.add_middleware(hardening.SecurityHeaders, csp_mode=(cfg["site"] or {}).get("csp"),
                       frames=ident.frame_ancestors)
    app.add_middleware(hardening.HeadAsGet)

    # The page names the site and its owner; it is filled in once, here, from the config.
    page = ident.render((STATIC / "index.html").read_text(encoding="utf-8")).encode()

    @app.exception_handler(StarletteHTTPException)
    async def not_found(request: Request, exc: StarletteHTTPException):
        """A person who mistypes an address gets a page, not a line of JSON. Programs
        (curl, the API, the feeds) keep the plain answer."""
        path = request.url.path
        wants_page = "text/html" in request.headers.get("accept", "")
        if exc.status_code == 404 and wants_page and not path.startswith(("/api/", "/feed/")):
            return HTMLResponse(sitefiles.not_found_html(site, brand), status_code=404)
        return await http_exception_handler(request, exc)

    @app.get("/")
    async def index():
        # A minute of caching lets an edge cache absorb a burst, and a deploy
        # still shows up within the minute.
        return Response(page, media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=60"})

    @app.get("/favicon.svg")
    async def favicon():
        return Response(sitefiles.FAVICON_SVG, media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/favicon.ico")
    async def favicon_ico():
        return RedirectResponse("/favicon.svg", status_code=308)

    @app.get("/robots.txt", response_class=PlainTextResponse)
    async def robots():
        return sitefiles.robots_txt(site)

    @app.get("/sitemap.xml")
    async def sitemap():
        return Response(sitefiles.sitemap_xml(site), media_type="application/xml")

    @app.get("/.well-known/security.txt", response_class=PlainTextResponse)
    async def security_txt():
        body = sitefiles.security_txt(site, (cfg["site"] or {}).get("security_contact"))
        if body is None:
            return PlainTextResponse("not found\n", status_code=404)
        return body

    @app.get("/security.txt")
    async def security_txt_alias():
        return RedirectResponse("/.well-known/security.txt", status_code=308)

    async def heavy(key: tuple, fn):
        """One heavy read, shared and bounded (see ReadCache). Busy becomes a 503
        the caller can retry, never a queue that grows."""
        try:
            return await hub.reads.get(key, fn)
        except Busy:
            return JSONResponse({"error": "busy, retry shortly"}, status_code=503,
                                headers={"Retry-After": "5"})

    @app.get("/api/stats")
    async def stats():
        return await heavy(("snapshot",), hub.snapshot)

    @app.get("/api/boards")
    async def boards(proto: str = Query("ALL"),
                     limit: int = Query(0, ge=0, le=200)):
        proto = clean_proto(proto)
        # limit=0 keeps the configured board size for the dashboard panels; the
        # expanded list view asks for more.
        size = limit or cfg["board_size"]
        out = await heavy(("boards", proto, size), lambda: store.boards(proto, size))
        return out if isinstance(out, Response) else {"proto": proto, "boards": out}

    @app.get("/api/feed")
    async def feed(proto: str = Query("ALL"), limit: int = Query(100, ge=1, le=500),
                   kind: str = Query("", max_length=16)):
        # kind= answers the live page's filters from the whole table, not the recent window:
        # the quiet decoys see a few events an hour, so a window of minutes shows them nothing.
        if kind:
            if kind != "exploit" and kind not in Store.KIND_PROTOS:
                return JSONResponse({"error": "unknown kind"}, status_code=400)
            out = await heavy(("feedkind", kind, limit), lambda: store.feed_kind(kind, limit))
            return out if isinstance(out, Response) else {"kind": kind, "feed": out}
        proto = clean_proto(proto)
        out = await heavy(("feed", proto, limit), lambda: store.feed(proto, limit))
        return out if isinstance(out, Response) else {"proto": proto, "feed": out}

    @app.get("/api/offenders")
    async def offenders(limit: int = Query(25, ge=1, le=100),
                        kind: str = Query("")):
        kind = kind if kind in ("attack", "research", "tor") else None
        out = await heavy(("offenders", limit, kind), lambda: store.offenders(limit, kind))
        return out if isinstance(out, Response) else {"offenders": out}

    @app.get("/api/split")
    async def split():
        return await heavy(("split",), store.traffic_split)

    @app.get("/api/whoami")
    async def whoami(request: Request):
        """Has the visitor's own address ever knocked here? Good party trick."""
        # Behind a Cloudflare Tunnel the socket peer is the tunnel, so trust
        # CF's header first and fall back to the standard proxy chain.
        ip = client_ip(request)
        if not ip:
            return {"ip": None, "seen": False}
        return {"ip": ip, "seen": store.actor(ip) is not None,
                "actor": store.actor(ip)}

    _card: dict = {"at": 0.0, "svg": "", "png": None}

    @app.get("/og.svg")
    async def og_svg():
        return Response(_render_card(), media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=600"})

    @app.get("/og.png")
    async def og_png():
        _render_card()
        if _card["png"] is not None:
            return Response(_card["png"], media_type="image/png",
                            headers={"Cache-Control": "public, max-age=600"})
        # No rasteriser available, so hand back the vector. Every major
        # unfurler accepts it.
        return Response(_card["svg"], media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=600"})

    def _render_card() -> str:
        # Regenerating per request would let anyone spin the CPU by refreshing
        # a preview, so the card is rebuilt at most once every ten minutes.
        if time.time() - _card["at"] < 600 and _card["svg"]:
            return _card["svg"]
        stats = store.totals()
        split = store.traffic_split()
        countries = [(r["label"] or r["key"], r["count"])
                     for r in store.top("loc", "ALL", 4)]
        svg = build_svg(stats, split, countries, site, brand)
        # Pillow first: no system libraries, and unfurlers want a raster.
        bars = store.timeline(24, 60, "ALL")
        png = build_png_native(stats, split, countries, site, bars, brand) or build_png(svg)
        _card.update({"at": time.time(), "svg": svg, "png": png})
        return svg

    @app.get("/api/wordlist", response_class=PlainTextResponse)
    async def wordlist(limit: int = Query(2000, ge=1, le=20000),
                       min_hits: int = Query(1, ge=1, le=1000),
                       counts: bool = Query(False)):
        """Observed passwords by frequency. Passwords only, deliberately.

        Usernames are not attached and neither are addresses. A ranked
        frequency list is the same shape as every published wordlist and is
        useful to other people; a pairing that resolves an account to its
        password is a different artefact entirely, and this is not that.
        """
        rows = store.top("pass", "ALL", limit * 2)
        out = []
        for row in rows:
            if row["count"] < min_hits:
                continue
            word = (row["key"] or "").replace("\n", "").replace("\r", "")
            if not word:
                continue
            out.append(f"{word}\t{row['count']}" if counts else word)
            if len(out) >= limit:
                break
        header = (f"# Passwords observed by {brand} ({site})\n"
                  f"# Ranked by frequency. No usernames, no addresses, no pairings.\n"
                  f"# {len(out)} entries, minimum {min_hits} occurrences.\n")
        return header + "\n".join(out) + "\n"

    @app.get("/api/campaigns")
    async def campaign_list(hours: int = Query(24, ge=1, le=168)):
        out = await heavy(("campaigns", hours), lambda: campaigns(store, hours))
        return out if isinstance(out, Response) else {"campaigns": out}

    @app.get("/api/services")
    async def service_counts(hours: int = Query(24, ge=1, le=168)):
        """Connections per service over a window, for the Threat intel page."""
        out = await heavy(("services", hours), lambda: store.services(hours))
        return out if isinstance(out, Response) else {"hours": hours, "services": out}

    @app.get("/api/heatmap")
    async def heatmap(days: int = Query(7, ge=1, le=30)):
        """Connections by weekday and hour (UTC), attack and research apart."""
        return await heavy(("heatmap", days), lambda: store.heatmap(days))

    @app.get("/api/credstats")
    async def credstats():
        """The shape of the guessed passwords: lengths, make-up, concentration. No passwords in it."""
        return await heavy(("credstats",), store.cred_stats)

    @app.get("/api/emerging")
    async def emerging(days: int = Query(7, ge=1, le=14)):
        """Exploit names, web paths and credential pairs first seen in the window."""
        return await heavy(("emerging", days), lambda: store.emerging(days))

    @app.get("/api/notables")
    async def notable_list(hours: int = Query(1, ge=1, le=24)):
        """The few events in the window worth stopping for (see notables.py)."""
        out = await heavy(("notables", hours), lambda: find_notables(store, hours, int(time.time())))
        return out if isinstance(out, Response) else {"hours": hours, "notables": out}

    @app.get("/api/narrative")
    async def narrative(hours: int = Query(1, ge=1, le=24)):
        return await heavy(("narrative", hours), lambda: narrate(store, hours))

    @app.get("/api/portcheck")
    async def portcheck(request: Request):
        """Probe the caller's own address only.

        There is deliberately no way to supply a target. Accepting one would
        make this an open scanning proxy, and the traffic would leave from a
        residential line that is not interested in the abuse reports.
        """
        ip = client_ip(request)
        if not ip:
            return {"error": "could not determine your address"}
        addr = parse_addr(ip)
        if addr is None:
            return {"error": "your address did not parse"}
        # Only an address on the public internet is ever probed: not private or shared
        # space, not this machine, whichever way the address is written.
        if not addr.is_global or addr.is_multicast:
            return {"ip": ip, "error": "private address, nothing to check from out here"}
        ip = str(addr)

        last = _check_seen.get(ip, 0.0)
        wait = CHECK_COOLDOWN - (time.time() - last)
        if wait > 0:
            return {"ip": ip, "error": f"already checked, try again in {int(wait)}s"}
        _check_seen[ip] = time.time()
        if len(_check_seen) > 5000:
            cut = time.time() - CHECK_COOLDOWN
            for k in [k for k, v in _check_seen.items() if v < cut]:
                _check_seen.pop(k, None)

        async with _check_gate:
            results = await asyncio.gather(
                *(probe_port(ip, port) for port, _ in CHECK_PORTS)
            )
        ports = [{"port": p, "name": n, "open": bool(o)}
                 for (p, n), o in zip(CHECK_PORTS, results)]
        return {"ip": ip, "ports": ports,
                "open": sum(1 for p in ports if p["open"]),
                "seen": store.actor(ip) is not None}

    @app.get("/api/timeline")
    async def timeline(proto: str = Query("ALL"), hours: int = Query(24, ge=1, le=168),
                       buckets: int = Query(144, ge=12, le=288)):
        proto = clean_proto(proto)

        def build():
            return {"proto": proto, "hours": hours,
                    "buckets": store.timeline(hours, buckets, proto),
                    "split": store.timeline_split(hours, buckets) if proto == "ALL" else None}

        return await heavy(("timeline", proto, hours, buckets), build)

    @app.get("/api/blocklist", response_class=PlainTextResponse)
    async def blocklist(hours: int = Query(24, ge=1, le=720),
                        min_hits: int = Query(3, ge=1, le=1000)):
        """Plain-text IP list, for a gateway sync script, CrowdSec or nftables.

        Same rules as the published feed: TCP-verified attackers only, no
        research scanners or Tor exits, no spoofable UDP sources. Served from
        the in-memory cache, so polling it costs no database work.
        """
        if not feeds.ready:
            return PlainTextResponse("feed is warming up, retry shortly\n",
                                     status_code=503, headers={"Retry-After": "30"})
        return "\n".join(feeds.blocklist(hours, min_hits)) + "\n"

    PRIVATE_ANSWER = {"ip": "", "found": False,
                      "why_not": "That is a private or reserved address, so it cannot be in the data."}

    def lookup_rate(request: Request) -> Response | None:
        """One budget for everything that reads a single address, so neither the API nor the
        address pages can be used to sweep the database address by address."""
        who, now = client_ip(request) or "?", time.time()
        hits = _lookup_hits.setdefault(who, collections.deque())
        while hits and now - hits[0] > 60:
            hits.popleft()
        if len(hits) >= LOOKUP_LIMIT:
            return JSONResponse({"error": "Slow down, try again in a minute."},
                                status_code=429, headers={"Retry-After": "60"})
        hits.append(now)
        if len(_lookup_hits) > 5000:
            for k in [k for k, v in _lookup_hits.items() if not v or now - v[-1] > 60]:
                _lookup_hits.pop(k, None)
        return None

    def lookup_answer(text: str) -> dict:
        """Everything the dashboard knows about one public address. Blocking: run it in an executor."""
        now = time.time()
        ev = store.evidence(text)
        intel = feeds.lookup(text) if feeds.ready else {
            "listed": {}, "score": None, "techniques": [], "cves": [],
            "exploits": [], "engaged_30d": 0}
        why = None
        if not ev["found"]:
            why = "This server has never seen that address."
        elif not any(intel["listed"].values()):
            actor = ev["actor"]
            if actor.get("kind") and actor["kind"] != "attack":
                why = (f"Classified as {actor.get('label') or actor['kind']}, so it is kept on "
                       "its own list and never in the attacker list.")
            elif now - (actor.get("last_ts") or 0) > 30 * 86400:
                when = time.strftime("%Y-%m-%d", time.gmtime(actor["last_ts"]))
                why = f"Last seen {when}, outside the 30 day window."
            elif intel["engaged_30d"] == 0:
                why = ("It connected but never went past a port scan, so it does not "
                       "qualify. The list needs 3 real attack events.")
            elif intel["engaged_30d"] < 3:
                n = intel["engaged_30d"]
                why = (f"Only {n} attack event{'s' if n != 1 else ''} in 30 days. "
                       "The list needs 3.")
            else:
                why = "Not on the list right now."
        return {"ip": text, **ev, **intel, "why_not": why}

    def is_public(addr) -> bool:
        # A hidden address gets the same answer as a private one, so the lookup
        # cannot be used to confirm what the scrubber is covering.
        text = str(addr)
        return addr.is_global and hub.scrub.text(text) == text

    @app.get("/api/lookup")
    async def lookup(request: Request, ip: str = Query(..., max_length=64)):
        """One address: is it on the feed, why or why not, and the evidence.

        Answers only from data the dashboard already shows. Rate limited per
        visitor, so it cannot be used to sweep the database address by address.
        """
        addr = parse_addr(ip)
        if addr is None:
            return JSONResponse({"error": "That is not an IP address."}, status_code=400)
        if (limited := lookup_rate(request)) is not None:
            return limited
        if not is_public(addr):
            return dict(PRIVATE_ANSWER)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lookup_answer, str(addr))

    @app.get("/ip/{ip}", response_class=HTMLResponse)
    async def address_page(request: Request, ip: str):
        """A page per address, so a shared link unfurls with the evidence. Same data and the same
        rate budget as the lookup; the page itself carries no script."""
        addr = parse_addr(ip[:64])
        if addr is None:
            return PlainTextResponse("That is not an IP address.\n", status_code=400)
        if (limited := lookup_rate(request)) is not None:
            return limited
        if not is_public(addr):
            body = ippage.page(dict(PRIVATE_ANSWER), [], ident)
        else:
            loop = asyncio.get_running_loop()
            text = str(addr)
            answer = await loop.run_in_executor(None, lookup_answer, text)
            daily = await loop.run_in_executor(None, store.daily_hits, text) if answer["found"] else []
            body = ippage.page(answer, daily, ident)
        # For sharing, not for search: a listing expires, a search engine's copy of it does not.
        return HTMLResponse(body, headers={"Cache-Control": "public, max-age=300", "X-Robots-Tag": "noindex"})

    _cards: dict[str, tuple[float, bytes, str]] = {}

    @app.get("/ip/{ip}/card.png")
    async def address_card(request: Request, ip: str):
        addr = parse_addr(ip[:64])
        if addr is None:
            return PlainTextResponse("That is not an IP address.\n", status_code=400)
        text = str(addr)
        hit = _cards.get(text)
        if hit and time.time() - hit[0] < 600:
            return Response(hit[1], media_type=hit[2], headers={"Cache-Control": "public, max-age=600"})
        if (limited := lookup_rate(request)) is not None:
            return limited
        if not is_public(addr):
            answer = dict(PRIVATE_ANSWER)
        else:
            loop = asyncio.get_running_loop()
            answer = await loop.run_in_executor(None, lookup_answer, text)
        png = ippage.card_png(answer, site, brand)
        body, ctype = (png, "image/png") if png else (ippage.card_svg(answer, site, brand).encode(), "image/svg+xml")
        if len(_cards) > 500:
            _cards.clear()
        _cards[text] = (time.time(), body, ctype)
        return Response(body, media_type=ctype, headers={"Cache-Control": "public, max-age=600"})

    def _week(week_id: str | None) -> dict | None:
        if week_id is None or (feeds.digest and feeds.digest.get("id") == week_id):
            return feeds.digest
        if not digest.valid_id(week_id) or not feeds.digest_dir:
            return None
        path = os.path.join(feeds.digest_dir, week_id + ".json")
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    @app.get("/week", response_class=HTMLResponse)
    @app.get("/week/{week_id}", response_class=HTMLResponse)
    async def week_page(week_id: str | None = None):
        """The weekly digest, written by the feed. /week is the current week; /week/<year>-<week>
        is kept as it was."""
        if week_id and week_id.endswith(".json"):
            d = _week(week_id[:-5])
            if d is None:
                return JSONResponse({"error": "No digest for that week."}, status_code=404)
            return JSONResponse(d, headers={"Cache-Control": "public, max-age=300"})
        d = _week(week_id)
        if d is None:
            return PlainTextResponse("No digest for that week.\n", status_code=404)
        current = feeds.digest is not None and d.get("id") == feeds.digest.get("id")
        return HTMLResponse(digest.page(d, ident, current), headers={"Cache-Control": "public, max-age=300"})

    @app.get("/week.json")
    async def week_json():
        if feeds.digest is None:
            return JSONResponse({"error": "The digest is not built yet."}, status_code=503)
        return JSONResponse(feeds.digest, headers={"Cache-Control": "public, max-age=300"})

    @app.post("/api/bulk")
    async def bulk(request: Request):
        """Check many addresses at once, for pasting in an auth or firewall log.

        Send {"ips": [...]} (the page does this, extracting the addresses in the
        browser so the log never leaves the visitor's machine) or {"text": "..."}
        and the addresses are pulled out here. Nothing is stored or logged
        beyond a count. Limited per visitor, and to 200 unique addresses.
        """
        try:
            raw = await read_limited(request, BULK_MAX_BODY)
        except TooLarge:
            return JSONResponse({"error": "That is too much to check at once."}, status_code=413)
        try:
            body = json.loads(raw)
        except ValueError:
            return JSONResponse({"error": "Send JSON with an ips list or some text."}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "Send JSON with an ips list or some text."}, status_code=400)
        if isinstance(body.get("ips"), list):
            text = " ".join(str(x) for x in body["ips"][:2000])
        elif isinstance(body.get("text"), str):
            text = body["text"]
        else:
            return JSONResponse({"error": "Send JSON with an ips list or some text."}, status_code=400)

        who, now = client_ip(request) or "?", time.time()
        hits = _bulk_hits.setdefault(who, collections.deque())
        while hits and now - hits[0] > 3600:
            hits.popleft()
        if len(hits) >= BULK_LIMIT:
            return JSONResponse({"error": "That is enough bulk checks for this hour."},
                                status_code=429, headers={"Retry-After": "3600"})
        hits.append(now)
        if len(_bulk_hits) > 5000:
            for k in [k for k, v in _bulk_hits.items() if not v or now - v[-1] > 3600]:
                _bulk_hits.pop(k, None)

        ips, truncated = extract_ips(text, BULK_MAX_ADDRESSES)
        loop = asyncio.get_running_loop()
        known = await loop.run_in_executor(None, store.actors_many, ips)

        rows = []
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            row: dict = {"ip": ip, "verdict": "unknown", "score": None, "tags": [],
                         "host_type": None, "expires": None, "first_seen": None,
                         "last_seen": None, "note": "Never seen by this server."}
            if not addr.is_global or hub.scrub.text(ip) != ip:
                row.update(verdict="private", note="Private or reserved, so it cannot be in the data.")
            elif ip in intel.NEVER_ADDRESSES:
                row.update(verdict="protected", note="A public DNS resolver. Never listed.")
            else:
                info = feeds.lookup(ip) if feeds.ready else {"listed": {}}
                actor = known.get(ip)
                if actor:
                    row.update(first_seen=actor["first_ts"], last_seen=actor["last_ts"])
                if any(info.get("listed", {}).values()):
                    row.update(verdict="listed", score=info["score"], tags=info["tags"],
                               host_type=info["host_type"], expires=info["expires"],
                               note="On the feed.")
                elif actor and actor.get("kind") and actor["kind"] != "attack":
                    row.update(verdict="scanner",
                               note=f"Classified as {actor.get('label') or actor['kind']}, kept on its own list.")
                elif actor:
                    row.update(verdict="seen",
                               note="Seen by this server but not listed: too few attack events, or too long ago.")
            rows.append(row)

        order = {"listed": 0, "seen": 1, "scanner": 2, "unknown": 3, "protected": 4, "private": 5}
        rows.sort(key=lambda r: (order[r["verdict"]], -(r["score"] or 0)))
        summary = {v: sum(1 for r in rows if r["verdict"] == v) for v in order}
        log.info("bulk check of %d addresses", len(ips))
        return {"count": len(ips), "truncated": truncated, "limit": BULK_MAX_ADDRESSES,
                "summary": summary, "results": rows}

    @app.post("/api/report")
    async def report(request: Request):
        """A visitor says a listing is wrong. Stored for the owner and never
        shown to anyone else. Tightly limited, since it accepts free text."""
        try:
            raw = await read_limited(request, 4096)
        except TooLarge:
            return JSONResponse({"error": "That is too long."}, status_code=413)
        try:
            body = json.loads(raw)
            addr = parse_addr(str(body.get("ip", "")))
            note = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(body.get("note", "")))[:500].strip()
        except (ValueError, AttributeError):
            addr = None
        if addr is None:
            return JSONResponse({"error": "Send an IP address and a short note."}, status_code=400)
        text = str(addr)
        if not addr.is_global or hub.scrub.text(text) != text:
            return JSONResponse({"error": "That address cannot be in the data."}, status_code=400)

        who, now = client_ip(request) or "?", time.time()
        hits = _report_hits.setdefault(who, collections.deque())
        while hits and now - hits[0] > 3600:
            hits.popleft()
        if len(hits) >= REPORT_LIMIT:
            return JSONResponse({"error": "That is enough reports for now, try again later."},
                                status_code=429, headers={"Retry-After": "3600"})
        hits.append(now)
        if len(_report_hits) > 5000:
            for k in [k for k, v in _report_hits.items() if not v or now - v[-1] > 3600]:
                _report_hits.pop(k, None)

        loop = asyncio.get_running_loop()
        stored = await loop.run_in_executor(None, store.add_report, text, note, who)
        if not stored:
            return JSONResponse({"error": "Reports are full right now."}, status_code=503)
        log.info("wrong-entry report for %s", text)
        return {"ok": True, "message": "Thanks. I will look at it."}

    def public_base(request: Request) -> str:
        """The address clients should use to come back. On the public site that is
        https plus the configured name; anywhere else (a laptop, a test) it is
        whatever address the request came in on."""
        host = request.headers.get("host", "").split(":")[0].lower()
        if host == site.lower():
            return "https://" + site
        return str(request.base_url).rstrip("/")

    taxii.add_routes(app, feeds.taxii, public_base, client_ip)

    @app.get("/feed/changes/{name}")
    async def feed_changes(name: str, since: str | None = Query(None, max_length=40)):
        """What was added to and removed from one list since a time, as a net
        effect. Only list names in the static table are answered."""
        if name not in CHANGE_LISTS:
            return JSONResponse({"error": "unknown list", "lists": list(CHANGE_LISTS)},
                                status_code=404)
        if not feeds.ready:
            return JSONResponse({"error": "feed is warming up, retry shortly"},
                                status_code=503, headers={"Retry-After": "30"})
        when = parse_since(since, int(time.time()))
        if when is None:
            return JSONResponse({"error": "since must be an ISO 8601 time or epoch seconds"},
                                status_code=400)
        doc = feeds.changes(name, when)
        return JSONResponse(doc, headers={"Cache-Control": "public, max-age=60",
                                          "X-Content-Type-Options": "nosniff"})

    @app.get("/feed/{name:path}")
    async def feed_file(name: str, request: Request):
        """Published lists and feeds. Prebuilt, cached, safe to poll.

        Only names in the feed builder's table are served, so nothing a client
        sends ever reaches a filesystem path.
        """
        if name not in feeds.names:
            return PlainTextResponse("not found\n", status_code=404)
        snap = feeds.get(name)
        if snap is None:
            return PlainTextResponse("feed is warming up, retry shortly\n",
                                     status_code=503, headers={"Retry-After": "30"})
        headers = {
            "ETag": snap.etag,
            "Last-Modified": snap.last_modified,
            # Only until the next rebuild is due. A flat five minutes on top of a five minute
            # rebuild let a cache serve a file up to ten minutes old.
            "Cache-Control": f"public, max-age={max(20, int(REFRESH_SECONDS - (time.time() - feeds.built_at)))}",
            "X-Content-Type-Options": "nosniff",
        }
        if request.headers.get("if-none-match") == snap.etag:
            return Response(status_code=304, headers=headers)
        return Response(snap.body, media_type=snap.content_type, headers=headers)

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await hub.join(ws)
        try:
            while True:
                # The browser never sends anything; this just parks the socket
                # and notices the disconnect.
                await ws.receive_text()
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.leave(ws)

    return app
