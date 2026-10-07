"""A read-only TAXII 2.1 server for the attacker lists.

TAXII is the standard way threat intelligence platforms pull indicators from a
server, so this is what lets OpenCTI, MISP's TAXII feed, Anomali, Splunk ES, Microsoft
Sentinel's TAXII connector and anything else that speaks TAXII 2.1 subscribe to the
lists without custom code. It publishes the same indicators as the downloadable STIX
bundles (stix.py), grouped into collections:

    attackers-24h, attackers-7d, attackers-30d   the attacker lists by window
    attackers-high-7d                            score 60 or higher, last 7 days
    tag-persistent-7d                            hosts that kept coming back

Endpoints (all GET, anonymous, nothing writes):

    /taxii2/                                                   discovery
    /taxii2/root/                                              API root
    /taxii2/root/collections/                                  the collections
    /taxii2/root/collections/{id}/                             one collection
    /taxii2/root/collections/{id}/manifest/                    ids, versions, date_added
    /taxii2/root/collections/{id}/objects/                     the indicators
    /taxii2/root/collections/{id}/objects/{object-id}/         one object
    /taxii2/root/collections/{id}/objects/{object-id}/versions/

The objects endpoint takes added_after, limit, next and match[id], match[type],
match[version], match[spec_version]. A POST or DELETE is answered 403: the
collections are read-only.

date_added. A collection is the current list. Each object carries the time it was
first served in its present version: a host that joins the list, or attacks again and
so extends its valid_until, gets a new date_added. A client that polls with
added_after set to the time of its last poll therefore sees exactly what is new or
changed. The times are kept in a small state file so a restart does not make every
object look new. Without that file (the first run) everything is dated now, which
costs a client one full sync and never a missed object. Only the latest version of an
object is kept.
"""
from __future__ import annotations

import base64
import bisect
import calendar
import collections
import datetime
import json
import logging
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import Response

from .stix import IDENTITY_TS, Maker

log = logging.getLogger("uninvited.taxii")

MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
PAGE_DEFAULT = 500
PAGE_MAX = 1000
MAX_CONTENT_LENGTH = 1_048_576
RATE = 120            # requests per client per minute
STATE_VERSION = 1

# stem -> (title, description). The stem is also the name of the downloadable list.
COLLECTIONS: dict[str, tuple[str, str]] = {
    "attackers-24h": ("Attacking hosts, last 24 hours",
                      "Hosts that completed a TCP session and attacked the honeypot at least 3 times in the last 24 hours."),
    "attackers-7d": ("Attacking hosts, last 7 days",
                     "The same rule over 7 days."),
    "attackers-30d": ("Attacking hosts, last 30 days",
                      "The same rule over 30 days."),
    "attackers-high-7d": ("High-confidence attackers, last 7 days",
                          "Attackers with a score of 60 or higher in the 7 day list."),
    "tag-persistent-7d": ("Persistent attackers, last 7 days",
                          "Attackers first seen at least 7 days before their latest activity. The list to block from."),
    "malware-urls-7d": ("Malware download URLs, last 7 days",
                        "Addresses attackers asked the honeypot to download from, delivered by at least two hosts "
                        "or hosted by the host that sent them. Listed from what was asked for; nothing is fetched."),
}
STEMS = tuple(COLLECTIONS)

_OBJECT_ID = re.compile(r"^[a-z][a-z0-9-]{1,40}--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_COLLECTION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$")


def fmt_us(us: int) -> str:
    """Microseconds since the epoch -> a TAXII timestamp."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(us // 1_000_000)) + f".{us % 1_000_000:06d}Z"


def parse_us(text: str) -> int | None:
    """A TAXII timestamp -> microseconds since the epoch, or None if it is not one."""
    m = _TIME.match(text or "")
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) for g in m.groups()[:6])
    frac = (m.group(7) or "").ljust(6, "0")
    try:
        # datetime refuses a day that does not exist (February 30); timegm would not.
        moment = datetime.datetime(y, mo, d, h, mi, s)
        return calendar.timegm(moment.timetuple()) * 1_000_000 + int(frac)
    except (ValueError, OverflowError):
        return None


@dataclass
class Entry:
    date_added: int          # microseconds
    modified: str            # the object's own version, a STIX timestamp
    text: str                # the object as compact JSON
    obj_id: str
    obj_type: str


class Snapshot:
    """One collection's contents, ordered for paging. Built whole and swapped in whole."""

    def __init__(self, entries: dict[str, Entry]):
        self.entries = entries
        self.order = sorted(((e.date_added, i) for i, e in entries.items()))
        self.times = [t for t, _ in self.order]


class TaxiiState:
    def __init__(self, maker: Maker, ns: uuid.UUID, state_path: str | None = None):
        self.maker, self.ns, self.path = maker, ns, state_path
        self.ids = {stem: str(uuid.uuid5(ns, "taxii-collection-" + stem)) for stem in STEMS}
        self.by_id = {cid: stem for stem, cid in self.ids.items()}
        self.snaps: dict[str, Snapshot] = {}
        self._saved: dict[str, dict[str, list]] = {}
        identity = maker.identity()
        self._identity = Entry(parse_us(IDENTITY_TS) or 0, identity["modified"],
                               json.dumps(identity, separators=(",", ":")), identity["id"], "identity")
        self._load()

    @property
    def ready(self) -> bool:
        return bool(self.snaps)

    # ---------------------------------------------------------------- state

    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if doc.get("v") != STATE_VERSION:
                raise ValueError("unknown state version")
            self._saved = {s: {i: [int(v[0]), str(v[1])] for i, v in items.items()}
                           for s, items in doc["collections"].items()}
        except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            log.warning("TAXII state unreadable, dating everything now: %s", exc)
            self._saved = {}

    def _save(self) -> None:
        if not self.path:
            return
        doc = {"v": STATE_VERSION, "collections": {
            stem: {i: [e.date_added, e.modified] for i, e in snap.entries.items()
                   if e.obj_type != "identity"}
            for stem, snap in self.snaps.items()}}
        try:
            fd, tmp = tempfile.mkstemp(prefix=".taxii_state.", dir=os.path.dirname(os.path.abspath(self.path)))
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("could not save TAXII state: %s", exc)

    # --------------------------------------------------------------- update

    def update(self, rows_by_stem: dict[str, list[dict[str, Any]]], now: float) -> None:
        """Recompute every collection from the latest lists. Blocking and cheap, and
        it swaps each collection in as one assignment."""
        now_us = int(now * 1_000_000)
        identity_entry = self._identity
        changed = False
        for stem in STEMS:
            rows = rows_by_stem.get(stem)
            if rows is None:
                continue
            old = self.snaps.get(stem)
            before = old.entries if old else {}
            saved = self._saved.get(stem, {})
            entries = {identity_entry.obj_id: identity_entry}
            urls = stem.startswith("malware-urls")
            build = self.maker.url_objects if urls else self.maker.ip_objects
            # A new attack pattern or relationship is dated when it first appears, like an indicator,
            # so a client asking for added_after receives it.
            for obj in self.maker.shared(rows, urls) + [o for r in rows for o in build(r)]:
                text = json.dumps(obj, separators=(",", ":"))
                prev = before.get(obj["id"])
                if prev and prev.text == text:
                    entries[obj["id"]] = prev
                    continue
                kept = saved.get(obj["id"])
                if prev is None and kept and kept[1] == obj["modified"]:
                    date_added = kept[0]               # same version as before the restart
                else:
                    date_added = now_us
                entries[obj["id"]] = Entry(date_added, obj["modified"], text, obj["id"], obj["type"])
            if old is None or set(entries) != set(before) or any(
                    entries[i] is not before.get(i) for i in entries):
                changed = True
            self.snaps[stem] = Snapshot(entries)
        self._saved = {}                               # only the first update needs it
        if changed:
            self._save()

    # ---------------------------------------------------------------- query

    def collection(self, cid: str) -> str | None:
        return self.by_id.get(cid)

    @staticmethod
    def _cursor(token: str | None) -> tuple[int, str] | None:
        if token is None:
            return None
        try:
            us, oid = json.loads(base64.urlsafe_b64decode(token.encode() + b"=" * (-len(token) % 4)))
            if isinstance(us, int) and isinstance(oid, str):
                return us, oid
        except (ValueError, TypeError):
            pass
        raise ValueError("bad next")

    @staticmethod
    def _token(us: int, oid: str) -> str:
        return base64.urlsafe_b64encode(json.dumps([us, oid]).encode()).decode().rstrip("=")

    def page(self, stem: str, *, added_after: int | None, limit: int, nxt: str | None,
             ids: set[str] | None, types: set[str] | None, versions: set[str] | None,
             spec_versions: set[str] | None) -> dict[str, Any]:
        """-> {entries, more, next, first, last} for one page, newest-added last."""
        snap = self.snaps.get(stem)
        if snap is None:
            return {"entries": [], "more": False, "next": None, "first": None, "last": None}
        start = 0
        if added_after is not None:
            start = bisect.bisect_right(snap.times, added_after)
        cursor = self._cursor(nxt)
        if cursor is not None:
            start = max(start, bisect.bisect_right(snap.order, cursor))
        picked: list[Entry] = []
        more = False
        for _t, oid in snap.order[start:]:
            e = snap.entries[oid]
            if ids and oid not in ids:
                continue
            if types and e.obj_type not in types:
                continue
            if spec_versions is not None and "2.1" not in spec_versions:
                continue
            if versions and not (versions & {"all", "last", "first"} or e.modified in versions):
                continue
            if len(picked) == limit:
                more = True
                break
            picked.append(e)
        last = picked[-1] if picked else None
        return {"entries": picked, "more": more,
                "next": self._token(last.date_added, last.obj_id) if more and last else None,
                "first": picked[0].date_added if picked else None,
                "last": last.date_added if last else None}

    def get(self, stem: str, oid: str) -> Entry | None:
        snap = self.snaps.get(stem)
        return snap.entries.get(oid) if snap else None

    def count(self, stem: str) -> int:
        snap = self.snaps.get(stem)
        return sum(1 for e in snap.entries.values() if e.obj_type == "indicator") if snap else 0


# ------------------------------------------------------------------ HTTP layer

def _error(status: int, title: str, description: str | None = None,
           headers: dict[str, str] | None = None) -> Response:
    body = {"title": title, "http_status": str(status)}
    if description:
        body["description"] = description
    return Response(json.dumps(body), status_code=status, media_type=MEDIA, headers=headers)


def _ok(doc: Any, headers: dict[str, str] | None = None, raw: str | None = None) -> Response:
    h = {"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"}
    h.update(headers or {})
    return Response(raw if raw is not None else json.dumps(doc), media_type=MEDIA, headers=h)


def _accepts(request: Request) -> bool:
    """TAXII asks clients to send Accept: application/taxii+json;version=2.1. Be
    lenient about everything that could mean the same, and refuse the rest."""
    header = request.headers.get("accept", "").strip()
    if not header:
        return True
    for part in header.split(","):
        kind, _, params = part.strip().partition(";")
        kind = kind.strip().lower()
        if kind in ("*/*", "application/*", "application/json", "application/taxii+json"):
            if "taxii+json" in kind and "version=" in params and "version=2.1" not in params.replace(" ", ""):
                continue
            return True
    return False


def _csv_param(request: Request, name: str, limit: int = 100) -> set[str] | None:
    raw = request.query_params.get(name)
    if raw is None:
        return None
    values = {v.strip() for v in raw.split(",") if v.strip()}
    if len(values) > limit:
        raise ValueError(f"{name} takes at most {limit} values")
    return values


def add_routes(app: FastAPI, state: TaxiiState, base_url: Callable[[Request], str],
               client: Callable[[Request], str]) -> None:
    hits: dict[str, collections.deque] = {}

    def guard(request: Request) -> Response | None:
        if not _accepts(request):
            return _error(406, "Not Acceptable", "This server speaks application/taxii+json;version=2.1.")
        who, now = client(request) or "?", time.time()
        q = hits.setdefault(who, collections.deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE:
            return _error(429, "Too Many Requests", f"At most {RATE} requests a minute.",
                          {"Retry-After": "30"})
        q.append(now)
        if len(hits) > 5000:
            for k in [k for k, v in hits.items() if not v or now - v[-1] > 60]:
                hits.pop(k, None)
        return None

    def root_url(request: Request) -> str:
        return base_url(request).rstrip("/") + "/taxii2/root/"

    def route(path: str, handler, methods=("GET",)) -> None:
        # Both with and without the trailing slash, so no client depends on a redirect.
        for p in (path, path.rstrip("/")):
            app.add_api_route(p, handler, methods=list(methods), include_in_schema=False)

    async def discovery(request: Request):
        if (r := guard(request)):
            return r
        return _ok({"title": f"{state.maker.brand} TAXII server",
                    "description": "Attacker lists from a honeypot, as STIX 2.1 indicators. Read-only, no key.",
                    "default": root_url(request), "api_roots": [root_url(request)]})

    async def api_root(request: Request):
        if (r := guard(request)):
            return r
        return _ok({"title": state.maker.brand, "description": "Attacker lists, rebuilt every five minutes.",
                    "versions": [MEDIA], "max_content_length": MAX_CONTENT_LENGTH})

    def describe(stem: str) -> dict[str, Any]:
        title, text = COLLECTIONS[stem]
        return {"id": state.ids[stem], "title": title, "description": text,
                "can_read": True, "can_write": False, "media_types": [STIX_MEDIA]}

    async def list_collections(request: Request):
        if (r := guard(request)):
            return r
        return _ok({"collections": [describe(s) for s in STEMS]})

    def find(cid: str) -> str | None:
        return state.collection(cid) if _COLLECTION_ID.match(cid) else None

    def warming() -> Response | None:
        """The first build takes a few seconds. Until then there is nothing to serve."""
        if state.ready:
            return None
        return _error(503, "Warming up", "The lists are being built. Try again shortly.", {"Retry-After": "30"})

    async def one_collection(request: Request, cid: str):
        if (r := guard(request)):
            return r
        stem = find(cid)
        if stem is None:
            return _error(404, "Collection not found", "There is no collection with that id.")
        return _ok(describe(stem))

    def query(request: Request, stem: str):
        """-> (page dict) or an error Response."""
        try:
            after = None
            if "added_after" in request.query_params:
                after = parse_us(request.query_params["added_after"])
                if after is None:
                    return _error(400, "Bad added_after", "Use a UTC time like 2026-10-02T12:00:00Z.")
            limit = PAGE_DEFAULT
            if "limit" in request.query_params:
                raw = request.query_params["limit"]
                if not raw.isdigit() or int(raw) < 1:
                    return _error(400, "Bad limit", "limit must be a positive whole number.")
                limit = min(int(raw), PAGE_MAX)
            ids = _csv_param(request, "match[id]")
            if ids and any(not _OBJECT_ID.match(i) for i in ids):
                return _error(400, "Bad match[id]", "Object ids look like indicator--<uuid>.")
            types = _csv_param(request, "match[type]")
            versions = _csv_param(request, "match[version]")
            specs = _csv_param(request, "match[spec_version]")
            return state.page(stem, added_after=after, limit=limit, nxt=request.query_params.get("next"),
                              ids=ids, types=types, versions=versions, spec_versions=specs)
        except ValueError as exc:
            return _error(400, "Bad request", str(exc) if "bad next" not in str(exc) else "That next value is not one this server issued.")

    def date_headers(page: dict[str, Any]) -> dict[str, str]:
        out = {}
        if page["first"] is not None:
            out["X-TAXII-Date-Added-First"] = fmt_us(page["first"])
            out["X-TAXII-Date-Added-Last"] = fmt_us(page["last"])
        return out

    async def manifest(request: Request, cid: str):
        if (r := guard(request)) or (r := warming()):
            return r
        stem = find(cid)
        if stem is None:
            return _error(404, "Collection not found", "There is no collection with that id.")
        page = query(request, stem)
        if isinstance(page, Response):
            return page
        doc: dict[str, Any] = {"more": page["more"]}
        if page["next"]:
            doc["next"] = page["next"]
        if page["entries"]:
            doc["objects"] = [{"id": e.obj_id, "date_added": fmt_us(e.date_added), "version": e.modified,
                               "media_type": STIX_MEDIA} for e in page["entries"]]
        return _ok(doc, date_headers(page))

    def envelope(entries: list[Entry], more: bool, nxt: str | None) -> str:
        head = '{"more":' + ("true" if more else "false")
        if nxt:
            head += ',"next":' + json.dumps(nxt)
        if not entries:
            return head + "}"
        return head + ',"objects":[' + ",".join(e.text for e in entries) + "]}"

    async def objects(request: Request, cid: str):
        if (r := guard(request)) or (r := warming()):
            return r
        stem = find(cid)
        if stem is None:
            return _error(404, "Collection not found", "There is no collection with that id.")
        page = query(request, stem)
        if isinstance(page, Response):
            return page
        return _ok(None, date_headers(page), raw=envelope(page["entries"], page["more"], page["next"]))

    async def one_object(request: Request, cid: str, oid: str):
        if (r := guard(request)) or (r := warming()):
            return r
        stem = find(cid)
        entry = state.get(stem, oid) if stem and _OBJECT_ID.match(oid) else None
        if stem is None or entry is None:
            return _error(404, "Object not found", "That collection holds no object with that id.")
        return _ok(None, {"X-TAXII-Date-Added-First": fmt_us(entry.date_added),
                          "X-TAXII-Date-Added-Last": fmt_us(entry.date_added)},
                   raw=envelope([entry], False, None))

    async def versions(request: Request, cid: str, oid: str):
        if (r := guard(request)) or (r := warming()):
            return r
        stem = find(cid)
        entry = state.get(stem, oid) if stem and _OBJECT_ID.match(oid) else None
        if stem is None or entry is None:
            return _error(404, "Object not found", "That collection holds no object with that id.")
        return _ok({"more": False, "versions": [entry.modified]})

    async def read_only(request: Request, cid: str, oid: str = ""):
        return _error(403, "Read only", "These collections are read-only. This server accepts no writes.")

    async def no_status(request: Request, sid: str):
        return _error(404, "Status not found", "No writes are accepted, so there are no statuses.")

    route("/taxii2/", discovery)
    route("/taxii2/root/", api_root)
    route("/taxii2/root/collections/", list_collections)
    route("/taxii2/root/collections/{cid}/", one_collection)
    route("/taxii2/root/collections/{cid}/manifest/", manifest)
    route("/taxii2/root/collections/{cid}/objects/", objects)
    route("/taxii2/root/collections/{cid}/objects/", read_only, methods=("POST",))
    route("/taxii2/root/collections/{cid}/objects/{oid}/", one_object)
    route("/taxii2/root/collections/{cid}/objects/{oid}/", read_only, methods=("DELETE",))
    route("/taxii2/root/collections/{cid}/objects/{oid}/versions/", versions)
    route("/taxii2/root/status/{sid}/", no_status)
