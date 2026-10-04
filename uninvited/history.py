"""What changed on each published list, and when.

Every feed rebuild hands this the new membership of every list. It records who
joined and who left, keeps two weeks of that, and answers one question: since
time T, which addresses were added and which were removed, as a net effect. An
address that joined and left again in between is not mentioned, because a
consumer who applies the answer to a copy of the list taken at T ends up
exactly right.

If T is older than the history, the answer is a reset: fetch the whole list.
A partial answer would silently corrupt the consumer's copy, so none is given.

State is a small JSON file next to the database, replaced atomically, so a
restart does not erase the history. Nothing here touches the honeypot's
database.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime, UTC

log = logging.getLogger("uninvited.history")

KEEP_SECONDS = 14 * 86400
MAX_CHANGES = 50_000
STATE_VERSION = 1


def parse_since(text: str | None, now: int) -> int | None:
    """Epoch seconds or milliseconds, or an ISO 8601 time. None if unreadable.
    No value means the last 24 hours. A time in the future means now."""
    if text is None or not text.strip():
        return now - 86400
    text = text.strip()
    if re.fullmatch(r"\d{1,13}", text):
        value = int(text)
        if value > 10 ** 11:          # milliseconds
            value //= 1000
        return min(value, now)
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return min(int(when.timestamp()), now)


class ListHistory:
    def __init__(self, path: str | None = None):
        self.path = path
        self.members: dict[str, set[str]] = {}
        self.list_from: dict[str, int] = {}          # when each list's history starts
        self.changes: list[tuple[int, str, str, str]] = []   # ts, list, ip, "+" or "-"
        self._load()

    # --------------------------------------------------------------- state

    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if doc.get("v") != STATE_VERSION:
                raise ValueError("unknown state version")
            self.members = {k: set(v) for k, v in doc["members"].items()}
            self.list_from = {k: int(v) for k, v in doc["list_from"].items()}
            self.changes = [(int(t), str(n), str(i), str(o)) for t, n, i, o in doc["changes"]]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning("feed history state unreadable, starting fresh: %s", exc)
            self.members, self.list_from, self.changes = {}, {}, []

    def _save(self) -> None:
        if not self.path:
            return
        doc = {"v": STATE_VERSION, "list_from": self.list_from,
               "members": {k: sorted(v) for k, v in self.members.items()},
               "changes": self.changes}
        directory = os.path.dirname(os.path.abspath(self.path))
        try:
            fd, tmp = tempfile.mkstemp(prefix=".feed_state.", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("could not save feed history: %s", exc)

    # -------------------------------------------------------------- update

    def update(self, current: dict[str, set[str]], now: int) -> int:
        """Record what changed since the last call. Returns how many changes.

        The first time a list is seen it is only noted as a starting point, so
        a fresh install or a newly added list does not report its whole
        contents as additions."""
        recorded = 0
        dirty = False
        for name, now_members in current.items():
            before = self.members.get(name)
            if before is None:
                self.members[name] = set(now_members)
                self.list_from[name] = now
                dirty = True
                continue
            for ip in sorted(now_members - before):
                self.changes.append((now, name, ip, "+"))
                recorded += 1
            for ip in sorted(before - now_members):
                self.changes.append((now, name, ip, "-"))
                recorded += 1
            if now_members != before:
                self.members[name] = set(now_members)
                dirty = True
        before_len = len(self.changes)
        cutoff = now - KEEP_SECONDS
        self.changes = [c for c in self.changes if c[0] >= cutoff][-MAX_CHANGES:]
        if len(self.changes) != before_len:
            dirty = True
            # History now starts later than it did: any list whose earliest
            # surviving change is newer than its start cannot vouch for older times.
            self._tighten(cutoff)
        if dirty:
            self._save()
        return recorded

    def _tighten(self, cutoff: int) -> None:
        for name in self.list_from:
            self.list_from[name] = max(self.list_from[name], cutoff)
        if len(self.changes) == MAX_CHANGES:
            oldest = self.changes[0][0]
            for name in self.list_from:
                self.list_from[name] = max(self.list_from[name], oldest)

    # --------------------------------------------------------------- query

    def known(self, name: str) -> bool:
        return name in self.members

    def history_from(self, name: str) -> int | None:
        return self.list_from.get(name)

    def net_changes(self, name: str, since: int) -> dict | None:
        """{"reset": bool, "added": [...], "removed": [...]} for changes after
        `since`, or None if the list is not tracked."""
        if name not in self.members:
            return None
        start = self.list_from.get(name)
        if start is None or since < start:
            return {"reset": True, "added": [], "removed": []}
        first: dict[str, str] = {}
        last: dict[str, str] = {}
        for ts, n, ip, op in self.changes:
            if n != name or ts <= since:
                continue
            first.setdefault(ip, op)
            last[ip] = op
        return {
            "reset": False,
            "added": sorted(ip for ip, op in first.items() if op == "+" and last[ip] == "+"),
            "removed": sorted(ip for ip, op in first.items() if op == "-" and last[ip] == "-"),
        }

    def removed(self, name: str) -> set[str]:
        """Addresses whose last recorded change on a list, in the history kept, was leaving it."""
        last: dict[str, str] = {}
        for _ts, n, ip, op in self.changes:
            if n == name:
                last[ip] = op
        return {ip for ip, op in last.items() if op == "-"}

    def size(self) -> int:
        return len(self.changes)
