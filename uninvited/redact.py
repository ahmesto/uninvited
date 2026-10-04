"""Last-mile scrubber for values that must never reach the public dashboard.

Scanners put the address they are attacking into the RDP username cookie, so a
honeypot with a home connection behind it ends up displaying that connection's
address as a "credential". Captured data stays exactly as captured in the
database. This only rewrites what leaves the process: REST responses and the
live WebSocket.

An address is matched whole. Hiding 192.0.2.4 leaves 192.0.2.44 alone.
"""
from __future__ import annotations

import re
from collections.abc import Iterable


class Scrubber:
    def __init__(self, values: Iterable[str] = (), label: str = "this server"):
        parts = [re.escape(str(v).strip()) for v in (values or []) if str(v).strip()]
        self.label = label
        self.active = bool(parts)
        # Not preceded or followed by a digit or a dot.
        self._re = (re.compile(r"(?<![\d.])(?:" + "|".join(parts) + r")(?![\d.])")
                    if parts else None)

    def text(self, s: str) -> str:
        return self._re.sub(self.label, s) if self._re else s

    def data(self, b: bytes) -> bytes:
        if not self._re:
            return b
        return self.text(b.decode("utf-8", "replace")).encode("utf-8")
