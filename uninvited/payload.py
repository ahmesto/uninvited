"""Raw request capture: what gets kept, and how it is made safe to read.

An HTTP request is stored once per distinct signature (method, target and the
start of the body), with a counter, so a scanner repeating one probe a million
times costs one row. The bytes are attacker-controlled. They are stored as
bytes and only ever shown through escape(), which leaves nothing that could
act as markup, a terminal control sequence or a log-injection newline.

Nothing here is served to the public. It is a log for the owner.
"""
from __future__ import annotations

import hashlib

MAX_RAW = 4096          # bytes kept per payload, headers and body together
MAX_SIG_BODY = 256      # bytes of body that count toward "is this the same request"
MAX_PAYLOADS = 20000    # distinct payloads kept; past this, new ones are not stored


def signature(method: str, target: str, body: bytes) -> bytes:
    """What makes two requests 'the same probe'. Headers are left out on purpose:
    User-Agent and Host vary per scanner and would make every request look new."""
    return f"{method} {target}\n".encode("utf-8", "replace") + body[:MAX_SIG_BODY]


def key(sig: bytes) -> str:
    return hashlib.sha256(sig).hexdigest()[:32]


def escape(raw: bytes, limit: int = MAX_RAW) -> str:
    """Printable text for bytes you do not trust. Tab, CR and LF are shown as
    \\t \\r \\n, every other control or non-ASCII byte as \\xNN, and the backslash
    itself is doubled so the output reads back unambiguously."""
    out = []
    for b in raw[:limit]:
        if b == 0x5C:
            out.append("\\\\")
        elif b == 0x09:
            out.append("\\t")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x0A:
            out.append("\\n")
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    if len(raw) > limit:
        out.append(f"...(+{len(raw) - limit} bytes)")
    return "".join(out)
