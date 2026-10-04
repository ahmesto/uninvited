"""TLS client fingerprints, read from a ClientHello that was sent to a plain web port.

Scanners and botnets often speak TLS to every port they find. The web decoys do not speak
it, but the first bytes of the handshake still say a lot: which cipher suites the client
offers, in what order, which extensions, which curves, and which host name it asked for.
That is the JA3 fingerprint and the server name (SNI). Like the SSH client fingerprint
(HASSH), it survives a change of address, so two hosts with the same JA3 are running the
same TLS stack.

Only the first record is read and the handshake is never answered, so nothing is negotiated
and nothing is stored but the numbers and the name. Input is hostile: every length is
checked against what is actually there, lists are capped, and a hello that does not parse
is simply not fingerprinted.

JA3 (Salesforce, 2017): md5 of "version,ciphers,extensions,curves,point formats", each list
joined by "-" with GREASE values removed. Checked against the reference implementation
(pyja3) on hellos from OpenSSL, Python's ssl module and Windows' Schannel: see
tests/test_tlsfp.py and tests/fixtures/ja3_cases.json.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field

GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
MAX_RECORD = 4096          # bytes of hello considered
MAX_ITEMS = 256            # entries read from any one list
HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

EXT_SNI, EXT_GROUPS, EXT_POINT_FORMATS, EXT_ALPN, EXT_VERSIONS = 0x0000, 0x000A, 0x000B, 0x0010, 0x002B


@dataclass
class ClientHello:
    version: int                                   # the version in the hello, not the record
    ciphers: list[int]
    extensions: list[int]                          # in the order sent
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)
    versions: list[int] = field(default_factory=list)


def looks_like_tls(first: bytes) -> bool:
    """A TLS handshake record: type 22, major version 3."""
    return len(first) >= 2 and first[0] == 0x16 and first[1] == 0x03


def record_length(header: bytes) -> int | None:
    """The total size of the first record, from its 5-byte header, or None if it is not a
    handshake record of a size worth reading."""
    if len(header) < 5 or not looks_like_tls(header):
        return None
    size = 5 + struct.unpack(">H", header[3:5])[0]
    return size if 9 <= size <= MAX_RECORD else None


def _u16s(data: bytes) -> list[int]:
    n = min(len(data) // 2, MAX_ITEMS)
    return list(struct.unpack(f">{n}H", data[:2 * n]))


def parse_client_hello(record: bytes) -> ClientHello | None:
    """The fields of the ClientHello in one TLS record (header included), or None."""
    try:
        if not looks_like_tls(record) or len(record) < 9:
            return None
        body = record[5:5 + struct.unpack(">H", record[3:5])[0]]
        if len(body) < 4 or body[0] != 0x01:                          # a ClientHello
            return None
        hello = body[4:4 + int.from_bytes(body[1:4], "big")]
        pos = 0
        version = struct.unpack(">H", hello[pos:pos + 2])[0]
        pos += 2 + 32                                                   # version, random
        pos += 1 + hello[pos]                                           # session id
        size = struct.unpack(">H", hello[pos:pos + 2])[0]
        pos += 2
        if size % 2 or pos + size > len(hello):
            return None
        ciphers = _u16s(hello[pos:pos + size])
        pos += size
        pos += 1 + hello[pos]                                           # compression methods
        out = ClientHello(version=version, ciphers=ciphers, extensions=[])
        if pos + 2 > len(hello):
            return out                                                  # no extensions at all
        total = struct.unpack(">H", hello[pos:pos + 2])[0]
        pos += 2
        end = min(pos + total, len(hello))
        while pos + 4 <= end and len(out.extensions) < MAX_ITEMS:
            kind, size = struct.unpack(">HH", hello[pos:pos + 4])
            data = hello[pos + 4:pos + 4 + size]
            pos += 4 + size
            out.extensions.append(kind)
            if kind == EXT_GROUPS and len(data) >= 2:
                out.groups = _u16s(data[2:2 + struct.unpack(">H", data[:2])[0]])
            elif kind == EXT_POINT_FORMATS and len(data) >= 1:
                out.point_formats = list(data[1:1 + data[0]][:MAX_ITEMS])
            elif kind == EXT_SNI and len(data) >= 5 and data[2] == 0:
                name = data[5:5 + struct.unpack(">H", data[3:5])[0]]
                text = name.decode("ascii", "ignore")
                out.sni = text.lower() if HOST.match(text) else None
            elif kind == EXT_ALPN and len(data) >= 3:
                items, i, stop = [], 2, min(len(data), 2 + struct.unpack(">H", data[:2])[0])
                while i < stop and len(items) < 16:
                    n = data[i]
                    proto = data[i + 1:i + 1 + n].decode("ascii", "ignore")
                    if proto and re.fullmatch(r"[A-Za-z0-9./_-]{1,32}", proto):
                        items.append(proto)
                    i += 1 + n
                out.alpn = items
            elif kind == EXT_VERSIONS and len(data) >= 1:
                out.versions = [v for v in _u16s(data[1:1 + data[0]]) if v not in GREASE]
        return out
    except (struct.error, IndexError, ValueError):
        return None


def ja3_string(h: ClientHello) -> str:
    keep = lambda values: "-".join(str(v) for v in values if v not in GREASE)       # noqa: E731
    return ",".join([str(h.version), keep(h.ciphers), keep(h.extensions), keep(h.groups),
                     "-".join(str(v) for v in h.point_formats)])


def ja3(h: ClientHello) -> str:
    return hashlib.md5(ja3_string(h).encode()).hexdigest()
