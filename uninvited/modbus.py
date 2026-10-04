"""Modbus TCP decoy: frame parsing and canned answers.

Pure functions, no sockets, so every rule here can be tested without a network.
Nothing a client sends is acted on. A write is acknowledged and remembered for
the life of that one connection so a follow-up read agrees with it, then it is
forgotten. The decoy answers with small fixed-size replies only.

Function codes handled: 1, 2 (read bits), 3, 4 (read registers), 5, 6, 15, 16
(writes), 8 (echo), 17 (server id), 43/14 (device identification). Anything else
gets the standard "illegal function" exception.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Function codes that change state on a real device.
WRITE_FCS = frozenset({0x05, 0x06, 0x0F, 0x10})

FC_NAMES = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x2B: "Encapsulated Interface Transport",
}

ILLEGAL_FUNCTION = 0x01
ILLEGAL_ADDRESS = 0x02
ILLEGAL_VALUE = 0x03

MAX_STATE = 512        # remembered writes per connection
MAX_ECHO = 64          # bytes of a diagnostics echo


@dataclass(frozen=True)
class Identity:
    """What the decoy says it is. Generic on purpose, and set in the config."""

    vendor: str = "Lakeside Controls"
    product: str = "LC-2200 Controller"
    revision: str = "V2.1.4"

    @classmethod
    def from_cfg(cls, cfg: dict | None) -> Identity:
        cfg = cfg or {}
        d = cls()
        return cls(
            vendor=str(cfg.get("vendor", d.vendor))[:64],
            product=str(cfg.get("product", d.product))[:64],
            revision=str(cfg.get("revision", d.revision))[:32],
        )


@dataclass
class State:
    """Per-connection memory of what the client wrote."""

    coils: dict[int, bool] = field(default_factory=dict)
    regs: dict[int, int] = field(default_factory=dict)

    def room(self) -> bool:
        return len(self.coils) + len(self.regs) < MAX_STATE


@dataclass
class Result:
    pdu: bytes                     # the response PDU
    info: dict                     # what to log


def fc_name(fc: int) -> str:
    return FC_NAMES.get(fc, f"Function 0x{fc:02x}")


def parse_mbap(head: bytes) -> tuple[int, int, int] | None:
    """Seven header bytes -> (transaction id, length, unit id), or None if this
    is not Modbus TCP. Protocol id must be 0 and the length must leave room for
    a function code without exceeding the 253-byte PDU limit."""
    if len(head) != 7:
        return None
    tid, pid, length, unit = struct.unpack(">HHHB", head)
    if pid != 0 or not 2 <= length <= 254:
        return None
    return tid, length, unit


def frame(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def _exc(fc: int, code: int, info: dict) -> Result:
    info["exception"] = code
    return Result(bytes([(fc | 0x80) & 0xFF, code]), info)


def _coil(state: State, addr: int) -> bool:
    if addr in state.coils:
        return state.coils[addr]
    return (addr * 7 + 3) % 5 == 0


def _reg(state: State, addr: int, now: float) -> int:
    if addr in state.regs:
        return state.regs[addr]
    # A stable base per address, with a slow wobble so two reads a few seconds
    # apart are not byte-identical, as a real process value would not be.
    base = 100 + ((addr * 2654435761) >> 7) % 900
    return base + (int(now) // 5 + addr) % 9


def handle(pdu: bytes, state: State, ident: Identity, now: float) -> Result:
    """Answer one request PDU. Never raises on client input."""
    fc = pdu[0] if pdu else 0
    info: dict = {"fc": fc, "name": fc_name(fc), "write": fc in WRITE_FCS}
    body = pdu[1:]

    if fc in (0x01, 0x02):
        if len(body) != 4:
            return _exc(fc, ILLEGAL_VALUE, info)
        addr, qty = struct.unpack(">HH", body)
        info.update(addr=addr, qty=qty)
        if not 1 <= qty <= 2000:
            return _exc(fc, ILLEGAL_VALUE, info)
        if addr + qty > 0x10000:
            return _exc(fc, ILLEGAL_ADDRESS, info)
        nbytes = (qty + 7) // 8
        bits = bytearray(nbytes)
        for i in range(qty):
            if _coil(state, addr + i):
                bits[i // 8] |= 1 << (i % 8)
        return Result(bytes([fc, nbytes]) + bytes(bits), info)

    if fc in (0x03, 0x04):
        if len(body) != 4:
            return _exc(fc, ILLEGAL_VALUE, info)
        addr, qty = struct.unpack(">HH", body)
        info.update(addr=addr, qty=qty)
        if not 1 <= qty <= 125:
            return _exc(fc, ILLEGAL_VALUE, info)
        if addr + qty > 0x10000:
            return _exc(fc, ILLEGAL_ADDRESS, info)
        data = b"".join(struct.pack(">H", _reg(state, addr + i, now) & 0xFFFF)
                        for i in range(qty))
        return Result(bytes([fc, qty * 2]) + data, info)

    if fc == 0x05:
        if len(body) != 4:
            return _exc(fc, ILLEGAL_VALUE, info)
        addr, value = struct.unpack(">HH", body)
        info.update(addr=addr, qty=1, value=value)
        if value not in (0x0000, 0xFF00):
            return _exc(fc, ILLEGAL_VALUE, info)
        if state.room():
            state.coils[addr] = value == 0xFF00
        return Result(pdu, info)

    if fc == 0x06:
        if len(body) != 4:
            return _exc(fc, ILLEGAL_VALUE, info)
        addr, value = struct.unpack(">HH", body)
        info.update(addr=addr, qty=1, value=value)
        if state.room():
            state.regs[addr] = value
        return Result(pdu, info)

    if fc == 0x0F:
        if len(body) < 5:
            return _exc(fc, ILLEGAL_VALUE, info)
        addr, qty, count = struct.unpack(">HHB", body[:5])
        info.update(addr=addr, qty=qty)
        if not 1 <= qty <= 1968 or count != (qty + 7) // 8 or len(body) != 5 + count:
            return _exc(fc, ILLEGAL_VALUE, info)
        if addr + qty > 0x10000:
            return _exc(fc, ILLEGAL_ADDRESS, info)
        data = body[5:]
        for i in range(min(qty, 64)):
            if not state.room():
                break
            state.coils[addr + i] = bool(data[i // 8] >> (i % 8) & 1)
        return Result(struct.pack(">BHH", fc, addr, qty), info)

    if fc == 0x10:
        if len(body) < 5:
            return _exc(fc, ILLEGAL_VALUE, info)
        addr, qty, count = struct.unpack(">HHB", body[:5])
        info.update(addr=addr, qty=qty)
        if not 1 <= qty <= 123 or count != qty * 2 or len(body) != 5 + count:
            return _exc(fc, ILLEGAL_VALUE, info)
        if addr + qty > 0x10000:
            return _exc(fc, ILLEGAL_ADDRESS, info)
        for i in range(qty):
            if not state.room():
                break
            state.regs[addr + i] = struct.unpack(">H", body[5 + 2 * i:7 + 2 * i])[0]
        return Result(struct.pack(">BHH", fc, addr, qty), info)

    if fc == 0x08:
        # Diagnostics. Sub-function 0 is "return query data": echo it back.
        if len(body) < 2:
            return _exc(fc, ILLEGAL_VALUE, info)
        sub = struct.unpack(">H", body[:2])[0]
        info["sub"] = sub
        if sub != 0:
            return _exc(fc, ILLEGAL_FUNCTION, info)
        return Result(bytes([fc]) + body[:MAX_ECHO], info)

    if fc == 0x11:
        text = f"{ident.product} {ident.revision}".encode("ascii", "replace")
        payload = b"\x01\xFF" + text          # server id, run indicator ON, text
        return Result(bytes([fc, len(payload)]) + payload, info)

    if fc == 0x2B:
        # Encapsulated Interface Transport. Only MEI type 0x0E (read device
        # identification) is answered.
        if len(body) != 3 or body[0] != 0x0E:
            return _exc(fc, ILLEGAL_FUNCTION, info)
        info["name"] = "Read Device Identification"
        code, obj_id = body[1], body[2]
        info.update(mei=0x0E, read_code=code, object=obj_id)
        objects = {
            0: ident.vendor.encode("ascii", "replace"),
            1: ident.product.encode("ascii", "replace"),
            2: ident.revision.encode("ascii", "replace"),
        }
        if code not in (1, 2, 3, 4):
            return _exc(fc, ILLEGAL_VALUE, info)
        if code == 4:                          # one object, by id
            if obj_id not in objects:
                return _exc(fc, ILLEGAL_ADDRESS, info)
            chosen = [(obj_id, objects[obj_id])]
        else:                                  # a stream, starting at obj_id
            if obj_id > 2:
                obj_id = 0
            chosen = [(i, v) for i, v in sorted(objects.items()) if i >= obj_id]
        out = bytes([fc, 0x0E, code, 0x01, 0x00, 0x00, len(chosen)])
        for oid, val in chosen:
            out += bytes([oid, len(val)]) + val
        return Result(out, info)

    return _exc(fc, ILLEGAL_FUNCTION, info)
