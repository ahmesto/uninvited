"""Siemens S7comm decoy: frame parsing and canned answers.

Pure functions, no sockets. Layers, outermost first: TPKT (4 bytes), COTP (connection
request and confirm, or a 3 byte data header), then the S7 PDU that starts with 0x32.

What the decoy does with a client:

  - answers the connection request and setup negotiation like a real CPU,
  - answers identity reads (SZL 0x0000, 0x0011, 0x001C, 0x0131, 0x0232) from a configured
    identity, which is what scanners such as nmap ask for,
  - answers a read with zeros and acknowledges a write, a stop, a start and a block
    transfer, so that whoever is attacking carries on and shows what they came to do,
  - refuses everything else with the error a CPU gives.

Nothing is stored, nothing a client sends changes any state, and every reply is small
and fixed. Each request is labelled for the log: identity, read, write, control (stop or
start a CPU) or program (move a block on or off it).
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

MAX_TPKT = 1024         # an S7 PDU is at most 960 bytes; anything bigger is not S7
MAX_READ_BYTES = 200    # per item
MAX_READ_TOTAL = 400    # per reply
MAX_ITEMS = 20

ROSCTR_JOB, ROSCTR_ACK, ROSCTR_ACK_DATA, ROSCTR_USERDATA = 1, 2, 3, 7

FUNC_NAMES = {
    0xF0: "Setup Communication", 0x04: "Read Var", 0x05: "Write Var",
    0x1A: "Request Download", 0x1B: "Download Block", 0x1C: "Download Ended",
    0x1D: "Start Upload", 0x1E: "Upload", 0x1F: "End Upload",
    0x28: "PLC Control", 0x29: "PLC Stop",
}
# What each function is, for the log and for the feed.
FUNC_LABEL = {
    0xF0: "read", 0x04: "read", 0x05: "write", 0x28: "control", 0x29: "control",
    0x1A: "program", 0x1B: "program", 0x1C: "program", 0x1D: "program", 0x1E: "program", 0x1F: "program",
}
AREAS = {0x81: "I", 0x82: "Q", 0x83: "M", 0x84: "DB", 0x1C: "C", 0x1D: "T", 0x05: "SM", 0x06: "AI", 0x07: "AQ"}
ELEMENT_BYTES = {1: 1, 2: 1, 3: 1, 4: 2, 5: 2, 6: 4, 7: 4, 8: 4, 9: 4}

PI_SERVICE = re.compile(rb"(_[A-Z]{4}|P_PROGRAM)")


@dataclass(frozen=True)
class Identity:
    """What the decoy says it is. Generic values, set in the config."""

    as_name: str = "PLC_1"
    module_name: str = "CPU 315-2 PN/DP"
    plant: str = "Pump Station 4"
    copyright: str = "Original Siemens Equipment"
    serial: str = "S C-X4U421302009"
    module_type: str = "CPU 315-2 PN/DP"
    order_code: str = "6ES7 315-2EH14-0AB0"
    firmware: tuple = (3, 2, 6)

    @classmethod
    def from_cfg(cls, cfg: dict | None) -> Identity:
        cfg = cfg or {}
        d = cls()
        pick = lambda k, n: str(cfg.get(k, getattr(d, k)))[:n]  # noqa: E731
        fw = cfg.get("firmware", d.firmware)
        if isinstance(fw, str):
            fw = tuple(int(x) for x in re.findall(r"\d+", fw)[:3])
        fw = tuple(int(x) & 0xFF for x in [*fw, 0, 0, 0][:3])
        return cls(as_name=pick("as_name", 24), module_name=pick("module_name", 24), plant=pick("plant", 32),
                   copyright=pick("copyright", 26), serial=pick("serial", 24),
                   module_type=pick("module_type", 32), order_code=pick("order_code", 20), firmware=fw)


@dataclass
class Result:
    reply: bytes | None                # the S7 PDU to send inside a COTP data frame
    info: dict = field(default_factory=dict)


# ----------------------------------------------------------------- TPKT, COTP

def parse_tpkt(head: bytes) -> int | None:
    """Four header bytes -> total length, or None when this is not TPKT."""
    if len(head) != 4 or head[0] != 3 or head[1] != 0:
        return None
    length = struct.unpack(">H", head[2:4])[0]
    return length if 7 <= length <= MAX_TPKT else None


def tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload


def cotp_data(s7_pdu: bytes) -> bytes:
    return tpkt(b"\x02\xf0\x80" + s7_pdu)


def cotp_type(body: bytes) -> str:
    """body is everything after the TPKT header."""
    if len(body) < 2:
        return "bad"
    return {0xE0: "CR", 0xF0: "DT", 0x80: "DR"}.get(body[1], "other")


def parse_cr(body: bytes) -> dict:
    """The TSAPs and size a connection request asks for. Fields that are missing or
    odd are simply left out."""
    out: dict = {}
    li = body[0]
    params = body[7:1 + li] if len(body) >= 1 + li and li >= 6 else b""
    i = 0
    while i + 2 <= len(params):
        code, n = params[i], params[i + 1]
        value = params[i + 2:i + 2 + n]
        if len(value) < n:
            break
        if code == 0xC1:
            out["tsap_src"] = value.hex()
        elif code == 0xC2:
            out["tsap_dst"] = value.hex()
        elif code == 0xC0:
            out["tpdu_size"] = value.hex()
        i += 2 + n
    return out


def cotp_confirm(body: bytes) -> bytes:
    """The connection confirm for a connection request: the client's reference back,
    ours, and its own TSAPs and size echoed."""
    client_ref = body[4:6] if len(body) >= 6 else b"\x00\x00"
    parsed = parse_cr(body)
    c0 = bytes.fromhex(parsed["tpdu_size"]) if "tpdu_size" in parsed else b"\x0a"
    c1 = bytes.fromhex(parsed["tsap_src"]) if "tsap_src" in parsed else b"\x01\x00"
    c2 = bytes.fromhex(parsed["tsap_dst"]) if "tsap_dst" in parsed else b"\x01\x02"
    params = (b"\xc0" + bytes([len(c0)]) + c0 + b"\xc1" + bytes([len(c1)]) + c1
              + b"\xc2" + bytes([len(c2)]) + c2)
    rest = b"\xd0" + client_ref + b"\x00\x01" + b"\x00" + params
    return tpkt(bytes([len(rest)]) + rest)


# ------------------------------------------------------------------- S7 PDUs

def parse_header(data: bytes) -> dict | None:
    if len(data) < 10 or data[0] != 0x32:
        return None
    rosctr = data[1]
    pduref = struct.unpack(">H", data[4:6])[0]
    plen, dlen = struct.unpack(">HH", data[6:10])
    hlen = 12 if rosctr in (ROSCTR_ACK, ROSCTR_ACK_DATA) else 10
    if len(data) < hlen + plen + dlen:
        return None
    return {"rosctr": rosctr, "pduref": pduref, "params": data[hlen:hlen + plen],
            "data": data[hlen + plen:hlen + plen + dlen]}


def _ack(pduref: int, params: bytes = b"", data: bytes = b"", err: tuple = (0, 0)) -> bytes:
    return struct.pack(">BBHHHHBB", 0x32, ROSCTR_ACK_DATA, 0, pduref, len(params), len(data), *err) + params + data


def _userdata(pduref: int, group: int, subfunc: int, seq: int, data: bytes) -> bytes:
    params = struct.pack(">BBBBBBBBBBBB", 0, 1, 0x12, 0x08, 0x12, 0x80 | group, subfunc, seq, 0, 0, 0, 0)
    return struct.pack(">BBHHHH", 0x32, ROSCTR_USERDATA, 0, pduref, len(params), len(data)) + params + data


def _userdata_error(pduref: int, code: int = 0x8104) -> bytes:
    params = struct.pack(">BBBBBBBBBBBB", 0, 1, 0x12, 0x08, 0x12, 0x84, 0x01, 0, 0, 0, 0, 0)
    data = struct.pack(">BBH", (code >> 8) & 0xFF, 0, 0)
    return struct.pack(">BBHHHH", 0x32, ROSCTR_USERDATA, 0, pduref, len(params), len(data)) + params + data


def _fixed(text: str, n: int) -> bytes:
    return text.encode("ascii", "replace")[:n].ljust(n, b"\x00")


def szl_data(szl_id: int, ident: Identity) -> bytes | None:
    """The record list for one SZL id: record length, record count, the records."""
    if szl_id == 0x001C:                    # component identification: index + 32 byte string
        records = [(1, ident.as_name), (2, ident.module_name), (3, ident.plant),
                   (4, ident.copyright), (5, ident.serial), (7, ident.module_type)]
        body = b"".join(struct.pack(">H", i) + _fixed(t, 32) for i, t in records)
        return struct.pack(">HH", 34, len(records)) + body
    if szl_id == 0x0011:                    # module identification: index, order code, version
        fw = bytes(ident.firmware)
        mlfb = _fixed(ident.order_code, 20)
        module = struct.pack(">H", 0x0001) + mlfb + b"\x00\x00\x00\x01\x00\x00"
        hardware = struct.pack(">H", 0x0006) + mlfb + b"\x00\x00\x00\x01\x00\x00"
        # index, 20 blank bytes, two filler bytes, 'V', then major, minor, patch: 28 bytes.
        firmware = struct.pack(">H", 0x0007) + _fixed("", 20) + b"\x00\x00\x56" + fw
        return struct.pack(">HH", 28, 3) + module + hardware + firmware
    if szl_id == 0x0131:                    # communication capabilities
        return struct.pack(">HH", 8, 1) + struct.pack(">HHHH", 240, 16, 12, 12)
    if szl_id == 0x0232:                    # protection level: none
        return struct.pack(">HH", 10, 1) + struct.pack(">HHHHH", 1, 0, 0, 0, 0)
    if szl_id == 0x0000:                    # which SZLs exist
        ids = [0x0000, 0x0011, 0x001C, 0x0131, 0x0232]
        return struct.pack(">HH", 2, len(ids)) + b"".join(struct.pack(">H", i) for i in ids)
    return None


def _items(params: bytes) -> list[dict]:
    """The address specifications in a read or write request."""
    out = []
    count = params[1] if len(params) > 1 else 0
    for i in range(min(count, MAX_ITEMS)):
        item = params[2 + 12 * i:2 + 12 * (i + 1)]
        if len(item) < 12 or item[0] != 0x12 or item[2] != 0x10:
            break
        tsize, n = item[3], struct.unpack(">H", item[4:6])[0]
        out.append({"tsize": tsize, "count": n, "db": struct.unpack(">H", item[6:8])[0],
                    "area": item[8], "addr": int.from_bytes(item[9:12], "big") >> 3})
    return out


def _describe(item: dict) -> str:
    area = AREAS.get(item["area"], f"0x{item['area']:02x}")
    where = f"DB{item['db']}" if item["area"] == 0x84 else area
    return f"{where} +{item['addr']} x{item['count']}"


def handle(data: bytes, ident: Identity) -> Result:
    """Answer one S7 PDU. Never raises on client input."""
    h = parse_header(data)
    if h is None:
        return Result(None, {"malformed": True})
    pduref, params, body = h["pduref"], h["params"], h["data"]

    if h["rosctr"] == ROSCTR_USERDATA:
        return _handle_userdata(pduref, params, body, ident)
    if h["rosctr"] != ROSCTR_JOB or not params:
        return Result(None, {"malformed": True})

    fc = params[0]
    info = {"fc": fc, "name": FUNC_NAMES.get(fc, f"Function 0x{fc:02x}"),
            "ics": FUNC_LABEL.get(fc, "read"), "write": False}

    if fc == 0xF0 and len(params) >= 8:
        client_pdu = struct.unpack(">H", params[6:8])[0]
        reply = struct.pack(">BBHHH", 0xF0, 0, 1, 1, min(client_pdu or 240, 240))
        info["pdu"] = client_pdu
        return Result(_ack(pduref, reply), info)

    if fc == 0x04:
        items = _items(params)
        if not items:
            return Result(_ack(pduref, err=(0x81, 0x04)), info)
        info["area"] = _describe(items[0])
        budget, parts = MAX_READ_TOTAL, []
        for it in items:
            size = ELEMENT_BYTES.get(it["tsize"], 1)
            n = max(0, min(it["count"] * size, MAX_READ_BYTES, budget))
            budget -= n
            chunk = b"\xff\x04" + struct.pack(">H", n * 8) + bytes(n)
            parts.append(chunk + (b"\x00" if len(chunk) % 2 and it is not items[-1] else b""))
        return Result(_ack(pduref, bytes([0x04, len(items)]), b"".join(parts)), info)

    if fc == 0x05:
        items = _items(params)
        if not items:
            return Result(_ack(pduref, err=(0x81, 0x04)), dict(info, write=True))
        info.update(write=True, area=_describe(items[0]))
        value = body[4:36]
        if value:
            info["value"] = value.hex()
        return Result(_ack(pduref, bytes([0x05, len(items)]), b"\xff" * len(items)), info)

    if fc in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
        info["write"] = True
        return Result(_ack(pduref, bytes([fc])), info)

    if fc in (0x28, 0x29):
        service = PI_SERVICE.search(params)
        text = service.group(1).decode() if service else ""
        if text:
            info["pi"] = text
        info["write"] = True
        if fc == 0x28 and text in ("_INSE", "_DELE"):
            info["ics"] = "program"
            info["name"] = "PLC Control: " + ("insert block" if text == "_INSE" else "delete block")
        return Result(_ack(pduref, bytes([fc])), info)

    return Result(_ack(pduref, err=(0x81, 0x04)), info)


def _handle_userdata(pduref: int, params: bytes, body: bytes, ident: Identity) -> Result:
    if len(params) < 8:
        return Result(None, {"malformed": True})
    group, subfunc, seq = params[5] & 0x0F, params[6], params[7]
    info = {"fc": 0x10000 | (group << 8) | subfunc, "name": f"Userdata group {group} function {subfunc}",
            "ics": "read", "write": False}
    if group == 4 and subfunc == 1 and len(body) >= 8:
        szl_id, index = struct.unpack(">HH", body[4:8])
        info.update(name="Read SZL", ics="identity", szl=f"{szl_id:04x}/{index:04x}")
        data = szl_data(szl_id, ident)
        if data is not None:
            payload = struct.pack(">HH", szl_id, index) + data
            return Result(_userdata(pduref, group, subfunc, seq, b"\xff\x09" + struct.pack(">H", len(payload)) + payload),
                          info)
    return Result(_userdata_error(pduref), info)
