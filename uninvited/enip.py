"""EtherNet/IP decoy (TCP 44818): encapsulation parsing and canned answers.

Pure functions, no sockets. EtherNet/IP wraps CIP in a 24 byte encapsulation header, all
little endian: command, length, session handle, status, 8 byte sender context, options.

What the decoy does:

  - answers ListIdentity, ListServices and ListInterfaces, which is what scanners send first,
  - registers a session, and answers unconnected CIP requests (SendRRData),
  - answers a read of the Identity object with the configured identity,
  - acknowledges writes, resets, starts and stops, and refuses everything else with the
    status a device gives for an unsupported service.

Nothing is stored and nothing a client sends changes any state. TCP only: a UDP reply
to a spoofed source would turn the decoy into a reflector, so it is not offered.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

MAX_PAYLOAD = 512       # a real unconnected message is far smaller
HEADER = struct.Struct("<HHII8sI")

CMD_NAMES = {0x0004: "ListServices", 0x0063: "ListIdentity", 0x0064: "ListInterfaces",
             0x0065: "RegisterSession", 0x0066: "UnRegisterSession",
             0x006F: "SendRRData", 0x0070: "SendUnitData"}

SERVICE_NAMES = {0x01: "Get_Attribute_All", 0x02: "Set_Attribute_All", 0x03: "Get_Attribute_List",
                 0x05: "Reset", 0x06: "Start", 0x07: "Stop", 0x0E: "Get_Attribute_Single",
                 0x10: "Set_Attribute_Single", 0x4B: "Execute_PCCC", 0x4C: "Read_Tag", 0x4D: "Write_Tag",
                 0x4E: "Forward_Close", 0x52: "Unconnected_Send", 0x54: "Forward_Open"}
SERVICE_LABEL = {0x02: "write", 0x10: "write", 0x4D: "write",
                 0x05: "control", 0x06: "control", 0x07: "control"}
CLASS_FILE = 0x37       # moving a program on or off a device goes through the File object

# General status codes.
OK, BAD_SERVICE, UNKNOWN_PATH, NOT_SUPPORTED = 0x00, 0x08, 0x05, 0x08

# Encapsulation status codes.
ENC_OK, ENC_BAD_COMMAND, ENC_BAD_SESSION, ENC_BAD_VERSION = 0x00, 0x01, 0x64, 0x69


@dataclass(frozen=True)
class Identity:
    """What the decoy says it is. Set in the config."""

    vendor: int = 1                      # 1 is the most scanned vendor id
    device_type: int = 14                # programmable logic controller
    product_code: int = 55
    revision: tuple = (20, 11)
    serial: int = 0x00A1B2C3
    name: str = "1756-L61/B LOGIX5561"
    advertise_ip: str = "0.0.0.0"        # a real device reports its own address; the decoy does not

    @classmethod
    def from_cfg(cls, cfg: dict | None) -> Identity:
        cfg = cfg or {}
        d = cls()
        rev = cfg.get("revision", d.revision)
        if isinstance(rev, str):
            rev = tuple(int(x) for x in rev.replace("V", "").split(".")[:2])
        rev = tuple(int(x) & 0xFF for x in [*rev, 0, 0][:2])
        ip = str(cfg.get("advertise_ip", d.advertise_ip))
        try:
            parts = [int(p) for p in ip.split(".")]
            assert len(parts) == 4 and all(0 <= p <= 255 for p in parts)
        except (ValueError, AssertionError):
            ip = d.advertise_ip
        return cls(vendor=int(cfg.get("vendor", d.vendor)) & 0xFFFF,
                   device_type=int(cfg.get("device_type", d.device_type)) & 0xFFFF,
                   product_code=int(cfg.get("product_code", d.product_code)) & 0xFFFF,
                   revision=rev, serial=int(cfg.get("serial", d.serial)) & 0xFFFFFFFF,
                   name=str(cfg.get("name", d.name))[:40], advertise_ip=ip)


@dataclass
class Result:
    reply: bytes | None
    info: dict = field(default_factory=dict)
    close: bool = False


def parse_header(raw: bytes) -> dict | None:
    if len(raw) != 24:
        return None
    command, length, session, status, context, options = HEADER.unpack(raw)
    if length > MAX_PAYLOAD:
        return None
    return {"command": command, "length": length, "session": session, "status": status,
            "context": context, "options": options}


def frame(command: int, session: int, context: bytes, data: bytes = b"", status: int = ENC_OK) -> bytes:
    return HEADER.pack(command, len(data), session, status, context, 0) + data


def _short(text: str) -> bytes:
    raw = text.encode("ascii", "replace")[:255]
    return bytes([len(raw)]) + raw


def identity_attributes(ident: Identity) -> bytes:
    """The Identity object, attributes 1 to 7, as Get_Attribute_All returns them."""
    return (struct.pack("<HHH", ident.vendor, ident.device_type, ident.product_code)
            + bytes(ident.revision) + struct.pack("<HI", 0x0030, ident.serial) + _short(ident.name))


def list_identity_item(ident: Identity) -> bytes:
    ip = bytes(int(p) for p in ident.advertise_ip.split("."))
    body = (struct.pack("<H", 1)                                   # encapsulation protocol version
            + struct.pack(">HH", 2, 44818) + ip + bytes(8)         # socket address, big endian
            + struct.pack("<HHH", ident.vendor, ident.device_type, ident.product_code)
            + bytes(ident.revision) + struct.pack("<HI", 0x0030, ident.serial)
            + _short(ident.name) + b"\x03")                        # state: operational
    return struct.pack("<HH", 0x000C, len(body)) + body


def _parse_path(path: bytes) -> dict:
    out: dict = {}
    i = 0
    while i < len(path):
        seg = path[i]
        if seg == 0x20 and i + 1 < len(path):
            out["class"], i = path[i + 1], i + 2
        elif seg == 0x21 and i + 3 < len(path):
            out["class"], i = struct.unpack("<H", path[i + 2:i + 4])[0], i + 4
        elif seg == 0x24 and i + 1 < len(path):
            out["instance"], i = path[i + 1], i + 2
        elif seg == 0x25 and i + 3 < len(path):
            out["instance"], i = struct.unpack("<H", path[i + 2:i + 4])[0], i + 4
        elif seg == 0x30 and i + 1 < len(path):
            out["attribute"], i = path[i + 1], i + 2
        elif seg == 0x31 and i + 3 < len(path):
            out["attribute"], i = struct.unpack("<H", path[i + 2:i + 4])[0], i + 4
        else:
            break
    return out


def _cip_reply(service: int, status: int, data: bytes = b"") -> bytes:
    return bytes([service | 0x80, 0, status, 0]) + data


def _rr_data(cip: bytes) -> bytes:
    """The SendRRData body that carries one unconnected CIP reply."""
    return (struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0x0000, 0)
            + struct.pack("<HH", 0x00B2, len(cip)) + cip)


def handle_cip(request: bytes, ident: Identity, nested: bool = False) -> tuple[bytes, dict]:
    """-> (the CIP reply, log fields) for one unconnected CIP request."""
    if len(request) < 2:
        return _cip_reply(0, BAD_SERVICE), {"service": 0, "ics": "read", "write": False}
    service, words = request[0], request[1]
    path = _parse_path(request[2:2 + words * 2])
    if service == 0x52 and path.get("class") == 0x06 and not nested:
        # Unconnected Send: a request wrapped to be routed on. Answer the request inside it,
        # which is what a real device returns. Only one level is unwrapped.
        body = request[2 + words * 2:]
        size = struct.unpack("<H", body[2:4])[0] if len(body) >= 4 else 0
        inner = body[4:4 + size]
        if inner:
            reply, info = handle_cip(inner, ident, nested=True)
            info["via"] = "Unconnected_Send"
            return reply, info
    name = SERVICE_NAMES.get(service, f"Service 0x{service:02x}")
    label = SERVICE_LABEL.get(service, "read")
    if path.get("class") == CLASS_FILE:
        label = "program"
    info = {"service": service, "name": name, "ics": label, "write": label != "read"}
    for key in ("class", "instance", "attribute"):
        if key in path:
            info[key] = path[key]
    if label != "read":
        return _cip_reply(service, OK), info
    is_identity = path.get("class") == 0x01
    if is_identity and service == 0x01:
        info["ics"] = "identity"
        return _cip_reply(service, OK, identity_attributes(ident)), info
    if is_identity and service == 0x0E and "attribute" in path:
        attrs = {1: struct.pack("<H", ident.vendor), 2: struct.pack("<H", ident.device_type),
                 3: struct.pack("<H", ident.product_code), 4: bytes(ident.revision),
                 5: struct.pack("<H", 0x0030), 6: struct.pack("<I", ident.serial), 7: _short(ident.name)}
        if path["attribute"] in attrs:
            info["ics"] = "identity"
            return _cip_reply(service, OK, attrs[path["attribute"]]), info
        return _cip_reply(service, UNKNOWN_PATH), info
    return _cip_reply(service, NOT_SUPPORTED), info


def handle(head: dict, payload: bytes, session: int | None, ident: Identity) -> Result:
    """Answer one encapsulated command. `session` is the handle this connection has
    registered, or None. The caller keeps it. Never raises on client input."""
    cmd, ctx = head["command"], head["context"]
    name = CMD_NAMES.get(cmd, f"Command 0x{cmd:04x}")
    info: dict = {"command": cmd, "name": name, "ics": "identity", "write": False}

    if cmd == 0x0063:
        data = struct.pack("<H", 1) + list_identity_item(ident)
        return Result(frame(cmd, 0, ctx, data), info)
    if cmd == 0x0004:
        item = struct.pack("<HHHH", 0x0100, 20, 1, 0x0120) + b"Communications".ljust(16, b"\x00")
        return Result(frame(cmd, 0, ctx, struct.pack("<H", 1) + item), info)
    if cmd == 0x0064:
        return Result(frame(cmd, 0, ctx, struct.pack("<H", 0)), info)
    if cmd == 0x0065:
        version = struct.unpack("<H", payload[:2])[0] if len(payload) >= 2 else 0
        if len(payload) != 4 or version != 1:
            return Result(frame(cmd, 0, ctx, struct.pack("<HH", 1, 0), ENC_BAD_VERSION), info)
        handle_id = int.from_bytes(os.urandom(4), "little") or 1
        info["registered"] = handle_id
        return Result(frame(cmd, handle_id, ctx, payload), info)
    if cmd == 0x0066:
        return Result(None, info, close=True)
    if cmd in (0x006F, 0x0070):
        if session is None or head["session"] != session:
            return Result(frame(cmd, head["session"], ctx, b"", ENC_BAD_SESSION), dict(info, ics="read"))
        if cmd == 0x0070:
            return Result(None, dict(info, ics="read"))
        return _send_rr_data(head, ctx, payload, ident, info)
    return Result(frame(cmd, head["session"], ctx, b"", ENC_BAD_COMMAND), info)


def _send_rr_data(head: dict, ctx: bytes, payload: bytes, ident: Identity, info: dict) -> Result:
    info["ics"] = "read"
    if len(payload) < 16:
        return Result(frame(0x006F, head["session"], ctx, b"", ENC_BAD_COMMAND), info)
    count = struct.unpack("<H", payload[6:8])[0]
    i, request = 8, b""
    for _ in range(min(count, 4)):
        if i + 4 > len(payload):
            break
        type_id, length = struct.unpack("<HH", payload[i:i + 4])
        body = payload[i + 4:i + 4 + length]
        i += 4 + length
        if type_id == 0x00B2:
            request = body
    cip, cip_info = handle_cip(request, ident)
    info.update(cip_info)
    return Result(frame(0x006F, head["session"], ctx, _rr_data(cip)), info)
