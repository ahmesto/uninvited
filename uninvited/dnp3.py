"""DNP3 decoy (TCP 20000): link layer framing and canned answers.

Pure functions, no sockets. A DNP3 frame is a 10 byte link header (0x05 0x64, length,
control, destination, source, CRC) followed by user data in blocks of up to 16 bytes,
each block with its own CRC. All CRCs are CRC-16/DNP.

What the decoy does:

  - answers a request for link status, a link reset and a link test like an outstation,
  - acknowledges confirmed user data and answers any application request with an empty,
    successful response,
  - logs what the application layer asked for: a read, a write, a control operation
    (select, operate, restart, stop or start the application) or a file transfer.

Nothing is stored and nothing a client sends changes any state.

Status: the link layer is complete and its CRC is checked against the published
check value. The application layer answers only with an empty response and is the part
to test against a real DNP3 master before relying on its replies.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAX_USER_DATA = 250      # link length is one byte; 5 of it is header

LINK_NAMES = {0: "Reset Link States", 1: "Reset User Process", 2: "Test Link States",
              3: "Confirmed User Data", 4: "Unconfirmed User Data", 9: "Request Link Status"}

APP_NAMES = {0x00: "Confirm", 0x01: "Read", 0x02: "Write", 0x03: "Select", 0x04: "Operate",
             0x05: "Direct Operate", 0x06: "Direct Operate No Ack", 0x07: "Immediate Freeze",
             0x0D: "Cold Restart", 0x0E: "Warm Restart", 0x0F: "Initialize Data",
             0x10: "Initialize Application", 0x11: "Start Application", 0x12: "Stop Application",
             0x13: "Save Configuration", 0x14: "Enable Unsolicited", 0x15: "Disable Unsolicited",
             0x16: "Assign Class", 0x17: "Delay Measurement", 0x18: "Record Current Time",
             0x19: "Open File", 0x1A: "Close File", 0x1B: "Delete File", 0x1C: "Get File Info",
             0x1D: "Authenticate File", 0x1E: "Abort File"}
APP_LABEL = {0x02: "write", 0x16: "write",
             0x03: "control", 0x04: "control", 0x05: "control", 0x06: "control", 0x0D: "control",
             0x0E: "control", 0x0F: "control", 0x10: "control", 0x11: "control", 0x12: "control",
             0x13: "control", 0x14: "control", 0x15: "control",
             0x19: "program", 0x1A: "program", 0x1B: "program", 0x1C: "read", 0x1D: "program", 0x1E: "program"}


def crc(data: bytes) -> int:
    """CRC-16/DNP: reflected polynomial 0xA6BC, initial value 0, inverted result."""
    value = 0
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ 0xA6BC if value & 1 else value >> 1
    return value ^ 0xFFFF


def blocks(user_data: bytes) -> bytes:
    """User data split into 16 byte blocks, each followed by its CRC."""
    out = b""
    for i in range(0, len(user_data), 16):
        chunk = user_data[i:i + 16]
        out += chunk + struct.pack("<H", crc(chunk))
    return out


def build(control: int, dest: int, src: int, user_data: bytes = b"") -> bytes:
    header = bytes([0x05, 0x64, len(user_data) + 5, control]) + struct.pack("<HH", dest, src)
    return header + struct.pack("<H", crc(header)) + blocks(user_data)


def data_bytes_on_wire(length_field: int) -> int:
    """How many bytes follow the 10 byte header for a given link length field."""
    n = max(length_field - 5, 0)
    return n + 2 * ((n + 15) // 16)


def parse_header(head: bytes) -> dict | None:
    """Ten header bytes -> fields, or None when this is not a DNP3 link header."""
    if len(head) != 10 or head[0] != 0x05 or head[1] != 0x64 or head[2] < 5:
        return None
    if struct.unpack("<H", head[8:10])[0] != crc(head[:8]):
        return None
    control = head[3]
    dest, src = struct.unpack("<HH", head[4:8])
    return {"length": head[2], "control": control, "dir": bool(control & 0x80), "prm": bool(control & 0x40),
            "function": control & 0x0F, "dest": dest, "src": src}


def user_data(body: bytes, length_field: int) -> bytes | None:
    """The user data from the blocks that follow a header, or None if a block's CRC is wrong."""
    n = max(length_field - 5, 0)
    out, i = b"", 0
    while len(out) < n:
        take = min(16, n - len(out))
        chunk, check = body[i:i + take], body[i + take:i + take + 2]
        if len(chunk) < take or len(check) < 2 or struct.unpack("<H", check)[0] != crc(chunk):
            return None
        out += chunk
        i += take + 2
    return out


@dataclass
class Result:
    reply: bytes
    info: dict = field(default_factory=dict)


def handle(head: dict, data: bytes, address: int | None = None) -> Result:
    """Answer one link frame. `address` is the outstation address to answer to, or
    None to answer whatever address was asked for. Never raises on client input."""
    info: dict = {"function": head["function"], "dest": head["dest"], "src": head["src"],
                  "ics": "identity", "write": False}
    if address is not None and head["dest"] not in (address, 0xFFFD, 0xFFFE, 0xFFFF):
        info["ignored"] = True
        return Result(b"", info)
    me, master = head["dest"], head["src"]
    if address is not None and me >= 0xFFFD:
        me = address
    fn = head["function"]

    if not head["prm"]:
        # A secondary frame sent to us (a reply to something we did not ask) is ignored.
        info["name"] = "Secondary frame"
        return Result(b"", info)
    info["name"] = LINK_NAMES.get(fn, f"Link function {fn}")

    if fn == 9:                                              # request link status
        return Result(build(0x0B, master, me), info)        # LINK_STATUS
    if fn in (0, 2):                                         # reset link, test link
        return Result(build(0x00, master, me), info)        # ACK
    if fn in (3, 4):
        app = _app(data, info)
        ack = build(0x00, master, me) if fn == 3 else b""
        if app is None:
            return Result(ack, info)
        return Result(ack + build(0x44, master, me, app), info)
    return Result(build(0x0F, master, me), info)            # NOT_SUPPORTED


def _app(data: bytes, info: dict) -> bytes | None:
    """The empty successful response to an application request, and what the request was."""
    if len(data) < 3:
        info["name"] = info["name"] + " (no application data)"
        return None
    transport, control, function = data[0], data[1], data[2]
    info["fc"] = function
    info["name"] = APP_NAMES.get(function, f"Function 0x{function:02x}")
    info["ics"] = APP_LABEL.get(function, "read")
    info["write"] = info["ics"] != "read"
    if function == 0x00:                                     # a confirm needs no answer
        return None
    seq = control & 0x0F
    # transport FIR+FIN, then application FIR+FIN with the request's sequence number,
    # response function 0x81, and the two internal indication bytes, all clear.
    return bytes([0xC0 | (transport & 0x3F), 0xC0 | seq, 0x81, 0x00, 0x00])
