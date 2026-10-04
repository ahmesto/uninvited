"""A TLS hello sent to a plain web port: what the decoy records, what the store keeps, and what the
feed and the evidence drawer show. The hellos are real ones captured from OpenSSL, Python and Schannel."""
import asyncio
import csv
import io
import json
import os
import socket
import ssl
import tempfile
import time
import unittest
from pathlib import Path

from uninvited.core import Knock
from uninvited.feeds import FeedCache
from uninvited.listeners import HttpListener
from uninvited.store import Store

CASES = json.loads((Path(__file__).resolve().parent / "fixtures" / "ja3_cases.json").read_text(encoding="utf-8"))["cases"]


def hello(name):
    return bytes.fromhex(CASES[name]["record_hex"])


class Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.knocks = []

        async def emit(k):
            self.knocks.append(k)

        self.listener = HttpListener({"port": 0}, emit, asyncio.Semaphore(20))
        self.listener.server = await asyncio.start_server(self.listener._wrap, "127.0.0.1", 0)
        self.port = self.listener.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.listener.server.close()

    async def send(self, data: bytes, close_first=False):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(data)
        await w.drain()
        if close_first:
            w.write_eof()
        try:
            reply = await asyncio.wait_for(r.read(4096), 2)
        except TimeoutError:
            reply = None
        w.close()
        await asyncio.sleep(0.1)
        return reply

    def real(self):
        return [k for k in self.knocks if not k.detail.get("scan")]


class ListenerTests(Base):
    async def test_a_real_hello_is_fingerprinted_and_never_answered(self):
        for name, case in CASES.items():
            self.knocks.clear()
            reply = await self.send(hello(name))
            self.assertEqual(reply, b"", name)                     # the decoy hangs up, it does not negotiate
            k = self.real()[0]
            self.assertEqual(k.ja3, case["ja3"], name)
            self.assertEqual(k.detail["ja3"], case["ja3"])
            self.assertEqual(k.detail["exploit"], "TLS Handshake on Plain HTTP")
            self.assertEqual(k.detail.get("sni"), case["sni"])
            self.assertIn(("ja3", case["ja3"]), k.lines)
            if case["sni"]:
                self.assertIn(("sni", case["sni"]), k.lines)
            self.assertEqual(k.raw, hello(name))                   # the owner keeps the record, bytes as sent
            self.assertEqual(k.public()["ja3"], case["ja3"])

    async def test_a_real_tls_stack_gets_the_same_treatment(self):
        # Python's own ssl module, which the decoy cannot answer, completing nothing.
        def client():
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=3) as s:
                    ctx.wrap_socket(s, server_hostname="live.example.org")
            except (ssl.SSLError, OSError):
                pass

        await asyncio.get_running_loop().run_in_executor(None, client)
        await asyncio.sleep(0.2)
        k = self.real()[0]
        self.assertEqual(k.detail["sni"], "live.example.org")
        self.assertRegex(k.ja3, r"^[0-9a-f]{32}$")

    async def test_plain_http_is_untouched(self):
        reply = await self.send(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 404"))
        k = self.real()[0]
        self.assertIsNone(k.ja3)
        self.assertEqual(k.detail["exploit"], "DotEnv File Exposure")

    async def test_a_very_short_request_still_works(self):
        reply = await self.send(b"GET\n", close_first=True)
        self.assertIsNotNone(reply)
        self.assertTrue(self.knocks)

    async def test_a_hello_that_does_not_parse_falls_back_to_the_ordinary_path(self):
        data = hello("python-default")
        await self.send(data[:60], close_first=True)       # cut off mid-record
        k = self.real()[0]
        self.assertIsNone(k.ja3)
        self.assertEqual(k.detail["exploit"], "TLS Handshake on Plain HTTP")   # still named, just not fingerprinted

    async def test_junk_that_starts_like_tls_is_survived(self):
        import random
        rnd = random.Random(9)
        for _ in range(40):
            junk = b"\x16\x03" + bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 700)))
            await self.send(junk, close_first=True)
        self.assertTrue(self.knocks)
        reply = await self.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertTrue(reply.startswith(b"HTTP/1.1 404"))


class StoreAndFeedTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)
        self.now = int(time.time())

    def tearDown(self):
        self.store.close()

    def knock(self, ip, ja3=None, **kw):
        k = Knock(proto="HTTP", ip=ip, port=80, ts=self.now - 60, **kw)
        k.ja3 = ja3
        k.detail = {"exploit": "Malware Dropper Command"}
        return k

    def test_the_fingerprint_is_kept_on_the_host_and_survives_later_knocks(self):
        self.store.record(self.knock("198.51.100.7", "a" * 32))
        self.store.record(self.knock("198.51.100.7"))
        self.assertEqual(self.store.db.execute("SELECT ja3 FROM actors WHERE ip='198.51.100.7'").fetchone()[0], "a" * 32)

    def test_evidence_says_how_many_other_hosts_share_it(self):
        for ip in ("198.51.100.7", "198.51.100.8", "198.51.100.9"):
            self.store.record(self.knock(ip, "b" * 32))
        self.store.record(self.knock("198.51.100.10", "c" * 32))
        ev = self.store.evidence("198.51.100.7")
        self.assertEqual(ev["ja3"], {"value": "b" * 32, "shared_with": 2})
        self.assertEqual(self.store.evidence("198.51.100.10")["ja3"], {"value": "c" * 32, "shared_with": 0})
        self.store.record(Knock(proto="SSH", ip="198.51.100.11", port=22))
        self.assertEqual(self.store.evidence("198.51.100.11")["ja3"], {"value": None, "shared_with": 0})

    def test_an_old_database_gains_the_column(self):
        import sqlite3
        path = os.path.join(self.dir, "old.db")
        con = sqlite3.connect(path)
        con.executescript("CREATE TABLE actors (ip TEXT PRIMARY KEY, hassh TEXT, first_ts INTEGER, last_ts INTEGER, hits INTEGER NOT NULL DEFAULT 0, iso TEXT, country TEXT, isp TEXT, asn INTEGER, protos TEXT, kind TEXT, label TEXT, rdns TEXT);")
        con.commit()
        con.close()
        upgraded = Store(path)
        try:
            cols = {r["name"] for r in upgraded.db.execute("PRAGMA table_info(actors)")}
            self.assertTrue({"ja3", "demoted", "hassh"} <= cols)
        finally:
            upgraded.close()

    def test_the_feed_publishes_it(self):
        for i in range(4):
            k = self.knock("45.9.148.7", "d" * 32)
            k.ts = self.now - 100 + i
            self.store.record(k)
        cache = FeedCache(self.db)
        cache.refresh()
        doc = json.loads(cache.files["attackers-7d.json"].body)
        rec = doc["indicators"][0]
        self.assertEqual((rec["ip"], rec["ja3"]), ("45.9.148.7", "d" * 32))
        self.assertIn("ja3", doc["fields"])
        rows = list(csv.reader(io.StringIO(cache.files["attackers-7d.csv"].body.decode())))
        self.assertEqual(rows[0][-1], "ja3")
        self.assertEqual(rows[1][-1], "d" * 32)
        self.assertEqual(rows[0][0], "ip")                          # the existing columns did not move


if __name__ == "__main__":
    unittest.main()
