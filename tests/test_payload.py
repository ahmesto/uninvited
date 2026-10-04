import asyncio
import os
import sqlite3
import tempfile
import time
import unittest

from uninvited import payload
from uninvited.core import Knock
from uninvited.listeners import HttpListener
from uninvited.store import Store


class EscapeTests(unittest.TestCase):
    def test_plain_text_passes_through(self):
        self.assertEqual(payload.escape(b"GET /a?b=c HTTP/1.1"), "GET /a?b=c HTTP/1.1")

    def test_controls_and_markup_bytes_are_neutralised(self):
        out = payload.escape(b"\x1b[31m\r\n\x00<script>\xff")
        for bad in ("\x1b", "\n", "\r", "\x00"):
            self.assertNotIn(bad, out)
        self.assertIn("\\x1b", out)
        self.assertIn("\\r\\n", out)
        self.assertIn("\\xff", out)

    def test_every_byte_value_is_printable_ascii(self):
        out = payload.escape(bytes(range(256)))
        self.assertTrue(all(c.isascii() and c.isprintable() for c in out), out[:80])

    def test_backslash_is_doubled_so_output_is_unambiguous(self):
        self.assertEqual(payload.escape(b"a\\n"), "a\\\\n")
        self.assertNotEqual(payload.escape(b"a\\n"), payload.escape(b"a\n"))

    def test_long_input_is_truncated_with_a_count(self):
        self.assertTrue(payload.escape(b"A" * 5000, limit=100).endswith("...(+4900 bytes)"))


class SignatureTests(unittest.TestCase):
    def test_same_request_same_key(self):
        a = payload.key(payload.signature("GET", "/x", b""))
        b = payload.key(payload.signature("GET", "/x", b""))
        self.assertEqual(a, b)

    def test_method_target_or_body_changes_the_key(self):
        base = payload.key(payload.signature("GET", "/x", b""))
        self.assertNotEqual(base, payload.key(payload.signature("POST", "/x", b"")))
        self.assertNotEqual(base, payload.key(payload.signature("GET", "/y", b"")))
        self.assertNotEqual(base, payload.key(payload.signature("GET", "/x", b"data")))

    def test_only_the_start_of_a_long_body_counts(self):
        a = payload.key(payload.signature("POST", "/x", b"A" * 300))
        b = payload.key(payload.signature("POST", "/x", b"A" * 256 + b"different tail"))
        self.assertEqual(a, b)


def make_knock(sig: bytes, raw: bytes = b"GET / HTTP/1.1\r\n\r\n", ts=None, ip="93.184.216.34"):
    return Knock(proto="HTTP", ip=ip, port=50000, ts=ts or int(time.time()),
                 lines=[("path", "/")], detail={"exploit": "x"}, raw=raw, raw_sig=sig)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()

    def rows(self, sql):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(sql).fetchall()
        finally:
            con.close()

    def test_repeats_cost_one_row_and_a_counter(self):
        for _ in range(5):
            self.store.record(make_knock(b"GET /\n"))
        (row,) = self.rows("select count, length(raw) from payloads")
        self.assertEqual(row[0], 5)
        self.assertEqual(self.rows("select count(*) from knocks")[0][0], 5)

    def test_knock_detail_points_at_the_payload(self):
        self.store.record(make_knock(b"GET /\n"))
        (detail,) = self.rows("select detail from knocks")[0]
        self.assertIn(payload.key(b"GET /\n"), detail)

    def test_distinct_requests_get_distinct_rows(self):
        self.store.record(make_knock(b"GET /a\n"))
        self.store.record(make_knock(b"GET /b\n"))
        self.assertEqual(self.rows("select count(*) from payloads")[0][0], 2)

    def test_raw_is_capped(self):
        self.store.record(make_knock(b"x", raw=b"A" * 9000))
        self.assertEqual(self.rows("select length(raw) from payloads")[0][0], payload.MAX_RAW)

    def test_a_full_table_stops_storing_new_payloads_but_keeps_counting_old_ones(self):
        old = payload.MAX_PAYLOADS
        payload.MAX_PAYLOADS = 2
        try:
            self.store.record(make_knock(b"1"))
            self.store.record(make_knock(b"2"))
            self.store.record(make_knock(b"3"))        # over the cap
            self.store.record(make_knock(b"1"))        # known, still counted
        finally:
            payload.MAX_PAYLOADS = old
        self.assertEqual(self.rows("select count(*) from payloads")[0][0], 2)
        self.assertEqual(self.rows("select count(*) from knocks")[0][0], 4)
        self.assertEqual(self.rows(
            f"select count from payloads where sha='{payload.key(b'1')}'")[0][0], 2)

    def test_knocks_without_raw_are_unchanged(self):
        self.store.record(Knock(proto="SSH", ip="93.184.216.34", port=22, lines=[], detail={}))
        self.assertEqual(self.rows("select count(*) from payloads")[0][0], 0)

    def test_prune_removes_old_payloads_only(self):
        now = int(time.time())
        self.store.record(make_knock(b"old", ts=now - 100 * 86400))
        self.store.record(make_knock(b"new", ts=now))
        self.store.prune(90)
        self.assertEqual(self.rows("select count(*) from payloads")[0][0], 1)

    def test_evidence_never_exposes_raw_bytes(self):
        self.store.record(make_knock(b"s", raw=b"GET /secret-marker HTTP/1.1\r\n\r\n"))
        text = repr(self.store.evidence("93.184.216.34"))
        self.assertNotIn("secret-marker", text)
        self.assertNotIn("payload", text)


class HttpCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.knocks = []

        async def emit(k):
            self.knocks.append(k)

        self.l = HttpListener({"port": 0}, emit, asyncio.Semaphore(10))
        self.l.server = await asyncio.start_server(self.l._wrap, "127.0.0.1", 0)
        self.port = self.l.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.l.server.close()
        await self.l.server.wait_closed()

    async def send(self, data: bytes, then_wait: float = 0.2):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(data)
        await w.drain()
        try:
            await asyncio.wait_for(r.read(500), 6)
        except TimeoutError:
            pass
        await asyncio.sleep(then_wait)
        w.close()

    async def test_get_is_captured_with_headers(self):
        await self.send(b"GET /admin?x=1 HTTP/1.1\r\nHost: h\r\nUser-Agent: zgrab\r\n\r\n")
        k = self.knocks[0]
        self.assertIn(b"GET /admin?x=1 HTTP/1.1", k.raw)
        self.assertIn(b"User-Agent: zgrab", k.raw)
        self.assertEqual(k.detail["body_len"], 0)

    async def test_post_body_is_captured(self):
        body = b"cmd=id;uname -a"
        await self.send(b"POST /run HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n%s"
                        % (len(body), body))
        k = self.knocks[0]
        self.assertTrue(k.raw.endswith(body))
        self.assertEqual(k.detail["body_len"], len(body))

    async def test_headers_do_not_change_the_signature(self):
        a = b"GET /p HTTP/1.1\r\nHost: a\r\nUser-Agent: one\r\n\r\n"
        b = b"GET /p HTTP/1.1\r\nHost: b\r\nUser-Agent: two\r\n\r\n"
        await self.send(a)
        await self.send(b)
        self.assertEqual(self.knocks[0].raw_sig, self.knocks[1].raw_sig)

    async def test_a_stalled_body_still_records_within_a_few_seconds(self):
        t = time.time()
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\nabcde")
        await w.drain()
        await asyncio.sleep(4.5)
        w.close()
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].raw.endswith(b"abcde"))
        self.assertLess(time.time() - t, 8)

    async def test_oversized_body_is_capped(self):
        body = b"A" * 20000
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 20000\r\n\r\n" + body)
        await w.drain()
        await asyncio.sleep(0.5)
        w.close()
        self.assertLessEqual(len(self.knocks[0].raw), payload.MAX_RAW)

    async def test_nonsense_content_length_is_ignored(self):
        await self.send(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: banana\r\n\r\n")
        self.assertEqual(self.knocks[0].detail["body_len"], 0)
        await self.send(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: -5\r\n\r\n")
        self.assertEqual(self.knocks[1].detail["body_len"], 0)


if __name__ == "__main__":
    unittest.main()
