"""Limits on what a stranger can make the server do: heavy reads, request bodies, WebSocket
seats, UDP replies and spreadsheet formulas."""
import asyncio
import os
import tempfile
import threading
import unittest

from fastapi.testclient import TestClient

from uninvited import app as webapp
from uninvited.app import Busy, Hub, ReadCache, TooLarge, build_app, read_limited
from uninvited.core import Config
from uninvited.feeds import FeedCache, csv_cell
from uninvited.listeners import SIP_REFUSAL, SipUdpProtocol, UdpGuard
from uninvited.store import Store


def make_client():
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "t.db")
    cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
    store = Store(db)
    feeds = FeedCache(db)
    feeds.refresh()
    hub = Hub(cfg, store)
    return TestClient(build_app(cfg, store, hub, feeds)), store, hub


class ReadCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_askers_share_one_computation(self):
        cache, calls = ReadCache(ttl=30), []
        release = threading.Event()

        def slow():
            calls.append(1)
            release.wait(2)
            return {"n": len(calls)}

        tasks = [asyncio.create_task(cache.get(("k",), slow)) for _ in range(20)]
        await asyncio.sleep(0.1)
        release.set()
        answers = await asyncio.gather(*tasks)
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(a == {"n": 1} for a in answers))

    async def test_an_answer_is_reused_until_it_expires(self):
        cache, calls = ReadCache(ttl=0.2), []
        def fn():
            calls.append(1)
            return len(calls)
        self.assertEqual(await cache.get(("k",), fn), 1)
        self.assertEqual(await cache.get(("k",), fn), 1)
        await asyncio.sleep(0.3)
        self.assertEqual(await cache.get(("k",), fn), 2)

    async def test_a_failure_is_not_remembered(self):
        cache, calls = ReadCache(ttl=30), []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("locked")
            return "ok"

        with self.assertRaises(RuntimeError):
            await cache.get(("k",), flaky)
        self.assertEqual(await cache.get(("k",), flaky), "ok")

    async def test_too_many_different_waiting_reads_are_refused_not_queued(self):
        cache = ReadCache(ttl=30, workers=1, limit=3)
        release = threading.Event()
        tasks = [asyncio.create_task(cache.get((i,), lambda: release.wait(2))) for i in range(3)]
        await asyncio.sleep(0.1)
        with self.assertRaises(Busy):
            await cache.get(("one more",), lambda: 1)
        # the same key as one already waiting just joins it
        joined = asyncio.create_task(cache.get((0,), lambda: 1))
        release.set()
        await asyncio.gather(*tasks, joined)

    async def test_the_cache_does_not_grow_without_bound(self):
        cache = ReadCache(ttl=30, max_keys=8)
        for i in range(40):
            await cache.get((i,), lambda i=i: i)
        self.assertLessEqual(len(cache._items), 8)

    async def test_the_work_runs_off_the_event_loop(self):
        cache = ReadCache()
        main = threading.get_ident()
        self.assertNotEqual(await cache.get(("t",), threading.get_ident), main)


class BodyLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store, cls.hub = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_a_large_body_is_refused_before_it_is_read(self):
        big = b"x" * (webapp.BULK_MAX_BODY + 1)
        r = self.client.post("/api/bulk", content=big, headers={"content-type": "application/json"})
        self.assertEqual(r.status_code, 413)
        r = self.client.post("/api/report", content=b"x" * 5000, headers={"content-type": "application/json"})
        self.assertEqual(r.status_code, 413)

    def test_a_body_that_lies_about_its_size_is_still_cut_off(self):
        async def run():
            class Req:
                headers = {"content-length": "10"}

                async def stream(self):
                    for _ in range(50):
                        yield b"y" * 100

            with self.assertRaises(TooLarge):
                await read_limited(Req(), 1000)

        asyncio.new_event_loop().run_until_complete(run())

    def test_json_that_is_not_an_object_is_a_400_not_a_crash(self):
        for body in (b"[]", b'"text"', b"123", b"null", b"[1,2,3]"):
            r = self.client.post("/api/bulk", content=body, headers={"content-type": "application/json"})
            self.assertEqual(r.status_code, 400, body)

    def test_the_heavy_endpoints_still_answer_and_share_their_work(self):
        for path in ("/api/stats", "/api/boards", "/api/feed", "/api/offenders", "/api/split",
                     "/api/campaigns", "/api/narrative", "/api/timeline"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertGreater(len(self.hub.reads._items), 5)

    def test_a_flood_of_distinct_requests_is_answered_with_503_not_a_queue(self):
        hub = self.hub
        original = hub.reads.limit
        hub.reads.limit = 0
        try:
            r = self.client.get("/api/timeline?hours=5&buckets=77")
            self.assertEqual(r.status_code, 503)
            self.assertEqual(r.headers["retry-after"], "5")
        finally:
            hub.reads.limit = original


class FakeSocket:
    def __init__(self, ip):
        self.client = type("C", (), {"host": ip})()
        self.headers = {}
        self.closed = None
        self.accepted = False
        self.sent = []

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000):
        self.closed = code

    async def send_text(self, text):
        self.sent.append(text)


class PublicSnapshotTests(unittest.TestCase):
    def test_the_public_snapshot_leaves_out_the_owners_settings(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "t.db")
        cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}],
                      "site": {"title": "T", "tagline": "t", "url": "example.org", "csp": "enforce",
                               "security_contact": "mailto:owner@example.org"}})
        store = Store(db)
        try:
            snap = Hub(cfg, store).snapshot()
            self.assertEqual(snap["site"], {"title": "T", "tagline": "t", "about": "", "url": "example.org"})
            client = TestClient(build_app(cfg, store, Hub(cfg, store), FeedCache(db)))
            self.assertNotIn("owner@example.org", client.get("/api/stats").text)
            # it is still served where the owner means it to be
            self.assertIn("owner@example.org", client.get("/.well-known/security.txt").text)
        finally:
            store.close()


class SeatTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        _, self.store, self.hub = make_client()

    async def asyncTearDown(self):
        self.store.close()

    async def test_one_address_cannot_take_every_seat(self):
        socks = [FakeSocket("198.51.100.7") for _ in range(Hub.MAX_PER_ADDRESS + 3)]
        for s in socks:
            await self.hub.join(s)
        self.assertEqual(sum(s.accepted for s in socks), Hub.MAX_PER_ADDRESS)
        self.assertEqual([s.closed for s in socks[Hub.MAX_PER_ADDRESS:]], [1013] * 3)
        other = FakeSocket("198.51.100.8")
        await self.hub.join(other)
        self.assertTrue(other.accepted)

    async def test_leaving_frees_the_seat(self):
        socks = [FakeSocket("198.51.100.7") for _ in range(Hub.MAX_PER_ADDRESS)]
        for s in socks:
            await self.hub.join(s)
        self.hub.leave(socks[0])
        again = FakeSocket("198.51.100.7")
        await self.hub.join(again)
        self.assertTrue(again.accepted)
        self.assertEqual(len(self.hub.clients), Hub.MAX_PER_ADDRESS)

    async def test_a_new_viewer_gets_the_snapshot(self):
        s = FakeSocket("198.51.100.7")
        await self.hub.join(s)
        self.assertIn('"type":"init"', s.sent[0])


class UdpGuardTests(unittest.TestCase):
    def test_a_source_gets_a_few_per_minute(self):
        g = UdpGuard(per_source=3, window=60)
        self.assertEqual([g.allow("198.51.100.7", t) for t in (0, 1, 2, 3, 4)], [True, True, True, False, False])
        self.assertTrue(g.allow("198.51.100.8", 5))
        self.assertTrue(g.allow("198.51.100.7", 61))          # the window moved on

    def test_the_whole_port_has_a_ceiling(self):
        g = UdpGuard(per_source=1000, per_second=10, burst=20)
        allowed = sum(g.allow(f"198.51.100.{i % 250}", 0.0) for i in range(500))
        self.assertEqual(allowed, 20)
        self.assertTrue(g.allow("198.51.100.250", 1.0))       # the bucket refills

    def test_the_table_of_sources_stays_bounded(self):
        g = UdpGuard(per_source=1, window=1, per_second=1e9, burst=1e9)
        for i in range(30000):
            g.allow(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", float(i))
        self.assertLess(len(g.sources), 12000)


class FakeTransport:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))


class SipUdpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().set_debug(False)    # debug mode makes 300 task creations slow enough to warn
        self.knocks = []

        async def emit(k):
            self.knocks.append(k)

        self.proto = SipUdpProtocol(emit, 5060, UdpGuard(per_source=3))
        self.proto.connection_made(FakeTransport())

    INVITE = (b"INVITE sip:0044123456789@203.0.113.5 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.7\r\n"
              b"From: <sip:100@198.51.100.7>\r\nTo: <sip:0044123456789@203.0.113.5>\r\n\r\n")

    async def test_a_real_request_is_recorded_and_refused(self):
        self.proto.datagram_received(self.INVITE, ("198.51.100.7", 5070))
        await asyncio.sleep(0.05)
        self.assertEqual(len(self.knocks), 1)
        self.assertEqual(self.proto.transport.sent, [(SIP_REFUSAL, ("198.51.100.7", 5070))])

    async def test_a_reply_is_never_larger_than_the_request(self):
        for size in range(1, len(SIP_REFUSAL) + 1):
            self.proto.guard = UdpGuard()
            self.proto.datagram_received(b"A" * size, ("198.51.100.7", 5070))
        for data, _ in self.proto.transport.sent:
            self.assertLess(len(data), len(SIP_REFUSAL) + 1)
        self.assertEqual(len(self.proto.transport.sent), 0)          # a datagram this small gets no answer at all

    async def test_a_flood_from_one_source_is_dropped_silently(self):
        for _ in range(50):
            self.proto.datagram_received(self.INVITE, ("198.51.100.7", 5070))
        await asyncio.sleep(0.05)
        self.assertEqual(len(self.knocks), 3)
        self.assertEqual(len(self.proto.transport.sent), 3)

    async def test_recordings_in_flight_are_capped(self):
        gate = asyncio.Event()

        async def stuck(k):
            await gate.wait()

        p = SipUdpProtocol(stuck, 5060, UdpGuard(per_source=10 ** 6, per_second=1e9, burst=1e9))
        p.connection_made(FakeTransport())
        for i in range(SipUdpProtocol.MAX_PENDING + 100):
            p.datagram_received(self.INVITE, (f"198.51.{i // 250}.{i % 250}", 5070))
        self.assertEqual(len(p._pending), SipUdpProtocol.MAX_PENDING)
        gate.set()
        await asyncio.sleep(0.05)
        self.assertEqual(len(p._pending), 0)


class CsvCellTests(unittest.TestCase):
    def test_formula_starters_are_defused(self):
        for bad in ("=cmd|' /C calc'!A0", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"):
            self.assertEqual(csv_cell(bad), "'" + bad)

    def test_ordinary_values_are_untouched(self):
        for ok in ("AS15169 Google LLC", "", "2026-10-02T10:00:00Z", "203.0.113.9", "a=b", 7, None, 0):
            self.assertEqual(csv_cell(ok), ok)

    def test_the_published_csv_applies_it(self):
        cache = FeedCache(":memory:")
        row = {"ip": "203.0.113.9", "kind": "attack", "engaged": 3, "verified": 3, "first_ts": 1, "last_ts": 2,
               "score": 10, "protocols": ["SSH"], "iso": "US", "asn": 1, "network": "=HYPERLINK(\"http://x\")",
               "hassh": None, "techniques": [], "cves": [], "exploits": [], "label": None,
               "classification": "malicious", "tags": [], "host_type": "unknown", "collateral": "unknown",
               "expires_ts": 3}
        body = cache._csv([row]).body.decode()
        self.assertIn("'=HYPERLINK", body)
        self.assertNotIn(",=HYPERLINK", body)


if __name__ == "__main__":
    unittest.main()
