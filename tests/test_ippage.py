"""The address page and its card, and the feed filtered by kind."""
import os
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

from uninvited import ippage
from uninvited.app import Hub, build_app
from uninvited.core import Config, Knock
from uninvited.feeds import FeedCache
from uninvited.store import Store

EVIL = "<script>alert(1)</script>"


def knock(ts, proto="SSH", ip="203.0.113.7", user=None, pw=None, lines=(), isp="Example Net", kind="attack"):
    k = Knock(proto=proto, ip=ip, port=22, ts=ts, username=user, password=pw, lines=list(lines))
    k.kind, k.country, k.iso, k.isp = kind, "The Netherlands", "NL", isp
    return k


def make():
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "t.db")
    cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
    store = Store(db)
    return cfg, store, db


class FeedKindTests(unittest.TestCase):
    def test_each_kind_reaches_past_the_recent_window(self):
        _, store, _ = make()
        now = int(time.time())
        store.record(knock(now - 5000, proto="CAM", ip="198.51.100.1", lines=[("method", "GET"), ("path", "/")]))
        store.record(knock(now - 4000, proto="S7", ip="198.51.100.2", lines=[("function", "PLC Stop")]))
        store.record(knock(now - 3000, proto="HTTP", ip="198.51.100.3", lines=[("exploit", "Hikvision RCE"), ("path", "/SDK")]))
        store.record(knock(now - 2000, proto="HTTP", ip="198.51.100.4", lines=[("exploit", "Root Fingerprint"), ("path", "/")]))
        for i in range(10):
            store.record(knock(now - i, ip="198.51.100.9", user="root", pw=f"p{i}"))
        self.assertEqual([r["proto"] for r in store.feed_kind("device", 5)], ["CAM"])
        self.assertEqual([r["proto"] for r in store.feed_kind("industrial", 5)], ["S7"])
        ex = store.feed_kind("exploit", 5)
        self.assertEqual([r["ip"] for r in ex], ["198.51.100.3"])      # the generic probe is not an exploit
        self.assertEqual(ex[0]["lines"][0], ["exploit", "Hikvision RCE"])
        self.assertEqual(len(store.feed_kind("login", 5)), 5)
        self.assertEqual(len(store.feed_kind("nonsense", 3)), 3)         # unknown kind: the plain feed
        store.close()

    def test_daily_hits_are_per_utc_day_oldest_first(self):
        _, store, _ = make()
        now = int(time.time())
        store.record(knock(now - 60, ip="198.51.100.5"))
        store.record(knock(now - 60 - 3 * 86400, ip="198.51.100.5"))
        store.record(knock(now - 60 - 3 * 86400, ip="198.51.100.5"))
        store.record(knock(now - 60 - 40 * 86400, ip="198.51.100.5"))   # outside the window
        d = store.daily_hits("198.51.100.5", 30)
        self.assertEqual(len(d), 30)
        self.assertEqual(sum(d), 3)
        self.assertEqual(d[-1], 1)
        store.close()


class PageTests(unittest.TestCase):
    def setUp(self):
        cfg, self.store, db = make()
        now = int(time.time())
        for i in range(4):
            self.store.record(knock(now - 100 * i, ip="45.33.32.20", user="root", pw=f"pw{i}", isp=EVIL))
        self.store.record(knock(now - 50, proto="HTTP", ip="45.33.32.20", lines=[("exploit", "Hikvision RCE " + EVIL)], isp=EVIL))
        feeds = FeedCache(db)
        feeds.refresh()
        self.client = TestClient(build_app(cfg, self.store, Hub(cfg, self.store), feeds))

    def tearDown(self):
        self.store.close()

    def test_the_page_carries_the_card_tags_and_escapes_everything(self):
        r = self.client.get("/ip/45.33.32.20")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("text/html"))
        self.assertIn('property="og:image" content="https://', r.text)
        self.assertIn("/ip/45.33.32.20/card.png", r.text)
        self.assertIn("45.33.32.20", r.text)
        self.assertNotIn(EVIL, r.text)
        self.assertIn("&lt;script&gt;", r.text)
        self.assertNotIn("<script", r.text.lower().replace("<script>alert", ""))  # no inline script at all
        self.assertIn("evidence", r.text)
        self.assertIn("Report a wrong entry", r.text)

    def test_an_unseen_address_is_a_page_that_says_so_and_is_not_indexed(self):
        r = self.client.get("/ip/45.33.32.99")
        self.assertEqual(r.status_code, 200)
        self.assertIn("never seen that address", r.text)
        self.assertIn('name="robots" content="noindex"', r.text)

    def test_private_and_bad_addresses(self):
        self.assertEqual(self.client.get("/ip/10.0.0.1").status_code, 200)
        self.assertIn("cannot be in the data", self.client.get("/ip/10.0.0.1").text)
        self.assertEqual(self.client.get("/ip/not-an-address").status_code, 400)
        self.assertEqual(self.client.get("/ip/not-an-address/card.png").status_code, 400)

    def test_the_card_is_an_image(self):
        r = self.client.get("/ip/45.33.32.20/card.png")
        self.assertEqual(r.status_code, 200)
        self.assertIn(r.headers["content-type"].split(";")[0], ("image/png", "image/svg+xml"))
        self.assertTrue(len(r.content) > 500)
        self.assertEqual(self.client.get("/ip/45.33.32.20/card.png").headers.get("cache-control"), "public, max-age=600")

    def test_the_verdict_is_built_from_the_record_only(self):
        self.assertEqual(ippage.verdict({"found": False}), "This server has never seen that address.")
        v = ippage.verdict({"found": True, "actor": {"hits": 3, "protos": ["SSH"], "first_ts": 1790000000, "last_ts": 1790100000},
                            "exploits": [], "listed": {"24h": True, "7d": True}, "expires": "2026-10-10T00:00:00Z"})
        self.assertIn("3 connections to this server on SSH", v)
        self.assertIn("On the 24h, 7d lists. Suggested expiry for your own copy: 2026-10-10.", v)
        self.assertNotIn("leaves", v)        # the expiry is advice for a copy, not when it leaves the lists
        svg = ippage.card_svg({"found": True, "ip": "203.0.113.1", "actor": {"isp": EVIL}, "score": 90, "listed": {}}, "example.org", "Uninvited")
        self.assertNotIn(EVIL, svg)

    def test_the_feed_endpoint_takes_a_kind(self):
        self.store.record(knock(int(time.time()) - 9000, proto="CAM", ip="45.33.32.30", lines=[("path", "/")]))
        r = self.client.get("/api/feed?kind=device&limit=10")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([x["proto"] for x in r.json()["feed"]], ["CAM"])
        self.assertEqual(self.client.get("/api/feed?kind=bogus&limit=10").status_code, 400)


if __name__ == "__main__":
    unittest.main()
