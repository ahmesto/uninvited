"""A reverse name is a claim. These tests pin down how far the classifier and the feed
trust one: forward confirmation, the demotion of a scanner believed on a name alone,
the never-list for big crawlers, and the store's reader connections."""
import asyncio
import os
import sqlite3
import tempfile
import threading
import unittest

from uninvited import classify, feeds, intel
from uninvited.classify import Classifier
from uninvited.core import Knock
from uninvited.store import Store


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class StubClassifier(Classifier):
    """Reverse and forward answers come from tables, so nothing touches the network."""

    def __init__(self, ptr, forward):
        super().__init__(enable_rdns=True, enable_tor=False)
        self.ptr, self.forward_ips = ptr, forward

    def _resolve(self, ip):
        return self.ptr.get(ip)


def classify_with(ptr, forward, ip):
    c = StubClassifier(ptr, forward)
    original = classify.forward_confirms
    classify.forward_confirms = lambda host, addr: addr in forward.get(host, ())
    try:
        return c, run(c.classify(ip))
    finally:
        classify.forward_confirms = original


class NameTrustTests(unittest.TestCase):
    def test_an_operator_name_that_resolves_back_is_research_and_confirmed(self):
        _, v = classify_with({"203.0.113.9": "census1.shodan.io"}, {"census1.shodan.io": ["203.0.113.9"]},
                             "203.0.113.9")
        self.assertEqual((v["kind"], v["label"], v["confirmed"]), ("research", "Shodan", True))

    def test_an_operator_name_with_no_forward_record_is_research_but_provisional(self):
        # BinaryEdge, IPIP and some Shodan hosts publish no forward records.
        _, v = classify_with({"203.0.113.9": "nyc1-4.binaryedge.ninja"}, {}, "203.0.113.9")
        self.assertEqual((v["kind"], v["label"], v["confirmed"]), ("research", "BinaryEdge", False))

    def test_a_generic_word_in_a_name_counts_only_when_confirmed(self):
        ptr = {"203.0.113.9": "scanner.example.org"}
        _, unconfirmed = classify_with(ptr, {}, "203.0.113.9")
        self.assertEqual((unconfirmed["kind"], unconfirmed["label"]), ("attack", None))
        _, confirmed = classify_with(ptr, {"scanner.example.org": ["203.0.113.9"]}, "203.0.113.9")
        self.assertEqual((confirmed["kind"], confirmed["label"]), ("research", "Unattributed scanner"))

    def test_a_name_that_resolves_to_someone_else_is_not_confirmed(self):
        _, v = classify_with({"203.0.113.9": "census1.shodan.io"}, {"census1.shodan.io": ["198.51.100.1"]},
                             "203.0.113.9")
        self.assertFalse(v["confirmed"])

    def test_an_address_in_a_known_range_needs_no_name(self):
        c = StubClassifier({}, {})
        v = run(c.classify("71.6.135.131"))
        self.assertEqual((v["kind"], v["confirmed"]), ("research", True))

    def test_demotion_is_remembered(self):
        c, v = classify_with({"203.0.113.9": "nyc1-4.binaryedge.ninja"}, {}, "203.0.113.9")
        self.assertEqual(v["kind"], "research")
        c.demote("203.0.113.9")
        again = run(c.classify("203.0.113.9"))
        self.assertEqual((again["kind"], again["label"]), ("attack", None))

    def test_a_full_queue_skips_the_lookup_and_does_not_poison_the_cache(self):
        c = StubClassifier({"203.0.113.9": "census1.shodan.io"}, {})
        c._dns_pending = classify.DNS_QUEUE
        v = run(c.classify("203.0.113.9"))
        self.assertEqual(v["kind"], "attack")
        self.assertNotIn("203.0.113.9", c.cache)     # the next knock looks again
        c._dns_pending = 0
        self.assertEqual(run(c.classify("203.0.113.9"))["kind"], "research")

    def test_lookups_do_not_use_the_default_executor(self):
        # A name server the attacker runs can stall a lookup, and the default executor
        # also writes the database.
        c = StubClassifier({}, {})
        self.assertEqual(c._dns_pool._thread_name_prefix, "dns")
        self.assertLessEqual(c._dns_pool._max_workers, classify.DNS_WORKERS)


class AttackEventTests(unittest.TestCase):
    def test_what_a_scanner_does_not_do(self):
        self.assertTrue(intel.is_attack_event("hunter2", {}))
        self.assertTrue(intel.is_attack_event("", {}))                       # an empty password is still a guess
        self.assertTrue(intel.is_attack_event(None, {"exploit": "Log4Shell (CVE-2021-44228)"}))
        self.assertTrue(intel.is_attack_event(None, {"ics": "write"}))
        self.assertTrue(intel.is_attack_event(None, {"ics": "control"}))

    def test_what_a_scanner_does_do(self):
        self.assertFalse(intel.is_attack_event(None, {}))
        self.assertFalse(intel.is_attack_event(None, {"exploit": "Root Fingerprint"}))
        self.assertFalse(intel.is_attack_event(None, {"exploit": "IP Camera Probe"}))
        self.assertFalse(intel.is_attack_event(None, {"ics": "identity"}))
        self.assertFalse(intel.is_attack_event(None, {"ics": "read"}))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()

    def knock(self, ip="203.0.113.9", kind="research", label="BinaryEdge", demoted=False, **kw):
        k = Knock(proto="SSH", ip=ip, port=22, **kw)
        k.kind, k.label, k.demoted = kind, label, demoted
        return k

    def actor_row(self, ip="203.0.113.9"):
        return self.store.db.execute("SELECT kind, label, demoted FROM actors WHERE ip=?", (ip,)).fetchone()

    def test_demotion_is_one_way_in_the_database(self):
        self.store.record(self.knock())
        self.assertEqual(tuple(self.actor_row())[:2], ("research", "BinaryEdge"))
        self.store.record(self.knock(kind="attack", label=None, demoted=True, username="root", password="x"))
        self.assertEqual(tuple(self.actor_row()), ("attack", None, 1))
        # After a restart the classifier believes the name again. The row must not flip back.
        self.store.record(self.knock())
        self.assertEqual(tuple(self.actor_row()), ("attack", None, 1))

    def test_an_ordinary_host_still_follows_its_latest_classification(self):
        self.store.record(self.knock(kind="attack", label=None))
        self.store.record(self.knock(kind="research", label="Shodan"))
        self.assertEqual(tuple(self.actor_row())[:2], ("research", "Shodan"))

    def test_an_old_database_gains_the_column(self):
        path = os.path.join(self.dir, "old.db")
        con = sqlite3.connect(path)
        con.executescript("""
            CREATE TABLE actors (ip TEXT PRIMARY KEY, hassh TEXT, first_ts INTEGER, last_ts INTEGER,
                hits INTEGER NOT NULL DEFAULT 0, iso TEXT, country TEXT, isp TEXT, asn INTEGER,
                protos TEXT, kind TEXT, label TEXT, rdns TEXT);
        """)
        con.commit()
        con.close()
        upgraded = Store(path)
        try:
            cols = {r["name"] for r in upgraded.db.execute("PRAGMA table_info(actors)")}
            self.assertIn("demoted", cols)
        finally:
            upgraded.close()

    def test_readers_are_separate_connections_and_see_committed_writes(self):
        self.store.record(self.knock(kind="attack", label=None))
        self.assertEqual(self.store.totals()["total"], 1)           # read through the reader
        seen = {}

        def other():
            seen["conn"] = self.store._reader()
            seen["total"] = self.store.totals()["total"]

        t = threading.Thread(target=other)
        t.start()
        t.join()
        self.assertIsNot(seen["conn"], self.store._reader())        # one per thread
        self.assertIsNot(seen["conn"], self.store.db)
        self.assertEqual(seen["total"], 1)

    def test_a_reader_cannot_write(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.store._reader().execute("DELETE FROM knocks")

    def test_a_long_read_does_not_hold_up_a_write(self):
        self.store.record(self.knock(kind="attack", label=None))
        reader = self.store._reader()
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM knocks").fetchall()           # a read transaction left open
        done = threading.Event()

        def write():
            self.store.record(self.knock(ip="203.0.113.10", kind="attack", label=None))
            done.set()

        t = threading.Thread(target=write)
        t.start()
        self.assertTrue(done.wait(5), "a read transaction blocked the writer")
        reader.execute("COMMIT")
        t.join()


class NeverListTests(unittest.TestCase):
    def feed(self, answers):
        cache = feeds.FeedCache(":memory:")
        cache.calls = []

        def confirm(host, ip):
            cache.calls.append((host, ip))
            return answers.get(ip, False)

        cache.confirm = confirm
        return cache

    def test_a_confirmed_crawler_is_never_listed(self):
        cache = self.feed({"66.249.66.1": True})
        self.assertFalse(cache._publishable("66.249.66.1", "crawl-66-249-66-1.googlebot.com"))

    def test_a_name_that_does_not_resolve_back_gets_no_protection(self):
        cache = self.feed({})
        self.assertTrue(cache._publishable("45.33.32.156", "crawl-1.googlebot.com"))

    def test_ordinary_names_cost_no_lookup(self):
        cache = self.feed({})
        cache._publishable("45.33.32.156", "dyn-9.example.net")
        cache._publishable("45.33.32.157", None)
        self.assertEqual(cache.calls, [])

    def test_answers_are_kept_and_a_no_is_retried_sooner(self):
        cache = self.feed({"66.249.66.1": True})
        for _ in range(3):
            cache._publishable("66.249.66.1", "crawl-1.googlebot.com")
            cache._publishable("45.33.32.156", "crawl-2.googlebot.com")
        self.assertEqual(len(cache.calls), 2)                        # one each, then cached
        cache._crawlers["45.33.32.156"] = (False, cache._crawlers["45.33.32.156"][1] - feeds.CRAWLER_RETRY - 1)
        cache._publishable("45.33.32.156", "crawl-2.googlebot.com")
        self.assertEqual(len(cache.calls), 3)                        # the no was asked again
        cache._crawlers["66.249.66.1"] = (True, cache._crawlers["66.249.66.1"][1] - feeds.CRAWLER_RETRY - 1)
        cache._publishable("66.249.66.1", "crawl-1.googlebot.com")
        self.assertEqual(len(cache.calls), 3)                        # the yes is still good

    def test_forward_confirmation_compares_addresses_not_text(self):
        original = classify.socket.getaddrinfo
        try:
            classify.socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("2001:db8:0:0:0:0:0:1", 0, 0, 0))]
            self.assertTrue(classify.forward_confirms("h.example", "2001:db8::1"))
            self.assertFalse(classify.forward_confirms("h.example", "2001:db8::2"))
            classify.socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(OSError("no such host"))
            self.assertFalse(classify.forward_confirms("h.example", "45.33.32.156"))
            self.assertFalse(classify.forward_confirms("h.example", "not an address"))
        finally:
            classify.socket.getaddrinfo = original


if __name__ == "__main__":
    unittest.main()
