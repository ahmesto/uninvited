import json
import os
import tempfile
import time
import unittest

from uninvited import feeds, history
from uninvited.core import Knock
from uninvited.feeds import FeedCache
from uninvited.history import ListHistory, parse_since
from uninvited.store import Store
from datetime import UTC

NOW = 1_800_000_000


class ParseSinceTests(unittest.TestCase):
    def test_default_is_the_last_day(self):
        self.assertEqual(parse_since(None, NOW), NOW - 86400)
        self.assertEqual(parse_since("  ", NOW), NOW - 86400)

    def test_epoch_seconds_and_milliseconds(self):
        self.assertEqual(parse_since("1799990000", NOW), 1799990000)
        self.assertEqual(parse_since("1799990000000", NOW), 1799990000)

    def test_iso_forms(self):
        from datetime import datetime
        want = int(datetime(2027, 1, 15, 8, 0, 0, tzinfo=UTC).timestamp())
        self.assertEqual(parse_since("2027-01-15T08:00:00Z", NOW), want)
        self.assertEqual(parse_since("2027-01-15T08:00:00+00:00", NOW), want)
        self.assertEqual(parse_since("2027-01-15T08:00:00", NOW), want)       # no zone means UTC
        self.assertEqual(parse_since("2027-01-15T03:00:00-05:00", NOW), want)

    def test_future_is_clamped_to_now(self):
        self.assertEqual(parse_since("9999999999", NOW), NOW)
        self.assertEqual(parse_since("2999-01-01T00:00:00Z", NOW), NOW)

    def test_junk_is_rejected(self):
        for bad in ("yesterday", "1.5", "-5", "2027-13-45", "'; drop table", "0x10"):
            self.assertIsNone(parse_since(bad, NOW), bad)


class HistoryTests(unittest.TestCase):
    def test_first_sight_is_a_baseline_not_a_flood_of_additions(self):
        h = ListHistory()
        self.assertEqual(h.update({"a": {"1.1.1.1", "2.2.2.2"}}, NOW), 0)
        self.assertEqual(h.net_changes("a", NOW), {"reset": False, "added": [], "removed": []})

    def test_added_and_removed(self):
        h = ListHistory()
        h.update({"a": {"1.1.1.1", "2.2.2.2"}}, NOW)
        h.update({"a": {"2.2.2.2", "3.3.3.3"}}, NOW + 300)
        self.assertEqual(h.net_changes("a", NOW),
                         {"reset": False, "added": ["3.3.3.3"], "removed": ["1.1.1.1"]})

    def test_joined_and_left_again_is_not_mentioned(self):
        h = ListHistory()
        h.update({"a": {"1.1.1.1"}}, NOW)
        h.update({"a": {"1.1.1.1", "9.9.9.9"}}, NOW + 300)
        h.update({"a": {"1.1.1.1"}}, NOW + 600)
        self.assertEqual(h.net_changes("a", NOW)["added"], [])
        self.assertEqual(h.net_changes("a", NOW)["removed"], [])

    def test_left_and_came_back_is_not_mentioned(self):
        h = ListHistory()
        h.update({"a": {"1.1.1.1", "2.2.2.2"}}, NOW)
        h.update({"a": {"2.2.2.2"}}, NOW + 300)
        h.update({"a": {"1.1.1.1", "2.2.2.2"}}, NOW + 600)
        net = h.net_changes("a", NOW)
        self.assertEqual((net["added"], net["removed"]), ([], []))

    def test_applying_the_answer_reproduces_the_list(self):
        import random
        rnd = random.Random(7)
        universe = [f"10.0.0.{i}" for i in range(40)]
        h = ListHistory()
        state = set(rnd.sample(universe, 15))
        h.update({"a": set(state)}, NOW)
        snapshots = {NOW: set(state)}
        t = NOW
        for _ in range(60):
            t += 300
            state = set(rnd.sample(universe, rnd.randrange(5, 25)))
            h.update({"a": set(state)}, t)
            snapshots[t] = set(state)
        for start in list(snapshots)[::7]:
            net = h.net_changes("a", start)
            rebuilt = (snapshots[start] | set(net["added"])) - set(net["removed"])
            self.assertEqual(rebuilt, snapshots[t], start)

    def test_since_before_the_history_is_a_reset(self):
        h = ListHistory()
        h.update({"a": {"1.1.1.1"}}, NOW)
        r = h.net_changes("a", NOW - 1)
        self.assertTrue(r["reset"])
        self.assertEqual((r["added"], r["removed"]), ([], []))

    def test_unknown_list(self):
        self.assertIsNone(ListHistory().net_changes("nope", NOW))

    def test_a_list_that_appears_later_is_baselined(self):
        h = ListHistory()
        h.update({"a": {"1.1.1.1"}}, NOW)
        h.update({"a": {"1.1.1.1"}, "b": {"5.5.5.5"}}, NOW + 300)
        self.assertEqual(h.history_from("b"), NOW + 300)
        self.assertEqual(h.net_changes("b", NOW + 300)["added"], [])
        self.assertTrue(h.net_changes("b", NOW)["reset"])

    def test_old_changes_are_pruned_and_the_history_start_moves(self):
        h = ListHistory()
        h.update({"a": set()}, NOW)
        h.update({"a": {"1.1.1.1"}}, NOW + 100)
        later = NOW + history.KEEP_SECONDS + 5000
        h.update({"a": {"1.1.1.1", "2.2.2.2"}}, later)
        self.assertEqual(len(h.changes), 1)
        self.assertGreaterEqual(h.history_from("a"), later - history.KEEP_SECONDS)
        self.assertTrue(h.net_changes("a", NOW + 50)["reset"])

    def test_change_cap(self):
        h = ListHistory()
        h.update({"a": set()}, NOW)
        old = history.MAX_CHANGES
        history.MAX_CHANGES = 10
        try:
            h.update({"a": {f"1.1.1.{i}" for i in range(30)}}, NOW + 10)
        finally:
            history.MAX_CHANGES = old
        self.assertEqual(len(h.changes), 10)


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "state.json")

    def test_survives_a_restart_and_reports_what_changed_while_down(self):
        h = ListHistory(self.path)
        h.update({"a": {"1.1.1.1"}}, NOW)
        h.update({"a": {"1.1.1.1", "2.2.2.2"}}, NOW + 300)
        again = ListHistory(self.path)
        self.assertEqual(again.net_changes("a", NOW)["added"], ["2.2.2.2"])
        again.update({"a": {"2.2.2.2", "4.4.4.4"}}, NOW + 900)
        net = again.net_changes("a", NOW)
        self.assertEqual((net["added"], net["removed"]), (["2.2.2.2", "4.4.4.4"], ["1.1.1.1"]))
        net = again.net_changes("a", NOW + 300)
        self.assertEqual((net["added"], net["removed"]), (["4.4.4.4"], ["1.1.1.1"]))

    def test_a_corrupt_file_means_a_fresh_start_not_a_crash(self):
        with open(self.path, "w") as fh:
            fh.write("{not json")
        h = ListHistory(self.path)
        self.assertEqual(h.update({"a": {"1.1.1.1"}}, NOW), 0)
        self.assertTrue(os.path.exists(self.path))
        with open(self.path, encoding="utf-8") as fh:
            json.load(fh)

    def test_nothing_is_written_when_nothing_changed(self):
        h = ListHistory(self.path)
        h.update({"a": {"1.1.1.1"}}, NOW)
        stamp = os.stat(self.path).st_mtime_ns
        time.sleep(0.02)
        h.update({"a": {"1.1.1.1"}}, NOW + 300)
        self.assertEqual(os.stat(self.path).st_mtime_ns, stamp)


class FeedCacheChangeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)
        self.cache = FeedCache(self.db, state_path=os.path.join(self.dir, "state.json"))

    def tearDown(self):
        self.store.close()

    def attack(self, ip, n=3):
        for i in range(n):
            self.store.record(Knock(proto="SSH", ip=ip, port=22, ts=int(time.time()) - i,
                                    username="root", password="x" * (i + 1), lines=[], detail={}))

    def test_a_host_that_qualifies_shows_up_as_added_and_status_says_so(self):
        self.cache.refresh()                          # baseline: empty
        start = self.cache.history.history_from("attackers-24h")
        time.sleep(1.1)
        self.attack("93.184.216.34")
        self.cache.refresh()
        doc = self.cache.changes("attackers-24h", start)
        self.assertFalse(doc["reset"])
        self.assertEqual([r["ip"] for r in doc["added"]], ["93.184.216.34"])
        self.assertIn("ssh-bruteforce", doc["added"][0]["tags"])
        self.assertEqual(doc["removed"], [])
        self.assertEqual(doc["count_now"], 1)
        # the next poll, using as_of, is empty
        again = self.cache.changes("attackers-24h", doc["as_of_epoch"])
        self.assertEqual((again["added"], again["removed"]), ([], []))

        status = json.loads(self.cache.get("status.json").body)
        self.assertEqual(status["lists"]["attackers-24h"], 1)
        self.assertTrue(status["changelog"])
        self.assertIn("attackers-24h", status["changes"]["history_from"])

    def test_unknown_list_and_cold_cache(self):
        self.assertIsNone(self.cache.changes("attackers-24h", 0))     # not ready yet
        self.cache.refresh()
        self.assertIsNone(self.cache.changes("../../etc/passwd", 0))
        self.assertIsNone(self.cache.changes("nope", 0))

    def test_every_tracked_list_is_served_by_name_and_listed_in_the_index(self):
        self.cache.refresh()
        index = json.loads(self.cache.get("index.json").body)
        self.assertEqual(index["changes_lists"], list(feeds.CHANGE_LISTS))
        self.assertIn("status.json", feeds.NAMES)
        for name in feeds.CHANGE_LISTS:
            self.assertIsNotNone(self.cache.history.history_from(name), name)

    def test_history_survives_a_new_cache_instance(self):
        self.cache.refresh()
        start = self.cache.history.history_from("attackers-24h")
        time.sleep(1.1)
        self.attack("93.184.216.35")
        self.cache.refresh()
        fresh = FeedCache(self.db, state_path=os.path.join(self.dir, "state.json"))
        fresh.refresh()
        doc = fresh.changes("attackers-24h", start)
        self.assertEqual([r["ip"] for r in doc["added"]], ["93.184.216.35"])


if __name__ == "__main__":
    unittest.main()
