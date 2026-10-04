"""The weekly digest: built from the data, escaped, served current and dated."""
import os
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

from uninvited import digest
from uninvited.app import Hub, build_app
from uninvited.core import Config, Knock
from uninvited.feeds import FeedCache
from uninvited.store import Store

EVIL = "<script>alert(1)</script>"


def knock(ts, proto="SSH", ip="203.0.113.7", user=None, pw=None, lines=(), country="The Netherlands", isp="Example Net"):
    k = Knock(proto=proto, ip=ip, port=22, ts=ts, username=user, password=pw, lines=list(lines))
    k.kind, k.country, k.iso, k.isp = "attack", country, "NL", isp
    return k


class DigestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        db = os.path.join(self.tmp, "t.db")
        self.cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
        self.store = Store(db)
        now = int(time.time()) - 5          # the week window ends at 'now' exclusive
        for i in range(6):
            for j in range(4):
                self.store.record(knock(now - 3600 * i - j, ip=f"45.33.32.{10 + i}", user="root", pw=f"pw{j}", country=EVIL))
        self.store.record(knock(now - 100, proto="HTTP", ip="45.33.32.30", lines=[("exploit", "Hikvision RCE " + EVIL), ("path", "/SDK")]))
        self.store.record(knock(now - 90, proto="HTTP", ip="45.33.32.31", lines=[("exploit", "Root Fingerprint"), ("path", "/")]))
        self.feeds = FeedCache(db, [], os.path.join(self.tmp, "feed_state.json"))
        self.feeds.refresh()
        self.client = TestClient(build_app(self.cfg, self.store, Hub(self.cfg, self.store), self.feeds))

    def tearDown(self):
        self.store.close()

    def test_the_numbers_come_from_the_data(self):
        d = self.feeds.digest
        self.assertIsNotNone(d)
        self.assertEqual(d["hits"], 26)
        self.assertEqual(d["hosts"], 8)
        self.assertEqual(d["exploit_hosts"], 1)          # the generic probe is not an exploit
        self.assertEqual(d["guess_share"], round(100 * 24 / 26))
        self.assertTrue(digest.valid_id(d["id"]))
        self.assertTrue(any("Password guessing was" in s for s in digest.story(d)))
        self.assertTrue(any("One host tried a named exploit" in s for s in digest.story(d)))

    def test_the_page_is_escaped_and_served_current_and_dated(self):
        r = self.client.get("/week")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(EVIL, r.text)
        self.assertIn("&lt;script&gt;", r.text)
        self.assertIn("This week on a server left open on purpose", r.text)
        self.assertIn("/static/vendor/jetbrains-mono.css", r.text)
        wid = self.feeds.digest["id"]
        self.assertEqual(self.client.get(f"/week/{wid}").status_code, 200)
        self.assertEqual(self.client.get(f"/week/{wid}.json").json()["id"], wid)
        self.assertEqual(self.client.get("/week.json").json()["hits"], 26)
        self.assertEqual(self.client.get("/week/1999-01").status_code, 404)
        self.assertEqual(self.client.get("/week/not-a-week").status_code, 404)
        self.assertEqual(self.client.get("/week/2026-01.json").status_code, 404)
        # the week's file is on disk, so an old week survives a restart
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "digests", wid + ".json")))

    def test_full_groups_with_one_basis_merge(self):
        groups = [{"id": "SET-01", "hosts": 40, "hits": 10, "basis": "shared credential list", "phrase": "x", "creds": []},
                  {"id": "SET-02", "hosts": 12, "hits": 5, "basis": "shared credential list", "phrase": "y", "creds": []},
                  {"id": "SET-03", "hosts": 40, "hits": 7, "basis": "shared credential list", "phrase": "x", "creds": []},
                  {"id": "SET-04", "hosts": 40, "hits": 3, "basis": "identical SSH client build", "phrase": "z", "creds": []}]
        out = digest._merge(groups)
        self.assertEqual([(g["id"], g["hosts"], g["groups"]) for g in out], [("SET-01", 80, 2), ("SET-02", 12, 1), ("SET-04", 40, 1)])


if __name__ == "__main__":
    unittest.main()
