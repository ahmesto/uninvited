"""The malware-URL lists, end to end: knocks recorded by the store, lists built by the feed
cache, files served by the app, indicators read by a strict STIX parser."""
import json
import os
import sys
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uninvited import droppers, urlfeed
from uninvited.app import Hub, build_app
from uninvited.core import Config, Knock
from uninvited.feeds import NAMES, FeedCache
from uninvited.store import Store

try:
    import stix2
except Exception:
    stix2 = None

MOZI = "http://175.107.3.233:43777/Mozi.a"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)
        self.now = int(time.time())

    def tearDown(self):
        self.store.close()

    def deliver(self, source, url, ago=60, exploit="Malware Dropper Command"):
        k = Knock(proto="HTTP", ip=source, port=80, ts=self.now - ago)
        k.detail = {"exploit": exploit}
        k.droppers = droppers.extract(f"wget {url}")
        assert k.droppers, url
        self.store.record(k)

    def build(self, **kw):
        cache = FeedCache(self.db, **kw)
        cache.refresh()
        return cache

    def listed(self, cache, stem="malware-urls-7d"):
        return [r["url"] for r in json.loads(cache.files[f"{stem}.json"].body)["indicators"]]


class RuleTests(Base):
    def test_a_url_delivered_by_one_other_host_is_not_listed(self):
        self.deliver("198.51.100.7", "http://45.9.148.5/x.sh")
        self.assertEqual(self.listed(self.build()), [])

    def test_two_different_hosts_make_it_listed(self):
        self.deliver("198.51.100.7", "http://45.9.148.5/x.sh")
        self.deliver("198.51.100.8", "http://45.9.148.5/x.sh", ago=30)
        self.assertEqual(self.listed(self.build()), ["http://45.9.148.5/x.sh"])

    def test_the_same_host_twice_is_still_one_source(self):
        for ago in (90, 60, 30):
            self.deliver("198.51.100.7", "http://45.9.148.5/x.sh", ago=ago)
        self.assertEqual(self.listed(self.build()), [])

    def test_a_host_offering_its_own_copy_is_listed_at_once(self):
        self.deliver("175.107.3.233", MOZI)
        cache = self.build()
        self.assertEqual(self.listed(cache), [MOZI])
        rec = json.loads(cache.files["malware-urls-7d.json"].body)["indicators"][0]
        self.assertEqual((rec["sources"], rec["self_hosted"], rec["confidence"], rec["family_hint"], rec["file"]),
                         (1, True, 50, "Mozi", "Mozi.a"))

    def test_naming_someone_elses_address_cannot_get_it_listed_alone(self):
        # The poisoning case: one host sends a request that points at an address that is not its own.
        self.deliver("198.51.100.7", "http://203.0.114.50/innocent.js")
        self.assertEqual(self.listed(self.build()), [])

    def test_confidence_rises_with_the_number_of_hosts(self):
        self.assertEqual([urlfeed.confidence(n) for n in (0, 1, 2, 3, 4, 10, 50)], [50, 50, 65, 80, 95, 95, 95])
        for i in range(4):
            self.deliver(f"198.51.100.{i + 1}", "http://45.9.148.5/x.sh", ago=100 - i)
        rec = json.loads(self.build().files["malware-urls-7d.json"].body)["indicators"][0]
        self.assertEqual((rec["sources"], rec["confidence"], rec["sightings"]), (4, 95, 4))

    def test_private_hosts_and_big_platforms_and_excluded_addresses_are_never_listed(self):
        for url in ("http://10.1.2.3/x", "http://192.168.1.5:8080/x", "http://raw.githubusercontent.com/o/r/main/x.sh",
                    "http://dl.google.com/x", "http://45.9.148.77/x"):
            if droppers.extract(f"wget {url}"):
                self.deliver("198.51.100.7", url)
                self.deliver("198.51.100.8", url, ago=30)
        self.assertEqual(self.listed(self.build(exclude=["45.9.148.77"])), [])

    def test_a_named_host_is_listed_when_it_is_not_a_big_platform(self):
        self.deliver("198.51.100.7", "http://dropper.example.net/x.sh")
        self.deliver("198.51.100.8", "http://dropper.example.net/x.sh", ago=30)
        self.assertEqual(self.listed(self.build()), ["http://dropper.example.net/x.sh"])

    def test_windows_and_ordering(self):
        self.deliver("175.107.3.233", MOZI, ago=3600 * 40)                       # last 7 days, not 24h
        self.deliver("45.9.148.5", "http://45.9.148.5/new.sh", ago=60)           # both
        old = "http://45.9.148.9/old.sh"
        self.deliver("45.9.148.9", old, ago=3600 * 24 * 20)                      # only 30 days
        cache = self.build()
        self.assertEqual(self.listed(cache, "malware-urls-24h"), ["http://45.9.148.5/new.sh"])
        self.assertEqual(set(self.listed(cache, "malware-urls-7d")), {MOZI, "http://45.9.148.5/new.sh"})
        self.assertEqual(set(self.listed(cache, "malware-urls-30d")), {MOZI, "http://45.9.148.5/new.sh", old})
        # same confidence, so the most recently asked-for first
        self.assertEqual(self.listed(cache, "malware-urls-7d")[0], "http://45.9.148.5/new.sh")

    def test_a_url_nobody_has_asked_for_in_30_days_is_gone(self):
        self.deliver("175.107.3.233", MOZI, ago=3600 * 24 * 40)
        self.assertEqual(self.listed(self.build(), "malware-urls-30d"), [])


class FileTests(Base):
    def setUp(self):
        super().setUp()
        self.deliver("175.107.3.233", MOZI, ago=600)
        self.deliver("198.51.100.7", "http://dropper.example.net/a'b.sh?x=1", ago=500)
        self.deliver("198.51.100.8", "http://dropper.example.net/a'b.sh?x=1", ago=400)
        self.cache = self.build()

    def test_every_format_exists_for_every_window(self):
        for stem in urlfeed.WINDOWS:
            for ext in ("txt", "json", "csv", "stix.json"):
                self.assertIn(f"{stem}.{ext}", self.cache.files)
                self.assertIn(f"{stem}.{ext}", NAMES)

    def test_the_text_list_is_one_url_per_line_with_a_plain_header(self):
        body = self.cache.files["malware-urls-7d.txt"].body.decode()
        lines = body.splitlines()
        header = [l for l in lines if l.startswith("#")]
        urls = [l for l in lines if not l.startswith("#")]
        self.assertEqual(len(urls), 2)
        self.assertTrue(any("Nothing is fetched" in h for h in header))
        self.assertTrue(any("Do not browse to them" in h for h in header))
        self.assertIn(MOZI, urls)

    def test_the_json_describes_each_field(self):
        doc = json.loads(self.cache.files["malware-urls-7d.json"].body)
        self.assertEqual((doc["window"], doc["count"], doc["schema_version"]), ("7d", 2, "1.0"))
        rec = next(r for r in doc["indicators"] if r["url"] == MOZI)
        self.assertEqual(set(rec), {"url", "host", "port", "scheme", "file", "family_hint", "first_seen", "last_seen",
                                    "sightings", "sources", "self_hosted", "delivered_by", "confidence", "expires"})
        self.assertEqual(rec["delivered_by"], ["Malware Dropper Command"])
        self.assertTrue(rec["expires"] > rec["last_seen"])
        for field in rec:
            self.assertIn(field, doc["fields"] | {k: 1 for k in rec if k not in doc["fields"]})

    def test_the_csv_has_a_header_and_defuses_formulas(self):
        text = self.cache.files["malware-urls-7d.csv"].body.decode()
        self.assertTrue(text.startswith("url,host,port,scheme,file,family_hint,"))
        self.assertEqual(len(text.strip().splitlines()), 3)
        original = urlfeed.csv_text([{"url": "=HYPERLINK(1)", "host": "x", "port": 1, "scheme": "http", "file": "-1",
                                      "family": None, "first_ts": 1, "last_ts": 2, "hits": 1, "sources": 1,
                                      "self_hosted": True, "exploits": [], "confidence": 50, "expires_ts": 3}])
        self.assertIn("'=HYPERLINK(1)", original)
        self.assertIn("'-1", original)

    @unittest.skipUnless(stix2, "stix2 not installed")
    def test_the_stix_bundle_parses_strictly_and_escapes_the_pattern(self):
        bundle = json.loads(self.cache.files["malware-urls-7d.stix.json"].body)
        parsed = stix2.parse(bundle, allow_custom=False, version="2.1")
        indicators = [o for o in parsed.objects if o.type == "indicator"]
        self.assertEqual(len(indicators), 2)
        patterns = {i.pattern for i in indicators}
        self.assertIn(f"[url:value = '{MOZI}']", patterns)
        self.assertIn("[url:value = 'http://dropper.example.net/a\\'b.sh?x=1']", patterns)
        mozi = next(i for i in indicators if "Mozi" in i.pattern)
        self.assertEqual(list(mozi.labels), ["malware-delivery", "mozi"])
        self.assertEqual(mozi.external_references[0].external_id, "T1105")
        self.assertIn("The address was not fetched", mozi.description)

    @unittest.skipUnless(stix2, "stix2 not installed")
    def test_the_taxii_collection_holds_the_same_urls(self):
        cid = self.cache.taxii.ids["malware-urls-7d"]
        page = self.cache.taxii.page("malware-urls-7d", added_after=None, limit=100, nxt=None, ids=None, types=None,
                                     versions=None, spec_versions=None)
        objs = [json.loads(e.text) for e in page["entries"]]
        for o in objs:
            stix2.parse(o, allow_custom=False, version="2.1")
        self.assertEqual({o["pattern"] for o in objs if o["type"] == "indicator"},
                         {f"[url:value = '{MOZI}']", "[url:value = 'http://dropper.example.net/a\\'b.sh?x=1']"})
        self.assertEqual(cid, self.cache.taxii.ids["malware-urls-7d"])
        self.assertEqual(self.cache.taxii.count("malware-urls-7d"), 2)

    def test_the_index_and_status_carry_the_lists(self):
        index = json.loads(self.cache.files["index.json"].body)
        self.assertEqual([(u["name"], u["count"]) for u in index["url_lists"]],
                         [("malware-urls-24h", 2), ("malware-urls-7d", 2), ("malware-urls-30d", 2)])
        self.assertIn("/feed/malware-urls-7d.stix.json", index["url_lists"][1]["files"]["stix.json"])
        status = json.loads(self.cache.files["status.json"].body)
        self.assertEqual(status["url_lists"]["malware-urls-7d"], 2)
        self.assertIn("malware-urls-7d", [c["name"] for c in index["taxii"]["collections"]])

    def test_the_app_serves_them_with_the_right_types(self):
        cfg = Config({"database": self.db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
        client = TestClient(build_app(cfg, self.store, Hub(cfg, self.store), self.cache))
        for ext, ctype in (("txt", "text/plain"), ("json", "application/json"), ("csv", "text/csv"),
                           ("stix.json", "application/stix+json")):
            r = client.get(f"/feed/malware-urls-7d.{ext}")
            self.assertEqual(r.status_code, 200, ext)
            self.assertTrue(r.headers["content-type"].startswith(ctype), (ext, r.headers["content-type"]))
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(client.get("/feed/malware-urls-1d.txt").status_code, 404)

    def test_the_urls_never_reach_the_public_api(self):
        # Download URLs are published through the feed rules only: not through the live API.
        cfg = Config({"database": self.db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
        client = TestClient(build_app(cfg, self.store, Hub(cfg, self.store), self.cache))
        for path in ("/api/feed?proto=HTTP&limit=200", "/api/stats", "/api/lookup?ip=175.107.3.233"):
            body = client.get(path).text
            self.assertNotIn("droppers", body, path)


if __name__ == "__main__":
    unittest.main()
