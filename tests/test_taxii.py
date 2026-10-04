"""The TAXII 2.1 server: the protocol rules, the date_added bookkeeping, and an independent
client (taxii2-client, with stix2 checking every object) talking to a real running server."""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import samples
from uninvited import taxii
from uninvited.app import Hub, build_app
from uninvited.core import Config
from uninvited.feeds import FeedCache
from uninvited.store import Store

HEADERS = {"Accept": taxii.MEDIA}


def make(rows_by_stem=None, now=samples.NOW, state_path=None):
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "t.db")
    cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": {"url": samples.LIVE.site}})
    store = Store(db)
    feeds = FeedCache(db, state_path=state_path, ident=samples.LIVE)
    rows = samples.rows()
    # The attacker collections take host rows; the URL collection has its own rows (see test_urlfeed).
    feeds.taxii.update(rows_by_stem or {s: rows for s in taxii.STEMS if not s.startswith("malware-urls")}, now)
    app = build_app(cfg, store, Hub(cfg, store), feeds)
    return app, feeds, store


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app, cls.feeds, cls.store = make()
        cls.client = TestClient(cls.app)
        cls.cid = cls.feeds.taxii.ids["attackers-7d"]

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def get(self, path, **kw):
        return self.client.get(path, headers=HEADERS, **kw)

    def objects(self, **params):
        r = self.get(f"/taxii2/root/collections/{self.cid}/objects/", params=params)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_discovery_names_the_api_root(self):
        r = self.get("/taxii2/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["content-type"], taxii.MEDIA)
        doc = r.json()
        self.assertEqual(doc["default"], "http://testserver/taxii2/root/")
        self.assertEqual(doc["api_roots"], ["http://testserver/taxii2/root/"])
        self.assertIn("title", doc)

    def test_api_root_declares_the_version_and_a_size(self):
        doc = self.get("/taxii2/root/").json()
        self.assertEqual(doc["versions"], [taxii.MEDIA])
        self.assertIsInstance(doc["max_content_length"], int)
        self.assertIn("title", doc)

    def test_the_collections_are_read_only_and_say_what_they_hold(self):
        doc = self.get("/taxii2/root/collections/").json()
        self.assertEqual([c["title"] for c in doc["collections"]],
                         [taxii.COLLECTIONS[s][0] for s in taxii.STEMS])
        for c in doc["collections"]:
            self.assertEqual((c["can_read"], c["can_write"]), (True, False))
            self.assertEqual(c["media_types"], [taxii.STIX_MEDIA])
            self.assertRegex(c["id"], r"^[0-9a-f-]{36}$")
        self.assertEqual(len({c["id"] for c in doc["collections"]}), len(taxii.STEMS))
        one = self.get(f"/taxii2/root/collections/{self.cid}/").json()
        self.assertEqual(one["id"], self.cid)

    def test_collection_ids_are_stable_for_one_site(self):
        again = taxii.TaxiiState(self.feeds.stix, samples.LIVE.ns)
        self.assertEqual(again.ids, self.feeds.taxii.ids)

    def test_a_trailing_slash_is_optional_and_nothing_redirects(self):
        for path in ("/taxii2", "/taxii2/root", "/taxii2/root/collections",
                     f"/taxii2/root/collections/{self.cid}", f"/taxii2/root/collections/{self.cid}/objects"):
            r = self.client.get(path, headers=HEADERS, follow_redirects=False)
            self.assertEqual(r.status_code, 200, path)

    def test_objects_come_back_in_an_envelope_with_the_identity_first(self):
        doc = self.objects()
        self.assertFalse(doc["more"])
        self.assertNotIn("next", doc)
        kinds = [o["type"] for o in doc["objects"]]
        self.assertEqual(kinds[0], "identity")
        self.assertEqual(kinds.count("indicator"), len(samples.rows()))
        self.assertEqual({o["pattern"] for o in doc["objects"][1:]},
                         {f"[{'ipv6' if ':' in r['ip'] else 'ipv4'}-addr:value = '{r['ip']}']" for r in samples.rows()})

    def test_the_objects_are_exactly_the_ones_in_the_downloadable_bundle(self):
        bundle = json.loads(self.feeds._stix(168, samples.rows()).body)
        def key(o):
            return o["id"]
        self.assertEqual(sorted(self.objects()["objects"], key=key), sorted(bundle["objects"], key=key))

    def test_date_added_headers_bracket_the_page(self):
        r = self.get(f"/taxii2/root/collections/{self.cid}/objects/")
        self.assertRegex(r.headers["x-taxii-date-added-first"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")
        self.assertLessEqual(r.headers["x-taxii-date-added-first"], r.headers["x-taxii-date-added-last"])

    def test_pagination_walks_every_object_once(self):
        seen, nxt, pages = [], None, 0
        while True:
            params = {"limit": 2}
            if nxt:
                params["next"] = nxt
            doc = self.objects(**params)
            pages += 1
            self.assertLessEqual(len(doc["objects"]), 2)
            seen += [o["id"] for o in doc["objects"]]
            if not doc["more"]:
                break
            nxt = doc["next"]
            self.assertTrue(nxt)
        self.assertEqual(pages, 4)                                   # identity + six hosts, two at a time
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(set(seen), {o["id"] for o in self.objects()["objects"]})

    def test_added_after_returns_only_what_came_later(self):
        everything = self.objects()["objects"]
        manifest = self.get(f"/taxii2/root/collections/{self.cid}/manifest/").json()["objects"]
        last = max(m["date_added"] for m in manifest if m["id"].startswith("indicator--"))
        self.assertEqual(self.objects(added_after=last).get("objects", []), [])
        # The identity is dated at the start of the data, so a later time never returns it.
        later = self.objects(added_after="2026-09-01T00:00:00Z")["objects"]
        self.assertEqual(len(later), len(everything) - 1)
        self.assertNotIn("identity", [o["type"] for o in later])

    def test_match_filters(self):
        indicators = [o for o in self.objects()["objects"] if o["type"] == "indicator"]
        want = indicators[2]["id"]
        self.assertEqual([o["id"] for o in self.objects(**{"match[id]": want})["objects"]], [want])
        two = ",".join(o["id"] for o in indicators[:2])
        self.assertEqual(len(self.objects(**{"match[id]": two})["objects"]), 2)
        self.assertEqual(len(self.objects(**{"match[type]": "indicator"})["objects"]), len(indicators))
        self.assertEqual([o["type"] for o in self.objects(**{"match[type]": "identity"})["objects"]], ["identity"])
        self.assertEqual(len(self.objects(**{"match[version]": "last"})["objects"]), len(indicators) + 1)
        self.assertEqual(len(self.objects(**{"match[version]": "all"})["objects"]), len(indicators) + 1)
        stamp = indicators[0]["modified"]
        self.assertEqual([o["id"] for o in self.objects(**{"match[version]": stamp})["objects"] if o["type"] == "indicator"
                          and o["modified"] == stamp][:1], [indicators[0]["id"]])
        self.assertEqual(self.objects(**{"match[version]": "2001-01-01T00:00:00.000Z"}).get("objects", []), [])
        self.assertEqual(self.objects(**{"match[spec_version]": "2.0"}).get("objects", []), [])
        self.assertEqual(len(self.objects(**{"match[spec_version]": "2.1"})["objects"]), len(indicators) + 1)

    def test_the_manifest_lists_ids_versions_and_media_types(self):
        doc = self.get(f"/taxii2/root/collections/{self.cid}/manifest/").json()
        self.assertEqual(len(doc["objects"]), len(samples.rows()) + 1)
        for m in doc["objects"]:
            self.assertEqual(set(m), {"id", "date_added", "version", "media_type"})
            self.assertEqual(m["media_type"], taxii.STIX_MEDIA)
        paged = self.get(f"/taxii2/root/collections/{self.cid}/manifest/", params={"limit": 3}).json()
        self.assertTrue(paged["more"] and paged["next"] and len(paged["objects"]) == 3)

    def test_one_object_and_its_versions(self):
        oid = self.objects(**{"match[type]": "indicator"})["objects"][0]["id"]
        one = self.get(f"/taxii2/root/collections/{self.cid}/objects/{oid}/").json()
        self.assertEqual([o["id"] for o in one["objects"]], [oid])
        v = self.get(f"/taxii2/root/collections/{self.cid}/objects/{oid}/versions/").json()
        self.assertEqual(v["more"], False)
        self.assertEqual(v["versions"], [one["objects"][0]["modified"]])

    def test_errors_are_taxii_errors(self):
        for path, status in ((f"/taxii2/root/collections/{self.cid[:-1]}0/", 404),
                             ("/taxii2/root/collections/not-a-uuid/", 404),
                             (f"/taxii2/root/collections/{self.cid}/objects/indicator--00000000-0000-4000-8000-000000000000/", 404),
                             (f"/taxii2/root/collections/{self.cid}/objects/garbage/", 404),
                             ("/taxii2/root/status/abc/", 404)):
            r = self.get(path)
            self.assertEqual(r.status_code, status, path)
            self.assertEqual(r.headers["content-type"], taxii.MEDIA)
            self.assertEqual(r.json()["http_status"], str(status))
            self.assertIn("title", r.json())

    def test_bad_parameters_are_a_400(self):
        base = f"/taxii2/root/collections/{self.cid}/objects/"
        for params in ({"added_after": "yesterday"}, {"added_after": "2026-10-02"}, {"added_after": "2026-13-45T00:00:00Z"},
                       {"limit": "0"}, {"limit": "-3"}, {"limit": "many"}, {"next": "not-a-token"},
                       {"match[id]": "nonsense"}, {"match[id]": ",".join(["indicator--00000000-0000-4000-8000-000000000000"] * 1) + ",x"}):
            r = self.get(base, params=params)
            self.assertEqual(r.status_code, 400, params)
            self.assertEqual(r.json()["http_status"], "400")

    def test_an_oversized_limit_is_capped_not_refused(self):
        r = self.get(f"/taxii2/root/collections/{self.cid}/objects/", params={"limit": 10 ** 9})
        self.assertEqual(r.status_code, 200)

    def test_writes_are_refused(self):
        base = f"/taxii2/root/collections/{self.cid}/objects/"
        self.assertEqual(self.client.post(base, headers=HEADERS, json={"objects": []}).status_code, 403)
        oid = self.objects()["objects"][1]["id"]
        self.assertEqual(self.client.delete(f"{base}{oid}/", headers=HEADERS).status_code, 403)

    def test_accept_negotiation(self):
        path = "/taxii2/root/"
        for accept, status in ((taxii.MEDIA, 200), ("application/taxii+json", 200), ("*/*", 200),
                               ("application/json", 200), ("", 200),
                               ("text/html,application/xhtml+xml,*/*;q=0.8", 200),
                               ("text/html", 406), ("application/taxii+json;version=2.0", 406),
                               ("application/stix+json;version=2.1", 406)):
            r = self.client.get(path, headers={"Accept": accept} if accept else {})
            self.assertEqual(r.status_code, status, accept)

    def test_head_works(self):
        r = self.client.head("/taxii2/root/", headers=HEADERS)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"")

    def test_a_client_that_hammers_is_slowed_down(self):
        original = taxii.RATE
        app, _feeds, store = make()
        try:
            taxii.RATE = 5
            client = TestClient(app)
            codes = [client.get("/taxii2/root/", headers=HEADERS).status_code for _ in range(8)]
            self.assertEqual(codes[:5], [200] * 5)
            self.assertEqual(set(codes[5:]), {429})
            self.assertEqual(client.get("/taxii2/root/", headers=HEADERS).headers["retry-after"], "30")
        finally:
            taxii.RATE = original
            store.close()

    def test_nothing_is_served_before_the_first_build(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "t.db")
        store = Store(db)
        feeds = FeedCache(db)
        app = build_app(Config({"database": db, "services": [], "site": {}}), store, Hub(Config({"site": {}}), store), feeds)
        try:
            client = TestClient(app)
            cid = feeds.taxii.ids["attackers-7d"]
            r = client.get(f"/taxii2/root/collections/{cid}/objects/", headers=HEADERS)
            self.assertEqual(r.status_code, 503)
            self.assertEqual(r.headers["retry-after"], "30")
            self.assertEqual(client.get("/taxii2/root/collections/", headers=HEADERS).status_code, 200)
        finally:
            store.close()

    def test_the_public_site_hands_out_https_links(self):
        client = TestClient(self.app, base_url="http://dmz.ahmadmesto.com")
        doc = client.get("/taxii2/", headers=HEADERS).json()
        self.assertEqual(doc["default"], "https://dmz.ahmadmesto.com/taxii2/root/")


class DatingTests(unittest.TestCase):
    """date_added: when each object was first served in its present version."""

    def state(self, path=None):
        maker = FeedCache(":memory:").stix
        return taxii.TaxiiState(maker, samples.LIVE.ns, path)

    def entries(self, st, stem="attackers-7d"):
        return {i: e for i, e in st.snaps[stem].entries.items() if e.obj_type == "indicator"}

    def test_everything_is_dated_when_first_served(self):
        st = self.state()
        st.update({"attackers-7d": samples.rows()}, 1000.0)
        self.assertEqual({e.date_added for e in self.entries(st).values()}, {1000 * 10 ** 6})
        self.assertEqual(st.snaps["attackers-7d"].entries[st._identity.obj_id].date_added,
                         taxii.parse_us("2026-08-14T00:00:00.000Z"))

    def test_an_unchanged_host_keeps_its_date(self):
        st = self.state()
        st.update({"attackers-7d": samples.rows()}, 1000.0)
        st.update({"attackers-7d": samples.rows()}, 2000.0)
        self.assertEqual({e.date_added for e in self.entries(st).values()}, {1000 * 10 ** 6})

    def test_a_host_that_attacks_again_is_new_again(self):
        st = self.state()
        rows = samples.rows()
        st.update({"attackers-7d": rows}, 1000.0)
        rows[0] = samples.row(rows[0]["ip"], last_ts=samples.NOW + 50, expires_ts=samples.NOW + 50 + 7 * 86400)
        st.update({"attackers-7d": rows}, 2000.0)
        by_ip = {json.loads(e.text)["name"]: e.date_added for e in self.entries(st).values()}
        self.assertEqual(by_ip[rows[0]["ip"]], 2000 * 10 ** 6)
        self.assertEqual(by_ip[rows[1]["ip"]], 1000 * 10 ** 6)

    def test_a_host_that_leaves_the_list_leaves_the_collection(self):
        st = self.state()
        st.update({"attackers-7d": samples.rows()}, 1000.0)
        st.update({"attackers-7d": samples.rows()[:3]}, 2000.0)
        self.assertEqual(len(self.entries(st)), 3)
        self.assertEqual(st.count("attackers-7d"), 3)

    def test_a_client_polling_with_added_after_never_misses_a_host(self):
        st = self.state()
        rows = samples.rows()
        st.update({"attackers-7d": rows[:3]}, 1000.0)
        got = {json.loads(e.text)["name"] for e in st.page("attackers-7d", added_after=None, limit=100, nxt=None,
                                                          ids=None, types=None, versions=None, spec_versions=None)["entries"]
               if e.obj_type == "indicator"}
        polled_at = 1000 * 10 ** 6
        st.update({"attackers-7d": rows}, 1500.0)                    # three more qualify
        later = st.page("attackers-7d", added_after=polled_at, limit=100, nxt=None, ids=None, types=None,
                        versions=None, spec_versions=None)["entries"]
        names = {json.loads(e.text)["name"] for e in later if e.obj_type == "indicator"}
        self.assertEqual(got | names, {r["ip"] for r in rows})
        self.assertEqual(names, {r["ip"] for r in rows[3:]})

    def test_a_restart_keeps_the_dates_it_saved(self):
        path = os.path.join(tempfile.mkdtemp(), "taxii_state.json")
        st = self.state(path)
        st.update({"attackers-7d": samples.rows()}, 1000.0)
        self.assertTrue(os.path.exists(path))
        again = self.state(path)
        again.update({"attackers-7d": samples.rows()}, 9000.0)
        self.assertEqual({e.date_added for e in self.entries(again).values()}, {1000 * 10 ** 6})
        # a host whose version moved on while we were down is dated now
        rows = samples.rows()
        rows[1] = samples.row(rows[1]["ip"], last_ts=samples.NOW + 99, expires_ts=samples.NOW + 99 + 86400)
        third = self.state(path)
        third.update({"attackers-7d": rows}, 9500.0)
        by_ip = {json.loads(e.text)["name"]: e.date_added for e in self.entries(third).values()}
        self.assertEqual(by_ip[rows[1]["ip"]], 9500 * 10 ** 6)
        self.assertEqual(by_ip[rows[0]["ip"]], 1000 * 10 ** 6)

    def test_an_unreadable_state_file_is_ignored(self):
        path = os.path.join(tempfile.mkdtemp(), "taxii_state.json")
        for junk in ("{not json", '{"v": 99}', '{"v":1,"collections":{"attackers-7d":{"x":[1]}}}', "[]"):
            with open(path, "w") as fh:
                fh.write(junk)
            st = self.state(path)
            st.update({"attackers-7d": samples.rows()}, 3000.0)
            self.assertEqual({e.date_added for e in self.entries(st).values()}, {3000 * 10 ** 6}, junk)

    def test_no_state_is_written_when_nothing_changed(self):
        path = os.path.join(tempfile.mkdtemp(), "taxii_state.json")
        st = self.state(path)
        st.update({"attackers-7d": samples.rows()}, 1000.0)
        first = os.stat(path).st_mtime_ns
        time.sleep(0.05)
        st.update({"attackers-7d": samples.rows()}, 2000.0)
        self.assertEqual(os.stat(path).st_mtime_ns, first)

    def test_timestamp_round_trip(self):
        for us in (0, 1, 1_790_000_000_123_456, 1_790_000_000_000_000):
            self.assertEqual(taxii.parse_us(taxii.fmt_us(us)), us)
        self.assertEqual(taxii.parse_us("2026-10-02T12:00:00Z"), taxii.parse_us("2026-10-02T12:00:00.000000Z"))
        self.assertEqual(taxii.parse_us("2026-10-02T12:00:00.5Z"), taxii.parse_us("2026-10-02T12:00:00.500000Z"))
        for bad in ("", "2026-10-02", "2026-10-02T12:00:00", "2026-10-02T12:00:00+00:00", "2026-02-30T12:00:00Z", "x"):
            self.assertIsNone(taxii.parse_us(bad), bad)


try:
    import taxii2client.v21 as t21
    import stix2
except Exception:
    t21 = stix2 = None


class RunningServer:
    """The real app behind a real socket, so an independent client can use it."""

    def __init__(self, app):
        import uvicorn
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
        self.thread = threading.Thread(target=lambda: self.server.run(sockets=[self.sock]), daemon=True)

    def __enter__(self):
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(5)
        self.sock.close()


@unittest.skipUnless(t21, "taxii2-client and stix2 not installed (pip install -r requirements-dev.txt)")
class RealClientTests(unittest.TestCase):
    """taxii2-client is the reference Python client, written by the TAXII authors' community.
    If it can discover, list, page and fetch, and stix2 accepts every object, a platform
    built on either will too."""

    @classmethod
    def setUpClass(cls):
        cls.app, cls.feeds, cls.store = make()
        cls.running = RunningServer(cls.app)
        cls.running.__enter__()
        cls.url = f"http://127.0.0.1:{cls.running.port}/taxii2/"

    @classmethod
    def tearDownClass(cls):
        cls.running.__exit__()
        cls.store.close()

    def server(self):
        return t21.Server(self.url, user="", password="", verify=False)

    def test_discovery_to_objects(self):
        srv = self.server()
        self.assertEqual(srv.title, "Uninvited TAXII server")
        self.assertEqual(len(srv.api_roots), 1)
        root = srv.api_roots[0]
        self.assertEqual(root.versions, [taxii.MEDIA])
        self.assertEqual({c.title for c in root.collections}, {taxii.COLLECTIONS[s][0] for s in taxii.STEMS})
        week = next(c for c in root.collections if c.title == taxii.COLLECTIONS["attackers-7d"][0])
        self.assertTrue(week.can_read and not week.can_write)
        env = week.get_objects()
        self.assertEqual(len(env["objects"]), len(samples.rows()) + 1)
        self.assertEqual(env["more"], False)

    def test_every_object_is_valid_stix(self):
        week = self.server().api_roots[0].collections[1]
        env = week.get_objects()
        parsed = [stix2.parse(o, allow_custom=False, version="2.1") for o in env["objects"]]
        self.assertEqual(sorted({p["type"] for p in parsed}), ["identity", "indicator"])
        patterns = {p["pattern"] for p in parsed if p["type"] == "indicator"}
        self.assertIn("[ipv4-addr:value = '198.51.100.20']", patterns)
        self.assertIn("[ipv6-addr:value = '2001:db8::7']", patterns)

    def test_the_client_pages_through_with_next(self):
        from taxii2client.v21 import as_pages
        week = self.server().api_roots[0].collections[1]
        ids = []
        for page in as_pages(week.get_objects, per_request=2):
            ids += [o["id"] for o in page["objects"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), len(samples.rows()) + 1)

    def test_manifest_and_single_object_and_filters(self):
        week = self.server().api_roots[0].collections[1]
        manifest = week.get_manifest()
        self.assertEqual(len(manifest["objects"]), len(samples.rows()) + 1)
        indicator = next(m["id"] for m in manifest["objects"] if m["id"].startswith("indicator--"))
        one = week.get_object(indicator)
        self.assertEqual([o["id"] for o in one["objects"]], [indicator])
        only = week.get_objects(type="identity")
        self.assertEqual([o["type"] for o in only["objects"]], ["identity"])
        later = week.get_objects(added_after="2030-01-01T00:00:00Z")
        self.assertEqual(later.get("objects", []), [])

    def test_a_read_only_collection_refuses_an_add(self):
        week = self.server().api_roots[0].collections[1]
        with self.assertRaises(Exception):
            week.add_objects({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": []})


if __name__ == "__main__":
    unittest.main()
