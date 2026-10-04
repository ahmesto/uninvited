"""Who the site says it is comes from the config, and a fresh install claims nobody's name."""
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from uninvited.app import Hub, build_app
from uninvited.configcheck import check
from uninvited.core import Config, Knock
from uninvited.feeds import FeedCache
from uninvited.identity import Identity
from uninvited.store import Store

ROOT = Path(__file__).resolve().parent.parent
OWNER = {"url": "https://feeds.example.net/", "title": "Doorstep", "owner": "Jane Doe",
         "owner_title": "Analyst", "owner_url": "https://example.net"}


def client(site):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": site})
    store = Store(db)
    k = Knock(proto="SSH", ip="45.33.32.40", port=22, ts=1_790_000_000, username="root", password="x")
    k.kind = "attack"
    store.record(k)
    feeds = FeedCache(db, ident=Identity.from_cfg(cfg))
    feeds.refresh()
    return TestClient(build_app(cfg, store, Hub(cfg, store), feeds)), store


class IdentityTests(unittest.TestCase):
    def test_a_fresh_install_names_example_org_and_credits_nobody(self):
        c, store = client({})
        try:
            page = c.get("/").text
            self.assertIn('href="https://example.org/"', page)
            self.assertNotIn("Designed and run by", page)
            self.assertNotIn("ahmadmesto", page)
            self.assertNotIn("{{", page)                          # every placeholder is filled
            self.assertIn("(example.org)", c.get("/feed/attackers-24h.txt").text)
        finally:
            store.close()

    def test_every_published_place_follows_the_config(self):
        c, store = client(OWNER)
        try:
            page = c.get("/").text
            self.assertIn('href="https://feeds.example.net/"', page)
            self.assertIn("<title>Doorstep", page)
            self.assertIn("DOORSTEP</span>", page)
            self.assertIn('Designed and run by <a href="https://example.net">Jane Doe</a>, Analyst', page)
            self.assertIn('<a class="cv" href="https://example.net">example.net &rarr;</a>', page)
            self.assertIn("# Doorstep feed: attacking hosts (feeds.example.net)", c.get("/feed/attackers-24h.txt").text)
            self.assertIn('"name": "Doorstep (feeds.example.net)"', c.get("/feed/attackers-7d.stix.json").text)
            self.assertIn("Sitemap: https://feeds.example.net/sitemap.xml", c.get("/robots.txt").text)
            self.assertIn("https://feeds.example.net/week", c.get("/sitemap.xml").text)
            self.assertIn("Jane Doe", c.get("/ip/45.33.32.40").text)
            frames = [v for k, v in c.get("/").headers.multi_items() if k == "content-security-policy" and "frame" in v]
            self.assertEqual(frames, ["frame-ancestors 'self' https://example.net https://www.example.net"])
        finally:
            store.close()

    def test_the_published_identifiers_follow_the_address_only(self):
        a = Identity(site="feeds.example.net")
        self.assertEqual(a.ns, Identity(site="feeds.example.net", brand="Other", owner="Someone").ns)
        self.assertNotEqual(a.ns, Identity().ns)

    def test_address_pages_are_never_indexed(self):
        c, store = client(OWNER)
        try:
            for ip in ("45.33.32.40", "45.33.32.99"):            # on record, and never seen
                r = c.get(f"/ip/{ip}")
                self.assertEqual(r.headers.get("x-robots-tag"), "noindex")
                self.assertIn('<meta name="robots" content="noindex">', r.text)
        finally:
            store.close()

    def test_the_config_check_refuses_an_identity_that_could_break_the_page(self):
        ssh = {"services": [{"proto": "SSH", "port": 2222}]}
        for bad, why in (({"title": 'Evil"</script>'}, "site.title"), ({"url": "not a host"}, "site.url"),
                         ({"owner_url": "http://example.net"}, "site.owner_url"), ({"owner": "<b>me</b>"}, "site.owner")):
            errors, _ = check({**ssh, "site": bad})
            self.assertTrue(any(why in e for e in errors), (bad, errors))
        errors, warnings = check(ssh)
        self.assertEqual(errors, [])
        self.assertTrue(any("example.org" in w for w in warnings))

    def test_the_page_file_names_no_one(self):
        raw = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        for name in ("ahmadmesto", "Ahmad Mesto", "Uninvited", "UNINVITED"):
            self.assertNotIn(name, raw)


if __name__ == "__main__":
    unittest.main()
