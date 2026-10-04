"""The pieces built on the night of 2026-10-03: heatmap, credential statistics, emerging items,
the notable-events Atom feed and the defender formats."""
import os
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

from fastapi.testclient import TestClient

from uninvited import defender, notables
from uninvited.app import Hub, build_app
from uninvited.core import Config, Knock
from uninvited.feeds import NAMES, FeedCache
from uninvited.store import Store

DAY = 86400


def knock(ts, proto="SSH", ip="203.0.113.7", user=None, pw=None, lines=(), detail=None, kind="attack"):
    k = Knock(proto=proto, ip=ip, port=22, ts=ts, username=user, password=pw, lines=list(lines), detail=dict(detail or {}))
    k.kind, k.country, k.iso = kind, "The Netherlands", "NL"
    return k


class HeatmapTests(unittest.TestCase):
    def test_counts_land_in_the_right_weekday_and_hour_split_by_kind(self):
        store = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
        # 2026-10-01 is a Thursday (weekday 3 with Monday first); 14:30 UTC
        ts = int(time.mktime(time.strptime("2026-10-01 14:30:00", "%Y-%m-%d %H:%M:%S"))) - time.timezone
        now = int(time.time())
        ts = ts if now - ts < 7 * DAY else now - 3600  # keep the test honest when it runs much later
        store.record(knock(ts))
        store.record(knock(ts + 60, ip="203.0.113.8", kind="research"))
        h = store.heatmap(7)
        wd = (time.gmtime(ts).tm_wday)
        hr = time.gmtime(ts).tm_hour
        self.assertEqual(h["attack"][wd][hr], 1)
        self.assertEqual(h["research"][wd][hr], 1)
        self.assertEqual(sum(map(sum, h["attack"])), 1)
        self.assertEqual(len(h["attack"]), 7)
        self.assertTrue(all(len(row) == 24 for row in h["attack"]))
        store.close()


class CredStatTests(unittest.TestCase):
    def test_the_shape_of_the_passwords_and_never_the_passwords(self):
        store = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
        now = int(time.time())
        for i, pw in enumerate(["123456", "123456", "Admin2024", "p@ss", "", "letmein"]):
            store.record(knock(now - i, ip=f"203.0.113.{i + 1}", user="root", pw=pw))
        s = store.cred_stats()
        self.assertEqual(s["tries"], 6)
        self.assertEqual(s["distinct"], 5)
        self.assertEqual(s["digits_only"], 33.3)
        self.assertEqual(s["with_upper"], 16.7)
        self.assertEqual(s["with_symbol"], 16.7)
        self.assertEqual(s["ends_with_year"], 16.7)
        self.assertEqual(s["empty"], 16.7)
        self.assertEqual(s["length_share"][6], 33.3)
        self.assertNotIn("123456", str(s))
        store.close()


class EmergingTests(unittest.TestCase):
    def test_only_what_is_new_this_week_and_tried_by_two_hosts(self):
        store = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
        now = int(time.time())
        old = now - 10 * DAY
        # known for weeks
        store.record(knock(old, proto="HTTP", ip="198.51.100.1", lines=[("exploit", "WordPress Probe"), ("path", "/wp-login.php")]))
        store.record(knock(now - 100, proto="HTTP", ip="198.51.100.2", lines=[("exploit", "WordPress Probe"), ("path", "/wp-login.php")]))
        store.record(knock(now - 90, proto="HTTP", ip="198.51.100.3", lines=[("exploit", "WordPress Probe"), ("path", "/wp-login.php")]))
        # new this week, two hosts
        for ip in ("198.51.100.4", "198.51.100.5"):
            store.record(knock(now - 50, proto="HTTP", ip=ip, lines=[("exploit", "Fresh Thing RCE"), ("path", "/fresh")]))
            store.record(knock(now - 40, ip=ip, user="svc", pw="Fresh2026"))
        # new this week, one host only: not enough
        store.record(knock(now - 30, proto="HTTP", ip="198.51.100.6", lines=[("exploit", "Lonely Probe")]))
        # a generic probe name is not an exploit, however many hosts carry it
        for ip in ("198.51.100.20", "198.51.100.21", "198.51.100.22"):
            store.record(knock(now - 25, proto="HTTP", ip=ip, lines=[("exploit", "Root Fingerprint"), ("path", "/")]))
        # a research scanner never counts
        store.record(knock(now - 20, proto="HTTP", ip="198.51.100.7", lines=[("exploit", "Scanner Thing")], kind="research"))
        store.record(knock(now - 19, proto="HTTP", ip="198.51.100.8", lines=[("exploit", "Scanner Thing")], kind="research"))
        # an old favourite: tried long before the baseline window, quiet for a month, back this week.
        # It is in the all-time top 100 with more hits than this week's, so it is not "emerging".
        store.record(knock(now - 60 * DAY, ip="198.51.100.30", user="admin", pw="admin"))
        store.record(knock(now - 60 * DAY, ip="198.51.100.31", user="admin", pw="admin"))
        store.record(knock(now - 60 * DAY, ip="198.51.100.32", user="admin", pw="admin"))
        for ip in ("198.51.100.33", "198.51.100.34"):
            store.record(knock(now - 10, ip=ip, user="admin", pw="admin"))
        e = store.emerging(7)
        self.assertEqual([x["value"] for x in e["exploits"]], ["Fresh Thing RCE"])
        self.assertEqual(e["exploits"][0]["hosts"], 2)
        self.assertEqual([x["value"] for x in e["paths"]], ["/", "/fresh"])
        self.assertEqual([x["value"] for x in e["credentials"]], ["svc:Fresh2026"])
        # the boards tag Mirai's pairs for the credentials panel
        store.record(knock(now - 5, ip="198.51.100.40", user="root", pw="xc3511"))
        creds = {r["key"]: r for r in store.top("cred", "ALL", 50)}
        self.assertTrue(creds["root:xc3511"]["mirai"])
        self.assertFalse(creds["svc:Fresh2026"]["mirai"])
        self.assertNotIn("mirai", store.top("user", "ALL", 5)[0])
        store.close()


class AtomTests(unittest.TestCase):
    def test_the_feed_is_well_formed_and_carries_no_credentials(self):
        items = [{"id": "n1", "tag": "FIRST THIS WEEK", "kind": "ics", "ts": 1790000000,
                  "title": "PLC Stop sent to the S7 decoy <x>", "meta": "S7 · The Netherlands & more", "ip": "203.0.113.9", "count": 3},
                 {"id": "d1", "tag": "NEW DROPPER", "kind": "dropper", "ts": 1789990000,
                  "title": "A Mozi download was requested", "meta": "hxxp://45[.]33[.]32[.]7/Mozi[.]a · asked for by 2 hosts", "count": 2}]
        xml = notables.atom(items, "Uninvited", "example.org", 1790001000)
        root = ET.fromstring(xml)
        ns = {"a": "http://www.w3.org/2005/Atom"}
        entries = root.findall("a:entry", ns)
        self.assertEqual(len(entries), 2)
        self.assertIn("PLC Stop sent to the S7 decoy <x>", entries[0].find("a:title", ns).text)
        self.assertEqual(entries[0].find("a:link", ns).get("href"), "https://example.org/#ip=203.0.113.9")
        self.assertEqual(entries[1].find("a:link", ns).get("href"), "https://example.org/#intel-urls")
        self.assertIn("(3 times)", entries[0].find("a:summary", ns).text)


class DefenderFormatTests(unittest.TestCase):
    rows = [{"ip": "203.0.113.5", "score": 80, "tags": ["persistent", "ssh-bruteforce"]},
            {"ip": "2001:db8::1", "score": 60, "tags": []},
            {"ip": "198.51.100.9", "score": 130, "tags": ["web-exploit"]}]

    def test_nftables_file_fills_its_own_set_and_a_reload_replaces(self):
        """Loaded into a live kernel (nftables 1.0.9) on 2026-10-03: two lists went into two sets,
        a reload replaced the contents, and the chain and rule in the header ran as written. The
        earlier layout shared one set named bad, so loading a second list widened the first."""
        t = defender.nft_set("Uninvited", "example.org", "attackers-7d", self.rows, 1790000000)
        self.assertIn("table inet uninvited {\n\tset attackers_7d {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n}\n", t)
        self.assertIn("flush set inet uninvited attackers_7d\nadd element inet uninvited attackers_7d { 203.0.113.5, 198.51.100.9 }\n", t)
        self.assertNotIn("2001:db8::1", t)
        self.assertIn("#   nft add chain inet uninvited input '{ type filter hook input priority 0 ; policy accept ; }'", t)
        self.assertIn("#   nft add rule inet uninvited input ip saddr @attackers_7d drop", t)
        other = defender.nft_set("Uninvited", "example.org", "tag-persistent-7d", self.rows, 1790000000)
        self.assertIn("set persistent_7d {", other)
        self.assertNotIn("attackers_7d", other)

    def test_an_empty_list_still_empties_the_set(self):
        t = defender.nft_set("Uninvited", "example.org", "attackers-7d", [], 1790000000)
        self.assertNotIn("add element", t)
        self.assertTrue(t.endswith("flush set inet uninvited attackers_7d\n"))

    def test_zeek_intel_is_tab_separated_with_the_fields_header(self):
        t = defender.zeek_intel("Uninvited", "example.org", "attackers-7d", self.rows, 1790000000)
        lines = t.strip().split("\n")
        self.assertEqual(lines[0], "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url")
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(len(l.split("\t")) == 5 for l in lines[1:]))
        self.assertIn("2001:db8::1\tIntel::ADDR", t)   # Zeek takes v6 addresses too

    def test_suricata_iprep_clamps_the_score_and_lists_its_categories(self):
        self.assertEqual(defender.iprep_list("attackers-7d", self.rows), "203.0.113.5,1,80\n198.51.100.9,1,127\n")
        cats = defender.iprep_categories()
        self.assertIn("1,attackers-7d,", cats)
        self.assertIn("2,tag-persistent-7d,", cats)


class PublishedTests(unittest.TestCase):
    def test_the_new_files_are_served_and_the_endpoints_answer(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "t.db")
        cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
        store = Store(db)
        now = int(time.time())
        for i in range(4):
            store.record(knock(now - 10 * i, ip="203.0.113.44", user="root", pw=f"pw{i}"))
        store.record(knock(now - 5, proto="S7", ip="203.0.113.45", lines=[("function", "PLC Stop")], detail={"ics": "control"}))
        feeds = FeedCache(db)
        feeds.refresh()
        client = TestClient(build_app(cfg, store, Hub(cfg, store), feeds))
        for name in ("notable.atom", "attackers-7d.nft", "attackers-7d.zeek.intel", "attackers-7d.iprep.list",
                     "tag-persistent-7d.nft", "iprep-categories.txt"):
            self.assertIn(name, NAMES)
            r = client.get("/feed/" + name)
            self.assertEqual(r.status_code, 200, name)
        atom = client.get("/feed/notable.atom")
        self.assertTrue(atom.headers["content-type"].startswith("application/atom+xml"))
        self.assertIn("PLC Stop", atom.text)
        self.assertNotIn("pw0", atom.text)
        # whatever the 7 day list holds, the set file holds the same addresses
        listed = [l for l in client.get("/feed/attackers-7d.txt").text.split("\n") if l and l[0] != "#"]
        nft = client.get("/feed/attackers-7d.nft").text
        self.assertIn(f"# {len(listed)} IPv4 addresses", nft)
        for ip in listed:
            self.assertIn(ip, nft)
        for path in ("/api/heatmap?days=7", "/api/credstats", "/api/emerging?days=7"):
            self.assertEqual(client.get(path).status_code, 200, path)
        self.assertEqual(client.get("/api/heatmap?days=99").status_code, 422)
        self.assertEqual(client.get("/api/credstats").json()["tries"], 4)
        store.close()


if __name__ == "__main__":
    unittest.main()
