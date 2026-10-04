"""The MISP feed: what a MISP server needs to fill its ATT&CK, vulnerability and ageing views,
and to remove an address that left the list. Checked against a stock MISP 2.5.48 import on
2026-10-03; these tests keep the shape that import accepted."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import samples
from uninvited import intel
from uninvited.feeds import FeedCache


def event(cache, rows=None, now=samples.NOW):
    files = cache._misp(168, samples.rows() if rows is None else rows, now)
    name = next(n for n in files if n.endswith(".json") and n != "misp/manifest.json")
    return json.loads(files[name].body)["Event"], files


class MispTests(unittest.TestCase):
    def setUp(self):
        self.cache = FeedCache(":memory:", ident=samples.LIVE)

    def test_every_address_carries_its_times_score_and_galaxy_tags(self):
        ev, _ = event(self.cache)
        ips = [a for a in ev["Attribute"] if a["type"] == "ip-src"]
        self.assertEqual(len(ips), len(samples.rows()))
        for a in ips:
            self.assertRegex(a["first_seen"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000000\+00:00$")
            self.assertLessEqual(a["first_seen"], a["last_seen"])
            names = [t["name"] for t in a["Tag"]]
            self.assertTrue(any(n.startswith('uninvited:score="') for n in names), names)
            for n in names:
                if n.startswith("misp-galaxy:"):
                    self.assertIn(n.split('"')[1], intel.MISP_ATTACK.values())
        rdp = next(a for a in ips if a["value"] == "198.51.100.22")
        self.assertIn('misp-galaxy:mitre-attack-pattern="Remote Desktop Protocol - T1021.001"', [t["name"] for t in rdp["Tag"]])
        # every tag has a colour: MISP logs a PHP warning for each one without
        for t in ev["Tag"] + [t for a in ips for t in a["Tag"]]:
            self.assertRegex(t.get("colour", ""), r"^#[0-9a-f]{6}$", t["name"])

    def test_the_event_carries_every_technique_once_and_its_build_time(self):
        ev, files = event(self.cache)
        galaxy = [t["name"] for t in ev["Tag"] if t["name"].startswith("misp-galaxy:")]
        self.assertEqual(len(galaxy), len(set(galaxy)))
        self.assertIn('misp-galaxy:mitre-attack-pattern="Command Message - T1692.001"', galaxy)
        self.assertEqual(ev["timestamp"], str(samples.NOW))
        manifest = json.loads(files["misp/manifest.json"].body)
        self.assertEqual(manifest[ev["uuid"]]["timestamp"], str(samples.NOW))

    def test_a_cve_tried_is_a_vulnerability_attribute(self):
        ev, files = event(self.cache)
        vulns = [a for a in ev["Attribute"] if a["type"] == "vulnerability"]
        self.assertEqual([v["value"] for v in vulns], ["CVE-2021-36260"])
        self.assertFalse(vulns[0]["to_ids"])
        self.assertIn("198.51.100.21", vulns[0]["comment"])
        hashes = files["misp/hashes.csv"].body.decode().split()
        self.assertEqual(len(hashes), len(samples.rows()) + 1)            # every live value, nothing deleted

    def test_an_address_that_left_the_list_is_sent_deleted(self):
        rows = samples.rows()
        self.cache.history.update({"attackers-7d": {r["ip"] for r in rows}}, samples.NOW - 600)
        ev, files = event(self.cache, rows[1:])                         # the first host left
        gone = [a for a in ev["Attribute"] if a.get("deleted")]
        self.assertEqual([a["value"] for a in gone], [rows[0]["ip"]])
        live_uuid = next(a["uuid"] for a in event(FeedCache(":memory:", ident=samples.LIVE))[0]["Attribute"]
                         if a["value"] == rows[0]["ip"])
        self.assertEqual(gone[0]["uuid"], live_uuid)                     # the same attribute, so MISP removes it
        self.assertNotIn(rows[0]["ip"].encode(), files["misp/hashes.csv"].body)
        # once it is back, it is live again
        self.cache.history.update({"attackers-7d": {r["ip"] for r in rows[1:]}}, samples.NOW - 300)
        ev, _ = event(self.cache, rows)
        self.assertFalse(any(a.get("deleted") for a in ev["Attribute"]))

    def test_a_timestamp_moves_only_when_its_attribute_changed(self):
        """MISP replaces an attribute only when its timestamp is newer than its own copy. Stamping
        last activity left 1,074 of 1,098 hosts without their new fields in a real MISP."""
        first, _ = event(self.cache, now=samples.NOW)
        again, files = event(self.cache, now=samples.NOW + 300)
        self.assertEqual([a["timestamp"] for a in first["Attribute"]], [a["timestamp"] for a in again["Attribute"]])
        self.assertEqual(again["timestamp"], str(samples.NOW))            # nothing changed, nothing to fetch
        rows = samples.rows()
        rows[2] = {**rows[2], "score": rows[2]["score"] + 10}              # one host's score moved
        later, files = event(self.cache, rows, now=samples.NOW + 600)
        moved = [a["value"] for a, b in zip(first["Attribute"], later["Attribute"]) if a["timestamp"] != b["timestamp"]]
        self.assertEqual(moved, [rows[2]["ip"]])
        self.assertEqual(later["timestamp"], str(samples.NOW + 600))
        self.assertEqual(json.loads(files["misp/manifest.json"].body)[later["uuid"]]["timestamp"], later["timestamp"])

    def test_the_galaxy_names_are_mapped_for_every_technique_the_feed_emits(self):
        self.assertEqual(set(intel.MISP_ATTACK), set(intel.TECHNIQUES))


if __name__ == "__main__":
    unittest.main()
