import json
import os
import tempfile
import time
import unittest

from uninvited import intel
from uninvited.core import Knock
from uninvited.feeds import FeedCache
from uninvited.store import Store


class ModbusTagTests(unittest.TestCase):
    def test_write_earns_ics_write_and_the_command_technique(self):
        tags = intel.behaviour_tags({"MODBUS": 3}, {}, [], 0, {"write": 3})
        self.assertIn("ics-write", tags)
        self.assertNotIn("ics-recon", tags)
        techniques, _ = intel.tags({"MODBUS": 3}, {}, {"write": 3})
        self.assertEqual(techniques, ["T1692.001"])

    def test_reads_earn_recon_and_discovery_techniques(self):
        ics = {"read": 2, "identity": 1}
        tags = intel.behaviour_tags({"MODBUS": 3}, {}, [], 0, ics)
        self.assertIn("ics-recon", tags)
        self.assertNotIn("ics-write", tags)
        techniques, _ = intel.tags({"MODBUS": 3}, {}, ics)
        self.assertEqual(techniques, ["T0801", "T0888"])

    def test_both_behaviours_carry_both_tags(self):
        tags = intel.behaviour_tags({"MODBUS": 4}, {}, [], 0, {"read": 2, "write": 2})
        self.assertIn("ics-recon", tags)
        self.assertIn("ics-write", tags)

    def test_without_detail_it_is_recon(self):
        self.assertIn("ics-recon", intel.behaviour_tags({"MODBUS": 3}, {}, [], 0))

    def test_no_engaged_modbus_no_tag(self):
        tags = intel.behaviour_tags({"MODBUS": 0, "SSH": 2}, {}, [], 0)
        self.assertNotIn("ics-write", tags)
        self.assertNotIn("ics-recon", tags)

    def test_every_tag_and_technique_is_described(self):
        for tag in intel.behaviour_tags(
                {"SSH": 1, "TNET": 1, "FTP": 1, "SMTP": 1, "RDP": 1, "SMB": 1,
                 "SIP": 1, "MODBUS": 1, "HTTP": 1}, {"X": 1}, ["CVE-1"], 9 * 86400,
                {"write": 1, "read": 1}):
            self.assertIn(tag, intel.TAG_DESCRIPTIONS)
        for t in intel.ICS_TECHNIQUES:
            self.assertIn(t, intel.TECHNIQUES)


class FeedEndToEnd(unittest.TestCase):
    """Real Store, real FeedCache, a public address, Modbus events."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)

    def knock(self, ip, ics, n, scan=False):
        for i in range(n):
            k = Knock(proto="MODBUS", ip=ip, port=40000 + i, ts=int(time.time()) - i,
                      lines=[("function", "x")],
                      detail={"fc": 6, "ics": ics, "write": ics == "write", "scan": scan})
            self.store.record(k)

    def rows(self):
        cache = FeedCache(self.db)
        cache.refresh()
        doc = json.loads(cache.get("attackers-24h.json").body)
        return {r["ip"]: r for r in doc["indicators"]}

    def test_writer_is_listed_with_ics_tag_and_technique(self):
        self.knock("93.184.216.34", "write", 3)
        row = self.rows()["93.184.216.34"]
        self.assertIn("ics-write", row["tags"])
        self.assertIn("T1692.001", row["attack_techniques"])
        self.assertIn("MODBUS", row["protocols"])

    def test_reader_is_listed_as_recon(self):
        self.knock("93.184.216.35", "read", 3)
        row = self.rows()["93.184.216.35"]
        self.assertIn("ics-recon", row["tags"])
        self.assertNotIn("ics-write", row["tags"])

    def test_bare_connections_do_not_list(self):
        self.knock("93.184.216.36", "", 5, scan=True)
        self.assertNotIn("93.184.216.36", self.rows())

    def test_stix_marks_ics_techniques_with_the_ics_source(self):
        self.knock("93.184.216.34", "write", 3)
        cache = FeedCache(self.db)
        cache.refresh()
        text = cache.get("attackers-24h.stix.json").body.decode()
        self.assertIn("mitre-ics-attack", text)
        self.assertIn("T1692.001", text)


if __name__ == "__main__":
    unittest.main()
