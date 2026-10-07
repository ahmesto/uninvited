"""What the feed publishes, byte for byte. The reference files were captured from the code
before the STIX builder moved into stix.py, so a refactor that changes a published byte
fails here. Regenerate them only on purpose, and say so in the changelog (feeds.CHANGELOG)."""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # for `samples`, however the tests are started

import samples
from uninvited.feeds import FeedCache

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cache = FeedCache(":memory:", ident=samples.LIVE)

    def test_the_stix_bundle_is_unchanged(self):
        body = self.cache._stix(168, samples.rows()).body
        self.assertEqual(body, (FIXTURES / "stix_bundle_reference.json").read_bytes())

    def test_the_csv_is_unchanged(self):
        body = self.cache._csv(samples.rows()).body
        self.assertEqual(body, (FIXTURES / "csv_reference.csv").read_bytes())

    def test_the_misp_files_are_unchanged(self):
        for name, snap in self.cache._misp(168, samples.rows(), samples.NOW).items():
            ref = FIXTURES / ("misp_" + name.replace("/", "_"))
            self.assertEqual(snap.body, ref.read_bytes(), name)

    def test_the_bundle_is_valid_json_with_one_identity_and_one_indicator_per_host(self):
        doc = json.loads(self.cache._stix(168, samples.rows()).body)
        kinds = [o["type"] for o in doc["objects"]]
        self.assertEqual(kinds[0], "identity")
        self.assertEqual(kinds.count("indicator"), len(samples.rows()))
        # every technique a host showed is an attack-pattern the indicator points at, each defined once
        by_id = {o["id"]: o for o in doc["objects"]}
        self.assertEqual(len(by_id), len(doc["objects"]))
        for r in samples.rows():
            ind = next(o for o in doc["objects"] if o["type"] == "indicator" and o["name"] == r["ip"])
            pointed = {by_id[o["target_ref"]]["external_references"][0]["external_id"]
                       for o in doc["objects"] if o["type"] == "relationship" and o["source_ref"] == ind["id"]}
            self.assertEqual(pointed, set(r["techniques"]), r["ip"])


if __name__ == "__main__":
    unittest.main()
