"""An address a stranger types is an address and nothing more.

Python reads "2001:db8::1%anything" as an IPv6 address with a zone and gives the zone back, so
before 2026-10-03 the text after the % reached the address page, the share card and the report
table, and from there the owner's terminal. These tests keep that door shut.
"""
import os
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from uninvited import app as webapp
from uninvited.app import Hub, build_app, parse_addr
from uninvited.core import Config
from uninvited.feeds import FeedCache
from uninvited.store import Store

ROOT = Path(__file__).resolve().parent.parent
ESC = "\x1b"
ZONED = "2606:4700::1%" + ESC + "[2J" + ESC + "[31mnot an address"


def make_client():
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "t.db")
    cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}], "site": {}})
    store = Store(db)
    feeds = FeedCache(db)
    feeds.refresh()
    return TestClient(build_app(cfg, store, Hub(cfg, store), feeds)), store, db


class ParseTests(unittest.TestCase):
    def test_plain_addresses_are_read(self):
        self.assertEqual(str(parse_addr("45.33.32.20")), "45.33.32.20")
        self.assertEqual(str(parse_addr("  2606:4700::1 ")), "2606:4700::1")

    def test_a_zone_is_refused_whatever_follows_it(self):
        for text in ("2606:4700::1%eth0", "fe80::1%1", "2606:4700::1% any words you like", ZONED, "45.33.32.20%x"):
            self.assertIsNone(parse_addr(text), text)

    def test_an_ipv4_address_written_as_ipv6_is_the_ipv4_address(self):
        self.assertEqual(str(parse_addr("::ffff:45.33.32.20")), "45.33.32.20")
        self.assertTrue(parse_addr("::ffff:127.0.0.1").is_loopback)
        self.assertTrue(parse_addr("::ffff:10.0.0.5").is_private)

    def test_anything_else_is_not_an_address(self):
        for text in ("", "not-an-address", "45.33.32", "45.33.32.20/32", "1.2.3.4 5.6.7.8"):
            self.assertIsNone(parse_addr(text), text)


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store, cls.db = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_the_address_page_and_its_card_refuse_a_zone(self):
        for path in ("/ip/2606:4700::1%25%20any%20words%20you%20like", "/ip/2606:4700::1%25eth0"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 400, path)
            self.assertNotIn("any words", r.text)
            self.assertEqual(self.client.get(path + "/card.png").status_code, 400, path)

    def test_the_lookup_refuses_a_zone(self):
        r = self.client.get("/api/lookup", params={"ip": "2606:4700::1%x"})
        self.assertEqual(r.status_code, 400)

    def test_a_report_with_a_zone_is_refused_and_nothing_is_stored(self):
        r = self.client.post("/api/report", json={"ip": ZONED, "note": "hello"})
        self.assertEqual(r.status_code, 400)
        rows = sqlite3.connect(self.db).execute("SELECT ip FROM reports").fetchall()
        self.assertFalse([ip for (ip,) in rows if "%" in ip or ESC in ip])

    def test_a_report_keeps_only_the_address_and_a_note_without_control_characters(self):
        r = self.client.post("/api/report", json={"ip": "::ffff:45.33.32.77", "note": "wrong" + ESC + "[2J\x9b31m entry"})
        self.assertEqual(r.status_code, 200)
        ip, note = sqlite3.connect(self.db).execute(
            "SELECT ip, note FROM reports WHERE ip = '45.33.32.77'").fetchone()
        self.assertEqual(ip, "45.33.32.77")
        self.assertFalse([c for c in note if not c.isprintable()], repr(note))

    def test_no_schema_or_documentation_page_is_served(self):
        for path in ("/openapi.json", "/docs", "/redoc"):
            self.assertEqual(self.client.get(path).status_code, 404, path)


class PortCheckTests(unittest.TestCase):
    """The port check connects out from the honeypot's own line, so the only thing it may ever
    probe is a public address, however the address is written."""

    @classmethod
    def setUpClass(cls):
        cls.client, cls.store, _ = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def check(self, visitor: str):
        probed = []

        async def probe(ip, port, timeout=1.2):
            probed.append(ip)
            return False

        with mock.patch.object(webapp, "client_ip", return_value=visitor), \
                mock.patch.object(webapp, "probe_port", probe):
            return self.client.get("/api/portcheck").json(), probed

    def test_nothing_but_a_public_address_is_probed(self):
        for visitor in ("10.0.0.5", "127.0.0.1", "::1", "169.254.1.1", "100.64.0.1", "224.0.0.1", "fe80::1",
                        "::ffff:127.0.0.1", "::ffff:10.0.0.5", "2606:4700::1%eth0", "not-an-address"):
            body, probed = self.check(visitor)
            self.assertIn("error", body, visitor)
            self.assertEqual(probed, [], visitor)

    def test_a_public_address_is_probed_under_its_plain_form(self):
        body, probed = self.check("::ffff:45.33.32.21")
        self.assertEqual(body["ip"], "45.33.32.21")
        self.assertEqual(set(probed), {"45.33.32.21"})
        self.assertEqual(len(probed), len(webapp.CHECK_PORTS))


class VisitorAddressTests(unittest.TestCase):
    """The limits and the port check are per visitor, so who the visitor is comes from the
    connection, or from the proxy on this machine, and from nobody else."""

    @staticmethod
    def request(peer: str, **headers):
        return types.SimpleNamespace(client=types.SimpleNamespace(host=peer), headers=headers)

    def test_a_direct_connection_cannot_name_another_address(self):
        r = self.request("198.51.100.7", **{"cf-connecting-ip": "203.0.113.1", "x-forwarded-for": "203.0.113.2"})
        self.assertEqual(webapp.client_ip(r), "198.51.100.7")

    def test_the_proxy_on_this_machine_is_believed(self):
        for peer in ("127.0.0.1", "::1"):
            self.assertEqual(webapp.client_ip(self.request(peer, **{"cf-connecting-ip": "203.0.113.1"})), "203.0.113.1")
            self.assertEqual(webapp.client_ip(self.request(peer)), peer)


class ReportReaderTests(unittest.TestCase):
    def test_a_stored_escape_sequence_never_reaches_the_terminal(self):
        """Rows written before the fix may still hold one, and the reader runs in the owner's shell."""
        _, store, db = make_client()
        store.add_report(ZONED, "note" + ESC + "]0;title\x07 with " + chr(0x202E) + " an override", "203.0.113.9")
        store.close()
        out = subprocess.run([sys.executable, str(ROOT / "deploy" / "reports.py"), "--db", db],
                             capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("2606:4700::1%", out.stdout)
        self.assertIn("not an address", out.stdout)
        body = out.stdout.replace("\n", "")
        self.assertFalse([c for c in body if not c.isprintable()], repr(out.stdout))


if __name__ == "__main__":
    unittest.main()
