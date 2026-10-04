"""TLS client fingerprints: JA3 against the reference implementation on real hellos, and everything
a hostile first record could do to the parser."""
import json
import random
import unittest
from pathlib import Path

from uninvited import tlsfp

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "ja3_cases.json").read_text(encoding="utf-8"))
CASES = FIXTURE["cases"]


class ReferenceTests(unittest.TestCase):
    def test_every_real_hello_matches_the_reference_implementation(self):
        self.assertGreaterEqual(len(CASES), 7)
        for name, case in CASES.items():
            with self.subTest(name):
                hello = tlsfp.parse_client_hello(bytes.fromhex(case["record_hex"]))
                self.assertIsNotNone(hello)
                self.assertEqual(tlsfp.ja3_string(hello), case["ja3_string"])
                self.assertEqual(tlsfp.ja3(hello), case["ja3"])

    def test_the_server_name_is_read(self):
        for name, case in CASES.items():
            with self.subTest(name):
                self.assertEqual(tlsfp.parse_client_hello(bytes.fromhex(case["record_hex"])).sni, case["sni"])

    def test_different_stacks_have_different_fingerprints(self):
        digests = {c["ja3"] for c in CASES.values()}
        self.assertEqual(len(digests), len({c["ja3_string"] for c in CASES.values()}))
        self.assertGreaterEqual(len(digests), 5)         # Python, Schannel and OpenSSL do not look alike
        # the server name is not part of the fingerprint: the same client with and without one differs only by extensions
        a, b = CASES["python-default"], CASES["python-alpn-no-sni"]
        self.assertNotEqual(a["ja3"], b["ja3"])

    def test_alpn_and_supported_versions(self):
        h = tlsfp.parse_client_hello(bytes.fromhex(CASES["python-alpn-no-sni"]["record_hex"]))
        self.assertEqual(h.alpn, ["h2", "http/1.1"])
        self.assertIn(0x0304, h.versions)                      # TLS 1.3 offered
        h12 = tlsfp.parse_client_hello(bytes.fromhex(CASES["python-tls12-only"]["record_hex"]))
        self.assertNotIn(0x0304, h12.versions)

    def test_grease_values_are_dropped_from_the_string(self):
        h = tlsfp.ClientHello(version=771, ciphers=[0x0A0A, 4865, 0xFAFA, 4866], extensions=[0x1A1A, 0, 10],
                              groups=[0x2A2A, 29], point_formats=[0])
        self.assertEqual(tlsfp.ja3_string(h), "771,4865-4866,0-10,29,0")


def hello_bytes(name="python-default"):
    return bytes.fromhex(CASES[name]["record_hex"])


class FramingTests(unittest.TestCase):
    def test_what_looks_like_tls(self):
        self.assertTrue(tlsfp.looks_like_tls(b"\x16\x03\x01"))
        for bad in (b"", b"\x16", b"\x16\x02", b"GET / HTTP/1.1", b"\x80\x2e\x01", b"\x15\x03\x01"):
            self.assertFalse(tlsfp.looks_like_tls(bad), bad)

    def test_record_length_comes_from_the_header_and_is_bounded(self):
        data = hello_bytes()
        self.assertEqual(tlsfp.record_length(data[:5]), len(data))
        self.assertIsNone(tlsfp.record_length(b"\x16\x03\x01\x00\x01"))             # too small to be a hello
        self.assertIsNone(tlsfp.record_length(b"\x16\x03\x01\xff\xff"))             # larger than anything read
        self.assertIsNone(tlsfp.record_length(b"\x16\x03\x01"))                     # header cut short
        self.assertIsNone(tlsfp.record_length(b"GET /\r\n"))


class HostileInputTests(unittest.TestCase):
    def test_every_truncation_is_handled(self):
        for name, case in CASES.items():
            data = bytes.fromhex(case["record_hex"])
            for cut in range(len(data)):
                tlsfp.parse_client_hello(data[:cut])                  # must not raise

    def test_mutated_hellos_never_raise(self):
        rnd = random.Random(3)
        for _ in range(4000):
            data = bytearray(hello_bytes(rnd.choice(list(CASES))))
            for _ in range(rnd.randrange(1, 8)):
                data[rnd.randrange(len(data))] = rnd.randrange(256)
            if rnd.random() < 0.3:
                del data[rnd.randrange(len(data)):]
            h = tlsfp.parse_client_hello(bytes(data))
            if h:
                tlsfp.ja3(h)
                self.assertLessEqual(len(h.ciphers), tlsfp.MAX_ITEMS)
                self.assertLessEqual(len(h.extensions), tlsfp.MAX_ITEMS)

    def test_random_bytes_never_raise(self):
        rnd = random.Random(4)
        for _ in range(4000):
            data = b"\x16\x03" + bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 300)))
            tlsfp.parse_client_hello(data)

    def test_lengths_that_lie(self):
        data = bytearray(hello_bytes())
        data[3:5] = b"\xff\xff"                                    # the record claims 65535 bytes
        self.assertIsNotNone(tlsfp.parse_client_hello(bytes(data)))  # reads what is there, no more
        body = bytearray(hello_bytes())
        body[6:9] = b"\xff\xff\xff"                                 # the handshake claims 16 MB
        tlsfp.parse_client_hello(bytes(body))
        wrong_type = bytearray(hello_bytes())
        wrong_type[5] = 0x02                                        # a ServerHello, not a ClientHello
        self.assertIsNone(tlsfp.parse_client_hello(bytes(wrong_type)))

    def test_a_hostile_server_name_is_not_kept(self):
        base = hello_bytes("python-default")
        name = CASES["python-default"]["sni"].encode()
        for bad in (b"<script>alert(1)</script>", b"a" * 300, b"evil\r\nname", b"\xff\xfe\xfd", b"a b", b"-"):
            if len(bad) <= len(name):
                swapped = base.replace(name, bad.ljust(len(name), b"x")[:len(name)] if len(bad) == len(name) else bad)
                h = tlsfp.parse_client_hello(swapped)
                self.assertTrue(h is None or h.sni is None or tlsfp.HOST.match(h.sni))
        self.assertIsNone(tlsfp.HOST.match("<script>"))
        self.assertIsNone(tlsfp.HOST.match("evil\r\nname"))
        self.assertIsNone(tlsfp.HOST.match("a" * 300))
        self.assertIsNotNone(tlsfp.HOST.match("scanme.example.org"))

    def test_an_old_style_hello_is_not_a_tls_record_here(self):
        self.assertIsNone(tlsfp.parse_client_hello(b"\x80\x2e\x01\x03\x01" + bytes(60)))


if __name__ == "__main__":
    unittest.main()
