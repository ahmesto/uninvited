"""The real app, over HTTP: security headers, HEAD, CORS, site files, the 404 page.

Needs httpx (pip install httpx), which Starlette's test client uses.
"""
import datetime as dt
import os
import re
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from fastapi.testclient import TestClient

from uninvited import hardening, sitefiles
from uninvited.app import Hub, build_app
from uninvited.core import Config
from uninvited.feeds import FeedCache
from uninvited.store import Store

ROOT = Path(__file__).resolve().parent.parent
PAGE = (Path(__file__).resolve().parent.parent / "static" / "index.html").read_text(encoding="utf-8")


def make_client(site=None):
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "t.db")
    cfg = Config({"database": db, "services": [{"proto": "SSH", "port": 22}],
                  "site": site or {}})
    store = Store(db)
    feeds = FeedCache(db)
    feeds.refresh()
    app = build_app(cfg, store, Hub(cfg, store), feeds)
    return TestClient(app), store


class HeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_every_kind_of_response_carries_the_browser_security_headers(self):
        for path in ("/", "/feed/index.json", "/api/stats", "/robots.txt", "/favicon.svg", "/no-such-page"):
            r = self.client.get(path)
            for name in hardening.BASE_HEADERS:
                self.assertIn(name, r.headers, f"{name} missing on {path}")
            self.assertEqual(r.headers["x-content-type-options"], "nosniff")
            self.assertTrue(r.headers["strict-transport-security"].startswith("max-age="))

    def test_html_gets_a_csp_and_json_does_not(self):
        html = self.client.get("/")
        self.assertIn("frame-ancestors", html.headers["content-security-policy"])
        self.assertIn("default-src 'self'", html.headers["content-security-policy-report-only"])
        api = self.client.get("/api/stats")
        self.assertNotIn("content-security-policy", api.headers)
        self.assertNotIn("content-security-policy-report-only", api.headers)

    def test_the_page_loads_nothing_from_a_third_party(self):
        """Fonts, flags, the coastline and the topojson client are served from static/vendor
        (2026-10-03), so the policy names no CDN and a blocker cannot blank the page. A host the
        page used but the policy omitted would break the page the day the policy is enforced."""
        hosts = set(re.findall(r'(?:src|href)="https://([a-z0-9.\-]+)/', PAGE))
        hosts |= set(re.findall(r'loadLand\("https://([a-z0-9.\-]+)/', PAGE))
        hosts |= set(re.findall(r"'src=\"https://([a-z0-9.\-]+)/", PAGE))
        hosts -= {"dmz.ahmadmesto.com", "ahmadmesto.com", "www.w3.org"}
        self.assertEqual(hosts, set(), f"the page still loads from {hosts}")
        for cdn in ("cdn.jsdelivr.net", "fonts.googleapis.com", "fonts.gstatic.com", "flagcdn.com"):
            self.assertNotIn(cdn, hardening.CSP_FULL)
        for path in ("/static/vendor/jetbrains-mono.css", "/static/vendor/topojson-client.min.js",
                     "/static/vendor/land-110m.json", "/static/vendor/flags/", "/static/vendor/land-50m.json"):
            self.assertIn(path, PAGE, path)
        vendor = ROOT / "static" / "vendor"
        self.assertTrue((vendor / "fonts" / "jetbrains-mono-700-latin.woff2").exists())
        self.assertGreater(len(list((vendor / "flags").glob("*.png"))), 240)
        r = self.client.get("/static/vendor/flags/nl.png")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get("cache-control"), "public, max-age=604800")

    def test_bundled_assets_ship_with_their_license_texts(self):
        """The font is under the OFL and the two map pieces under ISC. Both ask that the license
        text travels with every copy, and a public repository is a copy."""
        licenses = ROOT / "static" / "vendor" / "licenses"
        notices = (ROOT / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8")
        for name, holds in (("JetBrainsMono-OFL.txt", "SIL OPEN FONT LICENSE Version 1.1"),
                            ("topojson-client-LICENSE.txt", "this permission notice appear in all copies"),
                            ("world-atlas-LICENSE.txt", "this permission notice appear in all copies")):
            self.assertIn(holds, " ".join((licenses / name).read_text(encoding="utf-8").split()), name)
            self.assertIn(f"static/vendor/licenses/{name}", notices, name)
            self.assertEqual(self.client.get(f"/static/vendor/licenses/{name}").status_code, 200, name)
        self.assertIn("THIRD-PARTY-NOTICES.md", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_clickjacking_policy_names_the_owners_own_site_and_nobody_elses(self):
        self.assertEqual(hardening.CSP_FRAMES, "frame-ancestors 'self'")      # a fresh install trusts only itself
        client, store = make_client(site={"owner_url": "https://ahmadmesto.com"})
        try:
            frames = [v for k, v in client.get("/").headers.multi_items()
                      if k == "content-security-policy" and v.startswith("frame-ancestors")]
            self.assertEqual(frames, ["frame-ancestors 'self' https://ahmadmesto.com https://www.ahmadmesto.com"])
        finally:
            store.close()

    def test_enforce_mode_swaps_the_header_name(self):
        client, store = make_client(site={"csp": "enforce"})
        try:
            r = client.get("/")
            # Two enforced policies: framing, and everything else. Browsers apply both.
            policies = r.headers.get_list("content-security-policy")
            self.assertEqual(len(policies), 2)
            self.assertTrue(any(p.startswith("frame-ancestors") for p in policies))
            self.assertTrue(any("default-src 'self'" in p for p in policies))
            self.assertNotIn("content-security-policy-report-only", r.headers)
        finally:
            store.close()

    def test_the_index_is_cacheable_for_a_minute(self):
        self.assertIn("max-age=60", self.client.get("/").headers["cache-control"])


class HeadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_head_matches_get_without_a_body(self):
        for path in ("/", "/feed/index.json", "/feed/attackers-7d.txt", "/og.png", "/api/stats",
                     "/favicon.svg", "/robots.txt"):
            g, h = self.client.get(path), self.client.head(path)
            self.assertEqual(h.status_code, 200, path)
            self.assertEqual(h.content, b"", f"HEAD {path} sent a body")
            self.assertEqual(h.headers["content-type"], g.headers["content-type"], path)
            self.assertEqual(h.headers.get("content-length"), g.headers.get("content-length"), path)
            self.assertIn("strict-transport-security", h.headers)

    def test_head_on_a_missing_page_is_404(self):
        self.assertEqual(self.client.head("/no-such-page").status_code, 404)


class CorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_public_data_is_readable_from_other_sites(self):
        for path in ("/feed/index.json", "/feed/attackers-7d.txt", "/feed/status.json",
                     "/api/blocklist", "/api/wordlist"):
            r = self.client.get(path)
            self.assertEqual(r.headers.get("access-control-allow-origin"), "*", path)
            self.assertIn("ETag", r.headers.get("access-control-expose-headers", ""), path)

    def test_the_rate_limited_and_writing_endpoints_are_not(self):
        for path in ("/", "/api/lookup?ip=8.8.4.4", "/api/stats", "/api/boards"):
            self.assertNotIn("access-control-allow-origin", self.client.get(path).headers, path)

    def test_preflight_for_the_feeds(self):
        r = self.client.options("/feed/index.json", headers={
            "Origin": "https://example.org", "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "if-none-match"})
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.headers["access-control-allow-origin"], "*")
        self.assertIn("If-None-Match", r.headers["access-control-allow-headers"])

    def test_preflight_for_the_report_endpoint_is_refused(self):
        r = self.client.options("/api/report", headers={
            "Origin": "https://example.org", "Access-Control-Request-Method": "POST"})
        self.assertNotEqual(r.status_code, 204)
        self.assertNotIn("access-control-allow-origin", r.headers)


class SiteFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store = make_client()
        cls.with_contact, cls.store2 = make_client(
            site={"url": "feeds.example.net", "security_contact": "mailto:security@example.org"})

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.store2.close()

    def test_robots_keeps_crawlers_off_the_api_and_names_the_sitemap(self):
        r = self.client.get("/robots.txt")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Disallow: /api/", r.text)
        self.assertIn("Sitemap: https://example.org/sitemap.xml", r.text)      # a fresh install names nobody's site

    def test_the_site_name_follows_the_config_for_a_fork(self):
        self.assertIn("https://feeds.example.net/sitemap.xml", self.with_contact.get("/robots.txt").text)

    def test_sitemap_is_valid_xml(self):
        root = ET.fromstring(self.client.get("/sitemap.xml").content)
        self.assertTrue(root.tag.endswith("urlset"))
        self.assertGreaterEqual(len(list(root)), 1)

    def test_favicon_is_a_valid_svg_in_the_brand_red(self):
        r = self.client.get("/favicon.svg")
        self.assertEqual(r.headers["content-type"], "image/svg+xml")
        ET.fromstring(r.content)
        self.assertIn("#dc2626", r.text)
        redirect = self.client.get("/favicon.ico", follow_redirects=False)
        self.assertEqual((redirect.status_code, redirect.headers["location"]), (308, "/favicon.svg"))

    def test_the_page_links_the_favicon_and_canonical_url(self):
        self.assertIn('rel="icon" href="/favicon.svg"', PAGE)
        self.assertIn('rel="canonical"', PAGE)
        self.assertNotIn("OPEN PORT LOOKS LIKE", PAGE)

    def test_security_txt_is_only_served_when_a_contact_is_configured(self):
        self.assertEqual(self.client.get("/.well-known/security.txt").status_code, 404)
        r = self.with_contact.get("/.well-known/security.txt")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Contact: mailto:security@example.org", r.text)
        self.assertIn("Canonical: https://feeds.example.net/.well-known/security.txt", r.text)
        expires = re.search(r"Expires: (\S+)", r.text).group(1)
        when = dt.datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
        self.assertGreater(when, dt.datetime.now(dt.UTC) + dt.timedelta(days=300))
        alias = self.with_contact.get("/security.txt", follow_redirects=False)
        self.assertEqual(alias.headers["location"], "/.well-known/security.txt")

    def test_security_txt_builder_refuses_an_empty_contact(self):
        for blank in (None, "", "   "):
            self.assertIsNone(sitefiles.security_txt("example.org", blank))


class NotFoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    def test_a_browser_gets_a_page(self):
        r = self.client.get("/no-such-page", headers=self.BROWSER)
        self.assertEqual(r.status_code, 404)
        self.assertTrue(r.headers["content-type"].startswith("text/html"))
        self.assertIn("Nothing at this address", r.text)
        self.assertIn('href="/#intel"', r.text)
        self.assertIn("noindex", r.text)
        self.assertNotIn("<script", r.text)                      # self-contained, nothing to block
        self.assertNotIn("http://", r.text.replace("http://www.w3.org", ""))

    def test_curl_and_programs_still_get_json(self):
        r = self.client.get("/no-such-page", headers={"Accept": "*/*"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.headers["content-type"], "application/json")
        self.assertEqual(r.json(), {"detail": "Not Found"})

    def test_the_api_and_feeds_never_return_the_html_page(self):
        for path in ("/api/no-such", "/feed/no-such.txt"):
            r = self.client.get(path, headers=self.BROWSER)
            self.assertEqual(r.status_code, 404, path)
            self.assertNotIn("<html", r.text.lower(), path)

    def test_a_wrong_method_is_still_a_405_not_a_page(self):
        self.assertEqual(self.client.post("/", headers=self.BROWSER).status_code, 405)


class BrandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.store = make_client()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()

    def test_the_wordlist_header_names_the_project_not_a_placeholder(self):
        text = self.client.get("/api/wordlist").text
        self.assertIn("Uninvited", text.splitlines()[0])
        self.assertNotIn("HONEYPOT", text)

    def test_defaults_carry_the_current_name(self):
        site = Config({})["site"]
        self.assertEqual(site["title"], "Uninvited")
        self.assertNotIn("KNOCKING", repr(site))

    def test_websocket_still_works_behind_the_middleware(self):
        with self.client.websocket_connect("/ws") as ws:
            self.assertEqual(ws.receive_json()["type"], "init")


if __name__ == "__main__":
    unittest.main()
