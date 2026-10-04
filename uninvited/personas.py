"""Device personas for the web decoys: an IP camera, a router and an AI tool server.

Pure functions that turn one parsed HTTP request into one canned reply. No sockets,
no files, nothing executed. Three rules hold for every persona:

  1. Credentials are never accepted. A login always fails, so the decoy never grants
     access, which is what the site tells visitors.
  2. An exploit that works on the real device is answered with the reply the real
     device would give, because the second stage (the command, the download URL) is
     what is worth capturing. The request is only ever logged.
  3. Replies are small and fixed. Nothing here can be made to produce a large answer.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

# The model names a decoy uses when the config sets none. They are public with this code, so a
# sensor that keeps them can be found by searching for them (configcheck warns about it).
CAM_MODEL = "IPC-2100"
ROUTER_MODEL = "WR-1200"

REASONS = {200: "OK", 202: "Accepted", 302: "Found", 401: "Unauthorized", 403: "Forbidden",
           404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests"}

DIGEST_USER = re.compile(r'username="([^"]{0,120})"', re.I)


@dataclass
class HttpRequest:
    target: str                      # the request line, as received, capped
    method: str
    path: str                        # path and query, capped
    headers: dict[str, str]
    body: bytes
    raw: bytes                       # head plus body as received, capped for storage
    user: str | None = None
    password: str | None = None
    auth: str = ""                   # "basic", "digest" or ""

    @property
    def route(self) -> str:
        """The path without its query string, lower case."""
        return self.path.split("?", 1)[0].lower()


@dataclass
class Reply:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html"
    headers: list[tuple[str, str]] = field(default_factory=list)

    def render(self, server: str) -> bytes:
        head = [f"HTTP/1.1 {self.status} {REASONS.get(self.status, 'OK')}",
                f"Server: {server}",
                f"Content-Type: {self.content_type}",
                f"Content-Length: {len(self.body)}",
                "Connection: close"]
        head += [f"{k}: {v}" for k, v in self.headers]
        return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1", "replace") + self.body


def parse_auth(headers: dict[str, str]) -> tuple[str | None, str | None, str]:
    """(user, password, scheme) from an Authorization header. A Basic login carries
    the password. A Digest login carries only the user name and a hash, so the
    password stays unknown and is not guessed."""
    import base64
    value = headers.get("authorization", "")
    low = value.lower()
    if low.startswith("basic "):
        try:
            decoded = base64.b64decode(value[6:], validate=True).decode("utf-8", "replace")
        except Exception:
            return None, None, "basic"
        user, _, password = decoded.partition(":")
        return user[:120], password[:120], "basic"
    if low.startswith("digest "):
        m = DIGEST_USER.search(value)
        return (m.group(1) if m else None), None, "digest"
    return None, None, ""


def _html(title: str, body: str) -> bytes:
    return (f"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>"
            f"<body>{body}</body></html>").encode()


def _challenge_digest(realm: str) -> list[tuple[str, str]]:
    nonce = os.urandom(16).hex()
    return [("WWW-Authenticate",
             f'Digest realm="{realm}", qop="auth", nonce="{nonce}", stale="FALSE"')]


def _challenge_basic(realm: str) -> list[tuple[str, str]]:
    return [("WWW-Authenticate", f'Basic realm="{realm}"')]


def not_found(server: str) -> Reply:
    return Reply(404, _html("404 Not Found",
                            f"<center><h1>404 Not Found</h1></center><hr><center>{server}</center>"))


# --------------------------------------------------------------------- camera

HIK_NS = "http://www.hikvision.com/ver20/XMLSchema"


def camera(req: HttpRequest, cfg: dict) -> tuple[Reply, dict]:
    """A network camera web server in the style of the most common vendor. Returns
    the reply and extra fields for the log."""
    model = str(cfg.get("model", CAM_MODEL))[:40]
    route = req.route

    if req.method == "PUT" and route == "/sdk/weblanguage":
        # The reply a vulnerable camera gives when the injected command ran.
        body = (f'<?xml version="1.0" encoding="UTF-8"?>\n<ResponseStatus version="1.0" xmlns="{HIK_NS}">'
                '<requestURL>/SDK/webLanguage</requestURL><statusCode>1</statusCode>'
                '<statusString>OK</statusString><subStatusCode>ok</subStatusCode></ResponseStatus>')
        return Reply(200, body.encode(), "application/xml"), {"emulated": "hikvision-weblanguage"}

    if route.startswith("/security/users"):
        body = (f'<?xml version="1.0" encoding="UTF-8"?>\n<UserList version="1.0" xmlns="{HIK_NS}">'
                '<User><id>1</id><userName>admin</userName><priority>high</priority>'
                '<userLevel>Administrator</userLevel></User></UserList>')
        return Reply(200, body.encode(), "application/xml"), {"emulated": "hikvision-users"}

    if route in ("/", "/index.html", "/doc/page/login.asp", "/login.asp"):
        page = _html("Network Camera",
                     f'<div id="login"><h2>{model}</h2><form method="post" action="/ISAPI/Security/sessionLogin">'
                     '<input name="userName" type="text" placeholder="User Name">'
                     '<input name="password" type="password" placeholder="Password">'
                     '<button type="submit">Login</button></form></div>')
        return Reply(200, page), {}

    if route.startswith(("/isapi/", "/onvif", "/streaming/", "/system/", "/picture", "/sdk/")):
        return (Reply(401, _html("401", "Unauthorized"), headers=_challenge_digest(model)),
                {"challenge": "digest"})

    if route.startswith(("/cgi-bin/", "/snapshot", "/video", "/mjpeg", "/axis-cgi/", "/live", "/image",
                         "/rpc2")):
        return (Reply(401, _html("401", "Unauthorized"), headers=_challenge_basic(model)),
                {"challenge": "basic"})

    return not_found(str(cfg.get("server", "App-webs/"))), {}


# Which vendor a stream path belongs to. Scanners ask for the path of the camera
# they hope to find, so the path is evidence of what they are hunting.
RTSP_VENDOR_PATHS = (
    ("/streaming/channels", "hikvision"),
    ("realmonitor", "dahua"),
    ("/h264/ch", "hikvision-or-clone"),
    ("/live/ch", "generic-dvr"),
    ("axis-media", "axis"),
    ("/cam/", "generic"),
    ("/onvif", "onvif"),
    ("/ch0_", "generic-dvr"),
)
RTSP_PUBLIC = "OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN"


def rtsp(req: HttpRequest, cfg: dict) -> tuple[bytes, dict]:
    """A camera's RTSP port. OPTIONS is answered, everything else asks for a login
    and is refused. No media is ever served."""
    model = str(cfg.get("model", CAM_MODEL))[:40]
    # CSeq is echoed back, so it must be digits only: it is attacker-controlled and
    # a newline in it would let a client inject headers into our own reply.
    cseq = req.headers.get("cseq", "0")
    cseq = cseq if re.fullmatch(r"\d{1,9}", cseq) else "0"
    path = req.path.lower()
    hint = next((v for key, v in RTSP_VENDOR_PATHS if key in path), "")
    extra = {"service": "rtsp"}
    if hint:
        extra["vendor_hint"] = hint
    if req.method.upper() == "OPTIONS":
        head = f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nPublic: {RTSP_PUBLIC}\r\n\r\n"
    else:
        nonce = os.urandom(16).hex()
        head = (f"RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n"
                f'WWW-Authenticate: Digest realm="{model}", nonce="{nonce}"\r\n\r\n')
    return head.encode("latin-1"), extra


# --------------------------------------------------------------------- router

def router(req: HttpRequest, cfg: dict, service: str = "web") -> tuple[Reply, dict]:
    """A consumer router: its web interface, or its TR-069 management port."""
    model = str(cfg.get("model", ROUTER_MODEL))[:40]
    route = req.route

    if service == "tr069":
        if route.startswith(("/ud/act", "/ctrlt/", "/tr064")):
            body = ('<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV='
                    '"http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body></SOAP-ENV:Body>'
                    '</SOAP-ENV:Envelope>')
            return Reply(200, body.encode(), "text/xml"), {"emulated": "tr069-soap"}
        return (Reply(401, b"", "text/plain", headers=_challenge_digest(model)),
                {"challenge": "digest"})

    if route.startswith("/hnap1"):
        body = ('<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap='
                '"http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetDeviceSettingsResponse '
                'xmlns="http://purenetworks.com/HNAP1/"><GetDeviceSettingsResult>OK'
                '</GetDeviceSettingsResult></GetDeviceSettingsResponse></soap:Body></soap:Envelope>')
        return Reply(200, body.encode(), "text/xml"), {"emulated": "hnap"}

    if route.startswith("/gponform/"):
        return Reply(200, b"", "text/html"), {"emulated": "gpon"}

    if route.startswith("/boaform/"):
        return Reply(200, _html("Login", "<p>Invalid username or password.</p>")), {}

    if route in ("/login", "/login.cgi", "/login.asp", "/cgi-bin/luci", "/cgi-bin/luci/") or \
            route.startswith("/cgi-bin/luci"):
        page = _html(model, f'<h3>{model}</h3><form method="post" action="/login.cgi">'
                            '<input name="username"><input name="password" type="password">'
                            '<button>Log in</button></form>')
        return Reply(200, page), {}

    if route in ("/", "/index.html", "/admin", "/admin/"):
        return (Reply(401, _html("401 Unauthorized", "Unauthorized"), headers=_challenge_basic(model)),
                {"challenge": "basic"})

    return not_found(str(cfg.get("server", "mini_httpd/1.19"))), {}


# ----------------------------------------------------------------- AI endpoint

TOOLS = [
    {"name": "read_file", "description": "Read a file from the workspace",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "list_directory", "description": "List the files in a directory",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "run_command", "description": "Run a shell command in the workspace",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
]


def _rpc(msg_id, result=None, error=None) -> Reply:
    doc = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        doc["error"] = error
    else:
        doc["result"] = result
    return Reply(200, json.dumps(doc, separators=(",", ":")).encode(), "application/json")


def _json(status: int, doc) -> Reply:
    return Reply(status, json.dumps(doc, separators=(",", ":")).encode(), "application/json")


def mcp(req: HttpRequest, cfg: dict) -> tuple[Reply, dict, str | None]:
    """A Model Context Protocol server and the model endpoints scanners look for next
    to it. Returns the reply, extra log fields, and a label when the request is more
    than discovery."""
    name = str(cfg.get("name", "workspace-tools"))[:40]
    model = str(cfg.get("model", "llama3.1:8b"))[:40]
    route = req.route.rstrip("/") or "/"

    if route == "/sse" and req.method == "GET":
        sid = os.urandom(8).hex()
        body = f"event: endpoint\r\ndata: /messages?sessionId={sid}\r\n\r\n".encode()
        return Reply(200, body, "text/event-stream",
                     headers=[("Cache-Control", "no-cache")]), {"service": "sse"}, None

    if route in ("/mcp", "/api/mcp", "/messages") and req.method == "POST":
        try:
            msg = json.loads(req.body.decode("utf-8", "replace"))
        except ValueError:
            return _rpc(None, error={"code": -32700, "message": "Parse error"}), {"service": "mcp"}, None
        if not isinstance(msg, dict):
            return _rpc(None, error={"code": -32600, "message": "Invalid Request"}), {"service": "mcp"}, None
        method = str(msg.get("method", ""))[:60]
        mid = msg.get("id") if isinstance(msg.get("id"), (int, str)) else None
        extra = {"service": "mcp", "rpc_method": method}
        if "id" not in msg:                       # a notification gets no answer body
            return Reply(202, b"", "application/json"), extra, None
        if method == "initialize":
            return _rpc(mid, {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                              "serverInfo": {"name": name, "version": "0.3.1"}}), extra, None
        if method == "tools/list":
            return _rpc(mid, {"tools": TOOLS}), extra, None
        if method == "tools/call":
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            tool = str(params.get("name", ""))[:60]
            args = json.dumps(params.get("arguments", {}), separators=(",", ":"))[:200]
            extra.update(tool=tool, arguments=args)
            return (_rpc(mid, {"isError": True,
                               "content": [{"type": "text", "text": "Error: permission denied"}]}),
                    extra, "MCP Tool Call Attempt")
        return _rpc(mid, error={"code": -32601, "message": "Method not found"}), extra, None

    if route == "/v1/models" and req.method == "GET":
        return _json(200, {"object": "list", "data": [
            {"id": model, "object": "model", "owned_by": "library"}]}), {"service": "openai"}, None
    if route == "/api/tags" and req.method == "GET":
        return _json(200, {"models": [{"name": model, "model": model, "size": 4920753328}]}), \
            {"service": "ollama"}, None
    if route == "/api/version" and req.method == "GET":
        return _json(200, {"version": "0.5.1"}), {"service": "ollama"}, None
    if route in ("/v1/chat/completions", "/v1/completions", "/api/chat", "/api/generate") \
            and req.method == "POST":
        # Someone using a model that is not theirs. The prompt is in the raw capture.
        return (_json(429, {"error": {"message": "Rate limit reached for requests",
                                      "type": "rate_limit_error"}}),
                {"service": "llm"}, "LLM Endpoint Abuse")

    return not_found("uvicorn"), {}, None
