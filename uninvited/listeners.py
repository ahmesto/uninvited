"""Low-interaction protocol listeners.

Every listener follows the same contract: read a bounded amount of data,
extract whatever intelligence the protocol hands over for free, emit a Knock,
hang up. Nothing an attacker sends is ever executed, written to disk as a file,
or used to build a shell command. Reads are capped and every connection has a
hard timeout so a slowloris cannot pin memory.
"""
from __future__ import annotations

import asyncio
import base64
import contextvars
import logging
import re
import time
from typing import Any
from collections.abc import Awaitable, Callable

from . import dnp3, droppers, enip, intel, modbus, payload, personas, s7, tlsfp
from .core import Knock

log = logging.getLogger("uninvited.listen")

EmitFn = Callable[[Knock], Awaitable[None]]

MAX_LINE = 2048
CONN_TIMEOUT = 20

# Per-connection emit counter. Each connection runs in its own asyncio task, so
# a ContextVar gives every handler a private copy without threading a counter
# through every converse() signature.
_emitted: contextvars.ContextVar = contextvars.ContextVar("emitted", default=None)


def _printable(raw: bytes, limit: int = 128) -> str:
    text = raw.decode("utf-8", "replace")
    text = "".join(ch if ch.isprintable() else "." for ch in text)
    return text[:limit]


class LineReader:
    """Bounded line reader that never buffers more than one long line."""

    def __init__(self, reader: asyncio.StreamReader, timeout: int = CONN_TIMEOUT):
        self.reader = reader
        self.timeout = timeout
        self.buf = b""

    async def readline(self) -> bytes | None:
        while b"\n" not in self.buf:
            if len(self.buf) >= MAX_LINE:
                line, self.buf = self.buf[:MAX_LINE], b""
                return line
            chunk = await asyncio.wait_for(self.reader.read(512), self.timeout)
            if not chunk:
                if self.buf:
                    line, self.buf = self.buf, b""
                    return line
                return None
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        return line.rstrip(b"\r")

    async def peek(self, n: int, wait: float = 3.0) -> bytes:
        """Up to n bytes, left in the buffer for the next read. The first byte gets the
        usual timeout; once something has arrived the rest gets `wait` seconds."""
        while len(self.buf) < n:
            try:
                chunk = await asyncio.wait_for(self.reader.read(n - len(self.buf)),
                                               wait if self.buf else self.timeout)
            except TimeoutError:
                if self.buf:
                    break
                raise
            if not chunk:
                break
            self.buf += chunk
        return self.buf[:n]

    async def take(self, n: int, wait: float = 3.0) -> bytes:
        """Up to n more bytes, buffered ones first. A client that promised a
        body and stopped sending costs `wait` seconds, then we use what arrived."""
        out, self.buf = self.buf[:n], self.buf[n:]
        while len(out) < n:
            try:
                chunk = await asyncio.wait_for(self.reader.read(n - len(out)), wait)
            except (TimeoutError, ConnectionError):
                break
            if not chunk:
                break
            out += chunk
        return out


class Listener:
    """Base class. Subclasses implement converse()."""

    proto = "TCP"

    def __init__(self, cfg: dict[str, Any], emit: EmitFn, limiter: asyncio.Semaphore):
        self.cfg = cfg
        self._emit = emit
        self.limiter = limiter
        self.port = int(cfg["port"])
        self.server: asyncio.AbstractServer | None = None

    async def start(self, host: str) -> None:
        self.server = await asyncio.start_server(self._wrap, host, self.port)
        log.info("%-4s listening on %s:%d", self.proto, host, self.port)

    async def stop(self) -> None:
        if self.server is None:
            return
        self.server.close()
        try:
            # wait_closed() blocks until every in-flight connection finishes.
            # A scanner holding a Telnet session open will happily stall that
            # forever, so shutdown gets a hard ceiling and drops the rest.
            await asyncio.wait_for(self.server.wait_closed(), 3)
        except TimeoutError:
            log.warning("%s had connections still open at shutdown", self.proto)

    async def emit(self, knock: Knock) -> None:
        counter = _emitted.get()
        if counter is not None:
            counter[0] += 1
        await self._emit(knock)

    async def _wrap(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip, port = (peer[0], peer[1]) if peer else ("0.0.0.0", 0)
        if self.limiter.locked():
            writer.close()
            return
        counter = [0]
        _emitted.set(counter)
        async with self.limiter:
            try:
                await asyncio.wait_for(
                    self.converse(LineReader(reader), writer, ip, port),
                    CONN_TIMEOUT + 10,
                )
            except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                pass
            except Exception:
                log.exception("%s handler blew up on %s", self.proto, ip)
            finally:
                # A connection that sent nothing is a port scan, and scans are
                # most of what a honeypot sees. Record it rather than dropping
                # it just because no credentials showed up.
                if counter[0] == 0:
                    try:
                        await self._emit(self.knock(
                            ip, port,
                            lines=[("probe", "port scan, no data sent")],
                            detail={"scan": True},
                        ))
                    except Exception:
                        pass
                try:
                    writer.close()
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

    async def converse(self, lines: LineReader, writer, ip: str, port: int) -> None:
        raise NotImplementedError

    def knock(self, ip: str, port: int, **kwargs) -> Knock:
        return Knock(proto=self.proto, ip=ip, port=port, **kwargs)

    @staticmethod
    async def send(writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        await writer.drain()


# --------------------------------------------------------------------- telnet

IAC = 0xFF


def strip_iac(raw: bytes) -> bytes:
    """Drop telnet option negotiation so it does not end up in a username."""
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == IAC:
            if i + 1 < len(raw) and raw[i + 1] in (250, 251, 252, 253, 254):
                i += 3
                continue
            i += 2
            continue
        if raw[i] >= 32 or raw[i] in (9,):
            out.append(raw[i])
        i += 1
    return bytes(out)


class TelnetListener(Listener):
    proto = "TNET"

    async def converse(self, lines, writer, ip, port):
        banner = self.cfg.get("banner", "\r\nUbuntu 22.04.5 LTS\r\n")
        # Refuse the client's option offers, then act like a login prompt.
        await self.send(writer, bytes([IAC, 252, 1, IAC, 252, 3]))
        await self.send(writer, banner.encode() + b"\r\n")

        attempts = 0
        while attempts < 3:
            await self.send(writer, b"login: ")
            raw_user = await lines.readline()
            if raw_user is None:
                break
            await self.send(writer, b"Password: ")
            raw_pass = await lines.readline()
            if raw_pass is None:
                raw_pass = b""

            user = strip_iac(raw_user).decode("utf-8", "replace").strip()
            password = strip_iac(raw_pass).decode("utf-8", "replace").strip()
            await self.emit(self.knock(ip, port, username=user, password=password))
            attempts += 1
            await asyncio.sleep(1.0)
            await self.send(writer, b"\r\nLogin incorrect\r\n")


# ------------------------------------------------------------------------ ftp


class FtpListener(Listener):
    proto = "FTP"

    async def converse(self, lines, writer, ip, port):
        banner = self.cfg.get("banner", "220 (vsFTPd 3.0.5)")
        await self.send(writer, banner.encode() + b"\r\n")

        user = ""
        commands = 0
        while commands < 12:
            raw = await lines.readline()
            if raw is None:
                return
            commands += 1
            line = raw.decode("utf-8", "replace").strip()
            verb, _, arg = line.partition(" ")
            verb = verb.upper()

            if verb == "USER":
                user = arg.strip()
                await self.send(writer, b"331 Please specify the password.\r\n")
            elif verb == "PASS":
                await self.emit(
                    self.knock(ip, port, username=user, password=arg.strip())
                )
                await asyncio.sleep(0.8)
                await self.send(writer, b"530 Login incorrect.\r\n")
            elif verb == "AUTH":
                await self.send(writer, b"530 Please login with USER and PASS.\r\n")
            elif verb == "SYST":
                await self.send(writer, b"215 UNIX Type: L8\r\n")
            elif verb == "FEAT":
                await self.send(writer, b"211-Features:\r\n UTF8\r\n211 End\r\n")
            elif verb == "QUIT":
                await self.send(writer, b"221 Goodbye.\r\n")
                return
            else:
                await self.send(writer, b"530 Please login with USER and PASS.\r\n")


# ----------------------------------------------------------------------- smtp


class SmtpListener(Listener):
    proto = "SMTP"

    async def converse(self, lines, writer, ip, port):
        banner = self.cfg.get("banner", "220 mail.local ESMTP Postfix (Ubuntu)")
        await self.send(writer, banner.encode() + b"\r\n")

        helo = ""
        mail_from = ""
        commands = 0
        while commands < 20:
            raw = await lines.readline()
            if raw is None:
                return
            commands += 1
            line = raw.decode("utf-8", "replace").strip()
            verb, _, arg = line.partition(" ")
            verb = verb.upper()

            if verb in ("EHLO", "HELO"):
                helo = arg.strip()[:80]
                await self.send(
                    writer,
                    b"250-mail.local\r\n250-PIPELINING\r\n"
                    b"250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n",
                )
            elif verb == "AUTH":
                await self._auth(lines, writer, ip, port, arg.strip(), helo)
            elif verb == "MAIL":
                mail_from = arg[5:].strip("<> ")[:120] if arg[:5].upper() == "FROM:" else arg[:120]
                await self.send(writer, b"250 2.1.0 Ok\r\n")
            elif verb == "RCPT":
                rcpt = arg[3:].strip("<> ")[:120] if arg[:3].upper() == "TO:" else arg[:120]
                # An open-relay probe. Worth logging on its own.
                await self.emit(
                    self.knock(
                        ip, port,
                        lines=[
                            ("probe", "open relay test"),
                            ("mail from", mail_from or "<empty>"),
                            ("rcpt to", rcpt),
                            ("helo", helo or "<none>"),
                        ],
                        detail={"helo": helo, "mail_from": mail_from, "rcpt_to": rcpt},
                    )
                )
                await self.send(writer, b"554 5.7.1 Relay access denied\r\n")
            elif verb == "QUIT":
                await self.send(writer, b"221 2.0.0 Bye\r\n")
                return
            elif verb == "DATA":
                await self.send(writer, b"554 5.5.1 Error: no valid recipients\r\n")
            else:
                await self.send(writer, b"502 5.5.2 Error: command not recognized\r\n")

    @staticmethod
    def _b64(raw: bytes) -> str:
        try:
            return base64.b64decode(raw, validate=True).decode("utf-8", "replace")[:120]
        except Exception:
            return raw.decode("utf-8", "replace")[:120]

    async def _auth(self, lines, writer, ip, port, arg: str, helo: str):
        mech, _, inline = arg.partition(" ")
        mech = mech.upper()
        user = password = ""

        if mech == "PLAIN":
            blob = inline.strip()
            if not blob:
                await self.send(writer, b"334 \r\n")
                raw = await lines.readline()
                blob = (raw or b"").decode("utf-8", "replace")
            decoded = self._b64(blob.encode())
            parts = decoded.split("\x00")
            if len(parts) >= 3:
                user, password = parts[1], parts[2]
            else:
                user, password = decoded, ""
        elif mech == "LOGIN":
            await self.send(writer, b"334 VXNlcm5hbWU6\r\n")  # "Username:"
            user = self._b64((await lines.readline()) or b"")
            await self.send(writer, b"334 UGFzc3dvcmQ6\r\n")  # "Password:"
            password = self._b64((await lines.readline()) or b"")
        else:
            await self.send(writer, b"504 5.7.4 Unrecognized authentication type\r\n")
            return

        await self.emit(
            self.knock(
                ip, port, username=user, password=password,
                lines=[("mechanism", f"AUTH {mech}"), ("helo", helo or "<none>")],
                detail={"mechanism": mech, "helo": helo},
            )
        )
        await asyncio.sleep(0.8)
        await self.send(writer, b"535 5.7.8 Error: authentication failed\r\n")


# ----------------------------------------------------------------------- http

# Ordered most-specific first. Each entry is (regex, exploit name, purpose).
HTTP_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"\.env(\.|$|\?)|/\.env|env\.(bak|local|prod|save|old|dev)"),
     "DotEnv File Exposure", "data exfiltration"),
    (re.compile(r"/\.git/(config|HEAD|index)"),
     "Git Repository Exposure", "source code disclosure"),
    (re.compile(r"/\.(aws/credentials|ssh/id_rsa|npmrc|docker/config\.json)"),
     "Credential File Exposure", "secret harvesting"),
    (re.compile(r"\$\{jndi:", re.I), "Log4Shell (CVE-2021-44228)", "remote code execution"),
    (re.compile(r"/vendor/phpunit/.*eval-stdin\.php", re.I),
     "PHPUnit eval-stdin RCE", "remote code execution"),
    (re.compile(r"/_ignition/execute-solution", re.I),
     "Laravel Ignition RCE (CVE-2021-3129)", "remote code execution"),
    (re.compile(r"/actuator/(env|heapdump|health|beans)", re.I),
     "Spring Boot Actuator Exposure", "config disclosure"),
    (re.compile(r"/solr/.*(admin/info|dataimport)", re.I),
     "Apache Solr Probe", "remote code execution"),
    (re.compile(r"/manager/(html|text)|/host-manager/", re.I),
     "Tomcat Manager Probe", "credential attack"),
    (re.compile(r"/wp-(login\.php|admin|content|includes)|/xmlrpc\.php", re.I),
     "WordPress Probe", "credential attack"),
    (re.compile(r"/(phpmyadmin|pma|myadmin|phpMyAdmin)", re.I),
     "phpMyAdmin Probe", "credential attack"),
    # Cameras and routers. These are the exploits botnets actually send to them, and
    # the first two have a CVE that one request signature pins down exactly.
    (re.compile(r"/SDK/webLanguage", re.I),
     "Hikvision RCE (CVE-2021-36260)", "remote code execution"),
    (re.compile(r"/(Security/users|onvif-http/snapshot|System/configurationFile)\?auth=", re.I),
     "Hikvision Auth Bypass (CVE-2017-7921)", "credential theft"),
    (re.compile(r"/ctrlt/DeviceUpgrade_1", re.I),
     "Huawei HG532 RCE (CVE-2017-17215)", "botnet recruitment"),
    (re.compile(r"/UD/act\?1", re.I), "TR-064 Router Exploit", "botnet recruitment"),
    (re.compile(r"/GponForm/", re.I), "GPON Router Exploit", "botnet recruitment"),
    (re.compile(r"/tmUnblock\.cgi", re.I), "Linksys Router Exploit", "botnet recruitment"),
    (re.compile(r"/boaform/admin/formLogin|/HNAP1/|/cgi-bin/ViewLog\.asp", re.I),
     "IoT Router Exploit", "botnet recruitment"),
    (re.compile(r"/(ISAPI/|onvif/device_service|cgi-bin/(magicBox|configManager)\.cgi|RPC2_Login"
                 r"|axis-cgi/|snapshot\.cgi|hi3510/)", re.I),
     "IP Camera Probe", "camera hijack"),
    # Scanners looking for AI tooling: Model Context Protocol servers and model APIs.
    (re.compile(r"^/(mcp|sse|messages)(/|\?|\s|$)|/api/mcp|/\.well-known/mcp"
                r"|/v1/(models|chat/completions|completions)|/api/(tags|generate|chat|version)(\s|\?|$)",
                re.I),
     "MCP/LLM Endpoint Discovery", "AI endpoint discovery"),
    (re.compile(r"/cgi-bin/.*(luci|nas_sharing|supervisor)", re.I),
     "Embedded Device RCE", "botnet recruitment"),
    (re.compile(r"/api/v1/(namespaces|pods)|/version\?timeout", re.I),
     "Kubernetes API Probe", "cluster reconnaissance"),
    (re.compile(r"/(config|setup|install)\.php|/adminer\.php", re.I),
     "Installer Script Probe", "takeover attempt"),
    (re.compile(r"/(backup|dump|db)\.(sql|zip|tar\.gz|gz)$", re.I),
     "Backup Archive Hunt", "data exfiltration"),
    (re.compile(r"/(shell|cmd|eval|sh)\?|/\?XDEBUG_SESSION_START", re.I),
     "Webshell Probe", "remote code execution"),
    (re.compile(r"/owa/|/autodiscover/autodiscover\.xml", re.I),
     "Exchange Probe", "mailbox takeover"),
    (re.compile(r"/remote/(login|fgt_lang)|/\+CSCOE\+/", re.I),
     "VPN Appliance Probe", "perimeter breach"),
    # Seen on the live site: scanners reading a build's dependency lists, an Apache Ignite
    # REST probe, GeoServer, and Prometheus-style metrics pages.
    (re.compile(r"/ignite\?cmd=", re.I), "Apache Ignite Probe", "reconnaissance"),
    (re.compile(r"/geoserver/", re.I), "GeoServer Probe", "reconnaissance"),
    (re.compile(r"/(pom\.xml|build\.gradle|requirements\.txt|Gemfile(\.lock)?|composer\.(json|lock)"
                 r"|package(-lock)?\.json|yarn\.lock|Pipfile(\.lock)?)(\?|\s|$)", re.I),
     "Dependency File Hunt", "source code disclosure"),
    (re.compile(r"/(metrics|debug/pprof|debug/vars|server-status|prometheus)(/|\?|\s|$)", re.I),
     "Metrics Endpoint Probe", "config disclosure"),
    # A shell command smuggled into a request: a download tool, a shell, or a command that
    # reads a secret file. Last of the specific rules, so a named exploit keeps its name.
    (re.compile(r"(?:[;|&`=]|\$\()\s*(?:/\S{0,40}/)?(?:wget|curl|tftp|ftpget|busybox|chmod|nc|bash|sh)\s"
                r"|(?:[;|&`]|\$\()\s*(?:cat\s+/etc/passwd|uname|whoami)\b|/bin/(?:ba)?sh\s+-c", re.I),
     "Shell Command Injection", "remote code execution"),
]

SHELLSHOCK = re.compile(r"\(\s*\)\s*\{")
ROOT_PATH = re.compile(r"/+")


KNOWN_METHODS = frozenset({
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND",
    "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH", "REPORT", "PRI",
})
MGLNDD = re.compile(r"^MGLNDD_")

# What purpose to record for the labels a persona decides on its own.
PERSONA_PURPOSE = {
    "MCP Tool Call Attempt": "tool abuse",
    "LLM Endpoint Abuse": "resource abuse",
    "RTSP Stream Probe": "camera hijack",
}


class HttpListener(Listener):
    """The generic web decoy. A persona (camera, router, AI tool server) is a
    subclass that changes only respond(); reading, capture and classification are
    shared, so every persona records the same things."""

    proto = "HTTP"

    async def read_request(self, lines) -> personas.HttpRequest | None:
        request = await lines.readline()
        if not request:
            return None
        req = request.decode("utf-8", "replace").strip()[:512]
        parts = req.split(" ")
        method = parts[0][:10] if parts else "?"
        path = parts[1][:300] if len(parts) > 1 else "/"

        headers: dict[str, str] = {}
        header_lines: list[bytes] = []
        for _ in range(40):
            raw = await lines.readline()
            if raw is None or raw == b"":
                break
            header_lines.append(raw)
            name, _, value = raw.decode("utf-8", "replace").partition(":")
            headers[name.strip().lower()] = value.strip()[:400]

        # The head of the request as sent, then up to what is left of the 4 KB
        # budget as body. Log-only, see payload.py.
        head = request + b"\r\n" + b"\r\n".join(header_lines) + b"\r\n\r\n"
        body = b""
        try:
            declared = int(headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > 0:
            body = await lines.take(min(declared, max(payload.MAX_RAW - len(head), 0)))

        user, password, scheme = personas.parse_auth(headers)
        return personas.HttpRequest(
            target=req, method=method, path=path, headers=headers, body=body,
            raw=(head + body)[:payload.MAX_RAW], user=user, password=password, auth=scheme)

    def classify(self, req: personas.HttpRequest, text: str | None = None,
                 drops: list | None = None) -> tuple[str, str]:
        """-> (name, purpose). Static rules, in order: scanners hunting for an open
        proxy, the HTTP/2 preface, one known scanner banner, a TLS or SOCKS opening sent
        to a plain web port, then the exploit table against the path, the header values
        and the start of the body, as sent and with the percent-encoding taken off.

        `text` is the decoded request and `drops` the download URLs in it; both are worked
        out here when not given. A request that carries a download command and matched
        nothing more specific is named for what it is, a malware dropper."""
        if req.method == "CONNECT" or req.path.lower().startswith(("http://", "https://")):
            return "Open Proxy Probe", "proxy abuse"
        if req.method == "PRI" and req.path == "*":
            return "HTTP/2 Prior-Knowledge Probe", "reconnaissance"
        if MGLNDD.match(req.target):
            return "MGLNDD Scanner Banner", "reconnaissance"
        if req.target[:2] == "\x16\x03":
            return "TLS Handshake on Plain HTTP", "reconnaissance"
        if req.target[:1] == "\x05" or req.target[:2] == "\x04\x01":
            return "SOCKS Proxy Probe", "proxy abuse"
        if text is None:
            text = droppers.decode(req.path, req.headers, req.body)
        if drops is None:
            drops = droppers.extract(text)
        haystack = (req.path + " " + " ".join(req.headers.values()) + " "
                    + req.body[:1024].decode("utf-8", "replace"))
        if text != haystack:
            haystack += " " + text
        exploit, purpose = "Unclassified Probe", "reconnaissance"
        for pattern, name, why in HTTP_SIGNATURES:
            if pattern.search(haystack):
                exploit, purpose = name, why
                break
        if SHELLSHOCK.search(haystack):
            exploit, purpose = "Shellshock (CVE-2014-6271)", "remote code execution"
        if (exploit == "Unclassified Probe" and ROOT_PATH.fullmatch(req.path)
                and req.method.upper() in KNOWN_METHODS):
            exploit, purpose = "Root Fingerprint", "reconnaissance"
        if drops and (exploit in intel.GENERIC_EXPLOITS or exploit == "Shell Command Injection"):
            exploit, purpose = "Malware Dropper Command", "malware delivery"
        if exploit == "Unclassified Probe" and req.method.upper() not in KNOWN_METHODS:
            exploit = "Malformed Request"
        return exploit, purpose

    def server_banner(self) -> str:
        return self.cfg.get("server", "nginx/1.24.0 (Ubuntu)")

    def respond(self, req: personas.HttpRequest) -> tuple[personas.Reply, dict, str | None]:
        """-> (reply, extra log fields, a label that overrides the classification)."""
        return personas.not_found(self.server_banner()), {}, None

    async def tls_hello(self, lines, ip, port) -> bool:
        """A client that opens with a TLS ClientHello is talking TLS to a plain web port.
        Read the hello (never answer it), keep its JA3 fingerprint and the server name it
        asked for, and report whether it was one. A first record that does not parse as a
        hello is left in the buffer for the ordinary request reader."""
        head = await lines.peek(5)
        size = tlsfp.record_length(head)
        if size is None:
            return False
        record = await lines.peek(size)
        hello = tlsfp.parse_client_hello(record)
        if hello is None:
            return False
        lines.buf = lines.buf[len(record):]
        digest = tlsfp.ja3(hello)
        feed_lines = [("exploit", "TLS Handshake on Plain HTTP"), ("purpose", "reconnaissance"),
                      ("method", "TLS"), ("ja3", digest)]
        detail = {"method": "TLS", "path": "", "exploit": "TLS Handshake on Plain HTTP",
                  "purpose": "reconnaissance", "ja3": digest, "tls_version": hello.version,
                  "ciphers": len(hello.ciphers), "body_len": 0}
        if hello.sni:
            feed_lines.insert(3, ("sni", hello.sni))
            detail["sni"] = hello.sni
        if hello.alpn:
            detail["alpn"] = hello.alpn
        knock = self.knock(ip, port, lines=feed_lines, detail=detail, raw=record,
                           raw_sig=payload.signature("TLS", digest, b""))
        knock.ja3 = digest
        await self.emit(knock)
        return True

    async def converse(self, lines, writer, ip, port):
        if await self.tls_hello(lines, ip, port):
            return
        req = await self.read_request(lines)
        if req is None:
            return
        text = droppers.decode(req.path, req.headers, req.body)
        drops = droppers.extract(text)
        exploit, purpose = self.classify(req, text, drops)
        reply, extra, label = self.respond(req)
        if label:
            exploit, purpose = label, PERSONA_PURPOSE.get(label, "abuse")
        await self.log_request(req, ip, port, exploit, purpose, extra, drops)
        await self.send(writer, reply.render(self.server_banner()))

    async def log_request(self, req, ip, port, exploit, purpose, extra, drops=()) -> None:
        """One request becomes one knock: what it was, who sent it, and the raw bytes."""
        feed_lines = [
            ("exploit", exploit),
            ("purpose", purpose),
            ("method", req.method),
            ("path", req.path),
        ]
        for key, shown in (("rpc_method", "rpc"), ("tool", "tool"), ("emulated", "emulated"),
                           ("vendor_hint", "vendor")):
            if extra.get(key):
                feed_lines.append((shown, str(extra[key])[:90]))
        for d in drops[:2]:
            feed_lines.append(("dropper", f"{d.host}:{d.port}/{d.file}"[:90]))
        agent = req.headers.get("user-agent")
        if agent:
            feed_lines.append(("agent", agent[:90]))

        detail = {
            "method": req.method,
            "path": req.path,
            "exploit": exploit,
            "purpose": purpose,
            "host": req.headers.get("host", ""),
            "agent": agent or "",
            "body_len": len(req.body),
        }
        if req.auth:
            detail["auth"] = req.auth
        if drops:
            detail["droppers"] = [d.url for d in drops]
        detail.update({k: v for k, v in extra.items() if k not in detail})

        knock = self.knock(
            ip, port, username=req.user, password=req.password,
            lines=feed_lines, detail=detail,
            raw=req.raw,
            raw_sig=payload.signature(req.method, req.path, req.body),
        )
        knock.droppers = list(drops)
        await self.emit(knock)


# ------------------------------------------------------------------------ rdp

MSTSHASH = re.compile(rb"mstshash=([^\r\n\x00]{1,64})")


class RdpListener(Listener):
    proto = "RDP"

    async def converse(self, lines, writer, ip, port):
        raw = await asyncio.wait_for(lines.reader.read(2048), CONN_TIMEOUT)
        if not raw:
            return
        user = None
        match = MSTSHASH.search(raw)
        if match:
            user = match.group(1).decode("utf-8", "replace")[:64]

        feed_lines = [("probe", "X.224 connection request")]
        if user:
            feed_lines.append(("cookie", f"mstshash={user}"))
        if raw[:2] != b"\x03\x00":
            feed_lines = [("probe", "malformed TPKT"), ("bytes", _printable(raw[:32], 48))]

        await self.emit(
            self.knock(ip, port, username=user, lines=feed_lines,
                       detail={"first_bytes": raw[:32].hex()})
        )
        # X.224 negotiation failure: SSL_NOT_ALLOWED_BY_SERVER.
        await self.send(
            writer,
            b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x03\x00\x08\x00\x02\x00\x00\x00",
        )


# ------------------------------------------------------------------------ smb


class SmbListener(Listener):
    proto = "SMB"

    async def converse(self, lines, writer, ip, port):
        raw = await asyncio.wait_for(lines.reader.read(1024), CONN_TIMEOUT)
        if not raw:
            return
        if b"\xffSMB" in raw:
            dialect, note = "SMB1", "legacy dialect, EternalBlue class scanner"
        elif b"\xfeSMB" in raw:
            dialect, note = "SMB2+", "modern negotiate"
        else:
            dialect, note = "unknown", _printable(raw[:32], 48)

        await self.emit(
            self.knock(
                ip, port,
                lines=[("probe", "negotiate protocol"), ("dialect", dialect), ("note", note)],
                detail={"dialect": dialect, "first_bytes": raw[:48].hex()},
            )
        )


# ------------------------------------------------------------------------ sip

SIP_URI = re.compile(r"sip:([^@>;\s]{1,64})@?", re.I)
# Longest-prefix match against E.164 country codes, enough to spot toll fraud
# targets without shipping a full numbering plan.
DIAL_CODES = {
    "1": "North America", "20": "Egypt", "212": "Morocco", "213": "Algeria",
    "216": "Tunisia", "218": "Libya", "220": "Gambia", "221": "Senegal",
    "234": "Nigeria", "237": "Cameroon", "254": "Kenya", "27": "South Africa",
    "297": "Aruba", "30": "Greece", "31": "Netherlands",
    "32": "Belgium", "33": "France", "34": "Spain", "351": "Portugal",
    "352": "Luxembourg", "353": "Ireland", "355": "Albania", "356": "Malta",
    "358": "Finland", "359": "Bulgaria", "36": "Hungary", "370": "Lithuania",
    "371": "Latvia", "372": "Estonia", "373": "Moldova", "374": "Armenia",
    "375": "Belarus", "380": "Ukraine", "381": "Serbia", "385": "Croatia",
    "386": "Slovenia", "387": "Bosnia", "39": "Italy", "40": "Romania",
    "41": "Switzerland", "420": "Czechia", "421": "Slovakia", "43": "Austria",
    "44": "United Kingdom", "45": "Denmark", "46": "Sweden", "47": "Norway",
    "48": "Poland", "49": "Germany", "52": "Mexico", "54": "Argentina",
    "55": "Brazil", "57": "Colombia", "60": "Malaysia", "61": "Australia",
    "62": "Indonesia", "63": "Philippines", "64": "New Zealand", "65": "Singapore",
    "66": "Thailand", "7": "Russia/Kazakhstan", "81": "Japan", "82": "South Korea",
    "84": "Vietnam", "86": "China", "88213": "Satellite", "90": "Turkey",
    "91": "India", "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka",
    "95": "Myanmar", "961": "Lebanon", "962": "Jordan", "963": "Syria",
    "964": "Iraq", "965": "Kuwait", "966": "Saudi Arabia", "971": "UAE",
    "972": "Israel", "973": "Bahrain", "974": "Qatar", "976": "Mongolia",
    "98": "Iran", "992": "Tajikistan", "994": "Azerbaijan", "998": "Uzbekistan",
}


def dial_country(number: str) -> str | None:
    digits = re.sub(r"\D", "", number or "")
    # Scanners dial either +CC or 00CC. Drop the access prefix before matching.
    if digits.startswith("00"):
        digits = digits[2:]
    # Short strings are PBX extensions (1000, 5001), not international dials.
    if len(digits) < 8:
        return None
    for length in range(5, 0, -1):
        if digits[:length] in DIAL_CODES:
            return DIAL_CODES[digits[:length]]
    return None


def parse_sip(raw: bytes) -> tuple[str, dict[str, str]]:
    text = raw.decode("utf-8", "replace")
    head, _, _ = text.partition("\r\n\r\n")
    rows = head.split("\r\n")
    method = rows[0].split(" ")[0][:12] if rows else "?"
    headers: dict[str, str] = {}
    for row in rows[1:]:
        name, _, value = row.partition(":")
        headers[name.strip().lower()] = value.strip()[:200]
    return method, headers


def sip_knock(proto_lines_source: str, method: str, headers: dict[str, str]):
    to_hdr = headers.get("to", "")
    from_hdr = headers.get("from", "")
    to_match = SIP_URI.search(to_hdr)
    from_match = SIP_URI.search(from_hdr)
    target = to_match.group(1) if to_match else ""
    caller = from_match.group(1) if from_match else ""

    feed_lines = [("method", method)]
    if caller:
        feed_lines.append(("from", caller))
    if target:
        feed_lines.append(("to", target))
    country = dial_country(target) if method.upper() == "INVITE" else None
    if country:
        feed_lines.append(("toll call to", country))
    agent = headers.get("user-agent") or headers.get("server")
    if agent:
        feed_lines.append(("agent", agent[:80]))
    detail = {
        "method": method,
        "from": caller,
        "to": target,
        "dial_country": country or "",
        "agent": agent or "",
        "source": proto_lines_source,
    }
    return caller or target or None, feed_lines, detail


class SipListener(Listener):
    proto = "SIP"

    async def converse(self, lines, writer, ip, port):
        raw = await asyncio.wait_for(lines.reader.read(4096), CONN_TIMEOUT)
        if not raw:
            return
        method, headers = parse_sip(raw)
        user, feed_lines, detail = sip_knock("tcp", method, headers)
        await self.emit(
            self.knock(ip, port, username=user, lines=feed_lines, detail=detail)
        )
        await self.send(writer, b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n")


SIP_REFUSAL = b"SIP/2.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n"


class UdpGuard:
    """Limits for a service that answers over UDP.

    A UDP source address can be forged by anyone, so every datagram we answer is a
    packet a stranger can aim at a third party, and every datagram we record is
    work a stranger can make us do for free. Two buckets bound both: a few per
    source per minute, and a ceiling for the whole port. A datagram over either
    limit is dropped without a word."""

    def __init__(self, per_source: int = 5, window: float = 60.0,
                 per_second: float = 40.0, burst: float = 80.0):
        self.per_source, self.window = per_source, window
        self.rate, self.burst = per_second, burst
        self.tokens, self.stamp = burst, None
        self.sources: dict[str, list[float]] = {}

    def allow(self, ip: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        if self.stamp is None:
            self.stamp = now
        self.tokens = min(self.burst, self.tokens + max(0.0, now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens < 1:
            return False
        recent = [t for t in self.sources.get(ip, ()) if now - t < self.window]
        if len(recent) >= self.per_source:
            self.sources[ip] = recent
            return False
        recent.append(now)
        self.sources[ip] = recent
        self.tokens -= 1
        if len(self.sources) > 10000:
            self.sources = {k: v for k, v in self.sources.items()
                            if v and now - v[-1] < self.window}
        return True


class SipUdpProtocol(asyncio.DatagramProtocol):
    """SIP scanners overwhelmingly use UDP, so listen there too.

    UDP sources can be forged, so the port is rate limited (UdpGuard) and never
    sends a reply larger than the datagram it answers, which removes any
    amplification. Nothing from this port is published on the feed."""

    MAX_PENDING = 200     # recordings in flight; past this a datagram is dropped

    def __init__(self, emit: EmitFn, port: int, guard: UdpGuard | None = None):
        self.emit = emit
        self.port = port
        self.guard = guard or UdpGuard()
        self.transport: asyncio.DatagramTransport | None = None
        self._pending: set[asyncio.Task] = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if len(self._pending) >= self.MAX_PENDING or not self.guard.allow(addr[0]):
            return
        method, headers = parse_sip(data[:4096])
        user, feed_lines, detail = sip_knock("udp", method, headers)
        knock = Knock(
            proto="SIP", ip=addr[0], port=addr[1],
            username=user, lines=feed_lines, detail=detail,
        )
        task = asyncio.get_running_loop().create_task(self.emit(knock))
        self._pending.add(task)       # a task nobody refers to can be collected mid-run
        task.add_done_callback(self._pending.discard)
        if self.transport is not None and len(SIP_REFUSAL) < len(data):
            self.transport.sendto(SIP_REFUSAL, addr)


# --------------------------------------------------------------------- modbus


class ModbusListener(Listener):
    """Modbus TCP decoy for a generic small controller.

    Any well-formed request counts as engagement. Each is labelled write,
    identity or read so the feed can tell reconnaissance from manipulation.
    Connecting and leaving, or sending something that is not Modbus, is a scan.
    The frame and answer rules live in modbus.py.
    """

    proto = "MODBUS"
    MAX_FRAMES = 32         # requests served per connection
    MAX_READS_LOGGED = 8    # a scanner looping one read does not flood the table
    WRITE_TIMEOUT = 5

    def __init__(self, cfg: dict[str, Any], emit: EmitFn, limiter: asyncio.Semaphore):
        super().__init__(cfg, emit, limiter)
        self.ident = modbus.Identity.from_cfg(cfg.get("identity"))

    async def converse(self, lines, writer, ip, port):
        reader = lines.reader
        state = modbus.State()
        served = logged = 0
        while served < self.MAX_FRAMES:
            try:
                head = await asyncio.wait_for(reader.readexactly(7), CONN_TIMEOUT)
            except asyncio.IncompleteReadError as exc:
                if exc.partial and served == 0:
                    await self._malformed(ip, port, exc.partial)
                return
            parsed = modbus.parse_mbap(head)
            if parsed is None:
                await self._malformed(ip, port, head)
                return
            tid, length, unit = parsed
            pdu = await asyncio.wait_for(reader.readexactly(length - 1), CONN_TIMEOUT)
            served += 1

            result = modbus.handle(pdu, state, self.ident, time.time())
            info = result.info
            write = info["write"]
            if write or logged < self.MAX_READS_LOGGED:
                logged += 0 if write else 1
                await self.emit(self._request_knock(ip, port, unit, pdu, info))
            await asyncio.wait_for(
                self.send(writer, modbus.frame(tid, unit, result.pdu)),
                self.WRITE_TIMEOUT,
            )

    def _request_knock(self, ip, port, unit, pdu, info):
        feed = [("function", f"{info['name']} (0x{info['fc']:02x})"), ("unit", str(unit))]
        if "addr" in info:
            feed.append(("range", f"{info['addr']} x{info['qty']}"))
        if info["write"]:
            feed.append(("action", "write attempt"))
        # Any well-formed request is deliberate interaction, so it counts as
        # engaged. "ics" says how, and drives the recon / write tags.
        if info["write"]:
            ics = "write"
        elif info["fc"] in (0x11, 0x2B):
            ics = "identity"
        else:
            ics = "read"
        detail = {
            "fc": info["fc"], "unit": unit, "write": info["write"],
            "ics": ics, "first_bytes": pdu[:48].hex(),
        }
        for key in ("addr", "qty", "value", "sub", "read_code", "object", "exception"):
            if key in info:
                detail[key] = info[key]
        return self.knock(ip, port, lines=feed, detail=detail)

    async def _malformed(self, ip, port, raw: bytes):
        await self.emit(self.knock(
            ip, port,
            lines=[("probe", "not Modbus TCP"), ("bytes", _printable(raw[:32], 48))],
            detail={"scan": True, "first_bytes": raw[:32].hex()},
        ))


# ------------------------------------------------------------------------- s7


class S7Listener(Listener):
    """Siemens S7comm decoy for a generic small PLC. Frame and answer rules live in
    s7.py. Same bounds as the Modbus decoy: reads and writes time out, a connection
    serves a limited number of requests, and a looping scanner logs a limited number
    of reads. Writes, stops, starts and block transfers are always logged."""

    proto = "S7"
    MAX_FRAMES = 32
    MAX_READS_LOGGED = 8
    WRITE_TIMEOUT = 5

    def __init__(self, cfg: dict[str, Any], emit: EmitFn, limiter: asyncio.Semaphore):
        super().__init__(cfg, emit, limiter)
        self.ident = s7.Identity.from_cfg(cfg.get("identity"))

    async def converse(self, lines, writer, ip, port):
        reader = lines.reader
        served = logged = 0
        while served < self.MAX_FRAMES:
            try:
                head = await asyncio.wait_for(reader.readexactly(4), CONN_TIMEOUT)
            except asyncio.IncompleteReadError as exc:
                if exc.partial and served == 0:
                    await self._malformed(ip, port, exc.partial)
                return
            length = s7.parse_tpkt(head)
            if length is None:
                await self._malformed(ip, port, head)
                return
            body = await asyncio.wait_for(reader.readexactly(length - 4), CONN_TIMEOUT)
            served += 1
            kind = s7.cotp_type(body)

            if kind == "CR":
                parsed = s7.parse_cr(body)
                await self._write(writer, s7.cotp_confirm(body))
                feed = [("probe", "COTP connection request")]
                if parsed.get("tsap_src") or parsed.get("tsap_dst"):
                    feed.append(("tsap", f"{parsed.get('tsap_src', '?')} to {parsed.get('tsap_dst', '?')}"))
                await self.emit(self.knock(ip, port, lines=feed, detail={"scan": True, **parsed}))
                continue
            if kind == "DR":
                return
            if kind != "DT" or len(body) < 3:
                await self._malformed(ip, port, head + body)
                return

            result = s7.handle(body[3:], self.ident)
            if result.reply is None:
                await self._malformed(ip, port, head + body)
                return
            info = result.info
            if info["write"] or logged < self.MAX_READS_LOGGED:
                logged += 0 if info["write"] else 1
                await self.emit(self._request_knock(ip, port, body[3:], info))
            await self._write(writer, s7.cotp_data(result.reply))

    async def _write(self, writer, data: bytes) -> None:
        await asyncio.wait_for(self.send(writer, data), self.WRITE_TIMEOUT)

    def _request_knock(self, ip, port, pdu: bytes, info: dict):
        feed = [("function", info["name"])]
        for key, label in (("area", "address"), ("szl", "szl"), ("pi", "service")):
            if info.get(key):
                feed.append((label, str(info[key])))
        if info["write"]:
            feed.append(("action", "write or control attempt"))
        detail = {"fc": info["fc"], "write": info["write"], "ics": info["ics"],
                  "first_bytes": pdu[:48].hex()}
        for key in ("area", "szl", "pi", "value", "pdu"):
            if key in info:
                detail[key] = info[key]
        return self.knock(ip, port, lines=feed, detail=detail)

    async def _malformed(self, ip, port, raw: bytes):
        await self.emit(self.knock(
            ip, port,
            lines=[("probe", "not S7comm"), ("bytes", _printable(raw[:32], 48))],
            detail={"scan": True, "first_bytes": raw[:32].hex()},
        ))


# ----------------------------------------------------------------------- enip


class EnipListener(Listener):
    """EtherNet/IP decoy, TCP only, for a generic small controller. Frame and answer
    rules live in enip.py. Same bounds as the other industrial decoys."""

    proto = "ENIP"
    MAX_FRAMES = 32
    MAX_READS_LOGGED = 8
    WRITE_TIMEOUT = 5

    def __init__(self, cfg: dict[str, Any], emit: EmitFn, limiter: asyncio.Semaphore):
        super().__init__(cfg, emit, limiter)
        self.ident = enip.Identity.from_cfg(cfg.get("identity"))

    async def converse(self, lines, writer, ip, port):
        reader = lines.reader
        session = None
        served = logged = 0
        while served < self.MAX_FRAMES:
            try:
                raw = await asyncio.wait_for(reader.readexactly(24), CONN_TIMEOUT)
            except asyncio.IncompleteReadError as exc:
                if exc.partial and served == 0:
                    await self._malformed(ip, port, exc.partial)
                return
            head = enip.parse_header(raw)
            if head is None:
                await self._malformed(ip, port, raw)
                return
            payload = b""
            if head["length"]:
                payload = await asyncio.wait_for(reader.readexactly(head["length"]), CONN_TIMEOUT)
            served += 1

            result = enip.handle(head, payload, session, self.ident)
            if result.info.get("registered"):
                session = result.info["registered"]
            info = result.info
            if info["write"] or logged < self.MAX_READS_LOGGED:
                logged += 0 if info["write"] else 1
                await self.emit(self._request_knock(ip, port, raw + payload, info))
            if result.reply is not None:
                await asyncio.wait_for(self.send(writer, result.reply), self.WRITE_TIMEOUT)
            if result.close:
                return

    def _request_knock(self, ip, port, raw: bytes, info: dict):
        feed = [("command", info["name"])]
        if info.get("service") is not None and info.get("name") != enip.CMD_NAMES.get(info["command"]):
            feed = [("command", enip.CMD_NAMES.get(info["command"], info["name"])), ("service", info["name"])]
        if "class" in info:
            feed.append(("object", f"class 0x{info['class']:02x} instance {info.get('instance', '?')}"))
        if info["write"]:
            feed.append(("action", "write or control attempt"))
        detail = {"command": info["command"], "write": info["write"], "ics": info["ics"],
                  "first_bytes": raw[:48].hex()}
        for key in ("service", "class", "instance", "attribute", "via"):
            if key in info:
                detail[key] = info[key]
        return self.knock(ip, port, lines=feed, detail=detail)

    async def _malformed(self, ip, port, raw: bytes):
        await self.emit(self.knock(
            ip, port,
            lines=[("probe", "not EtherNet/IP"), ("bytes", _printable(raw[:32], 48))],
            detail={"scan": True, "first_bytes": raw[:32].hex()},
        ))


# ----------------------------------------------------------------------- dnp3


class Dnp3Listener(Listener):
    """DNP3 decoy (TCP). Experimental: see dnp3.py for what is and is not verified.
    `address` in the config makes it answer only that outstation address (and the
    broadcast addresses); without it, it answers whatever address is asked for."""

    proto = "DNP3"
    MAX_FRAMES = 32
    MAX_READS_LOGGED = 8
    WRITE_TIMEOUT = 5

    def __init__(self, cfg: dict[str, Any], emit: EmitFn, limiter: asyncio.Semaphore):
        super().__init__(cfg, emit, limiter)
        addr = cfg.get("address")
        self.address = int(addr) & 0xFFFF if addr is not None else None

    async def converse(self, lines, writer, ip, port):
        reader = lines.reader
        served = logged = 0
        while served < self.MAX_FRAMES:
            try:
                raw = await asyncio.wait_for(reader.readexactly(10), CONN_TIMEOUT)
            except asyncio.IncompleteReadError as exc:
                if exc.partial and served == 0:
                    await self._malformed(ip, port, exc.partial)
                return
            head = dnp3.parse_header(raw)
            if head is None:
                await self._malformed(ip, port, raw)
                return
            wire = await asyncio.wait_for(reader.readexactly(dnp3.data_bytes_on_wire(head["length"])), CONN_TIMEOUT)
            data = dnp3.user_data(wire, head["length"])
            if data is None:
                await self._malformed(ip, port, raw + wire)
                return
            served += 1

            result = dnp3.handle(head, data, self.address)
            info = result.info
            if info.get("ignored"):
                await self.emit(self.knock(
                    ip, port, lines=[("probe", "DNP3 frame for another address"), ("address", str(head["dest"]))],
                    detail={"scan": True, "dest": head["dest"], "src": head["src"]}))
            elif info["write"] or logged < self.MAX_READS_LOGGED:
                logged += 0 if info["write"] else 1
                await self.emit(self._request_knock(ip, port, raw + wire, info))
            if result.reply:
                await asyncio.wait_for(self.send(writer, result.reply), self.WRITE_TIMEOUT)

    def _request_knock(self, ip, port, raw: bytes, info: dict):
        feed = [("function", info["name"]), ("address", f"{info['src']} to {info['dest']}")]
        if info["write"]:
            feed.append(("action", "write or control attempt"))
        detail = {"write": info["write"], "ics": info["ics"], "dest": info["dest"], "src": info["src"],
                  "link_function": info["function"], "first_bytes": raw[:48].hex()}
        if "fc" in info:
            detail["fc"] = info["fc"]
        return self.knock(ip, port, lines=feed, detail=detail)

    async def _malformed(self, ip, port, raw: bytes):
        await self.emit(self.knock(
            ip, port,
            lines=[("probe", "not DNP3"), ("bytes", _printable(raw[:32], 48))],
            detail={"scan": True, "first_bytes": raw[:32].hex()},
        ))


# -------------------------------------------------------------- web personas
# Same reading, capture and classification as the generic web decoy, a different
# face. Each is a separate service in the config, on its own port, so a visitor who
# reaches it is looking for that kind of device. See personas.py for the rules.


class CameraListener(HttpListener):
    """An IP camera. service: web (default) or rtsp."""

    proto = "CAM"

    def __init__(self, cfg, emit, limiter):
        super().__init__(cfg, emit, limiter)
        self.service = str(cfg.get("service", "web")).lower()

    def server_banner(self) -> str:
        return self.cfg.get("server", "App-webs/")

    def respond(self, req):
        reply, extra = personas.camera(req, self.cfg)
        return reply, extra, None

    async def converse(self, lines, writer, ip, port):
        if self.service != "rtsp":
            await super().converse(lines, writer, ip, port)
            return
        # RTSP is HTTP-shaped, so the request reads the same way. The answer is
        # always a refusal that asks for a login, and the path says which vendor
        # the scanner is hunting.
        req = await self.read_request(lines)
        if req is None:
            return
        data, extra = personas.rtsp(req, self.cfg)
        await self.log_request(req, ip, port, "RTSP Stream Probe", "camera hijack", extra)
        await self.send(writer, data)


class RouterListener(HttpListener):
    """A consumer router. service: web (default) or tr069 (the management port)."""

    proto = "ROUTER"

    def __init__(self, cfg, emit, limiter):
        super().__init__(cfg, emit, limiter)
        self.service = str(cfg.get("service", "web")).lower()

    def server_banner(self) -> str:
        default = "gSOAP/2.7" if self.service == "tr069" else "mini_httpd/1.19 19dec2003"
        return self.cfg.get("server", default)

    def respond(self, req):
        reply, extra = personas.router(req, self.cfg, self.service)
        return reply, extra, None


class McpListener(HttpListener):
    """An AI tool server (Model Context Protocol) and the model endpoints scanners
    look for beside it."""

    proto = "MCP"

    def server_banner(self) -> str:
        return self.cfg.get("server", "uvicorn")

    def respond(self, req):
        return personas.mcp(req, self.cfg)


LISTENERS: dict[str, type[Listener]] = {
    "TNET": TelnetListener,
    "FTP": FtpListener,
    "SMTP": SmtpListener,
    "HTTP": HttpListener,
    "RDP": RdpListener,
    "SMB": SmbListener,
    "SIP": SipListener,
    "MODBUS": ModbusListener,
    "S7": S7Listener,
    "ENIP": EnipListener,
    "DNP3": Dnp3Listener,
    "CAM": CameraListener,
    "ROUTER": RouterListener,
    "MCP": McpListener,
}
