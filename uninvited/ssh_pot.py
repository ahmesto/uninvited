"""SSH honeypot.

Capturing SSH credentials means completing a real key exchange, so this one
cannot be a dumb socket reader. Paramiko does the transport work on its own
threads; every auth attempt is answered with AUTH_FAILED so a session is never
established, and the knock is pushed back onto the asyncio loop.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
import os
import socket
import threading
from collections.abc import Awaitable, Callable

import paramiko

from .core import Knock

log = logging.getLogger("uninvited.ssh")


def _kexinit_lists(blob: bytes) -> list[str] | None:
    """SSH_MSG_KEXINIT: one byte type, sixteen byte cookie, then name-lists."""
    if not blob or blob[0] != 20:
        return None
    off, lists = 17, []
    for _ in range(10):
        if off + 4 > len(blob):
            break
        n = struct.unpack(">I", blob[off:off + 4])[0]
        off += 4
        if off + n > len(blob):
            break
        lists.append(blob[off:off + n].decode("utf-8", "replace"))
        off += n
    return lists if len(lists) >= 8 else None


def hassh_of(transport) -> tuple[str | None, str | None]:
    """Fingerprint the client's SSH implementation.

    HASSH hashes the algorithms a client offers and the order it offers them
    in, which is a property of the software build rather than the host. It
    survives address rotation completely, so two IPs with the same HASSH are
    running the same binary. That is a far stronger claim than two IPs trying
    the same password, because wordlists are public and binaries are not.
    """
    try:
        blob = getattr(transport, "kex_seen", None) or getattr(transport, "remote_kex_init", None)
        if not blob:
            return None, None
        lists = _kexinit_lists(bytes(blob))
        if not lists:
            return None, None
        kex, _hostkey, enc_c2s, _enc_s2c, mac_c2s = lists[0], lists[1], lists[2], lists[3], lists[4]
        comp_c2s = lists[6]
        raw = ";".join([kex, enc_c2s, mac_c2s, comp_c2s])
        return hashlib.md5(raw.encode()).hexdigest(), raw
    except Exception:
        return None, None

class _Transport(paramiko.Transport):
    """Keeps the client's KEXINIT message. paramiko frees remote_kex_init as soon as the keys are
    exchanged, which is before any login, so without this the fingerprint survived only for
    clients that hung up in the middle of the handshake (about one SSH host in eight)."""

    kex_seen: bytes | None = None

    def _parse_kex_init(self, m):
        super()._parse_kex_init(m)
        self.kex_seen = self.remote_kex_init


# Scanners connect and hang up without speaking SSH, which paramiko reports as
# a full traceback every time. We record those connections ourselves, so the
# stack traces are pure noise. Raise this to WARNING if you need to debug.
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

MAX_ATTEMPTS = 6
AUTH_WINDOW = 30


def load_host_key(path: str) -> paramiko.RSAKey:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    log.info("generating SSH host key at %s", path)
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(path)
    os.chmod(path, 0o600)
    return key


class _Interface(paramiko.ServerInterface):
    def __init__(self, sink: Callable[[str, str, str], None]):
        self.sink = sink
        self.attempts = 0
        self.finished = threading.Event()

    def _record(self, username: str, secret: str, method: str):
        self.attempts += 1
        self.sink(username, secret, method)
        if self.attempts >= MAX_ATTEMPTS:
            self.finished.set()

    def get_allowed_auths(self, username):
        return "password,publickey,keyboard-interactive"

    def check_auth_password(self, username, password):
        self._record(username[:120], password[:120], "password")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        fingerprint = key.get_fingerprint().hex()
        self._record(username[:120], f"<{key.get_name()} {fingerprint[:16]}>", "publickey")
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SshPot:
    def __init__(
        self,
        host: str,
        port: int,
        host_key_path: str,
        banner: str,
        emit: Callable[[Knock], Awaitable[None]],
        loop: asyncio.AbstractEventLoop,
        max_connections: int = 200,
    ):
        # Each session is a thread that can live for AUTH_WINDOW seconds, so an
        # uncapped accept loop lets one scanner burst exhaust memory. Past the
        # ceiling new connections are closed immediately, same as the asyncio
        # listeners do.
        self.slots = threading.BoundedSemaphore(max_connections)
        self.host = host
        self.port = port
        self.banner = banner
        self.emit = emit
        self.loop = loop
        self.key = load_host_key(host_key_path)
        self.stop_event = threading.Event()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(64)
        self.sock.settimeout(1.0)
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        log.info("SSH  listening on %s:%d", self.host, self.port)

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=3)
        if self.sock is not None:
            self.sock.close()

    def _accept_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, addr = self.sock.accept()  # type: ignore[union-attr]
            except TimeoutError:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(
                target=self._session_guarded, args=(conn, addr), daemon=True
            ).start()

    def _session_guarded(self, conn: socket.socket, addr) -> None:
        try:
            self._session(conn, addr)
        finally:
            self.slots.release()

    def _push(self, ip: str, port: int, username: str, secret: str,
              method: str, client: str, hassh: str | None = None) -> None:
        lines = [("client", client or "<none>"), ("auth", method)]
        if hassh:
            lines.append(("hassh", hassh[:16]))
        knock = Knock(
            proto="SSH", ip=ip, port=port,
            username=username, password=secret,
            lines=lines,
            detail={"client_version": client, "auth_method": method,
                    "hassh": hassh},
            hassh=hassh,
        )
        asyncio.run_coroutine_threadsafe(self.emit(knock), self.loop)

    def _push_scan(self, ip: str, port: int, transport) -> None:
        client = ""
        fp, _raw = hassh_of(transport)
        try:
            if transport is not None:
                client = transport.remote_version or ""
        except Exception:
            pass
        knock = Knock(
            proto="SSH", ip=ip, port=port,
            lines=[("probe", "connected, no credentials offered"),
                   ("client", client or "no banner sent")],
            detail={"client_version": client, "scan": True},
            hassh=fp,
        )
        asyncio.run_coroutine_threadsafe(self.emit(knock), self.loop)

    def _session(self, conn: socket.socket, addr) -> None:
        ip, port = addr[0], addr[1]
        transport = None
        iface = None
        try:
            conn.settimeout(AUTH_WINDOW)
            transport = _Transport(conn)
            transport.local_version = self.banner
            transport.add_server_key(self.key)
            active = transport

            def sink(username: str, secret: str, method: str) -> None:
                # Read the client banner at capture time: auth callbacks run on
                # paramiko's own thread and can fire the moment KEX completes.
                self._push(ip, port, username, secret, method,
                           active.remote_version or "",
                           hassh_of(active)[0])

            iface = _Interface(sink)
            transport.start_server(server=iface)
            iface.finished.wait(AUTH_WINDOW)
        except (paramiko.SSHException, EOFError, OSError):
            pass
        except Exception:
            log.exception("SSH session error from %s", ip)
        finally:
            # No auth attempt means this was a banner grab or a port scan,
            # which is the bulk of what lands on port 22. Log it either way.
            if iface is None or iface.attempts == 0:
                self._push_scan(ip, port, transport)
            try:
                if transport is not None:
                    transport.close()
                conn.close()
            except OSError:
                pass
