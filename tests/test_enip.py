"""The EtherNet/IP decoy: encapsulation rules, the listener, and a real client (pycomm3) against it."""
import asyncio
import logging
import random
import struct
import threading
import time
import unittest

from uninvited import enip
from uninvited.listeners import EnipListener

IDENT = enip.Identity()
CTX = b"12345678"


def encap(command, data=b"", session=0, context=CTX):
    return enip.frame(command, session, context, data)


def head(raw):
    return enip.parse_header(raw[:24])


def cip(service, class_id, instance, attribute=None, data=b""):
    path = bytes([0x20, class_id, 0x24, instance]) + (bytes([0x30, attribute]) if attribute is not None else b"")
    return bytes([service, len(path) // 2]) + path + data


def rr_data(cip_bytes):
    return (struct.pack("<IHH", 0, 5, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip_bytes)) + cip_bytes)


def register(session_out=None):
    return encap(0x0065, struct.pack("<HH", 1, 0))


def run(raw, session=None):
    h = head(raw)
    return enip.handle(h, raw[24:], session, IDENT)


class EncapsulationTests(unittest.TestCase):
    def test_header_parse_and_limits(self):
        raw = encap(0x0063)
        self.assertEqual(head(raw)["command"], 0x0063)
        self.assertIsNone(enip.parse_header(b"short"))
        big = enip.HEADER.pack(0x6F, 5000, 0, 0, CTX, 0)
        self.assertIsNone(enip.parse_header(big))

    def test_list_identity_has_one_item_with_the_configured_identity(self):
        r = run(encap(0x0063))
        data = r.reply[24:]
        self.assertEqual(struct.unpack("<H", data[:2])[0], 1)
        type_id, length = struct.unpack("<HH", data[2:6])
        self.assertEqual((type_id, length), (0x000C, len(data) - 6))
        item = data[6:]
        self.assertEqual(item[2:4], b"\x00\x02")                      # socket family, big endian
        self.assertEqual(item[4:6], struct.pack(">H", 44818))
        self.assertEqual(item[6:10], bytes(4))                        # the address advertised is 0.0.0.0
        self.assertIn(b"1756-L61/B LOGIX5561", item)
        self.assertEqual(r.reply[12:20], CTX)                         # the sender context comes back
        self.assertEqual(r.info["ics"], "identity")

    def test_the_vm_address_is_never_put_in_the_identity_by_default(self):
        self.assertEqual(enip.Identity().advertise_ip, "0.0.0.0")
        self.assertEqual(enip.Identity.from_cfg({"advertise_ip": "not an ip"}).advertise_ip, "0.0.0.0")
        self.assertEqual(enip.Identity.from_cfg({"advertise_ip": "203.0.113.9"}).advertise_ip, "203.0.113.9")

    def test_list_services_and_interfaces(self):
        data = run(encap(0x0004)).reply[24:]
        self.assertIn(b"Communications", data)
        self.assertEqual(struct.unpack("<H", run(encap(0x0064)).reply[24:])[0], 0)

    def test_register_session_gives_a_nonzero_handle_and_echoes_the_body(self):
        r = run(register())
        handle_id = struct.unpack("<I", r.reply[4:8])[0]
        self.assertNotEqual(handle_id, 0)
        self.assertEqual(r.info["registered"], handle_id)
        self.assertEqual(r.reply[24:], struct.pack("<HH", 1, 0))

    def test_a_bad_protocol_version_is_refused(self):
        r = run(encap(0x0065, struct.pack("<HH", 7, 0)))
        self.assertEqual(struct.unpack("<I", r.reply[8:12])[0], enip.ENC_BAD_VERSION)

    def test_unregister_closes_without_a_reply(self):
        r = run(encap(0x0066))
        self.assertIsNone(r.reply)
        self.assertTrue(r.close)

    def test_unknown_command_is_an_error_frame(self):
        r = run(encap(0x7777))
        self.assertEqual(struct.unpack("<I", r.reply[8:12])[0], enip.ENC_BAD_COMMAND)

    def test_cip_needs_a_registered_session(self):
        raw = encap(0x006F, rr_data(cip(0x01, 1, 1)), session=99)
        self.assertEqual(struct.unpack("<I", run(raw, session=None).reply[8:12])[0], enip.ENC_BAD_SESSION)
        self.assertEqual(struct.unpack("<I", run(raw, session=5).reply[8:12])[0], enip.ENC_BAD_SESSION)
        self.assertEqual(struct.unpack("<I", run(encap(0x006F, rr_data(cip(0x01, 1, 1)), session=5), session=5).reply[8:12])[0], 0)


class CipTests(unittest.TestCase):
    def ask(self, request):
        return enip.handle_cip(request, IDENT)

    def test_identity_object_read_returns_all_attributes(self):
        reply, info = self.ask(cip(0x01, 1, 1))
        self.assertEqual(reply[:4], bytes([0x81, 0, 0, 0]))
        self.assertEqual(reply[4:], enip.identity_attributes(IDENT))
        self.assertEqual(info["ics"], "identity")

    def test_single_attributes(self):
        for attr, expect in ((1, struct.pack("<H", 1)), (3, struct.pack("<H", 55)), (4, bytes((20, 11))),
                             (7, bytes([len(IDENT.name)]) + IDENT.name.encode())):
            reply, _ = self.ask(cip(0x0E, 1, 1, attr))
            self.assertEqual(reply[4:], expect, attr)
        self.assertEqual(self.ask(cip(0x0E, 1, 1, 99))[0][2], enip.UNKNOWN_PATH)

    def test_writes_resets_starts_and_stops_are_acknowledged_and_labelled(self):
        for service, label in ((0x10, "write"), (0x02, "write"), (0x4D, "write"),
                               (0x05, "control"), (0x06, "control"), (0x07, "control")):
            reply, info = self.ask(cip(service, 1, 1, 3, b"\x01"))
            self.assertEqual((reply[2], info["ics"], info["write"]), (0, label, True), hex(service))

    def test_the_file_object_means_a_program_transfer(self):
        _reply, info = self.ask(cip(0x4B, 0x37, 1))
        self.assertEqual((info["ics"], info["write"]), ("program", True))

    def test_unknown_services_are_refused_as_a_device_would(self):
        reply, info = self.ask(cip(0x99, 0x77, 1))
        self.assertEqual(reply[2], enip.NOT_SUPPORTED)
        self.assertFalse(info["write"])

    def test_an_unconnected_send_is_unwrapped(self):
        inner = cip(0x01, 1, 1)
        body = bytes([5, 10]) + struct.pack("<H", len(inner)) + inner + (b"\x00" if len(inner) % 2 else b"") + bytes([1, 0, 1, 0])
        wrapped = cip(0x52, 6, 1, None, body)
        reply, info = self.ask(wrapped)
        self.assertEqual(reply[4:], enip.identity_attributes(IDENT))
        self.assertEqual((info["ics"], info["via"]), ("identity", "Unconnected_Send"))

    def test_nesting_is_one_level_only(self):
        inner = cip(0x52, 6, 1, None, bytes([5, 10, 2, 0, 1, 1]))
        body = bytes([5, 10]) + struct.pack("<H", len(inner)) + inner
        reply, _info = self.ask(cip(0x52, 6, 1, None, body))
        self.assertEqual(reply[2], enip.NOT_SUPPORTED)

    def test_two_byte_class_and_instance_paths(self):
        path = bytes([0x21, 0, 0x01, 0x00, 0x25, 0, 0x01, 0x00])
        reply, _info = self.ask(bytes([0x01, len(path) // 2]) + path)
        self.assertEqual(reply[4:], enip.identity_attributes(IDENT))


class RobustnessTests(unittest.TestCase):
    def test_garbage_never_raises_and_never_answers_big(self):
        rnd = random.Random(5)
        for _ in range(4000):
            cmd = rnd.choice([0x63, 0x04, 0x64, 0x65, 0x66, 0x6F, 0x70, rnd.randrange(0x10000)])
            payload = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 80)))
            h = {"command": cmd, "length": len(payload), "session": rnd.choice([0, 5]), "status": 0,
                 "context": CTX, "options": 0}
            r = enip.handle(h, payload, rnd.choice([None, 5]), IDENT)
            self.assertTrue(r.reply is None or len(r.reply) < 600)

    def test_truncated_rr_data_and_lying_item_lengths(self):
        for body in (b"", bytes(15), struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0xB2, 9999) + b"\x01"):
            r = enip.handle({"command": 0x6F, "length": len(body), "session": 5, "status": 0, "context": CTX, "options": 0},
                            body, 5, IDENT)
            self.assertIsNotNone(r.reply)


class ServerThread:
    def __init__(self):
        self.knocks = []
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop

        async def emit(k):
            self.knocks.append(k)

        async def main():
            l = EnipListener({"port": 0}, emit, asyncio.Semaphore(10))
            l.server = await asyncio.start_server(l._wrap, "127.0.0.1", 0)
            self.port = l.server.sockets[0].getsockname()[1]
            self.stop = asyncio.Event()
            self.ready.set()
            await self.stop.wait()
            l.server.close()

        loop.run_until_complete(main())

    def __enter__(self):
        self.thread.start()
        self.ready.wait(5)
        return self

    def __exit__(self, *exc):
        self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(3)


try:
    from pycomm3 import CIPDriver
except Exception:
    CIPDriver = None


@unittest.skipUnless(CIPDriver, "pycomm3 not installed")
class RealClientTests(unittest.TestCase):
    """An independent EtherNet/IP implementation, written by other people, against the decoy."""

    def test_a_real_client_identifies_the_device_and_everything_is_logged(self):
        logging.disable(logging.CRITICAL)
        try:
            with ServerThread() as srv:
                addr = f"127.0.0.1:{srv.port}"
                identity = CIPDriver.list_identity(addr)
                self.assertEqual((identity["vendor"], identity["product_type"], identity["product_code"]),
                                 ("Rockwell Automation/Allen-Bradley", "Programmable Logic Controller", 55))
                self.assertEqual((identity["revision"], identity["product_name"], identity["serial"]),
                                 ({"major": 20, "minor": 11}, "1756-L61/B LOGIX5561", "00a1b2c3"))
                drv = CIPDriver(addr)
                self.assertTrue(drv.open())
                info = drv.get_module_info(0)
                self.assertEqual(info["product_name"], "1756-L61/B LOGIX5561")
                kw = {"connected": False, "unconnected_send": False, "route_path": False}
                self.assertIsNone(drv.generic_message(service=0x10, class_code=1, instance=1, attribute=3,
                                                      request_data=b"\x01\x00", **kw).error)
                self.assertIsNone(drv.generic_message(service=0x07, class_code=1, instance=1, **kw).error)
                drv.close()
                time.sleep(0.3)
        finally:
            logging.disable(logging.NOTSET)
        labels = [(k.detail.get("ics"), k.detail.get("write")) for k in srv.knocks]
        self.assertIn(("identity", False), labels)
        self.assertIn(("write", True), labels)
        self.assertIn(("control", True), labels)
        self.assertTrue(any(k.detail.get("via") == "Unconnected_Send" for k in srv.knocks))


class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.knocks = []

        async def emit(k):
            self.knocks.append(k)

        self.l = EnipListener({"port": 0}, emit, asyncio.Semaphore(10))
        self.l.server = await asyncio.start_server(self.l._wrap, "127.0.0.1", 0)
        self.port = self.l.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.l.server.close()
        await self.l.server.wait_closed()

    async def test_reads_are_capped_in_the_log_but_writes_always_log(self):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(encap(0x0065, struct.pack("<HH", 1, 0)))
        await w.drain()
        reply = await asyncio.wait_for(r.read(100), 2)
        session = struct.unpack("<I", reply[4:8])[0]
        frames = [encap(0x0063)] * 20 + [encap(0x006F, rr_data(cip(0x10, 1, 1, 3, b"\x01")), session=session)]
        w.write(b"".join(frames))
        await w.drain()
        await asyncio.sleep(0.6)
        w.close()
        await asyncio.sleep(0.05)
        writes = [k for k in self.knocks if k.detail.get("ics") == "write"]
        non_writes = [k for k in self.knocks if k.detail.get("ics") != "write"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(len(non_writes), EnipListener.MAX_READS_LOGGED)

    async def test_the_frame_limit_closes_the_connection(self):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(encap(0x0004) * (EnipListener.MAX_FRAMES + 10))
        await w.drain()
        total = b""
        while True:
            chunk = await asyncio.wait_for(r.read(8192), 3)
            if not chunk:
                break
            total += chunk
        w.close()
        self.assertEqual(len(total) % len(run(encap(0x0004)).reply), 0)
        self.assertEqual(len(total) // len(run(encap(0x0004)).reply), EnipListener.MAX_FRAMES)

    async def test_http_on_the_port_is_logged_as_not_enip(self):
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: scan\r\n\r\n")
        await w.drain()
        await asyncio.sleep(0.3)
        w.close()
        await asyncio.sleep(0.05)
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])
        self.assertIn("not EtherNet/IP", self.knocks[0].lines[0][1])

    async def test_an_oversized_length_field_is_refused_before_any_big_read(self):
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(enip.HEADER.pack(0x6F, 60000, 0, 0, CTX, 0))
        await w.drain()
        await asyncio.sleep(0.3)
        w.close()
        await asyncio.sleep(0.05)
        self.assertTrue(self.knocks[0].detail["scan"])

    async def test_connect_and_leave_is_a_scan(self):
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.close()
        await asyncio.sleep(0.3)
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])


if __name__ == "__main__":
    unittest.main()
