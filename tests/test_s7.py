"""The S7comm decoy: frame rules, the listener, and a real S7 client (python-snap7) against it."""
import asyncio
import random
import struct
import threading
import time
import unittest

from uninvited import s7
from uninvited.listeners import S7Listener

IDENT = s7.Identity()


def job(pduref, params, data=b""):
    return struct.pack(">BBHHHH", 0x32, 1, 0, pduref, len(params), len(data)) + params + data


def setup_comm(pdu=480):
    return job(1, struct.pack(">BBHHH", 0xF0, 0, 1, 1, pdu))


def read_var(items):
    params = bytes([0x04, len(items)])
    for tsize, count, db, area, addr in items:
        params += bytes([0x12, 0x0A, 0x10, tsize]) + struct.pack(">HH", count, db) + bytes([area]) + (addr * 8).to_bytes(3, "big")
    return job(2, params)


def write_var(db, addr, value: bytes):
    params = bytes([0x05, 1, 0x12, 0x0A, 0x10, 0x02]) + struct.pack(">HH", len(value), db) + bytes([0x84]) + (addr * 8).to_bytes(3, "big")
    data = b"\x00\x04" + struct.pack(">H", len(value) * 8) + value
    return job(3, params, data)


def szl(szl_id, index=0):
    params = bytes([0, 1, 0x12, 4, 0x11, 0x44, 0x01, 0])
    data = bytes([0x0A, 0, 0, 4]) + struct.pack(">HH", szl_id, index)
    return struct.pack(">BBHHHH", 0x32, 7, 0, 4, len(params), len(data)) + params + data


def stop():
    return job(5, bytes.fromhex("29000000000009") + b"P_PROGRAM")


def start():
    return job(6, bytes.fromhex("2800000000000000fd0000") + b"\x09P_PROGRAM")


def insert_block():
    return job(7, bytes.fromhex("2800000000000000fd000a") + b"\x01_INSE")


class FrameTests(unittest.TestCase):
    def test_tpkt_header(self):
        self.assertEqual(s7.parse_tpkt(b"\x03\x00\x00\x16"), 22)
        for bad in (b"\x04\x00\x00\x16", b"\x03\x01\x00\x16", b"\x03\x00\x00\x03", b"\x03\x00\xff\xff", b"\x03\x00"):
            self.assertIsNone(s7.parse_tpkt(bad), bad)

    # A real connection request: length, type CR, destination ref, source ref, class, then options.
    CR_BODY = bytes([0x11, 0xE0, 0, 0, 0, 1, 0]) + bytes.fromhex("c1020100c2020102c0010a")

    def test_connection_confirm_echoes_the_clients_choices(self):
        cr = bytes([0x11, 0xE0, 0, 0, 0x12, 0x34, 0]) + bytes.fromhex("c1020200c2020103c0010b")
        cc = s7.cotp_confirm(cr)
        self.assertEqual(cc[:2], b"\x03\x00")
        self.assertEqual(struct.unpack(">H", cc[2:4])[0], len(cc))
        body = cc[4:]
        self.assertEqual(body[0], len(body) - 1)
        self.assertEqual(body[1], 0xD0)
        self.assertEqual(body[2:4], b"\x12\x34")            # the client's reference, sent back
        self.assertIn(b"\xc1\x02\x02\x00", body)            # its own choices echoed, not defaults
        self.assertIn(b"\xc2\x02\x01\x03", body)
        self.assertIn(b"\xc0\x01\x0b", body)
        self.assertEqual(s7.cotp_type(body), "other")       # a confirm is not a request

    def test_connection_request_fields(self):
        parsed = s7.parse_cr(self.CR_BODY)
        self.assertEqual(parsed, {"tsap_src": "0100", "tsap_dst": "0102", "tpdu_size": "0a"})
        self.assertEqual(s7.parse_cr(b"\x06\xe0\x00\x00\x00\x01\x00"), {})
        self.assertEqual(s7.parse_cr(bytes([0x0A, 0xE0, 0, 0, 0, 1, 0]) + bytes.fromhex("c1ff0100")), {})   # truncated option

    def test_cotp_types(self):
        self.assertEqual(s7.cotp_type(b"\x02\xf0\x80"), "DT")
        self.assertEqual(s7.cotp_type(b"\x11\xe0"), "CR")
        self.assertEqual(s7.cotp_type(b"\x02\x80"), "DR")
        self.assertEqual(s7.cotp_type(b"\x02"), "bad")


class PduTests(unittest.TestCase):
    def test_setup_negotiates_a_pdu_size_and_echoes_the_reference(self):
        r = s7.handle(setup_comm(960), IDENT)
        self.assertEqual(r.reply[1], s7.ROSCTR_ACK_DATA)
        self.assertEqual(struct.unpack(">H", r.reply[4:6])[0], 1)
        self.assertEqual(struct.unpack(">H", r.reply[-2:])[0], 240)
        self.assertEqual((r.info["ics"], r.info["write"]), ("read", False))

    def test_read_returns_zeros_of_the_requested_size(self):
        r = s7.handle(read_var([(0x02, 4, 1, 0x84, 0)]), IDENT)
        self.assertEqual(r.reply[-8:], b"\xff\x04\x00\x20\x00\x00\x00\x00")
        self.assertEqual(r.info["area"], "DB1 +0 x4")
        self.assertFalse(r.info["write"])

    def test_read_sizes_are_capped_per_item_and_in_total(self):
        r = s7.handle(read_var([(0x02, 60000, 1, 0x84, 0)]), IDENT)
        self.assertLessEqual(len(r.reply), 12 + 2 + 4 + s7.MAX_READ_BYTES)
        many = s7.handle(read_var([(0x02, 200, 1, 0x84, 0)] * 20), IDENT)
        self.assertLessEqual(len(many.reply), 12 + 2 + s7.MAX_READ_TOTAL + 20 * 5)

    def test_odd_sized_items_are_padded_except_the_last(self):
        r = s7.handle(read_var([(0x02, 3, 1, 0x84, 0), (0x02, 3, 1, 0x84, 0)]), IDENT)
        data = r.reply[14:]
        self.assertEqual(data, b"\xff\x04\x00\x18" + bytes(3) + b"\x00" + b"\xff\x04\x00\x18" + bytes(3))

    def test_a_write_is_acknowledged_and_labelled(self):
        r = s7.handle(write_var(1, 8, b"\x01\x02"), IDENT)
        self.assertEqual(r.reply[-3:], b"\x05\x01\xff")
        self.assertEqual((r.info["ics"], r.info["write"], r.info["area"], r.info["value"]),
                         ("write", True, "DB1 +8 x2", "0102"))

    def test_stop_and_start_are_control(self):
        for frame, name in ((stop(), "PLC Stop"), (start(), "PLC Control")):
            r = s7.handle(frame, IDENT)
            self.assertEqual((r.info["ics"], r.info["write"], r.info["name"], r.info["pi"]),
                             ("control", True, name, "P_PROGRAM"))
            self.assertEqual(len(r.reply), 12 + 1)

    def test_block_transfer_is_program(self):
        r = s7.handle(insert_block(), IDENT)
        self.assertEqual((r.info["ics"], r.info["pi"]), ("program", "_INSE"))
        for fc in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F):
            self.assertEqual(s7.handle(job(9, bytes([fc])), IDENT).info["ics"], "program")

    def test_unknown_function_gets_the_error_a_cpu_gives(self):
        r = s7.handle(job(9, b"\x77"), IDENT)
        self.assertEqual(r.reply[10:12], b"\x81\x04")


class SzlTests(unittest.TestCase):
    def payload(self, szl_id):
        r = s7.handle(szl(szl_id), IDENT)
        self.assertEqual(r.reply[1], s7.ROSCTR_USERDATA)
        self.assertEqual(r.info["ics"], "identity")
        data = r.reply[10 + 12:]
        self.assertEqual(data[:2], b"\xff\x09")
        self.assertEqual(struct.unpack(">H", data[2:4])[0], len(data) - 4)
        return data[4:]

    def test_component_identification_has_six_34_byte_records(self):
        p = self.payload(0x001C)
        self.assertEqual(struct.unpack(">HH", p[4:8]), (34, 6))
        self.assertEqual(len(p), 8 + 34 * 6)
        self.assertEqual(p[10:15], b"PLC_1")                  # record 1 string, where clients read the system name
        self.assertEqual(p[8 + 34 * 5: 8 + 34 * 5 + 2], b"\x00\x07")

    def test_module_identification_carries_order_code_and_firmware(self):
        p = self.payload(0x0011)
        self.assertEqual(struct.unpack(">HH", p[4:8]), (28, 3))
        records = [p[8 + 28 * i: 8 + 28 * (i + 1)] for i in range(3)]
        self.assertTrue(all(len(r) == 28 for r in records))
        self.assertEqual(records[0][2:22].rstrip(b"\x00"), b"6ES7 315-2EH14-0AB0")
        self.assertEqual(records[2][-4:], b"V\x03\x02\x06")

    def test_the_other_known_lists(self):
        for szl_id in (0x0000, 0x0131, 0x0232):
            self.assertGreater(len(self.payload(szl_id)), 8)

    def test_an_unknown_list_gets_an_error_not_silence(self):
        r = s7.handle(szl(0x0424), IDENT)
        self.assertEqual(r.reply[1], s7.ROSCTR_USERDATA)
        self.assertEqual(r.reply[22], 0x81)

    def test_identity_is_configurable_and_bounded(self):
        ident = s7.Identity.from_cfg({"as_name": "X" * 99, "firmware": "V4.1.2", "plant": "Line 9"})
        self.assertEqual(len(ident.as_name), 24)
        self.assertEqual(ident.firmware, (4, 1, 2))
        r = s7.handle(szl(0x001C), ident)
        self.assertIn(b"Line 9", r.reply)


class RobustnessTests(unittest.TestCase):
    def test_garbage_never_raises_and_never_answers_big(self):
        rnd = random.Random(11)
        for _ in range(4000):
            data = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 60)))
            if rnd.random() < 0.6 and data:
                data = b"\x32" + data[1:]
            r = s7.handle(data, IDENT)
            self.assertTrue(r.reply is None or len(r.reply) < 700)

    def test_lengths_that_lie_are_refused(self):
        frame = bytearray(read_var([(0x02, 4, 1, 0x84, 0)]))
        frame[6:8] = b"\xff\xff"                                # claims 65535 bytes of parameters
        self.assertIsNone(s7.handle(bytes(frame), IDENT).reply)
        self.assertIsNone(s7.handle(read_var([(0x02, 4, 1, 0x84, 0)])[:-3], IDENT).reply)

    def test_a_read_request_with_no_valid_item_is_an_error_not_a_crash(self):
        r = s7.handle(job(2, b"\x04\x01" + bytes(12)), IDENT)
        self.assertEqual(r.reply[10:12], b"\x81\x04")


class ServerThread:
    """Runs a listener in its own event loop so a blocking client can talk to it."""

    def __init__(self, cfg=None):
        self.knocks = []
        self.cfg = cfg or {}
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop

        async def emit(k):
            self.knocks.append(k)

        async def main():
            l = S7Listener(dict(self.cfg, port=0), emit, asyncio.Semaphore(10))
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
    from snap7.client import Client as Snap7Client
except Exception:
    Snap7Client = None


@unittest.skipUnless(Snap7Client, "python-snap7 not installed")
class RealClientTests(unittest.TestCase):
    """An independent S7 implementation, written by other people, against the decoy."""

    def test_a_real_client_reads_the_identity_and_everything_is_logged(self):
        with ServerThread() as srv:
            c = Snap7Client()
            c.connect("127.0.0.1", 0, 1, tcp_port=srv.port)
            info = c.get_cpu_info()
            self.assertEqual((info.ASName, info.ModuleName, info.ModuleTypeName),
                             (b"PLC_1", b"CPU 315-2 PN/DP", b"CPU 315-2 PN/DP"))
            self.assertEqual(info.Copyright, b"Original Siemens Equipment")
            order = c.get_order_code()
            self.assertEqual((order.OrderCode, (order.V1, order.V2, order.V3)), (b"6ES7 315-2EH14-0AB0", (3, 2, 6)))
            self.assertEqual(bytes(c.db_read(1, 0, 4)), bytes(4))
            c.db_write(1, 0, bytearray([1, 2, 3, 4]))
            c.plc_stop()
            c.plc_hot_start()
            c.disconnect()
            time.sleep(0.3)
        labels = [(k.detail.get("ics"), k.detail.get("write")) for k in srv.knocks if not k.detail.get("scan")]
        self.assertIn(("identity", False), labels)
        self.assertIn(("read", False), labels)
        self.assertIn(("write", True), labels)
        self.assertEqual(labels.count(("control", True)), 2)
        self.assertTrue(any(k.detail.get("scan") and k.detail.get("tsap_dst") for k in srv.knocks))


class SocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.knocks = []

        async def emit(k):
            self.knocks.append(k)

        self.l = S7Listener({"port": 0}, emit, asyncio.Semaphore(10))
        self.l.server = await asyncio.start_server(self.l._wrap, "127.0.0.1", 0)
        self.port = self.l.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.l.server.close()
        await self.l.server.wait_closed()

    CR = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")

    @staticmethod
    def dt(pdu):
        return s7.cotp_data(pdu)

    async def exchange(self, *frames, wait=0.2):
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        out = []
        for f in frames:
            w.write(f)
            await w.drain()
            try:
                out.append(await asyncio.wait_for(r.read(2000), 2))
            except TimeoutError:
                out.append(None)
        await asyncio.sleep(wait)
        w.close()
        await asyncio.sleep(0.05)
        return out

    async def test_a_full_conversation(self):
        out = await self.exchange(self.CR, self.dt(setup_comm()), self.dt(szl(0x001C)), self.dt(write_var(1, 0, b"\x07")),
                                  self.dt(stop()))
        self.assertTrue(out[0].startswith(b"\x03\x00") and out[0][5] == 0xD0)
        self.assertEqual(out[1][4:7], b"\x02\xf0\x80")
        self.assertEqual(out[1][7], 0x32)
        events = [(k.detail.get("ics"), k.detail.get("scan", False)) for k in self.knocks]
        self.assertEqual(events[0], (None, True))                       # the connection request, a scan row
        self.assertEqual([e[0] for e in events[1:]], ["read", "identity", "write", "control"])
        self.assertTrue(all(not e[1] for e in events[1:]))              # each real request counts as engaged

    async def test_reads_are_capped_in_the_log_but_writes_always_log(self):
        frames = [self.CR, self.dt(setup_comm())] + [self.dt(read_var([(0x02, 1, 1, 0x84, 0)]))] * 20 + [self.dt(write_var(1, 0, b"\x01"))]
        _r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(b"".join(frames))
        await w.drain()
        await asyncio.sleep(0.6)
        w.close()
        await asyncio.sleep(0.05)
        reads = [k for k in self.knocks if k.detail.get("ics") == "read"]
        writes = [k for k in self.knocks if k.detail.get("ics") == "write"]
        self.assertEqual(len(reads), S7Listener.MAX_READS_LOGGED)
        self.assertEqual(len(writes), 1)

    async def test_the_frame_limit_closes_the_connection(self):
        frames = b"".join([self.dt(setup_comm())] * (S7Listener.MAX_FRAMES + 10))
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(frames)
        await w.drain()
        total = b""
        while True:
            chunk = await asyncio.wait_for(r.read(4096), 3)
            if not chunk:
                break
            total += chunk
        w.close()
        self.assertEqual(len(total), S7Listener.MAX_FRAMES * 27)    # 4 TPKT + 3 COTP + 12 header + 8 params each

    async def test_http_on_the_port_is_logged_as_not_s7(self):
        await self.exchange(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])
        self.assertIn("not S7comm", self.knocks[0].lines[0][1])

    async def test_connect_and_leave_is_a_scan(self):
        await self.exchange()
        self.assertEqual(len(self.knocks), 1)
        self.assertTrue(self.knocks[0].detail["scan"])

    async def test_a_disconnect_request_ends_the_conversation(self):
        await self.exchange(self.CR, bytes.fromhex("0300000a02800000000000")[:7], wait=0.1)
        self.assertEqual(len(self.knocks), 1)


if __name__ == "__main__":
    unittest.main()
